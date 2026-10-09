//go:build windows

package main

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

var (
	winhttp                     = syscall.NewLazyDLL("winhttp.dll")
	procWinHTTPGetIEProxyConfig = winhttp.NewProc("WinHttpGetIEProxyConfigForCurrentUser")
	procWinHTTPOpen             = winhttp.NewProc("WinHttpOpen")
	procWinHTTPClose            = winhttp.NewProc("WinHttpCloseHandle")
	procWinHTTPTimeouts         = winhttp.NewProc("WinHttpSetTimeouts")
	procWinHTTPGetProxy         = winhttp.NewProc("WinHttpGetProxyForUrl")
	procGlobalFreeProxy         = kernel32.NewProc("GlobalFree")
	systemProxyGate             = make(chan struct{}, 1)
	systemProxyConfigGate       = make(chan struct{}, 1)
	// Explicit consent lasts for this process only, including existing clients
	// and background downloads. It is never written to Windows or preferences.
	windowsProxyBypassApproved atomic.Bool
)

type ieProxyConfig struct {
	autoDetect             int32
	autoURL, proxy, bypass *uint16
}
type autoProxyOptions struct {
	flags, detectFlags uint32
	configURL          *uint16
	reserved           uintptr
	reservedFlags      uint32
	autoLogon          int32
}
type winHTTPProxyInfo struct {
	accessType    uint32
	proxy, bypass *uint16
}

func proxyString(p *uint16) string {
	if p == nil {
		return ""
	}
	return syscall.UTF16ToString(unsafe.Slice(p, proxyStringLength(p)))
}
func proxyStringLength(p *uint16) int {
	for i := 0; i < 32768; i++ {
		if *(*uint16)(unsafe.Add(unsafe.Pointer(p), i*2)) == 0 {
			return i
		}
	}
	return 32768
}
func freeProxyStrings(values ...*uint16) {
	for _, p := range values {
		if p != nil {
			procGlobalFreeProxy.Call(uintptr(unsafe.Pointer(p)))
		}
	}
}

type windowsProxySettings struct {
	autoDetect             bool
	autoURL, proxy, bypass string
}

// Test seams: fixture tests supply settings without reading Internet Options,
// and native PAC tests can retain real WinHTTP with an explicit fixture PAC.
// Production always starts with the current user's settings and real WinHTTP.
var readWindowsProxySettings = loadWindowsProxySettings
var windowsAutomaticProxy = windowsProxyForSettings

// Reading settings is a native call too. Keep it bounded and cancellable,
// without confusing a settings timeout with an identified PAC/WPAD failure.
func windowsProxySettingsForRequest(req *http.Request) (windowsProxySettings, error) {
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case systemProxyConfigGate <- struct{}{}:
	case <-req.Context().Done():
		return windowsProxySettings{}, req.Context().Err()
	case <-timer.C:
		return windowsProxySettings{}, fmt.Errorf("reading Windows proxy settings timed out")
	}
	type result struct {
		settings windowsProxySettings
		err      error
	}
	done := make(chan result, 1)
	read := readWindowsProxySettings
	go func() {
		defer func() { <-systemProxyConfigGate }()
		settings, err := read()
		done <- result{settings, err}
	}()
	select {
	case r := <-done:
		if err := req.Context().Err(); err != nil {
			return windowsProxySettings{}, err
		}
		return r.settings, r.err
	case <-req.Context().Done():
		return windowsProxySettings{}, req.Context().Err()
	case <-timer.C:
		return windowsProxySettings{}, fmt.Errorf("reading Windows proxy settings timed out")
	}
}

func loadWindowsProxySettings() (windowsProxySettings, error) {
	var cfg ieProxyConfig
	ok, _, err := procWinHTTPGetIEProxyConfig.Call(uintptr(unsafe.Pointer(&cfg)))
	if ok == 0 {
		return windowsProxySettings{}, fmt.Errorf("reading Windows proxy settings: %w", err)
	}
	defer freeProxyStrings(cfg.autoURL, cfg.proxy, cfg.bypass)
	return windowsProxySettings{cfg.autoDetect != 0, proxyString(cfg.autoURL), proxyString(cfg.proxy), proxyString(cfg.bypass)}, nil
}

func environmentProxyConfigured() bool {
	for _, name := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"} {
		if os.Getenv(name) != "" {
			return true
		}
	}
	return false
}

func downloadStaticProxy(req *http.Request) (*url.URL, error) {
	if err := req.Context().Err(); err != nil {
		return nil, err
	}
	if environmentProxyConfigured() {
		return http.ProxyFromEnvironment(req)
	}
	cfg, err := windowsProxySettingsForRequest(req)
	if err != nil {
		return nil, err
	}
	return systemProxyURL(req.URL, cfg.proxy, cfg.bypass)
}

func downloadProxy(req *http.Request) (*url.URL, error) {
	if err := req.Context().Err(); err != nil {
		return nil, err
	}
	if windowsProxyBypassApproved.Load() {
		return downloadStaticProxy(req)
	}
	if environmentProxyConfigured() {
		return http.ProxyFromEnvironment(req)
	}
	started := time.Now()
	cfg, err := windowsProxySettingsForRequest(req)
	if err != nil {
		return nil, err
	}
	if cfg.autoURL == "" && !cfg.autoDetect {
		return systemProxyURL(req.URL, cfg.proxy, cfg.bypass)
	}
	// Only automatic lookups own this gate. Settings are copied before starting
	// the worker so cancellation cannot free native strings it still uses.
	timer := time.NewTimer(max(time.Duration(0), 5*time.Second-time.Since(started)))
	defer timer.Stop()
	timeout := func() error { return &automaticProxyError{fmt.Errorf("Windows automatic proxy lookup timed out")} }
	select {
	case systemProxyGate <- struct{}{}:
	case <-req.Context().Done():
		return nil, req.Context().Err()
	case <-timer.C:
		return nil, timeout()
	}
	type result struct {
		proxy *url.URL
		err   error
	}
	done := make(chan result, 1)
	go func() {
		defer func() { <-systemProxyGate }()
		proxy, err := windowsAutomaticProxy(req.URL, cfg)
		done <- result{proxy, err}
	}()
	select {
	case r := <-done:
		if err := req.Context().Err(); err != nil {
			return nil, err
		}
		return r.proxy, r.err
	case <-req.Context().Done():
		return nil, req.Context().Err()
	case <-timer.C:
		return nil, timeout()
	}
}

func windowsProxyForSettings(target *url.URL, settings windowsProxySettings) (*url.URL, error) {
	cfg := ieProxyConfig{}
	if settings.autoDetect {
		cfg.autoDetect = 1
	}
	if settings.autoURL != "" {
		cfg.autoURL, _ = syscall.UTF16PtrFromString(settings.autoURL)
	}
	if settings.proxy != "" {
		cfg.proxy, _ = syscall.UTF16PtrFromString(settings.proxy)
	}
	if settings.bypass != "" {
		cfg.bypass, _ = syscall.UTF16PtrFromString(settings.bypass)
	}
	return windowsProxyForConfig(target, &cfg)
}

func windowsProxyForConfig(target *url.URL, cfg *ieProxyConfig) (*url.URL, error) {
	if cfg.autoURL == nil && cfg.autoDetect == 0 {
		return systemProxyURL(target, proxyString(cfg.proxy), proxyString(cfg.bypass))
	}
	agent, _ := syscall.UTF16PtrFromString("Try Omarchy updater")
	session, _, err := procWinHTTPOpen.Call(uintptr(unsafe.Pointer(agent)), 1, 0, 0, 0)
	if session == 0 {
		return nil, &automaticProxyError{fmt.Errorf("opening Windows proxy session: %w", err)}
	}
	defer procWinHTTPClose.Call(session)
	if ok, _, err := procWinHTTPTimeouts.Call(session, 4000, 4000, 4000, 4000); ok == 0 {
		return nil, &automaticProxyError{fmt.Errorf("setting Windows proxy timeouts: %w", err)}
	}
	options := autoProxyOptions{configURL: cfg.autoURL}
	if cfg.autoURL != nil {
		options.flags = 2
	} else {
		options.flags = 1
		options.detectFlags = 3
	}
	source, _ := syscall.UTF16PtrFromString(target.String())
	var info winHTTPProxyInfo
	ok, _, err := procWinHTTPGetProxy.Call(session, uintptr(unsafe.Pointer(source)), uintptr(unsafe.Pointer(&options)), uintptr(unsafe.Pointer(&info)))
	if ok == 0 {
		return windowsProxyLookupFailure(target, cfg, err)
	}
	defer freeProxyStrings(info.proxy, info.bypass)
	if info.accessType == 1 {
		return nil, nil
	}
	return systemProxyURL(target, proxyString(info.proxy), proxyString(info.bypass))
}

func windowsProxyLookupFailure(target *url.URL, cfg *ieProxyConfig, cause error) (*url.URL, error) {
	// WPAD finding no configuration is normal on a direct network. A failed
	// explicit PAC configuration must not silently bypass the user's policy.
	if cfg.autoURL == nil && cause == syscall.Errno(12180) {
		return systemProxyURL(target, proxyString(cfg.proxy), proxyString(cfg.bypass))
	}
	return nil, &automaticProxyError{cause}
}
