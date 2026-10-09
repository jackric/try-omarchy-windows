//go:build windows

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func isolatedProxySettings(t *testing.T, settings windowsProxySettings) {
	t.Helper()
	for _, name := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"} {
		t.Setenv(name, "")
	}
	oldBypass := windowsProxyBypassApproved.Load()
	windowsProxyBypassApproved.Store(false)
	t.Cleanup(func() { windowsProxyBypassApproved.Store(oldBypass) })
	old := readWindowsProxySettings
	readWindowsProxySettings = func() (windowsProxySettings, error) { return settings, nil }
	t.Cleanup(func() { readWindowsProxySettings = old })
}

func payloadDigest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

func failingAutomaticClient(t *testing.T, calls *atomic.Int32) *http.Client {
	t.Helper()
	client := newDownloadClient()
	client.Transport.(*http.Transport).Proxy = func(*http.Request) (*url.URL, error) {
		calls.Add(1)
		return nil, &automaticProxyError{syscall.Errno(12167)}
	}
	t.Cleanup(client.CloseIdleConnections)
	return client
}

func TestProxyDecisionDownloadScopeAndResume(t *testing.T) {
	isolatedProxySettings(t, windowsProxySettings{})
	data := []byte("verified payload for resumed proxy download")
	var requests, lookups atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/payload?secret=redirect-token", http.StatusFound)
			return
		}
		if r.Header.Get("Range") != "bytes=8-" {
			t.Errorf("resume range: %q", r.Header.Get("Range"))
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes 8-%d/%d", len(data)-1, len(data)))
		w.WriteHeader(http.StatusPartialContent)
		w.Write(data[8:])
	}))
	defer server.Close()
	client := failingAutomaticClient(t, &lookups)
	originalTransport := client.Transport
	decisions := 0
	opts := downloadOptions{ctx: context.Background(), maxAttempts: 1, decideProxy: func(ctx context.Context, label string, err error) (bool, error) {
		decisions++
		if strings.Contains(label+err.Error(), "secret") {
			t.Fatal("unsafe prompt")
		}
		if requests.Load() != 0 {
			t.Fatal("payload fetched before consent")
		}
		return true, nil
	}}
	for i := 0; i < 2; i++ {
		dest := filepath.Join(t.TempDir(), "payload")
		if err := os.WriteFile(dest+".part", data[:8], 0600); err != nil {
			t.Fatal(err)
		}
		if err := downloadVerifiedWithOptions(client, server.URL+"/redirect?secret=request-token", dest, payloadDigest(data), nil, opts); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(dest)
		if err != nil || string(got) != string(data) {
			t.Fatalf("payload: %q %v", got, err)
		}
		requests.Store(0)
	}
	if lookups.Load() != 2 || decisions != 2 {
		t.Fatalf("lookup/prompt counts: %d/%d", lookups.Load(), decisions)
	}
	if client.Transport != originalTransport {
		t.Fatal("shared client mutated")
	}
}

func TestProxyDecisionStopsAndPreservesCause(t *testing.T) {
	isolatedProxySettings(t, windowsProxySettings{})
	for _, mode := range []string{"decline", "no callback", "dialog failure", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			var lookups atomic.Int32
			client := failingAutomaticClient(t, &lookups)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			prompts := 0
			opts := downloadOptions{ctx: ctx, maxAttempts: 4}
			if mode != "no callback" {
				opts.decideProxy = func(context.Context, string, error) (bool, error) {
					prompts++
					if mode == "cancel" {
						cancel()
						return true, nil
					}
					if mode == "dialog failure" {
						return false, errors.New("window unavailable")
					}
					return false, nil
				}
			}
			err := downloadVerifiedWithOptions(client, "http://user:password@example.org/file?token=secret", filepath.Join(t.TempDir(), "payload"), payloadDigest([]byte("payload")), nil, opts)
			if err == nil || lookups.Load() != 1 || prompts > 1 {
				t.Fatalf("err/counts: %v %d %d", err, lookups.Load(), prompts)
			}
			if strings.Contains(err.Error(), "password") || strings.Contains(err.Error(), "secret") {
				t.Fatal("error leaked credentials")
			}
			if mode == "cancel" {
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
				return
			}
			if !errors.Is(err, syscall.Errno(12167)) {
				t.Fatalf("lost PAC cause: %v", err)
			}
		})
	}
}

func TestProxyDecisionFailureRetryBudgetAndIntegrity(t *testing.T) {
	isolatedProxySettings(t, windowsProxySettings{})
	for _, mode := range []string{"transient", "permanent", "checksum"} {
		t.Run(mode, func(t *testing.T) {
			var requests, lookups atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := requests.Add(1)
				if mode == "transient" || mode == "permanent" {
					status := 503
					if mode == "permanent" {
						status = 403
					}
					w.WriteHeader(status)
					return
				}
				if n > 1 {
					t.Error("checksum failure retried")
				}
				w.Write([]byte("wrong"))
			}))
			defer server.Close()
			prompts := 0
			opts := downloadOptions{ctx: context.Background(), maxAttempts: 2, decideProxy: func(context.Context, string, error) (bool, error) { prompts++; return true, nil }}
			dest := filepath.Join(t.TempDir(), "payload")
			err := downloadVerifiedWithOptions(failingAutomaticClient(t, &lookups), server.URL, dest, payloadDigest([]byte("right")), nil, opts)
			want := int32(1)
			if mode == "transient" {
				want = 2
			}
			if err == nil || !errors.Is(err, syscall.Errno(12167)) || prompts != 1 || lookups.Load() != 1 || requests.Load() != want {
				t.Fatalf("err/counts: %v %d %d %d", err, prompts, lookups.Load(), requests.Load())
			}
			if _, err := os.Stat(dest); !os.IsNotExist(err) {
				t.Fatal("published failed download")
			}
		})
	}
}

func TestProxyDecisionOnFinalNormalAttempt(t *testing.T) {
	isolatedProxySettings(t, windowsProxySettings{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer server.Close()
	client := newDownloadClient()
	defer client.CloseIdleConnections()
	calls := 0
	client.Transport.(*http.Transport).Proxy = func(*http.Request) (*url.URL, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("ordinary DNS failure")
		}
		return nil, &automaticProxyError{syscall.Errno(12167)}
	}
	prompts := 0
	opts := downloadOptions{ctx: context.Background(), maxAttempts: 2, decideProxy: func(context.Context, string, error) (bool, error) { prompts++; return true, nil }}
	if err := downloadVerifiedWithOptions(client, server.URL, filepath.Join(t.TempDir(), "payload"), payloadDigest([]byte("ok")), nil, opts); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || prompts != 1 {
		t.Fatalf("calls/prompts: %d/%d", calls, prompts)
	}
}

func TestProxyDecisionSmallFileFreshDeadline(t *testing.T) {
	isolatedProxySettings(t, windowsProxySettings{})
	var lookups atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("checksums")) }))
	defer server.Close()
	client := failingAutomaticClient(t, &lookups)
	decide := func(ctx context.Context, _ string, _ error) (bool, error) {
		if _, bounded := ctx.Deadline(); bounded {
			t.Fatal("prompt inherited network deadline")
		}
		return true, nil
	}
	data, err := fetchSmallFileContext(context.Background(), client, server.URL, 1024, decide)
	if err != nil || string(data) != "checksums" {
		t.Fatalf("small file: %q %v", data, err)
	}
	// Each subsequent file, including SHA256SUMS, needs a fresh policy.
	_, err = fetchSmallFileContext(context.Background(), client, server.URL, 2, decide)
	if err == nil || !strings.Contains(err.Error(), "exceeds") || lookups.Load() != 2 {
		t.Fatalf("size/count: %v %d", err, lookups.Load())
	}
}

func TestProxyDecisionManifestAuthentication(t *testing.T) {
	isolatedProxySettings(t, windowsProxySettings{})
	sums := []byte(payloadDigest([]byte("payload")) + "  payload\n")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(sums) }))
	defer server.Close()
	var lookups atomic.Int32
	client := failingAutomaticClient(t, &lookups)
	prompts := 0
	decide := func(context.Context, string, error) (bool, error) { prompts++; return true, nil }
	if _, err := releaseSums(client, server.URL, payloadDigest(sums), decide); err != nil {
		t.Fatal(err)
	}
	if _, err := releaseSums(client, server.URL, payloadDigest([]byte("untrusted")), decide); err == nil {
		t.Fatal("manifest not authenticated")
	}
	if _, err := releaseSums(client, defaultReleaseURL, defaultSumsSHA256, decide); err != nil {
		t.Fatal(err)
	}
	if prompts != 2 {
		t.Fatalf("embedded manifest prompted: %d", prompts)
	}
}

func TestProxyDecisionResponseBodyLifetime(t *testing.T) {
	isolatedProxySettings(t, windowsProxySettings{})
	var lookups atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("body")) }))
	defer server.Close()
	response, err := getWithSetupRetry(failingAutomaticClient(t, &lookups), server.URL, 1, func(context.Context, string, error) (bool, error) { return true, nil })
	if err != nil {
		t.Fatal(err)
	}
	body, ok := response.Body.(*proxyResponseBody)
	if !ok {
		t.Fatal("response does not own cleanup")
	}
	closed := false
	original := body.closePolicy
	body.closePolicy = func() { closed = true; original() }
	data, err := io.ReadAll(response.Body)
	if err != nil || string(data) != "body" || closed {
		t.Fatalf("body lifetime: %q %v %t", data, err, closed)
	}
	if err := response.Body.Close(); err != nil || !closed {
		t.Fatalf("cleanup: %v %t", err, closed)
	}
}

func TestAutomaticProxyClassification(t *testing.T) {
	cause := &automaticProxyError{syscall.Errno(12167)}
	wrapped := &url.Error{Op: "Get", URL: "https://secret@example.org/?token=hidden", Err: fmt.Errorf("request failed: %w", cause)}
	var automatic *automaticProxyError
	if !errors.As(wrapped, &automatic) || !errors.Is(wrapped, syscall.Errno(12167)) {
		t.Fatal("typed cause lost")
	}
	policy := newDownloadPolicy(newDownloadClient(), wrapped.URL, nil)
	defer policy.client.CloseIdleConnections()
	_, handled, err := policy.consider(context.Background(), wrapped)
	if !handled || strings.Contains(err.Error(), "hidden") || strings.Contains(err.Error(), "secret") {
		t.Fatal(err)
	}
	for _, ordinary := range []error{context.Canceled, context.DeadlineExceeded, errors.New("TLS failed"), errors.New("Windows proxy lookup timed out")} {
		if _, handled, _ := policy.consider(context.Background(), ordinary); handled {
			t.Fatalf("ordinary failure classified: %v", ordinary)
		}
	}
}

func TestApprovedStaticRouteSkipsStalledGate(t *testing.T) {
	isolatedProxySettings(t, windowsProxySettings{autoDetect: true, proxy: "http=127.0.0.1:18081", bypass: "localhost"})
	systemProxyGate <- struct{}{}
	defer func() { <-systemProxyGate }()
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.org/payload", nil)
	proxy, err := downloadStaticProxy(req)
	if err != nil || proxy.String() != "http://127.0.0.1:18081" {
		t.Fatalf("static route: %v %v", proxy, err)
	}
	req.URL, _ = url.Parse("http://localhost/payload")
	if proxy, err := downloadStaticProxy(req); err != nil || proxy != nil {
		t.Fatalf("bypass: %v %v", proxy, err)
	}
}

func TestAutomaticProxyGateTimeoutAndStaticSettingsError(t *testing.T) {
	isolatedProxySettings(t, windowsProxySettings{autoDetect: true})
	systemProxyGate <- struct{}{}
	defer func() { <-systemProxyGate }()
	req, _ := http.NewRequest("GET", "http://example.org/payload", nil)
	started := time.Now()
	_, err := downloadProxy(req)
	var automatic *automaticProxyError
	if !errors.As(err, &automatic) || time.Since(started) > 7*time.Second {
		t.Fatalf("automatic timeout: %v", err)
	}
	readWindowsProxySettings = func() (windowsProxySettings, error) {
		return windowsProxySettings{}, errors.New("reading settings failed")
	}
	_, err = downloadProxy(req)
	if errors.As(err, &automatic) {
		t.Fatalf("settings error classified: %v", err)
	}
}

func TestProxyEnvironmentPrecedenceNative(t *testing.T) {
	if os.Getenv("TRYOMARCHY_PROXY_ENV_CHILD") != "1" {
		self, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, self, "-test.run=^TestProxyEnvironmentPrecedenceNative$")
		cmd.Env = append(os.Environ(), "TRYOMARCHY_PROXY_ENV_CHILD=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("proxy child: %v\n%s", err, out)
		}
		return
	}
	isolatedProxySettings(t, windowsProxySettings{autoURL: "http://invalid.invalid/broken.pac", proxy: "127.0.0.1:1"})
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("environment proxy")) }))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	reads := 0
	readWindowsProxySettings = func() (windowsProxySettings, error) {
		reads++
		return windowsProxySettings{}, errors.New("settings should not be read")
	}
	for i, resolver := range []func(*http.Request) (*url.URL, error){downloadProxy, downloadProxy, downloadStaticProxy} {
		if i > 0 {
			windowsProxyBypassApproved.Store(true)
		}
		client := newDownloadClient()
		client.Transport.(*http.Transport).Proxy = resolver
		response, err := client.Get("http://example.org/payload")
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(response.Body)
		response.Body.Close()
		client.CloseIdleConnections()
		if err != nil || string(data) != "environment proxy" {
			t.Fatalf("environment route: %q %v", data, err)
		}
	}
	if reads != 0 {
		t.Fatalf("environment override read Windows settings %d times", reads)
	}
}

func TestProxyDecisionPreservesClientAndTLS(t *testing.T) {
	isolatedProxySettings(t, windowsProxySettings{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/payload", 302)
			return
		}
		w.Write([]byte("tls payload"))
	}))
	defer server.Close()
	client := server.Client()
	defer client.CloseIdleConnections()
	client.Transport.(*http.Transport).Proxy = func(*http.Request) (*url.URL, error) { return nil, &automaticProxyError{syscall.Errno(12167)} }
	jar, _ := cookiejar.New(nil)
	client.Jar = jar
	client.Timeout = 3 * time.Second
	redirects := 0
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error { redirects++; return nil }
	policy := newDownloadPolicy(client, server.URL, func(context.Context, string, error) (bool, error) { return true, nil })
	defer policy.close()
	approved, handled, err := policy.consider(context.Background(), &automaticProxyError{syscall.Errno(12167)})
	if !approved || !handled || err != nil {
		t.Fatal(err)
	}
	if policy.client.Jar != client.Jar || policy.client.Timeout != client.Timeout || policy.transport.TLSClientConfig.RootCAs != client.Transport.(*http.Transport).TLSClientConfig.RootCAs {
		t.Fatal("client or TLS settings changed")
	}
	response, err := policy.client.Get(server.URL + "/redirect")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if redirects != 1 {
		t.Fatalf("redirect policy ignored: %d", redirects)
	}
}

func TestProxySmallFileDeadlineAndCancellation(t *testing.T) {
	isolatedProxySettings(t, windowsProxySettings{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer server.Close()
	client := newDownloadClient()
	defer client.CloseIdleConnections()
	var failedContext context.Context
	client.Transport.(*http.Transport).Proxy = func(req *http.Request) (*url.URL, error) {
		failedContext = req.Context()
		return nil, &automaticProxyError{syscall.Errno(12167)}
	}
	var remaining time.Duration
	client.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		deadline, _ := ctx.Deadline()
		remaining = time.Until(deadline)
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	data, err := fetchSmallFileContext(context.Background(), client, server.URL, 1024, func(ctx context.Context, _ string, _ error) (bool, error) {
		if failedContext.Err() == nil {
			t.Error("failed request context still alive during consent")
		}
		if ctx.Err() != nil {
			t.Error("parent cancelled with failed request")
		}
		return true, nil
	})
	// Transport's dialing context intentionally strips request cancellation;
	// the successful body proves the cancelled first context was not reused.
	if err != nil || string(data) != "ok" {
		t.Fatalf("fresh request: %q %v (dial deadline %v)", data, err, remaining)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err = fetchSmallFileContext(ctx, client, server.URL, 1024, func(ctx context.Context, _ string, _ error) (bool, error) { <-ctx.Done(); return true, nil })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("parent deadline ignored: %v", err)
	}
}

func TestApprovedRouteErrorRedaction(t *testing.T) {
	policy := newDownloadPolicy(newDownloadClient(), "https://user:password@example.org/file?token=secret", nil)
	defer policy.client.CloseIdleConnections()
	policy.original = &automaticProxyError{syscall.Errno(12167)}
	cause := &url.Error{Op: "Get", URL: "https://example.org/?token=secret", Err: fmt.Errorf("proxy rejected https://proxy:password@example.org/?token=secret: connection refused")}
	err := policy.failure(cause)
	if strings.Contains(err.Error(), "password") || strings.Contains(err.Error(), "secret") || !strings.Contains(err.Error(), "connection refused") || !errors.Is(err, cause) {
		t.Fatalf("safe context: %v", err)
	}
}

func TestWPADNoConfigurationFallback(t *testing.T) {
	target, _ := url.Parse("https://example.org/payload")
	static, _ := syscall.UTF16PtrFromString("127.0.0.1:18081")
	cfg := ieProxyConfig{autoDetect: 1, proxy: static}
	proxy, err := windowsProxyLookupFailure(target, &cfg, syscall.Errno(12180))
	if err != nil || proxy.String() != "http://127.0.0.1:18081" {
		t.Fatalf("WPAD fallback: %v %v", proxy, err)
	}
	cfg.autoURL, _ = syscall.UTF16PtrFromString("http://example.org/broken.pac")
	_, err = windowsProxyLookupFailure(target, &cfg, syscall.Errno(12180))
	var automatic *automaticProxyError
	if !errors.As(err, &automatic) {
		t.Fatalf("explicit PAC silently bypassed: %v", err)
	}
}

func TestProxyTimeoutBypassDoesNotWaitForWorker(t *testing.T) {
	isolatedProxySettings(t, windowsProxySettings{autoDetect: true})
	old := windowsAutomaticProxy
	release, finished := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	windowsAutomaticProxy = func(*url.URL, windowsProxySettings) (*url.URL, error) {
		calls.Add(1)
		<-release
		close(finished)
		return nil, nil
	}
	t.Cleanup(func() { close(release); <-finished; windowsAutomaticProxy = old })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	prompts := 0
	client := newDownloadClient()
	defer client.CloseIdleConnections()
	opts := downloadOptions{ctx: ctx, maxAttempts: 1, decideProxy: func(context.Context, string, error) (bool, error) { prompts++; return true, nil }}
	if err := downloadVerifiedWithOptions(client, server.URL, filepath.Join(t.TempDir(), "payload"), payloadDigest([]byte("ok")), nil, opts); err != nil {
		t.Fatal(err)
	}
	if prompts != 1 || calls.Load() != 1 {
		t.Fatalf("prompt/lookup count: %d/%d", prompts, calls.Load())
	}
}

func TestStaticOnlyProxyDoesNotWaitForAutomaticGate(t *testing.T) {
	isolatedProxySettings(t, windowsProxySettings{proxy: "127.0.0.1:18081"})
	systemProxyGate <- struct{}{}
	defer func() { <-systemProxyGate }()
	req, _ := http.NewRequest("GET", "http://example.org/payload", nil)
	proxy, err := downloadProxy(req)
	if err != nil || proxy.String() != "http://127.0.0.1:18081" {
		t.Fatalf("static normal route: %v %v", proxy, err)
	}
}

func TestProxyDecisionWaitBeyondSmallFileDeadline(t *testing.T) {
	isolatedProxySettings(t, windowsProxySettings{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer server.Close()
	var calls atomic.Int32
	data, err := fetchSmallFileContext(context.Background(), failingAutomaticClient(t, &calls), server.URL, 1024, func(ctx context.Context, _ string, _ error) (bool, error) {
		t.Log("waiting beyond the 20-second request deadline before granting consent")
		select {
		case <-time.After(21 * time.Second):
			return true, nil
		case <-ctx.Done():
			return false, ctx.Err()
		}
	})
	if err != nil || string(data) != "ok" {
		t.Fatalf("consent exceeded network deadline: %q %v", data, err)
	}
}

func TestProxyDecisionCannotCloneCustomTransport(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, &automaticProxyError{syscall.Errno(12167)}
	})}
	opts := downloadOptions{ctx: context.Background(), maxAttempts: 4, decideProxy: func(context.Context, string, error) (bool, error) { return true, nil }}
	err := downloadVerifiedWithOptions(client, "https://example.org/payload", filepath.Join(t.TempDir(), "payload"), payloadDigest([]byte("payload")), nil, opts)
	if err == nil || calls != 1 || !strings.Contains(err.Error(), "cannot clone") || !errors.Is(err, syscall.Errno(12167)) {
		t.Fatalf("unsafe transport fallback: %v (%d calls)", err, calls)
	}
}

func TestWindowsProxySettingsTimeoutIsIneligible(t *testing.T) {
	isolatedProxySettings(t, windowsProxySettings{})
	release, finished := make(chan struct{}), make(chan struct{})
	readWindowsProxySettings = func() (windowsProxySettings, error) { <-release; close(finished); return windowsProxySettings{}, nil }
	t.Cleanup(func() { close(release); <-finished })
	req, _ := http.NewRequest("GET", "http://example.org/payload", nil)
	_, err := downloadProxy(req)
	var automatic *automaticProxyError
	if err == nil || errors.As(err, &automatic) || !strings.Contains(err.Error(), "settings timed out") {
		t.Fatalf("settings timeout misclassified: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, _ = http.NewRequestWithContext(ctx, "GET", "http://example.org/payload", nil)
	if _, err := downloadStaticProxy(req); !errors.Is(err, context.Canceled) {
		t.Fatalf("settings cancellation: %v", err)
	}
}

func TestWindowsProxySessionApprovalCoversAllDownloads(t *testing.T) {
	isolatedProxySettings(t, windowsProxySettings{autoDetect: true})
	old := windowsAutomaticProxy
	var lookups atomic.Int32
	windowsAutomaticProxy = func(*url.URL, windowsProxySettings) (*url.URL, error) {
		lookups.Add(1)
		return nil, &automaticProxyError{syscall.Errno(12167)}
	}
	t.Cleanup(func() { windowsAutomaticProxy = old })
	payload := []byte("session approved payload")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/payload", 302)
			return
		}
		w.Write(payload)
	}))
	defer server.Close()
	client := newDownloadClient()
	defer client.CloseIdleConnections()
	prompts := 0
	opts := downloadOptions{ctx: context.Background(), maxAttempts: 1, decideProxy: func(context.Context, string, error) (bool, error) {
		prompts++
		windowsProxyBypassApproved.Store(true)
		return true, nil
	}}
	if err := downloadVerifiedWithOptions(client, server.URL+"/payload", filepath.Join(t.TempDir(), "first"), payloadDigest(payload), nil, opts); err != nil {
		t.Fatal(err)
	}
	// An existing client, a new client, and non-interactive metadata workers
	// all skip automatic lookup without another callback after session consent.
	if _, err := fetchSmallFileContext(context.Background(), client, server.URL+"/redirect", 1024); err != nil {
		t.Fatal(err)
	}
	second := newDownloadClient()
	defer second.CloseIdleConnections()
	if err := downloadVerified(second, server.URL+"/redirect", filepath.Join(t.TempDir(), "second"), payloadDigest(payload), nil); err != nil {
		t.Fatal(err)
	}
	response, err := getWithSetupRetry(second, server.URL+"/payload", 1)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if lookups.Load() != 1 || prompts != 1 {
		t.Fatalf("session lookups/prompts: %d/%d", lookups.Load(), prompts)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", server.URL, nil)
	if _, err := downloadProxy(req); !errors.Is(err, context.Canceled) {
		t.Fatalf("approval ignored cancellation: %v", err)
	}
}

func TestWindowsProxySessionApprovalKeepsStaticProxy(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("static proxy")) }))
	defer proxy.Close()
	isolatedProxySettings(t, windowsProxySettings{autoDetect: true, proxy: proxy.URL})
	windowsProxyBypassApproved.Store(true)
	old := windowsAutomaticProxy
	windowsAutomaticProxy = func(*url.URL, windowsProxySettings) (*url.URL, error) {
		return nil, errors.New("automatic proxy must not be called")
	}
	t.Cleanup(func() { windowsAutomaticProxy = old })
	client := newDownloadClient()
	defer client.CloseIdleConnections()
	data, err := fetchSmallFileContext(context.Background(), client, "http://example.org/payload", 1024)
	if err != nil || string(data) != "static proxy" {
		t.Fatalf("approved static route: %q %v", data, err)
	}
}

func TestWindowsProxyNewLaunchNeedsApproval(t *testing.T) {
	if os.Getenv("TRYOMARCHY_PROXY_SESSION_CHILD") == "1" {
		if windowsProxyBypassApproved.Load() {
			t.Fatal("session consent persisted to a new process")
		}
		return
	}
	old := windowsProxyBypassApproved.Load()
	windowsProxyBypassApproved.Store(true)
	t.Cleanup(func() { windowsProxyBypassApproved.Store(old) })
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, self, "-test.run=^TestWindowsProxyNewLaunchNeedsApproval$")
	cmd.Env = append(os.Environ(), "TRYOMARCHY_PROXY_SESSION_CHILD=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("new launch: %v\n%s", err, out)
	}
}
