//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
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
	"unsafe"
)

// Native WinHTTP and the production dialog are used; Internet Options and
// registry settings are never changed. Manual mode never sends UI input.
func TestWindowsPACDownloadBypassNative(t *testing.T) {
	if os.Getenv("TRYOMARCHY_UI_TEST") != "1" {
		t.Skip("requires interactive Windows and TRYOMARCHY_UI_TEST=1")
	}
	manual := os.Getenv("TRYOMARCHY_PROXY_BYPASS_MANUAL") == "1"
	timeout := 90 * time.Second
	if manual {
		timeout = 8 * time.Minute
	}
	if os.Getenv("TRYOMARCHY_PROXY_UI_CHILD") != "1" {
		self, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout+15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, self, "-test.v", "-test.run=^TestWindowsPACDownloadBypassNative$", "-test.timeout="+(timeout+10*time.Second).String())
		cmd.Env = append(os.Environ(), "TRYOMARCHY_PROXY_UI_CHILD=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		// Stream instructions so an attended user sees the pending physical click.
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			t.Fatal(err)
		}
		return
	}
	data := []byte("native PAC bypass verified fixture")
	var requests, lookups atomic.Int32
	payload := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path == "/fail" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Write(data)
	}))
	defer payload.Close()
	pac := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
		fmt.Fprint(w, "this is deliberately invalid PAC JavaScript !!!")
	}))
	defer pac.Close()
	isolatedProxySettings(t, windowsProxySettings{autoURL: pac.URL + "/broken.pac"})
	oldNative := windowsAutomaticProxy
	windowsAutomaticProxy = func(target *url.URL, cfg windowsProxySettings) (*url.URL, error) {
		lookups.Add(1)
		return oldNative(target, cfg)
	}
	defer func() { windowsAutomaticProxy = oldNative }()
	modes := []string{"approve", "decline", "escape", "close", "cancel", "failed retry", "all subsequent downloads"}
	if manual {
		modes = []string{"approve"}
		t.Log("ATTENDED: inspect the policy warning and physically click Bypass for all downloads. No input will be sent by the test.")
	}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			windowsProxyBypassApproved.Store(false)
			t.Cleanup(func() { windowsProxyBypassApproved.Store(false) })
			requests.Store(0)
			lookups.Store(0)
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			dest := filepath.Join(t.TempDir(), "payload")
			source := payload.URL + "/payload"
			if mode == "failed retry" {
				source = payload.URL + "/fail"
			}
			opts := downloadOptions{ctx: ctx, maxAttempts: 1, decideProxy: chooseProxyBypass}
			done := make(chan error, 1)
			go func() {
				done <- downloadVerifiedWithOptions(newDownloadClient(), source, dest, payloadDigest(data), nil, opts)
			}()
			window, button := waitProxyDialog(t, ctx, done)
			t.Cleanup(func() { procPostMessageW.Call(window, wmClose, 0, 0) })
			readText := func(h uintptr) string {
				length, _, _ := user32.NewProc("GetWindowTextLengthW").Call(h)
				buf := make([]uint16, length+1)
				user32.NewProc("GetWindowTextW").Call(h, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
				return syscall.UTF16ToString(buf)
			}
			body, _, _ := user32.NewProc("GetDlgItem").Call(window, 3000)
			decline, _, _ := user32.NewProc("GetDlgItem").Call(window, 3001)
			text := readText(body)
			if !strings.Contains(text, uiText("proxy.bypass.warning")) || !strings.Contains(text, uiText("proxy.bypass.scope")) || !strings.Contains(text, "automatic proxy") {
				t.Fatalf("warning missing: %q", text)
			}
			if readText(button) != uiText("proxy.bypass.approve") || readText(decline) != uiText("proxy.bypass.cancel") {
				t.Fatal("wrong button labels")
			}
			if lookups.Load() != 1 || requests.Load() != 0 {
				t.Fatalf("before consent: lookups=%d requests=%d", lookups.Load(), requests.Load())
			}
			if _, err := os.Stat(dest); !os.IsNotExist(err) {
				t.Fatal("published before consent")
			}
			if !manual {
				switch mode {
				case "decline":
					procPostMessageW.Call(decline, 0x00F5, 0, 0)
				case "escape":
					procPostMessageW.Call(decline, wmKeydown, vkEscape, 0)
				case "close":
					procPostMessageW.Call(window, wmClose, 0, 0)
				case "cancel":
					cancel()
				default:
					procPostMessageW.Call(button, 0x00F5, 0, 0)
				}
			}
			select {
			case err := <-done:
				approved := mode == "approve" || mode == "all subsequent downloads"
				if approved {
					if err != nil {
						t.Fatal(err)
					}
					got, err := os.ReadFile(dest)
					if err != nil || payloadDigest(got) != payloadDigest(data) {
						t.Fatalf("verified retry: %v", err)
					}
					if requests.Load() != 1 {
						t.Fatalf("approved requests: %d", requests.Load())
					}
				} else {
					if err == nil {
						t.Fatal("expected declined/cancelled/failed result")
					}
					var automatic *automaticProxyError
					if mode == "cancel" {
						if !errors.Is(err, context.Canceled) {
							t.Fatal(err)
						}
					} else if !errors.As(err, &automatic) {
						t.Fatalf("native cause lost: %v", err)
					}
					want := int32(0)
					if mode == "failed retry" {
						want = 1
					}
					if requests.Load() != want {
						t.Fatalf("requests after %s: %d", mode, requests.Load())
					}
				}
				if lookups.Load() != 1 {
					t.Fatalf("approved route repeated native lookup: %d", lookups.Load())
				}
				consented := approved || mode == "failed retry"
				if windowsProxyBypassApproved.Load() != consented {
					t.Fatalf("session approval after %s: %t", mode, windowsProxyBypassApproved.Load())
				}
				if mode == "all subsequent downloads" {
					// Use a separate client and no interactive callback: later
					// background/checksum downloads inherit explicit consent.
					client := newDownloadClient()
					defer client.CloseIdleConnections()
					if _, err := fetchSmallFileContext(ctx, client, payload.URL+"/payload", 1024); err != nil {
						t.Fatal(err)
					}
					if err := downloadVerifiedWithOptions(client, payload.URL+"/payload", filepath.Join(t.TempDir(), "second"), payloadDigest(data), nil, downloadOptions{ctx: ctx, maxAttempts: 1}); err != nil {
						t.Fatal(err)
					}
					if lookups.Load() != 1 || requests.Load() != 3 {
						t.Fatalf("subsequent lookups/requests: %d/%d", lookups.Load(), requests.Load())
					}
				}
				t.Logf("native warning inspected; mode=%s verified=%t", mode, approved)
			case <-time.After(timeout):
				t.Fatal("native exercise timed out awaiting decision/result")
			}
		})
	}
}

func waitProxyDialog(t *testing.T, ctx context.Context, done <-chan error) (uintptr, uintptr) {
	t.Helper()
	class, _ := syscall.UTF16PtrFromString("TryOmarchyChoice")
	title, _ := syscall.UTF16PtrFromString(uiText("proxy.bypass.title"))
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		window, _, _ := user32.NewProc("FindWindowW").Call(uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(title)))
		if window != 0 {
			button, _, _ := user32.NewProc("GetDlgItem").Call(window, 3002)
			visible, _, _ := user32.NewProc("IsWindowVisible").Call(window)
			if button != 0 && visible != 0 {
				return window, button
			}
		}
		select {
		case err := <-done:
			t.Fatalf("download exited before native dialog: %v", err)
		case <-ctx.Done():
			t.Fatal("native dialog did not appear")
		case <-ticker.C:
		}
	}
}

// This attended exercise uses the machine's real proxy configuration and the
// production setup payload path. It only downloads to a disposable directory;
// it does not unpack, launch a VM, or alter an existing install/cache.
func TestWindowsPACDownloadBypassMachine(t *testing.T) {
	if os.Getenv("TRYOMARCHY_UI_TEST") != "1" || os.Getenv("TRYOMARCHY_PROXY_BYPASS_MACHINE") != "1" {
		t.Skip("requires attended desktop and TRYOMARCHY_PROXY_BYPASS_MACHINE=1")
	}
	if os.Getenv("TRYOMARCHY_PROXY_MACHINE_CHILD") != "1" {
		self, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 9*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, self, "-test.v", "-test.run=^TestWindowsPACDownloadBypassMachine$", "-test.timeout=8m30s")
		cmd.Env = append(os.Environ(), "TRYOMARCHY_PROXY_MACHINE_CHILD=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			t.Fatal(err)
		}
		return
	}
	configureSetupCancellation(false)
	timer := time.AfterFunc(8*time.Minute, requestSetupCancel)
	defer timer.Stop()
	ui := getUI()
	defer ui.finish()
	client := newDownloadClient()
	defer client.CloseIdleConnections()
	sums, err := releaseSums(client, defaultReleaseURL, defaultSumsSHA256)
	if err != nil {
		t.Fatal(err)
	}
	var nativeFailures atomic.Int32
	old := windowsAutomaticProxy
	windowsAutomaticProxy = func(target *url.URL, cfg windowsProxySettings) (*url.URL, error) {
		proxy, err := old(target, cfg)
		var automatic *automaticProxyError
		if errors.As(err, &automatic) {
			nativeFailures.Add(1)
		}
		return proxy, err
	}
	// Automatic calls can outlive cancellation. This child exits after testing;
	// avoid restoring a global seam while a timed-out worker may still use it.
	dest := filepath.Join(t.TempDir(), runtimeZip)
	t.Log("ATTENDED REAL NETWORK: inspect the warning and physically click Bypass for all downloads. A verified runtime archive is downloaded to a temporary directory. No input will be sent.")
	err = ensureVerifiedDownload(client, normalizedRelease(defaultReleaseURL)+"/"+runtimeZip, dest, sums[runtimeZip], uiText("status.downloading_runtime"), ui)
	if err != nil {
		t.Fatalf("real-machine alternate route outcome: %v", err)
	}
	if nativeFailures.Load() == 0 {
		t.Fatal("runtime verified, but no native automatic proxy failure occurred; bypass acceptance remains unexercised")
	}
	ok, err := verifyFileSHA256(dest, sums[runtimeZip], nil)
	if err != nil || !ok {
		t.Fatalf("runtime verification: %t %v", ok, err)
	}
	t.Log("real-machine runtime downloaded and SHA256 verified after the attended proxy choice")
}
