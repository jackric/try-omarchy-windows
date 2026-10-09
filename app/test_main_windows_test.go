//go:build windows

package main

import (
	"fmt"
	"os"
	"testing"
)

// Fixture downloads must not inherit PAC, WPAD, static proxies, or cached
// environment proxy settings from the developer/CI host. This also runs in
// copied test executables used by native update/restart tests.
func TestMain(m *testing.M) {
	// Only the explicitly attended real-machine child uses host settings. The
	// parent and every deterministic native PAC test still use isolated defaults.
	attendedHost := os.Getenv("TRYOMARCHY_UI_TEST") == "1" &&
		os.Getenv("TRYOMARCHY_PROXY_BYPASS_MACHINE") == "1" &&
		os.Getenv("TRYOMARCHY_PROXY_MACHINE_CHILD") == "1"
	if !attendedHost {
		readWindowsProxySettings = func() (windowsProxySettings, error) {
			return windowsProxySettings{}, nil
		}
		// Clear overrides before the first http.ProxyFromEnvironment call, which
		// caches its environment. Proxy-specific tests then set their own values.
		for _, name := range []string{
			"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy",
			"NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy",
		} {
			if err := os.Unsetenv(name); err != nil {
				fmt.Fprintln(os.Stderr, "isolating test proxy environment:", err)
				os.Exit(2)
			}
		}
	}
	// Do not restore the seam here: timed-out native workers can outlive tests,
	// and exiting the test process releases the entire isolated environment.
	os.Exit(m.Run())
}
