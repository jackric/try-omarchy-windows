package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

func getWithSetupRetry(client *http.Client, source string, attempts int, decisions ...proxyDecision) (*http.Response, error) {
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	policy := newDownloadPolicy(client, source, firstProxyDecision(decisions))
	// A returned response owns cleanup until its body is closed.
	returned := false
	defer func() {
		if !returned {
			policy.close()
		}
	}()
	for attempt := 0; attempt < attempts; attempt++ {
		req, err := http.NewRequestWithContext(setupContext(), http.MethodGet, source, nil)
		if err != nil {
			return nil, err
		}
		resp, err := policy.client.Do(req)
		if err == nil && !retryableHTTPStatus(resp.StatusCode) {
			if policy.transport != nil {
				resp.Body = &proxyResponseBody{ReadCloser: resp.Body, closePolicy: policy.close}
			}
			returned = true
			return resp, nil
		}
		if err == nil {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			resp.Body.Close()
		} else {
			approved, handled, choiceErr := policy.consider(setupContext(), err)
			if approved {
				attempt = -1
				continue
			}
			if handled {
				return nil, choiceErr
			}
			lastErr = err
		}
		if attempt+1 == attempts {
			break
		}
		delay := time.Second << min(attempt, 3)
		if err := sleepDuringSetup(delay); err != nil {
			return nil, err
		}
	}
	return nil, policy.failure(lastErr)
}

type proxyResponseBody struct {
	io.ReadCloser
	closePolicy func()
}

func (b *proxyResponseBody) Close() error {
	err := b.ReadCloser.Close()
	b.closePolicy()
	return err
}

func retryableHTTPStatus(status int) bool {
	return status == http.StatusRequestTimeout || status == http.StatusTooManyRequests || status >= 500
}

func setupFailureHelp(err error) string {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return uiText("setup.help.dns")
	}
	// Setup writes several GB, and an image update needs room for the old and
	// new copies at once. Retrying on connection advice never clears that.
	if errors.Is(err, errInsufficientDiskSpace) || isDiskFull(err) {
		return uiText("setup.help.disk_full")
	}
	if errors.Is(err, os.ErrPermission) {
		return uiText("setup.help.permission")
	}
	var networkErr net.Error
	if errors.As(err, &networkErr) {
		return uiText("setup.help.network")
	}
	return uiText("setup.help.retry")
}
