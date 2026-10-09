package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"regexp"
)

// automaticProxyError identifies failures in automatic configuration, never
// ordinary transfer failures. Its cause remains available to errors.As/Is.
type automaticProxyError struct{ cause error }

func (e *automaticProxyError) Error() string {
	return "resolving Windows automatic proxy: " + e.cause.Error()
}
func (e *automaticProxyError) Unwrap() error { return e.cause }

type proxyDecision func(context.Context, string, error) (bool, error)

type downloadPolicy struct {
	client     *http.Client
	decide     proxyDecision
	label      string
	original   error
	transport  *http.Transport
	considered bool
}

func newDownloadPolicy(client *http.Client, source string, decide proxyDecision) *downloadPolicy {
	label := "download"
	if u, err := url.Parse(source); err == nil {
		label = path.Base(u.Path) + " (" + u.Hostname() + ")"
	}
	return &downloadPolicy{client: client, decide: decide, label: label}
}

func (p *downloadPolicy) close() {
	if p.transport != nil {
		p.transport.CloseIdleConnections()
	}
}

// consider runs outside Transport.Proxy, after the failed request has returned.
// handled prevents generic retry/backoff after an eligible declined failure.
func (p *downloadPolicy) consider(ctx context.Context, err error) (approved, handled bool, result error) {
	var automatic *automaticProxyError
	if !errors.As(err, &automatic) {
		return false, false, err
	}
	if ctx.Err() != nil {
		return false, true, ctx.Err()
	}
	if p.considered {
		return false, true, p.failure(err)
	}
	p.considered = true
	// Retain wrappers internally, but never display their credential-bearing URL.
	p.original = err
	if p.decide == nil {
		return false, true, p.failure(err)
	}
	logf("automatic proxy failed for %s: %s", p.label, automatic)
	ok, decisionErr := p.decide(ctx, p.label, automatic)
	if ctx.Err() != nil {
		return false, true, ctx.Err()
	}
	if decisionErr != nil {
		return false, true, p.failure(fmt.Errorf("proxy choice failed: %w", decisionErr))
	}
	logf("automatic proxy bypass choice for %s: %t", p.label, ok)
	if !ok {
		return false, true, p.failure(err)
	}
	transport, ok := p.client.Transport.(*http.Transport)
	if p.client.Transport == nil {
		transport, ok = http.DefaultTransport.(*http.Transport)
	}
	if !ok {
		return false, true, p.failure(fmt.Errorf("cannot clone download transport for approved proxy route"))
	}
	p.transport = transport.Clone()
	p.transport.Proxy = downloadStaticProxy
	client := *p.client
	client.Transport = p.transport
	p.client = &client
	return true, true, nil
}

// safeDownloadFailure preserves causes without rendering URL/proxy credentials.
type safeDownloadFailure struct {
	text   string
	causes []error
}

func (e *safeDownloadFailure) Error() string   { return e.text }
func (e *safeDownloadFailure) Unwrap() []error { return e.causes }

func (p *downloadPolicy) failure(err error) error {
	if p.original == nil {
		return err
	}
	if _, ok := err.(*safeDownloadFailure); ok {
		return err
	}
	var automatic *automaticProxyError
	errors.As(p.original, &automatic)
	if err == p.original {
		return &safeDownloadFailure{text: automatic.Error(), causes: []error{p.original}}
	}
	// Transfer errors may also contain a redirect URL or proxy credentials.
	// Keep the underlying error accessible, with a safe explanation for the UI.
	return &safeDownloadFailure{text: "download failed after automatic proxy failure (" + automatic.Error() + "); " + safeTransferError(err), causes: []error{err, p.original}}
}

func safeTransferError(err error) string {
	var u *url.Error
	if errors.As(err, &u) {
		return "alternate-route request failed: " + redactDownloadText(u.Err.Error())
	}
	return redactDownloadText(err.Error())
}

var downloadErrorURL = regexp.MustCompile(`(?i)\b(?:https?|socks5h?)://[^\s]+`)

func redactDownloadText(text string) string {
	return downloadErrorURL.ReplaceAllString(text, "[redacted URL]")
}

func firstProxyDecision(decisions []proxyDecision) proxyDecision {
	if len(decisions) > 0 {
		return decisions[0]
	}
	return nil
}
