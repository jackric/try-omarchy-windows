//go:build windows

package main

import "context"

// Serialize interactive decisions and recheck consent after acquiring the gate,
// so concurrent failed downloads cannot open duplicate session prompts.
var proxyChoiceGate = make(chan struct{}, 1)

func chooseProxyBypass(ctx context.Context, label string, cause error) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	select {
	case proxyChoiceGate <- struct{}{}:
	case <-ctx.Done():
		return false, ctx.Err()
	}
	defer func() { <-proxyChoiceGate }()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if windowsProxyBypassApproved.Load() {
		return true, nil
	}
	body := uiTextWith("proxy.bypass.explanation", map[string]string{"file": label, "error": cause.Error()}) + "\n\n" +
		uiText("proxy.bypass.warning") + "\n\n" + uiText("proxy.bypass.scope")
	action, err := chooseActionCancelable(ctx.Done(), uiText("proxy.bypass.title"), body, 380,
		uiText("proxy.bypass.cancel"), uiText("proxy.bypass.approve"))
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	approved := action == 2 && err == nil
	if approved {
		windowsProxyBypassApproved.Store(true)
		logf("Windows automatic proxy bypass approved for all downloads in this app session")
	}
	return approved, err
}
