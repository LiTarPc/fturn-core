package vk

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/LiTarPc/fturn-core/internal/provider/vk/internal/browserprofile"
	"github.com/LiTarPc/fturn-core/internal/provider/vk/internal/captcha"
	manualcaptcha "github.com/LiTarPc/fturn-core/internal/provider/vk/internal/captcha/manual"
)

var browserProxyGate = make(chan struct{}, 1)

func acquireBrowser(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case browserProxyGate <- struct{}{}:
		if err := ctx.Err(); err != nil {
			releaseBrowser()
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func releaseBrowser() { <-browserProxyGate }

// ProxyManualSolver показывает UI после запуска локального captcha-прокси.
func ProxyManualSolver(show func(url string), hide func()) ManualSolverFunc {
	return func(ctx context.Context, e *captcha.Error, dialer net.Dialer, profile browserprofile.Profile) (string, error) {
		if e.RedirectURI == "" {
			return "", fmt.Errorf("manual captcha: no redirect_uri")
		}

		if err := acquireBrowser(ctx); err != nil {
			return "", err
		}
		defer releaseBrowser()
		if hide != nil {
			defer hide()
		}

		return manualcaptcha.SolveViaProxyWithPresenter(ctx, e.RedirectURI, dialer, profile, show)
	}
}

// ProxyPowCapture uses the same port ownership as the manual solver.
func ProxyPowCapture(show func(string), hide func()) PowCaptureFunc {
	return func(ctx context.Context, uri string, dialer net.Dialer, p browserprofile.Profile) (string, error) {
		if show == nil {
			return "", fmt.Errorf("browser PoW host unavailable")
		}
		bounded, cancel := context.WithTimeout(ctx, 12*time.Second)
		defer cancel()
		if err := acquireBrowser(bounded); err != nil {
			return "", err
		}
		defer releaseBrowser()
		if hide != nil {
			defer hide()
		}
		return manualcaptcha.CapturePowViaProxyWithPresenter(bounded, uri, dialer, p, show)
	}
}
