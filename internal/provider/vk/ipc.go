package vk

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/LiTarPc/fturn-core/internal/captchaipc"
	"github.com/LiTarPc/fturn-core/internal/provider/vk/internal/browserprofile"
	"github.com/LiTarPc/fturn-core/internal/provider/vk/internal/captcha"
	manual "github.com/LiTarPc/fturn-core/internal/provider/vk/internal/captcha/manual"
)

// IPCManualSolver reports metadata only after the private local server is ready.
func IPCManualSolver(host *captchaipc.Server, mode string) ManualSolverFunc {
	return func(ctx context.Context, e *captcha.Error, d net.Dialer, p browserprofile.Profile) (token string, err error) {
		bounded, cancel := context.WithTimeout(ctx, 3*time.Minute)
		defer cancel()
		if err = acquireBrowser(bounded); err != nil {
			return "", err
		}
		defer releaseBrowser()
		var id string
		var beginErr error
		token, err = manual.SolveViaProxyWithPresenter(bounded, e.RedirectURI, d, p, func(uri string) {
			id, beginErr = host.Begin(bounded, uri, mode)
			if beginErr != nil {
				cancel()
			}
		})
		if beginErr != nil {
			return "", beginErr
		}
		if bounded.Err() != nil {
			token = ""
			err = bounded.Err()
		}
		phase := "resolved"
		if err != nil {
			phase = "unavailable"
			if errors.Is(err, context.DeadlineExceeded) {
				phase = "expired"
			} else if errors.Is(err, context.Canceled) {
				phase = "cancelled"
			}
		}
		if id != "" {
			host.End(id, phase)
		}
		return token, err
	}
}

// IPCPowCapture has a separate request ID and lifetime from a manual solve.
func IPCPowCapture(host *captchaipc.Server) PowCaptureFunc {
	return func(ctx context.Context, uri string, d net.Dialer, p browserprofile.Profile) (value string, err error) {
		bounded, cancel := context.WithTimeout(ctx, 12*time.Second)
		defer cancel()
		if err = acquireBrowser(bounded); err != nil {
			return "", err
		}
		defer releaseBrowser()
		var id string
		var beginErr error
		value, err = manual.CapturePowViaProxyWithPresenter(bounded, uri, d, p, func(local string) {
			id, beginErr = host.BeginCapture(bounded, local, cancel)
			if beginErr != nil {
				cancel()
			}
		})
		if beginErr != nil {
			return "", beginErr
		}
		if bounded.Err() != nil {
			value = ""
			err = bounded.Err()
		}
		phase := "captured"
		if err != nil {
			phase = "unavailable"
			if errors.Is(err, context.DeadlineExceeded) {
				phase = "expired"
			} else if ctx.Err() != nil {
				phase = "cancelled"
			}
		}
		if id != "" {
			host.End(id, phase)
		}
		return value, err
	}
}
