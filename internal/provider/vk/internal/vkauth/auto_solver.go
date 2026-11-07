package vkauth

import (
	"context"
	"errors"
	"fmt"
	"github.com/LiTarPc/fturn-core/internal/provider/vk/internal/captcha/manual"
	"time"

	"github.com/LiTarPc/fturn-core/internal/provider/vk/internal/browserprofile"
	"github.com/LiTarPc/fturn-core/internal/provider/vk/internal/captcha"

	tlsclient "github.com/bogdanfinn/tls-client"
)

func (c *Client) defaultAutoSolve(
	ctx context.Context,
	captchaErr *captcha.Error,
	streamID int,
	client tlsclient.HttpClient,
	profile browserprofile.Profile,
) (string, error) {
	log := captcha.Log
	log.Infof("[STREAM %d] [Captcha] Solving captcha (platform=%s)...", streamID, profile.Platform)

	if captchaErr.SessionToken == "" {
		return "", fmt.Errorf("no session_token in redirect_uri for auto-solve")
	}
	if captchaErr.RedirectURI == "" {
		return "", fmt.Errorf("no redirect_uri for auto-solve")
	}

	if c.advancedCaptcha && !c.manualOnly {
		capture := c.powCapture
		if capture == nil {
			capture = manual.CapturePowViaProxy
		}
		captureCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
		value, captureErr := capture(captureCtx, captchaErr.RedirectURI, c.dialer, profile)
		cancel()
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		if errors.Is(captureErr, captcha.ErrRateLimited) || errors.Is(captureErr, captcha.ErrUnavailable) {
			return "", captureErr
		}
		if captureErr == nil {
			token, err := captcha.SolveWithBrowserPow(ctx, captchaErr, streamID, client, profile, log, value)
			if err == nil {
				return token, nil
			}
			if !errors.Is(err, captcha.ErrInvalidBrowserPow) {
				return "", err
			}
		}
		// Fallback is safe only before a verification request was submitted.
		log.Infof("[STREAM %d] [Captcha] browser PoW unavailable; using legacy automatic solver", streamID)
	}
	successToken, err := captcha.Solve(ctx, captchaErr, streamID, client, profile, log)
	if err != nil {
		return "", err
	}
	log.Infof("[STREAM %d] [Captcha] solver succeeded", streamID)
	return successToken, nil
}
