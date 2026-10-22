package vkauth

import (
	"context"
	"errors"
	"fmt"
	neturl "net/url"
	"strings"
	"time"

	"github.com/LiTarPc/fturn-core/internal/provider/vk/internal/browserprofile"
	"github.com/LiTarPc/fturn-core/internal/provider/vk/internal/captcha"

	tlsclient "github.com/bogdanfinn/tls-client"
)

func (c *Client) fetchCallToken(
	ctx context.Context,
	httpClient tlsclient.HttpClient,
	profile browserprofile.Profile,
	streamID int,
	link, escapedName, token1 string,
	creds VKCredentials,
) (string, error) {
	urlAddr := fmt.Sprintf("https://api.vk.ru/method/calls.getAnonymousToken?v=%s&client_id=%s", APIVersion, creds.ClientID)
	data := fmt.Sprintf("vk_join_link=https://vk.ru/call/join/%s&name=%s&access_token=%s",
		link, escapedName, token1)

	captchaSubmitted := false
	for {
		resp, err := c.doRequest(ctx, httpClient, profile, data, urlAddr)
		if err != nil {
			if captchaSubmitted {
				c.log.Warnf("[STREAM %d] [Captcha] event=CAPTCHA_SUBMIT_RESULT outcome=request_failed error=%v", streamID, err)
			}
			return "", err
		}

		if errObj, hasErr := resp["error"].(map[string]any); hasErr {
			captchaErr := captcha.ParseError(errObj)
			if captchaSubmitted {
				outcome := "rejected"
				if captchaErr != nil && captchaErr.IsCaptcha() {
					outcome = "challenge_repeated"
				}
				c.log.Warnf("[STREAM %d] [Captcha] event=CAPTCHA_SUBMIT_RESULT outcome=%s response=%s", streamID, outcome, captcha.SafeResponse(resp))
			}
			if captchaErr != nil && captchaErr.IsCaptcha() {
				retryData, err := c.solveCaptcha(ctx, httpClient, profile, streamID, link, escapedName, token1, captchaErr)
				if err != nil {
					return "", err
				}
				captchaSubmitted = true
				data = retryData
				continue
			}
			if termErr := classifyLinkError(errObj); termErr != nil {
				c.log.Errorf("[STREAM %d] [Messenger Auth] terminal link error: %v", streamID, termErr)
				return "", termErr
			}
			return "", fmt.Errorf("messenger API error: response=%s", captcha.SafeResponse(errObj))
		}

		respMap, ok := resp["response"].(map[string]any)
		if !ok {
			if captchaSubmitted {
				c.log.Warnf("[STREAM %d] [Captcha] event=CAPTCHA_SUBMIT_RESULT outcome=invalid_response response=%s", streamID, captcha.SafeResponse(resp))
			}
			return "", fmt.Errorf("unexpected getAnonymousToken response: response=%s", captcha.SafeResponse(resp))
		}
		token2, ok := respMap["token"].(string)
		if !ok || token2 == "" {
			if captchaSubmitted {
				c.log.Warnf("[STREAM %d] [Captcha] event=CAPTCHA_SUBMIT_RESULT outcome=invalid_response response=%s", streamID, captcha.SafeResponse(resp))
			}
			return "", fmt.Errorf("missing token in response: response=%s", captcha.SafeResponse(resp))
		}
		if captchaSubmitted {
			c.log.Infof("[STREAM %d] [Captcha] event=CAPTCHA_SUBMIT_RESULT outcome=accepted", streamID)
		}
		return token2, nil
	}
}

func classifyLinkError(errObj map[string]any) error {
	code := 0
	if f, ok := errObj["error_code"].(float64); ok {
		code = int(f)
	}

	if code == 9000 || code == 9008 {
		return ErrInvalidJoinLink
	}
	switch code {
	case 5, 6, 9, 14, 29:
		return nil
	}

	msg := ""
	if s, ok := errObj["error_msg"].(string); ok {
		msg = strings.ToLower(s)
	}
	switch {
	case strings.Contains(msg, "not valid") || strings.Contains(msg, "not found"):
		return ErrInvalidJoinLink
	case strings.Contains(msg, "anonym"):
		return ErrAnonymousBlocked
	case strings.Contains(msg, "full"):
		return ErrCallFull
	}
	return nil
}

func (c *Client) solveCaptcha(
	ctx context.Context,
	httpClient tlsclient.HttpClient,
	profile browserprofile.Profile,
	streamID int,
	link, escapedName, token1 string,
	captchaErr *captcha.Error,
) (retryData string, err error) {
	attempt := c.captchaAttempt
	c.captchaAttempt++

	solveMode, hasSolveMode := CaptchaSolveModeForAttempt(attempt, c.manualOnly)
	if !hasSolveMode {
		c.log.Warnf("[STREAM %d] [Captcha] No more solve modes available (attempt %d)", streamID, attempt+1)
		c.burnPersona(streamID)
		c.engageLockout(60 * time.Second)
		if c.streamsFn() == 0 {
			c.log.Errorf("[STREAM %d] [Captcha] FATAL: 0 connected streams and solve modes exhausted", streamID)
			return "", ErrFatalCaptchaNoStreams
		}
		return "", ErrCaptchaWaitRequired
	}

	var successToken string
	var solveErr error
	started := time.Now()
	mode := "auto"
	if solveMode == CaptchaSolveModeManual {
		mode = "manual"
	}
	c.log.Infof("[STREAM %d] [Captcha] event=CAPTCHA_SOLVE_STARTED mode=%s attempt=%d", streamID, mode, attempt+1)
	defer func() {
		outcome := "token_received"
		cause := solveErr
		if cause == nil {
			cause = err
		}
		switch {
		case ctx.Err() != nil:
			outcome = "cancelled"
		case errors.Is(cause, captcha.ErrRateLimited):
			outcome = "rate_limited"
		case errors.Is(cause, captcha.ErrUnavailable):
			outcome = "service_unavailable"
		case errors.Is(cause, context.DeadlineExceeded):
			outcome = "timed_out"
		case cause != nil:
			outcome = "failed"
		}
		logResult := c.log.Infof
		if cause != nil {
			logResult = c.log.Warnf
		}
		logResult("[STREAM %d] [Captcha] event=CAPTCHA_SOLVE_RESULT mode=%s attempt=%d outcome=%s duration=%s", streamID, mode, attempt+1, outcome, time.Since(started).Truncate(time.Millisecond))
	}()

	switch solveMode {
	case CaptchaSolveModeAuto:
		solveFn := c.autoSolver
		if solveFn == nil {
			solveFn = c.defaultAutoSolve
		}
		if captchaErr.SessionToken != "" && captchaErr.RedirectURI != "" {
			successToken, solveErr = solveFn(ctx, captchaErr, streamID, httpClient, profile)
			if solveErr != nil {
				c.log.Warnf("[STREAM %d] [Captcha] Auto captcha failed: %v", streamID, solveErr)
			}
		} else {
			solveErr = fmt.Errorf("missing fields for auto solve")
		}

	case CaptchaSolveModeManual:
		if c.manualSolve == nil {
			solveErr = fmt.Errorf("manual captcha solver not configured")
			break
		}
		c.log.Infof("[STREAM %d] [Captcha] Triggering manual captcha fallback", streamID)
		manualCtx, manualCancel := context.WithTimeout(ctx, 3*time.Minute)

		type manualRes struct {
			token string
			err   error
		}
		resCh := make(chan manualRes, 1)
		go func() {
			t, e := c.manualSolve(manualCtx, captchaErr, c.dialer, profile)
			resCh <- manualRes{t, e}
		}()

		select {
		case res := <-resCh:
			successToken = res.token
			solveErr = res.err
			if successToken != "" {
				if solveErr != nil {
					c.log.Debugf("[STREAM %d] [Captcha] Token received (ignoring cleanup error: %v)", streamID, solveErr)
					solveErr = nil
				}
				c.log.Infof("[STREAM %d] [Captcha] Got token from browser", streamID)
			} else if solveErr != nil {
				c.log.Warnf("[STREAM %d] [Captcha] Manual solver error: %v", streamID, solveErr)
			}
		case <-manualCtx.Done():
			if errors.Is(manualCtx.Err(), context.DeadlineExceeded) {
				solveErr = fmt.Errorf("manual captcha timed out after 3m: %w", manualCtx.Err())
			} else {
				solveErr = fmt.Errorf("manual captcha interrupted: %w", manualCtx.Err())
			}
		}
		manualCancel()
	}

	// Сессию свернули (стоп, смена сети, рецикл) - решателю просто не дали доработать.
	// Считать это провалом значит жечь поколение персоны и вешать lockout на своих же
	// перезапусках.
	if solveErr == nil && successToken == "" {
		solveErr = errors.New("captcha solver returned an empty success token")
	}

	if solveErr != nil && ctx.Err() != nil {
		c.log.Warnf("[STREAM %d] [Captcha] solve interrupted by shutdown: %v", streamID, solveErr)
		return "", solveErr
	}

	if errors.Is(solveErr, captcha.ErrRateLimited) || errors.Is(solveErr, captcha.ErrUnavailable) {
		c.captchaAttempt = attempt
		kind := pauseService
		if errors.Is(solveErr, captcha.ErrRateLimited) {
			kind = pauseRate
		}
		return "", c.pauseAuth(streamID, kind, solveErr)
	}

	if solveErr != nil {
		c.log.Warnf("[STREAM %d] [Captcha] %s failed (attempt %d): %v",
			streamID, CaptchaSolveModeLabel(solveMode), attempt+1, solveErr)
		nextSolveMode, hasNextSolveMode := CaptchaSolveModeForAttempt(attempt+1, c.manualOnly)
		if hasNextSolveMode {
			c.log.Infof("[STREAM %d] [Captcha] Falling back to %s with a new persona",
				streamID, CaptchaSolveModeLabel(nextSolveMode))
			c.burnPersona(streamID)
			return "", ErrPersonaBurned
		}
		c.burnPersona(streamID)
		c.engageLockout(60 * time.Second)
		if c.streamsFn() == 0 {
			c.log.Errorf("[STREAM %d] [Captcha] FATAL: 0 connected streams and manual captcha failed/timed out", streamID)
			return "", ErrFatalCaptchaNoStreams
		}
		return "", ErrCaptchaWaitRequired
	}

	if captchaErr.CaptchaAttempt == "0" || captchaErr.CaptchaAttempt == "" {
		captchaErr.CaptchaAttempt = "1"
	}
	return buildCaptchaRetryData(link, escapedName, token1, captchaErr, successToken), nil
}

func buildCaptchaRetryData(link, escapedName, token1 string, captchaErr *captcha.Error, successToken string) string {
	if captchaErr.CaptchaSid == "" {
		return fmt.Sprintf(
			"vk_join_link=https://vk.ru/call/join/%s&name=%s&success_token=%s&access_token=%s",
			link, escapedName, neturl.QueryEscape(successToken), token1,
		)
	}
	return fmt.Sprintf(
		"vk_join_link=https://vk.ru/call/join/%s&name=%s&captcha_key=&captcha_sid=%s&is_sound_captcha=0&success_token=%s&captcha_ts=%s&captcha_attempt=%s&access_token=%s",
		link, escapedName, captchaErr.CaptchaSid, neturl.QueryEscape(successToken),
		captchaErr.CaptchaTs, captchaErr.CaptchaAttempt, token1,
	)
}
