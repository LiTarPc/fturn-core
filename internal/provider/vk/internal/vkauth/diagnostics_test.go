package vkauth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/LiTarPc/fturn-core/internal/provider/vk/internal/browserprofile"
	"github.com/LiTarPc/fturn-core/internal/provider/vk/internal/captcha"
	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
)

type outcomeLogger struct {
	lines []string
	debug bool
}

func (l *outcomeLogger) Debugf(f string, v ...any) {
	if l.debug {
		l.lines = append(l.lines, fmt.Sprintf(f, v...))
	}
}
func (l *outcomeLogger) Infof(f string, v ...any)  { l.lines = append(l.lines, fmt.Sprintf(f, v...)) }
func (l *outcomeLogger) Warnf(f string, v ...any)  { l.lines = append(l.lines, fmt.Sprintf(f, v...)) }
func (l *outcomeLogger) Errorf(f string, v ...any) { l.lines = append(l.lines, fmt.Sprintf(f, v...)) }
func (l *outcomeLogger) DebugEnabled() bool        { return l.debug }

func TestCaptchaOutcomeLogsWithoutDebug(t *testing.T) {
	for _, tc := range []struct {
		name, mode, token, outcome string
		failure                    error
		cancel                     bool
	}{
		{name: "automatic success", mode: "auto", token: "PRIVATE_RESULT", outcome: "token_received"},
		{name: "manual success", mode: "manual", token: "PRIVATE_RESULT", outcome: "token_received"},
		{name: "bot", mode: "auto", outcome: "failed", failure: errors.New("checkbox captcha rejected: status=BOT")},
		{name: "rate limit", mode: "auto", outcome: "rate_limited", failure: captcha.NewRateLimitError("check", "120")},
		{name: "service failure", mode: "auto", outcome: "service_unavailable", failure: fmt.Errorf("%w: VK API code=10 subcode=5", captcha.ErrUnavailable)},
		{name: "manual timeout", mode: "manual", outcome: "timed_out", failure: context.DeadlineExceeded},
		{name: "cancelled", mode: "auto", outcome: "cancelled", failure: context.Canceled, cancel: true},
		{name: "empty token", mode: "auto", outcome: "failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logger := &outcomeLogger{}
			c := New(Config{ManualOnly: tc.mode == "manual", Log: logger, StreamsAlive: func() int32 { return 1 }})
			c.autoSolver = func(context.Context, *captcha.Error, int, tlsclient.HttpClient, browserprofile.Profile) (string, error) {
				return tc.token, tc.failure
			}
			c.manualSolve = func(context.Context, *captcha.Error, net.Dialer, browserprofile.Profile) (string, error) {
				return tc.token, tc.failure
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancel {
				cancel()
			}
			_, err := c.solveCaptcha(ctx, nil, c.currentPersona(), 7, "test", "name", "PRIVATE_ACCESS", testCaptchaErr())
			logs := strings.Join(logger.lines, "\n")
			for _, want := range []string{"[STREAM 7]", "event=CAPTCHA_SOLVE_STARTED", "event=CAPTCHA_SOLVE_RESULT", "mode=" + tc.mode, "outcome=" + tc.outcome, "duration="} {
				if !strings.Contains(logs, want) {
					t.Fatalf("missing %q: %s", want, logs)
				}
			}
			if (err == nil) != (tc.outcome == "token_received") {
				t.Fatalf("outcome=%s err=%v", tc.outcome, err)
			}
			if strings.Contains(logs, "PRIVATE_") {
				t.Fatalf("secret in log: %s", logs)
			}
			t.Log(logs)
		})
	}
}

func TestCaptchaSubmitOutcomeLogs(t *testing.T) {
	const challenge = `{"error":{"error_code":14,"error_msg":"Captcha needed","redirect_uri":"https://id.vk.ru/captcha?session_token=PRIVATE_SESSION"}}`
	for _, tc := range []struct {
		name, reply, outcome string
		accepted             bool
	}{
		{"accepted", `{"response":{"token":"PRIVATE_CALL_TOKEN"}}`, "accepted", true},
		{"rejected", `{"error":{"error_code":5,"error_msg":"Captcha answer rejected","request_params":[{"key":"success_token","value":"PRIVATE_SUCCESS"}]}}`, "rejected", false},
		{"repeated", challenge, "challenge_repeated", false},
		{"service error", `{"error":{"error_code":10,"subcode":5,"error_msg":"Internal server error"}}`, "request_failed", false},
		{"invalid success", `{"response":{"token":""}}`, "invalid_response", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logger := &outcomeLogger{}
			c := New(Config{Log: logger, StreamsAlive: func() int32 { return 1 }})
			c.autoSolver = func(context.Context, *captcha.Error, int, tlsclient.HttpClient, browserprofile.Profile) (string, error) {
				return "PRIVATE_SUCCESS", nil
			}
			c.manualSolve = func(context.Context, *captcha.Error, net.Dialer, browserprofile.Profile) (string, error) {
				return "", context.DeadlineExceeded
			}
			calls := 0
			client := &authResponseClient{respond: func(*fhttp.Request) *fhttp.Response {
				calls++
				if calls == 1 {
					return authTestResponse(200, challenge)
				}
				return authTestResponse(200, tc.reply)
			}}
			_, err := c.fetchCallToken(context.Background(), client, c.currentPersona(), 7, "test", "name", "PRIVATE_ACCESS", VKCredentials{ClientID: "test"})
			logs := strings.Join(logger.lines, "\n")
			if !strings.Contains(logs, "event=CAPTCHA_SUBMIT_RESULT outcome="+tc.outcome) {
				t.Fatalf("missing submit outcome: %s", logs)
			}
			if (err == nil) != tc.accepted {
				t.Fatalf("accepted=%v err=%v", tc.accepted, err)
			}
			if strings.Contains(logs, "PRIVATE_") {
				t.Fatalf("secret in log: %s", logs)
			}
			if !tc.accepted && strings.Contains(logs, "outcome=accepted") {
				t.Fatalf("false acceptance: %s", logs)
			}
			t.Log(logs)
		})
	}
}

func TestAuthResponseDiagnosticsDebug(t *testing.T) {
	for _, debug := range []bool{false, true} {
		t.Run(fmt.Sprintf("debug=%t", debug), func(t *testing.T) {
			logger := &outcomeLogger{debug: debug}
			c := New(Config{Log: logger})
			client := &authResponseClient{respond: func(*fhttp.Request) *fhttp.Response {
				return authTestResponse(200, `{"error":{"error_code":14,"error_msg":"Captcha needed","trace_id":"debug-trace","redirect_uri":"https://id.vk.ru/captcha?session_token=PRIVATE_REDIRECT","request_params":[{"key":"session_token","value":"PRIVATE_SESSION"},{"key":"v","value":"5.282"}]}}`)
			}}
			_, err := c.doRequest(context.Background(), client, c.currentPersona(), "", "https://api.vk.ru/method/test")
			if err != nil {
				t.Fatal(err)
			}
			logs := strings.Join(logger.lines, "\n")
			if debug {
				for _, want := range []string{"response source=", `"error_code":14`, "Captcha needed", "debug-trace", "5.282"} {
					if !strings.Contains(logs, want) {
						t.Fatalf("missing %q in %s", want, logs)
					}
				}
			} else if logs != "" {
				t.Fatalf("debug output with debug disabled: %s", logs)
			}
			if strings.Contains(logs, "PRIVATE_") {
				t.Fatalf("secret in debug log: %s", logs)
			}
			t.Log(logs)
		})
	}
}
