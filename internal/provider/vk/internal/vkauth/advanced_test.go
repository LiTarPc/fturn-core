package vkauth

import (
	"context"
	"errors"
	"github.com/LiTarPc/fturn-core/internal/provider/vk/internal/browserprofile"
	"github.com/LiTarPc/fturn-core/internal/provider/vk/internal/captcha"
	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"io"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

type fixtureAuthControl struct{ paused, authorized, acquired, released int }

func (g *fixtureAuthControl) Acquire(context.Context) error { g.acquired++; return nil }
func (g *fixtureAuthControl) Release()                      { g.released++ }
func (g *fixtureAuthControl) Pause()                        { g.paused++ }
func (g *fixtureAuthControl) Authorized()                   { g.authorized++ }

func TestAdvancedFailureFreshManualSameIdentity(t *testing.T) {
	defer automaticChecksDisabled.Store(false)
	for _, tc := range []struct {
		name      string
		autoErr   error
		manualErr error
		repeat    bool
		wantPause bool
	}{
		{"auto failure manual success", errors.New("verification failed"), nil, false, false},
		{"bot manual success", captcha.ErrBot, nil, false, false},
		{"manual timeout", errors.New("verification failed"), context.DeadlineExceeded, false, true},
		{"manual rejected", errors.New("verification failed"), nil, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			automaticChecksDisabled.Store(false)
			gate := &fixtureAuthControl{}
			logger := &outcomeLogger{debug: true}
			c := New(Config{AdvancedCaptcha: true, AuthControl: gate, Log: logger, FingerprintSeed: "identity-fixture"})
			original := c.currentPersona()
			auto, manual, calls := 0, 0, 0
			c.autoSolver = func(context.Context, *captcha.Error, int, tlsclient.HttpClient, browserprofile.Profile) (string, error) {
				auto++
				return "", tc.autoErr
			}
			c.manualSolve = func(_ context.Context, e *captcha.Error, _ net.Dialer, _ browserprofile.Profile) (string, error) {
				manual++
				if e.SessionToken != "PRIVATE_FRESH" {
					t.Error("manual reused consumed challenge")
				}
				if tc.manualErr != nil {
					return "", tc.manualErr
				}
				return "PRIVATE_SOLUTION", nil
			}
			client := &authResponseClient{respond: func(r *fhttp.Request) *fhttp.Response {
				calls++
				if r.URL.Query().Get("client_id") != "fixed" {
					t.Error("client ID changed")
				}
				b, _ := io.ReadAll(r.Body)
				form, _ := url.ParseQuery(string(b))
				switch calls {
				case 1:
					if form.Get("success_token") != "" {
						t.Error("unexpected submission")
					}
					return authTestResponse(200, `{"error":{"error_code":14,"error_msg":"Captcha needed","redirect_uri":"https://id.vk.ru/captcha?session_token=PRIVATE_OLD"}}`)
				case 2:
					if form.Get("success_token") != "" {
						t.Error("fresh challenge request submitted prior answer")
					}
					return authTestResponse(200, `{"error":{"error_code":14,"error_msg":"Captcha needed","redirect_uri":"https://id.vk.ru/captcha?session_token=PRIVATE_FRESH"}}`)
				default:
					if tc.repeat {
						return authTestResponse(200, `{"error":{"error_code":14,"error_msg":"Captcha needed","redirect_uri":"https://id.vk.ru/captcha?session_token=PRIVATE_REPEAT"}}`)
					}
					return authTestResponse(200, `{"response":{"token":"PRIVATE_CALL"}}`)
				}
			}}
			token, err := c.fetchCallToken(context.Background(), client, original, 1, "fixture", "name", "PRIVATE_ACCESS", VKCredentials{ClientID: "fixed"})
			if tc.wantPause {
				if !errors.Is(err, ErrCaptchaWaitRequired) || gate.paused != 1 {
					t.Fatalf("missing user pause: %v", err)
				}
			} else if err != nil || token != "PRIVATE_CALL" {
				t.Fatalf("manual continuation: %v", err)
			}
			if auto != 1 || manual != 1 || calls > 3 {
				t.Fatalf("unbounded attempts: auto=%d manual=%d calls=%d", auto, manual, calls)
			}
			if c.currentPersona().VisitorID != original.VisitorID || c.currentPersona().UserAgent != original.UserAgent {
				t.Fatal("identity changed")
			}
			if errors.Is(tc.autoErr, captcha.ErrBot) && !automaticChecksDisabled.Load() {
				t.Fatal("BOT did not disable automatic checks")
			}
			if strings.Contains(strings.Join(logger.lines, "\n"), "PRIVATE_") {
				t.Fatal("private value escaped into logs")
			}
		})
	}
}
func TestAdvancedStopsOnRefusalAndCancel(t *testing.T) {
	for _, failure := range []error{captcha.NewRateLimitError("fixture", "120"), captcha.ErrUnavailable, context.Canceled} {
		gate := &fixtureAuthControl{}
		c := New(Config{AdvancedCaptcha: true, AuthControl: gate})
		ctx, cancel := context.WithCancel(context.Background())
		c.autoSolver = func(context.Context, *captcha.Error, int, tlsclient.HttpClient, browserprofile.Profile) (string, error) {
			if errors.Is(failure, context.Canceled) {
				cancel()
			}
			return "", failure
		}
		_, err := c.solveCaptcha(ctx, nil, c.currentPersona(), 1, "fixture", "name", "PRIVATE_ACCESS", testCaptchaErr())
		cancel()
		if !errors.Is(err, failure) {
			t.Fatalf("refusal lost: %v", err)
		}
		if errors.Is(err, errFreshManualChallenge) || gate.paused != 0 {
			t.Fatal("refusal created another challenge")
		}
	}
}
func TestAdvancedBotSkipsFutureAutomaticAttempts(t *testing.T) {
	automaticChecksDisabled.Store(true)
	defer automaticChecksDisabled.Store(false)
	c := New(Config{AdvancedCaptcha: true})
	auto, manual := 0, 0
	c.autoSolver = func(context.Context, *captcha.Error, int, tlsclient.HttpClient, browserprofile.Profile) (string, error) {
		auto++
		return "", nil
	}
	c.manualSolve = func(context.Context, *captcha.Error, net.Dialer, browserprofile.Profile) (string, error) {
		manual++
		return "private", nil
	}
	if _, err := c.solveCaptcha(context.Background(), nil, c.currentPersona(), 1, "fixture", "name", "private", testCaptchaErr()); err != nil || auto != 0 || manual != 1 {
		t.Fatalf("auto=%d manual=%d err=%v", auto, manual, err)
	}
}
func TestAdvancedFreshAuthorizationNotification(t *testing.T) {
	gate := &fixtureAuthControl{}
	c := newTestClient(t, func(context.Context, string, int, VKCredentials, tlsclient.CookieJar) (string, string, []string, error) {
		return "user", "password", []string{"relay:3478"}, nil
	}, func(c *Client) { c.authControl = gate; c.minFetchIntervalFn = func() time.Duration { return 0 } })
	for range 2 {
		if _, _, _, err := c.GetCredentials(context.Background(), "fixture", 1); err != nil {
			t.Fatal(err)
		}
	}
	if gate.authorized != 1 || gate.acquired != 1 || gate.released != 1 {
		t.Fatalf("fresh/cache notifications: %+v", gate)
	}
}

func TestAdvancedAndIPCTokenRejectionDoesNotCycleIdentity(t *testing.T) {
	const challenge = `{"error":{"error_code":14,"error_msg":"Captcha needed","redirect_uri":"https://id.vk.ru/captcha?session_token=PRIVATE_FRESH"}}`
	for _, tc := range []struct {
		name                                                            string
		advanced, manual, browser, rejectManual, repeatBrowser, timeout bool
		wantRequests                                                    int
		wantPause                                                       bool
	}{
		{name: "advanced API rejection fresh manual succeeds", advanced: true, wantRequests: 4},
		{name: "advanced manual API rejection pauses", advanced: true, rejectManual: true, wantRequests: 4, wantPause: true},
		{name: "IPC manual-only rejection pauses", manual: true, rejectManual: true, wantRequests: 2, wantPause: true},
		{name: "IPC browser token rejection pauses", browser: true, rejectManual: true, wantRequests: 2, wantPause: true},
		{name: "IPC browser repeated challenge pauses", browser: true, repeatBrowser: true, wantRequests: 2, wantPause: true},
		{name: "IPC browser timeout pauses", browser: true, timeout: true, wantRequests: 1, wantPause: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gate := &fixtureAuthControl{}
			c := New(Config{AdvancedCaptcha: tc.advanced, ManualOnly: tc.manual, AuthControl: gate})
			original := c.currentPersona()
			auto, manual, calls := 0, 0, 0
			c.autoSolver = func(context.Context, *captcha.Error, int, tlsclient.HttpClient, browserprofile.Profile) (string, error) {
				auto++
				return "PRIVATE_AUTO", nil
			}
			solve := func(context.Context, *captcha.Error, net.Dialer, browserprofile.Profile) (string, error) {
				manual++
				if tc.timeout {
					return "", context.DeadlineExceeded
				}
				return "PRIVATE_MANUAL", nil
			}
			c.manualSolve = solve
			if tc.browser {
				c.browserSolve = solve
			}
			client := &authResponseClient{respond: func(r *fhttp.Request) *fhttp.Response {
				calls++
				if calls > tc.wantRequests {
					t.Fatal("unexpected request after rejection")
				}
				b, _ := io.ReadAll(r.Body)
				form, _ := url.ParseQuery(string(b))
				answer := form.Get("success_token")
				if answer == "" {
					return authTestResponse(200, challenge)
				}
				if tc.repeatBrowser {
					return authTestResponse(200, challenge)
				}
				if answer == "PRIVATE_AUTO" || tc.rejectManual {
					return authTestResponse(200, `{"error":{"error_code":5,"error_msg":"Rejected answer"}}`)
				}
				return authTestResponse(200, `{"response":{"token":"PRIVATE_CALL"}}`)
			}}
			token, err := c.fetchCallToken(context.Background(), client, original, 1, "fixture", "name", "PRIVATE_ACCESS", VKCredentials{ClientID: "fixed"})
			if tc.wantPause {
				if !errors.Is(err, ErrCaptchaWaitRequired) || gate.paused != 1 {
					t.Fatalf("expected explicit pause: %v", err)
				}
			} else if err != nil || token != "PRIVATE_CALL" {
				t.Fatalf("fresh manual failed: %v", err)
			}
			if calls != tc.wantRequests || auto > 1 || manual != 1 || c.currentPersona().VisitorID != original.VisitorID {
				t.Fatalf("requests=%d auto=%d manual=%d", calls, auto, manual)
			}
		})
	}
}
