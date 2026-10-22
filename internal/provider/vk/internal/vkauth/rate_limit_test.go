package vkauth

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LiTarPc/fturn-core/internal/provider/vk/internal/captcha"
	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
)

type authResponseClient struct {
	tlsclient.HttpClient
	respond func(*fhttp.Request) *fhttp.Response
	calls   []string
}

func (c *authResponseClient) Do(req *fhttp.Request) (*fhttp.Response, error) {
	c.calls = append(c.calls, req.URL.Path)
	return c.respond(req), nil
}

func authTestResponse(status int, body string) *fhttp.Response {
	return &fhttp.Response{StatusCode: status, Header: fhttp.Header{"Retry-After": []string{"3600"}}, Body: io.NopCloser(strings.NewReader(body))}
}

func TestAuthRequestRecognizesLimits(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		body    string
		limited bool
	}{
		{"HTTP with HTML", 429, "<html>slow down</html>", true},
		{"API 6", 200, `{"error":{"error_code":6}}`, true},
		{"API 29", 200, `{"error":{"error_code":29}}`, true},
		{"captcha required", 200, `{"error":{"error_code":14}}`, false},
		{"success", 200, `{"response":{"token":"ok"}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := New(Config{})
			client := &authResponseClient{respond: func(*fhttp.Request) *fhttp.Response { return authTestResponse(tc.status, tc.body) }}
			_, err := c.doRequest(context.Background(), client, c.currentPersona(), "", "https://api.vk.ru/method/test")
			if errors.Is(err, captcha.ErrRateLimited) != tc.limited {
				t.Fatalf("err=%v", err)
			}
			if tc.limited {
				var limit *captcha.RateLimitError
				if !errors.As(err, &limit) || time.Until(limit.RetryAt) < 59*time.Minute {
					t.Fatalf("Retry-After lost: %v", err)
				}
			}
		})
	}
}

func TestTokenChainStopsOnLimitAtEveryStage(t *testing.T) {
	stages := []string{"/call/join/test", "/", "/method/calls.getCallPreview", "/method/calls.getAnonymousToken", "/fb.do"}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			limited := false
			c := New(Config{})
			client := &authResponseClient{respond: func(req *fhttp.Request) *fhttp.Response {
				if limited {
					t.Errorf("request after limit: %s", req.URL.Path)
				}
				if req.URL.Path == stage {
					limited = true
					return authTestResponse(429, "<html>limited</html>")
				}
				switch req.URL.Path {
				case "/":
					return authTestResponse(200, `{"data":{"access_token":"anon"}}`)
				case "/method/calls.getAnonymousToken":
					return authTestResponse(200, `{"response":{"token":"call"}}`)
				default:
					return authTestResponse(200, `{"response":{}}`)
				}
			}}
			_, _, _, err := c.getTokenChainWithClient(context.Background(), "test", 1, VKCredentials{}, c.currentPersona(), client)
			if !limited || !errors.Is(err, captcha.ErrRateLimited) {
				t.Fatalf("limited=%v err=%v", limited, err)
			}
			if client.calls[len(client.calls)-1] != stage {
				t.Fatalf("requests=%v", client.calls)
			}
		})
	}
}

func TestFetchPausesOnGeneralAPILimitWithoutCredentialFallback(t *testing.T) {
	requests := 0
	c := newTestClient(t, func(context.Context, string, int, VKCredentials, tlsclient.CookieJar) (string, string, []string, error) {
		requests++
		return "", "", nil, captcha.NewRateLimitError("API 29", "3600")
	})
	persona := c.currentPersona()
	_, _, _, err := c.fetch(context.Background(), "test", 1)
	if !errors.Is(err, captcha.ErrRateLimited) || !errors.Is(err, ErrCaptchaWaitRequired) || requests != 1 {
		t.Fatalf("requests=%d err=%v", requests, err)
	}
	if c.currentPersona().VisitorID != persona.VisitorID {
		t.Fatal("persona changed")
	}
	if time.Until(time.Unix(c.LockoutUntilUnix(), 0)) < time.Hour {
		t.Fatal("Retry-After shortened")
	}
	_, _, _, _ = c.fetch(context.Background(), "test", 2)
	if requests != 1 {
		t.Fatal("worker sent another request during pause")
	}
}

func TestRateLimitBackoffGrowsAndResetsAfterSuccessfulFetch(t *testing.T) {
	c := newTestClient(t, func(context.Context, string, int, VKCredentials, tlsclient.CookieJar) (string, string, []string, error) {
		return "u", "p", []string{"server"}, nil
	})
	for i, want := range []time.Duration{5 * time.Minute, 10 * time.Minute, 20 * time.Minute, 40 * time.Minute, time.Hour, time.Hour} {
		_ = c.pauseAuth(1, pauseRate, captcha.ErrRateLimited)
		remaining := time.Until(time.Unix(c.LockoutUntilUnix(), 0))
		if remaining < want-time.Second || remaining > want {
			t.Fatalf("attempt=%d pause=%v want=%v", i, remaining, want)
		}
	}
	c.captchaPause.Store(0)
	c.lockout.Store(0)
	_, _, _, err := c.fetch(context.Background(), "test", 1)
	if err != nil || c.rateLimitStreak.Load() != 0 {
		t.Fatalf("err=%v streak=%d", err, c.rateLimitStreak.Load())
	}
}

func TestFetchDoesNotCountCaptchaLimitTwice(t *testing.T) {
	c := newTestClient(t, nil)
	c.tokenChain = func(context.Context, string, int, VKCredentials, tlsclient.CookieJar) (string, string, []string, error) {
		return "", "", nil, c.pauseAuth(1, pauseRate, captcha.ErrRateLimited)
	}
	_, _, _, _ = c.fetch(context.Background(), "test", 1)
	if c.rateLimitStreak.Load() != 1 {
		t.Fatal("one refusal counted twice")
	}
}

// Keep the mock's embedded interface compatible with the production client.
var _ tlsclient.HttpClient = (*authResponseClient)(nil)

func TestProviderRetryAfterLongerThanADaySurvivesRestart(t *testing.T) {
	paths := []string{filepath.Join(t.TempDir(), "vk_persona.json")}
	c := New(Config{StatePaths: paths})
	_ = c.pauseAuth(1, pauseRate, captcha.NewRateLimitError("test", "172800"))
	until := c.LockoutUntilUnix()
	restarted := New(Config{StatePaths: paths})
	if restarted.LockoutUntilUnix() != until || time.Until(time.Unix(until, 0)) < 48*time.Hour-time.Second {
		t.Fatal("provider pause lost after restart")
	}
}
