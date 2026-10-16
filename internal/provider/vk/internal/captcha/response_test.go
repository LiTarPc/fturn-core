package captcha

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/LiTarPc/fturn-core/internal/provider/vk/internal/browserprofile"
)

func TestProviderErrorTenIsTemporaryAndRedacted(t *testing.T) {
	raw := map[string]any{"error": map[string]any{
		"error_code": float64(10), "subcode": float64(5), "error_msg": "Internal server error",
		"request_params": []any{map[string]any{"key": "session_token", "value": "SECRET_SESSION_TOKEN"}},
	}}
	err := ResponseError("captchaNotRobot.check", 200, "120", raw)
	var provider *APIError
	if !errors.As(err, &provider) || provider.Code != 10 || provider.Subcode != 5 || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err=%v", err)
	}
	if errors.Is(err, ErrRateLimited) || strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "request_params") {
		t.Fatalf("unsafe error=%v", err)
	}
	if time.Until(RetryDeadline(err)) < 119*time.Second {
		t.Fatal("lost Retry-After")
	}
}

func TestCaptchaRequestClassifiesErrorTenBeforeSuccessParser(t *testing.T) {
	client := &limitTestClient{status: 200, body: `{"error":{"error_code":10,"subcode":5,"request_params":[{"value":"SECRET"}]}}`}
	session := &captchaSession{ctx: context.Background(), client: client, apiHost: "api.example.test", pageOrigin: "https://example.test"}
	_, err := session.performCaptchaCheck("token", "{}")
	var provider *APIError
	if !errors.As(err, &provider) || !errors.Is(err, ErrUnavailable) || client.calls != 1 {
		t.Fatalf("err=%v calls=%d", err, client.calls)
	}
	if strings.Contains(err.Error(), "invalid captcha check response") || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("unexpected diagnostic=%v", err)
	}
}

func TestProviderResponseErrorClassification(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		raw    map[string]any
		want   error
	}{
		{"HTTP rate", 429, nil, ErrRateLimited},
		{"HTTP service", 503, nil, ErrUnavailable},
		{"API rate", 200, map[string]any{"error": map[string]any{"error_code": "29"}}, ErrRateLimited},
		{"API service", 200, map[string]any{"error": map[string]any{"error_code": 10}}, ErrUnavailable},
		{"success", 200, map[string]any{"response": map[string]any{"status": "ok"}}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ResponseError("test", tc.status, "", tc.raw)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err=%v want=%v", err, tc.want)
			}
		})
	}
}

func TestCaptchaServiceFailureDoesNotRestartSession(t *testing.T) {
	client := &limitTestClient{status: 503, body: "unavailable"}
	_, err := Solve(context.Background(), &Error{SessionToken: "token", RedirectURI: "https://example.test/captcha"}, 1, client, browserprofile.Profile{}, nil)
	if !errors.Is(err, ErrUnavailable) || client.calls != 1 {
		t.Fatalf("err=%v calls=%d", err, client.calls)
	}
}
