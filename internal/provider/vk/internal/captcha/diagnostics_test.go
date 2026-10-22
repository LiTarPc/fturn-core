package captcha

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSafeResponseRetainsProviderDetailsAndMasksEchoedSecrets(t *testing.T) {
	raw := map[string]any{"error": map[string]any{
		"error_code": 10, "subcode": 5, "error_msg": "Internal server error for PRIVATE_SESSION",
		"trace_id": "trace-123", "new_diagnostic": map[string]any{"reason": "unavailable", "retry_after": 120},
		"request_params": []any{
			"UNNAMED_SECRET",
			map[string]any{"key": "session_token", "value": "PRIVATE_SESSION"},
			map[string]any{"key": "v", "value": "5.282"},
			map[string]any{"value": "MALFORMED_SECRET"},
			map[string]any{"key": "redirect_uri", "value": "https://id.vk.ru/captcha?session_token=URL_SECRET&variant=checkbox"},
		},
		"cookies":      map[string]any{"sid": "COOKIE_SECRET"},
		"access_token": "ACCESS_SECRET",
		"details":      "session_token=PRIVATE_SESSION hash=HASH_SECRET",
	}}
	before, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	got := SafeResponse(raw)
	for _, want := range []string{"Internal server error", `"error_code":10`, `"subcode":5`, "trace-123", "new_diagnostic", "unavailable", `"retry_after":120`, `"request_params"`, `"value":"5.282"`, "variant"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %s", want, got)
		}
	}
	for _, secret := range []string{"PRIVATE_SESSION", "UNNAMED_SECRET", "MALFORMED_SECRET", "URL_SECRET", "COOKIE_SECRET", "ACCESS_SECRET", "HASH_SECRET"} {
		if strings.Contains(got, secret) {
			t.Errorf("exposed %q: %s", secret, got)
		}
	}
	after, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("diagnostics mutated the API response")
	}
	if strings.Contains(got, "\n") || !json.Valid([]byte(got)) {
		t.Fatalf("not a single JSON log record: %s", got)
	}
}

func TestDiagnosticRedactionBeforeTruncation(t *testing.T) {
	secret := strings.Repeat("private", 1000)
	got := SafeResponse(map[string]any{"error_msg": "reflected " + secret, "session_token": secret, "tail": strings.Repeat("я", 10000)})
	if strings.Contains(got, "private") || !utf8.ValidString(got) || !strings.Contains(got, "truncated") {
		t.Fatalf("invalid/truncated diagnostic, bytes=%d", len(got))
	}
}

func TestDiagnosticWrapperKeepsErrorIdentity(t *testing.T) {
	rate := NewRateLimitError("captchaNotRobot.check", "120")
	err := WithResponse(rate, map[string]any{"error": map[string]any{"error_msg": "Too many requests", "subcode": 5}})
	var typed *RateLimitError
	if !errors.Is(err, ErrRateLimited) || !errors.As(err, &typed) || typed != rate {
		t.Fatalf("lost error identity: %v", err)
	}
	if !strings.Contains(err.Error(), "Too many requests") {
		t.Fatalf("lost message: %v", err)
	}
	if WithResponse(nil, map[string]any{"status": "BOT"}) != nil {
		t.Fatal("created failure from success")
	}
}

func TestCheckboxBotIncludesProviderDetailsWithoutDebug(t *testing.T) {
	client := &limitTestClient{status: 200, body: `{"response":{"status":"BOT","show_captcha_type":"checkbox","reason":"challenge rejected","trace_id":"bot-trace","session_token":"HIDDEN_SESSION"}}`}
	s := &captchaSession{ctx: context.Background(), client: client, apiHost: "api.example.test", pageOrigin: "https://example.test"}
	_, err := s.solveCheckboxCaptcha("HIDDEN_SESSION")
	if !errors.Is(err, errCaptchaBot) {
		t.Fatalf("err=%v", err)
	}
	for _, want := range []string{"BOT", "checkbox", "challenge rejected", "bot-trace"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("missing %q in %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "HIDDEN_SESSION") {
		t.Fatalf("exposed session: %v", err)
	}
}

func TestCaptchaHTTPFailureRetainsJSONDetails(t *testing.T) {
	for _, status := range []int{429, 503} {
		client := &limitTestClient{status: status, body: `{"error":{"error_code":10,"error_msg":"Provider unavailable","trace_id":"http-trace","access_token":"HIDDEN_ACCESS"}}`}
		s := &captchaSession{ctx: context.Background(), client: client, apiHost: "api.example.test", pageOrigin: "https://example.test"}
		_, err := s.performCaptchaCheck("session", "{}")
		want := ErrUnavailable
		if status == 429 {
			want = ErrRateLimited
		}
		if !errors.Is(err, want) || !strings.Contains(err.Error(), "Provider unavailable") || !strings.Contains(err.Error(), "http-trace") || strings.Contains(err.Error(), "HIDDEN_ACCESS") {
			t.Fatalf("HTTP=%d err=%v", status, err)
		}
		if client.calls != 1 {
			t.Fatalf("extra requests: %d", client.calls)
		}
	}
}

func TestUnexpectedCheckResponseIncludesSafePayload(t *testing.T) {
	_, err := parseCaptchaCheck(map[string]any{"new_error": map[string]any{"reason": "schema changed", "session_token": "HIDDEN_TOKEN"}})
	if err == nil || !strings.Contains(err.Error(), "schema changed") || strings.Contains(err.Error(), "HIDDEN_TOKEN") {
		t.Fatalf("err=%v", err)
	}
}
