package manual

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestPowCaptureEndpointPrivateAndOneShot(t *testing.T) {
	const path = "/local-captcha-pow/fixture-secret"
	value := "v2." + base64.StdEncoding.EncodeToString([]byte(`{"hash":"fixture","telemetry":{}}`))
	result := make(chan string, 1)
	handler := powCaptureHandler(path, result)
	for _, tc := range []struct {
		name, path, method, host, origin, body string
		want                                   int
	}{
		{"wrong path", path + "wrong", "POST", "localhost:8765", "", "pow=" + url.QueryEscape(value), 404},
		{"get", path, "GET", "localhost:8765", "", "", 405},
		{"wrong host", path, "POST", "evil.invalid", "", "pow=" + url.QueryEscape(value), 403},
		{"wrong origin", path, "POST", "localhost:8765", "https://evil.invalid", "pow=" + url.QueryEscape(value), 403},
		{"malformed", path, "POST", "localhost:8765", "", "pow=invalid", 400},
		{"oversized", path, "POST", "localhost:8765", "", "pow=" + strings.Repeat("a", 200*1024), 400},
		{"success", path, "POST", "localhost:8765", localCaptchaOrigin(), "pow=" + url.QueryEscape(value), 204},
		{"duplicate", path, "POST", "localhost:8765", "", "pow=" + url.QueryEscape(value), 410},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(context.Background(), tc.method, "http://localhost:8765"+tc.path, strings.NewReader(tc.body))
			r.Host = tc.host
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Origin", tc.origin)
			w := httptest.NewRecorder()
			handler(w, r)
			if w.Code != tc.want {
				t.Fatalf("status=%d want=%d", w.Code, tc.want)
			}
		})
	}
	select {
	case got := <-result:
		if got != value {
			t.Fatal("captured value changed")
		}
	default:
		t.Fatal("missing captured envelope")
	}
	// Draining the channel cannot make a completed capture reusable.
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "http://localhost:8765"+path, strings.NewReader("pow="+url.QueryEscape(value)))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler(w, r)
	if w.Code != 410 {
		t.Fatal("capture endpoint accepted a second result")
	}
}
func TestCaptureInjectionBeforeInlineAndOpaquePath(t *testing.T) {
	html := `<html><head><script>window.captchaPowResult="computed";</script></head><body></body></html>`
	target, _ := url.Parse("https://id.vk.ru")
	rewritten := rewriteCaptchaHTML(html, target, "/local-captcha-pow/opaque-secret")
	if strings.Index(rewritten, "Object.defineProperty") > strings.Index(rewritten, `window.captchaPowResult="computed"`) {
		t.Fatal("capture observer installed after page script")
	}
	if !strings.Contains(rewritten, `"capturePow":true`) || !strings.Contains(rewritten, "opaque-secret") {
		t.Fatal("capture config absent")
	}
}
