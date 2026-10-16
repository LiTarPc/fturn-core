package captcha

import (
	"context"
	"errors"
	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"io"
	"net/url"
	"strings"
	"testing"
)

type limitTestClient struct {
	tlsclient.HttpClient
	status int
	body   string
	calls  int
}

func (c *limitTestClient) Do(*fhttp.Request) (*fhttp.Response, error) {
	c.calls++
	return &fhttp.Response{StatusCode: c.status, Header: fhttp.Header{}, Body: io.NopCloser(strings.NewReader(c.body))}, nil
}
func TestCaptchaExplicitLimits(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{"http", 429, `not JSON`, true},
		{"status", 200, `{"response":{"status":"error_limit","show_captcha_type":"slider"}}`, true},
		{"type", 200, `{"response":{"status":"error","show_captcha_type":"error_limit"}}`, true},
		{"api code", 200, `{"error":{"error_code":29}}`, true},
		{"ordinary rejection", 200, `{"response":{"status":"bot"}}`, false},
		{"success", 200, `{"response":{"status":"ok","success_token":"test"}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &limitTestClient{status: tc.status, body: tc.body}
			s := &captchaSession{ctx: context.Background(), client: client, apiHost: "api.example.test", pageOrigin: "https://example.test"}
			_, err := s.captchaRequest("captchaNotRobot.check", nil)
			if errors.Is(err, ErrRateLimited) != tc.want {
				t.Fatalf("err=%v want limit=%v", err, tc.want)
			}
			if client.calls != 1 {
				t.Fatal("extra requests")
			}
		})
	}
}
func TestCaptchaPage429StopsBeforeParsing(t *testing.T) {
	client := &limitTestClient{status: 429, body: "temporarily limited"}
	s := &captchaSession{ctx: context.Background(), client: client, pageOrigin: "https://example.test"}
	_, err := s.fetchCaptchaHTML("https://example.test/captcha")
	if !errors.Is(err, ErrRateLimited) || !errors.Is(err, ErrUnavailable) || client.calls != 1 {
		t.Fatalf("err=%v calls=%d", err, client.calls)
	}
}

func (c *limitTestClient) GetCookies(*url.URL) []*fhttp.Cookie { return nil }
