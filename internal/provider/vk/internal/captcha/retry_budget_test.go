package captcha

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"image"
	"image/jpeg"
	"io"
	"net/url"
	"strings"
	"testing"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
)

func TestRetryAfterParsing(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		value string
		want  time.Time
	}{
		{"3600", now.Add(time.Hour)}, {" 60 ", now.Add(time.Minute)}, {"0", now},
		{"Sat, 03 Oct 2026 13:00:00 GMT", now.Add(time.Hour)},
		{"Sat, 03 Oct 2026 11:00:00 GMT", time.Time{}},
		{"+60", time.Time{}}, {"-1", time.Time{}}, {"9223372036854775807", time.Time{}}, {"invalid", time.Time{}}, {"", time.Time{}},
	} {
		if got := parseRetryAfter(tc.value, now); !got.Equal(tc.want) {
			t.Errorf("%q: got=%v want=%v", tc.value, got, tc.want)
		}
	}
}

func TestSliderExplicitAttemptBudget(t *testing.T) {
	for _, tc := range []struct {
		name     string
		steps    []int
		attempts int
		invalid  bool
	}{
		{"legacy absent", []int{2, 0, 1}, 4, false},
		{"positive", []int{2, 0, 1, 2}, 2, false},
		{"zero", []int{2, 0, 1, 0}, 0, false},
		{"negative", []int{2, 0, 1, -1}, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, attempts, err := splitSliderSteps(tc.steps)
			if (err != nil) != tc.invalid || attempts != tc.attempts {
				t.Fatalf("attempts=%d err=%v", attempts, err)
			}
		})
	}
}

type sliderResponseClient struct {
	tlsclient.HttpClient
	content string
	status  string
	checks  int
	calls   int
}

func (c *sliderResponseClient) GetCookies(*url.URL) []*fhttp.Cookie { return nil }
func (c *sliderResponseClient) Do(req *fhttp.Request) (*fhttp.Response, error) {
	c.calls++
	body := `{"response":{"status":"ok"}}`
	switch {
	case strings.Contains(req.URL.Path, "getContent"):
		body = c.content
	case strings.Contains(req.URL.Path, "check"):
		c.checks++
		body = `{"response":{"status":"` + c.status + `","show_captcha_type":"slider"}}`
	}
	return &fhttp.Response{StatusCode: 200, Header: fhttp.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
}

func TestSliderStopsBeforeCheckOnZeroBudgetAndAfterBot(t *testing.T) {
	var picture bytes.Buffer
	if err := jpeg.Encode(&picture, image.NewRGBA(image.Rect(0, 0, 16, 16)), nil); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		attempts int
		checks   int
		calls    int
		want     error
	}{
		{"zero budget", 0, 0, 1, ErrRateLimited}, {"bot", 4, 1, 3, errCaptchaBot},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(map[string]any{"response": map[string]any{"status": "ok", "image": base64.StdEncoding.EncodeToString(picture.Bytes()), "steps": []int{2, 0, 1, 2, 3, tc.attempts}}})
			if err != nil {
				t.Fatal(err)
			}
			client := &sliderResponseClient{content: string(raw), status: "bot"}
			session := &captchaSession{ctx: context.Background(), client: client, apiHost: "api.example.test", pageOrigin: "https://example.test", sensors: defaultSensorConfig(), sensorsStart: time.Now()}
			_, err = session.solveSliderCaptcha("session", captchaContentRef{Value: "settings"})
			if !errors.Is(err, tc.want) || client.checks != tc.checks || client.calls != tc.calls {
				t.Fatalf("err=%v checks=%d calls=%d", err, client.checks, client.calls)
			}
		})
	}
}

func TestCaptchaHTTPAndAPILimitsPreserveRetryAfter(t *testing.T) {
	for _, status := range []int{429, 200} {
		client := &retryResponseClient{status: status}
		s := &captchaSession{ctx: context.Background(), client: client, apiHost: "api.example.test", pageOrigin: "https://example.test"}
		_, err := s.captchaRequest("captchaNotRobot.settings", [][2]string{{"session_token", "s"}})
		var limit *RateLimitError
		if !errors.As(err, &limit) || time.Until(limit.RetryAt) < 59*time.Minute {
			t.Fatalf("status=%d err=%v", status, err)
		}
	}
}

type retryResponseClient struct {
	limitTestClient
	status int
}

func (c *retryResponseClient) Do(*fhttp.Request) (*fhttp.Response, error) {
	return &fhttp.Response{StatusCode: c.status, Header: fhttp.Header{"Retry-After": []string{"3600"}}, Body: io.NopCloser(strings.NewReader(`{"error":{"error_code":29}}`))}, nil
}
