package manual

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/LiTarPc/fturn-core/internal/provider/vk/internal/captcha"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestManualTransportReportsLimitsAndBlocksLaterRequests(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		body    string
		gzip    bool
		limited bool
	}{
		{"HTTP", 429, "<html>limited</html>", false, true},
		{"API", 200, `{"error":{"error_code":6}}`, false, true},
		{"gzip error limit", 200, `{"response":{"status":"error_limit"}}`, true, true},
		{"show type limit", 200, `{"response":{"show_captcha_type":"error_limit"}}`, false, true},
		{"success", 200, `{"response":{"status":"ok","success_token":"token"}}`, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(tc.body)
			if tc.gzip {
				var compressed bytes.Buffer
				writer := gzip.NewWriter(&compressed)
				if _, err := writer.Write(body); err != nil {
					t.Fatal(err)
				}
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
				body = compressed.Bytes()
			}
			calls := 0
			errCh := make(chan error, 1)
			transport := &limitTransport{errors: errCh, rt: roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				header := http.Header{"Retry-After": []string{"3600"}}
				if tc.gzip {
					header.Set("Content-Encoding", "gzip")
				}
				return &http.Response{StatusCode: tc.status, Header: header, Body: io.NopCloser(bytes.NewReader(body))}, nil
			})}
			req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://api.vk.ru/method/captchaNotRobot.check", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := transport.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			returned, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil || !bytes.Equal(returned, body) {
				t.Fatal("browser response was changed")
			}
			if tc.limited {
				select {
				case refusal := <-errCh:
					var limit *captcha.RateLimitError
					if !errors.As(refusal, &limit) || time.Until(limit.RetryAt) < 59*time.Minute {
						t.Fatalf("refusal=%v", refusal)
					}
				default:
					t.Fatal("limit not reported")
				}
				resp, err = transport.RoundTrip(req)
				if resp != nil {
					_ = resp.Body.Close()
				}
				if !errors.Is(err, captcha.ErrRateLimited) || calls != 1 {
					t.Fatalf("calls=%d err=%v", calls, err)
				}
			} else if len(errCh) != 0 {
				t.Fatal("success treated as a limit")
			}
		})
	}
}

func TestManualServerReturnsLimitWithoutWaitingForTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	errCh := make(chan error, 1)
	start := func(s *http.Server, _ string) error { go func() { _ = s.Serve(listener) }(); return nil }
	present := func(string) { errCh <- captcha.ErrRateLimited }
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.Copy(w, strings.NewReader("ready")) })
	token, err := runCaptchaServerWithStart(ctx, handler, "http://"+listener.Addr().String(), nil, errCh, "test", present, start)
	if token != "" || !errors.Is(err, captcha.ErrRateLimited) || ctx.Err() != nil {
		t.Fatalf("token=%q err=%v", token, err)
	}
}

func TestManualTransportReportsServiceErrorWithoutLeakingRequest(t *testing.T) {
	errCh := make(chan error, 1)
	transport := &limitTransport{errors: errCh, rt: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"error":{"error_code":10,"subcode":5,"request_params":["SECRET"]}}`))}, nil
	})}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://api.vk.ru/method/captchaNotRobot.check", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	select {
	case refusal := <-errCh:
		if !errors.Is(refusal, captcha.ErrUnavailable) || strings.Contains(refusal.Error(), "SECRET") {
			t.Fatalf("refusal=%v", refusal)
		}
	default:
		t.Fatal("service refusal was not reported")
	}
	response, err = transport.RoundTrip(req)
	if response != nil {
		_ = response.Body.Close()
	}
	if !errors.Is(err, captcha.ErrUnavailable) {
		t.Fatalf("later request err=%v", err)
	}
}
