package captcha

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/LiTarPc/fturn-core/internal/logx"
	"github.com/LiTarPc/fturn-core/internal/provider/vk/internal/browserprofile"
	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
)

func browserFixturePow(t *testing.T, p powParams, mutate func(*powResult)) string {
	t.Helper()
	hash, nonce := solvePoW(context.Background(), p.Input, p.Difficulty)
	telemetry := json.RawMessage(`{"ua":{"ok":true,"result":{"userAgent":"Fixture Android WebView","userAgentData":{"brands":[{"brand":"Chromium","version":"146"}],"platform":"Android","mobile":true}}}}`)
	telHash, err := telemetryHash(telemetry)
	if err != nil {
		t.Fatal(err)
	}
	r := powResult{Hash: hash, Nonce: nonce, DurationMs: 1, Telemetry: telemetry, TelHash: telHash}
	if mutate != nil {
		mutate(&r)
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return p.Prefix + base64.StdEncoding.EncodeToString(b)
}
func TestBrowserPowValidationAndLegacyWire(t *testing.T) {
	p := powParams{Input: "fixture-input", Difficulty: 1, Prefix: "v2."}
	for _, tc := range []struct {
		name   string
		mutate func(*powResult)
		valid  bool
	}{
		{"valid", nil, true},
		{"wrong hash", func(r *powResult) { r.Hash = strings.Repeat("0", 64) }, false},
		{"negative nonce", func(r *powResult) { r.Nonce = -1 }, false},
		{"negative duration", func(r *powResult) { r.DurationMs = -1 }, false},
		{"browser error", func(r *powResult) { r.Error = "PRIVATE_ERROR" }, false},
		{"missing telemetry", func(r *powResult) { r.Telemetry = nil }, false},
		{"nonobject telemetry", func(r *powResult) { r.Telemetry = json.RawMessage(`[]`) }, false},
		{"wrong telemetry hash", func(r *powResult) { r.TelHash = "wrong" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := browserFixturePow(t, p, tc.mutate)
			got, err := validateBrowserPow(v, p)
			if tc.valid {
				if err != nil || got != v {
					t.Fatal("valid browser proof rejected")
				}
			} else if !errors.Is(err, ErrInvalidBrowserPow) || strings.Contains(err.Error(), "PRIVATE_") {
				t.Fatalf("invalid proof result: %v", err)
			}
		})
	}
	for _, v := range []string{"", "v2.not-base64", "v2." + base64.StdEncoding.EncodeToString([]byte(`{}`)), strings.Repeat("x", 128*1024+1)} {
		if _, err := validateBrowserPow(v, p); !errors.Is(err, ErrInvalidBrowserPow) {
			t.Fatal("malformed proof accepted")
		}
	}
	value := browserFixturePow(t, p, nil)
	if _, err := validateBrowserPow(value, powParams{Input: "another", Difficulty: 1, Prefix: "v2."}); !errors.Is(err, ErrInvalidBrowserPow) {
		t.Fatal("proof for another challenge accepted")
	}
	if _, err := validateBrowserPow(value, powParams{Input: p.Input, Difficulty: 1, Prefix: "v3."}); !errors.Is(err, ErrInvalidBrowserPow) {
		t.Fatal("wrong prefix accepted")
	}
	// Exact wire regression: the new optional error field must not change legacy JSON.
	b, err := marshalJS(powResult{Hash: "h", Nonce: 0, DurationMs: 1, Telemetry: json.RawMessage(`{}`), TelHash: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"hash":"h","nonce":0,"duration_ms":1,"telemetry":{},"tel_hash":"t"}` {
		t.Fatalf("legacy envelope changed: %s", b)
	}
	profile := profileFromBrowserPow(browserprofile.Profile{}, value)
	if profile.UserAgent != "Fixture Android WebView" || profile.SecChUaMobile != "?1" || profile.SecChUaPlatform != `"Android"` {
		t.Fatal("browser profile was not applied")
	}
}

type browserFixtureClient struct {
	tlsclient.HttpClient
	mu                    sync.Mutex
	html, proof, reply    string
	status, checks, after int
	checked               bool
}

func (*browserFixtureClient) GetCookies(*url.URL) []*fhttp.Cookie { return nil }
func (c *browserFixtureClient) Do(r *fhttp.Request) (*fhttp.Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	status := 200
	body := `{"response":{"status":"ok"}}`
	switch {
	case r.URL.Path == "/not_robot_captcha":
		body = c.html
	case strings.Contains(r.URL.Path, "initSession"):
		body = `{"response":{"show_captcha_type":"checkbox"}}`
	case strings.Contains(r.URL.Path, ".check"):
		c.checks++
		c.checked = true
		data, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(data))
		c.proof = form.Get("hash")
		body = c.reply
		if c.status != 0 {
			status = c.status
		}
	default:
		if c.checked {
			c.after++
		}
	}
	return &fhttp.Response{StatusCode: status, Header: fhttp.Header{"Retry-After": []string{"120"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
}
func TestBrowserPowContinuationAndRefusal(t *testing.T) {
	html, err := os.ReadFile("testdata/not_robot_captcha.html")
	if err != nil {
		t.Fatal(err)
	}
	page, err := parseCaptchaPage(string(html))
	if err != nil {
		t.Fatal(err)
	}
	valid := browserFixturePow(t, page.Pow, nil)
	for _, tc := range []struct {
		name, proof, reply string
		status, checks     int
		want               error
	}{
		{"success", valid, `{"response":{"status":"ok","success_token":"PRIVATE_SUCCESS"}}`, 200, 1, nil},
		{"mismatched", browserFixturePow(t, powParams{Input: "different", Difficulty: 1, Prefix: page.Pow.Prefix}, nil), "", 200, 0, ErrInvalidBrowserPow},
		{"rate limit", valid, `{"response":{"status":"error_limit"}}`, 429, 1, ErrRateLimited},
		{"service 10-5", valid, `{"error":{"error_code":10,"subcode":5,"error_msg":"Internal server error"}}`, 200, 1, ErrUnavailable},
		{"bot", valid, `{"response":{"status":"bot"}}`, 200, 1, ErrBot},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &browserFixtureClient{html: string(html), reply: tc.reply, status: tc.status}
			token, err := SolveWithBrowserPow(context.Background(), &Error{SessionToken: "PRIVATE_SESSION", RedirectURI: "https://id.vk.ru/not_robot_captcha?session_token=PRIVATE_SESSION"}, 1, client, browserprofile.For(browserprofile.Desktop, browserprofile.Identity{Seed: "fixture"}), logx.Nop(), tc.proof)
			if tc.want == nil {
				if err != nil || token != "PRIVATE_SUCCESS" {
					t.Fatalf("continuation failed: %v", err)
				}
			} else if !errors.Is(err, tc.want) {
				t.Fatalf("error=%v want=%v", err, tc.want)
			}
			if client.checks != tc.checks {
				t.Fatalf("checks=%d want=%d", client.checks, tc.checks)
			}
			if tc.checks > 0 && client.proof != valid {
				t.Fatal("browser proof was replaced")
			}
			if (tc.want == ErrRateLimited || tc.want == ErrUnavailable) && client.after != 0 {
				t.Fatal("request after refusal")
			}
		})
	}
}
