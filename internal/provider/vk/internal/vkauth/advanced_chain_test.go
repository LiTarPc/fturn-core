package vkauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"github.com/LiTarPc/fturn-core/internal/provider/vk/internal/browserprofile"
	"github.com/LiTarPc/fturn-core/internal/provider/vk/internal/captcha"
	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
)

type advancedChainClient struct {
	tlsclient.HttpClient
	mu                  sync.Mutex
	html, checkedProof  string
	checks, submissions int
}

func (*advancedChainClient) GetCookies(*url.URL) []*fhttp.Cookie { return nil }
func (c *advancedChainClient) Do(r *fhttp.Request) (*fhttp.Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b := []byte{}
	if r.Body != nil {
		b, _ = io.ReadAll(r.Body)
	}
	form, _ := url.ParseQuery(string(b))
	body := `{"response":{"status":"ok"}}`
	switch r.URL.Path {
	case "/":
		body = `{"data":{"access_token":"PRIVATE_ANON"}}`
	case "/not_robot_captcha":
		body = c.html
	case "/method/captchaNotRobot.initSession":
		body = `{"response":{"show_captcha_type":"checkbox"}}`
	case "/method/captchaNotRobot.check":
		c.checks++
		c.checkedProof = form.Get("hash")
		body = `{"response":{"status":"ok","success_token":"PRIVATE_SUCCESS"}}`
	case "/method/calls.getAnonymousToken":
		if form.Get("success_token") == "PRIVATE_SUCCESS" || form.Get("success_token") == "PRIVATE_MANUAL" {
			c.submissions++
			body = `{"response":{"token":"PRIVATE_CALL"}}`
		} else {
			body = `{"error":{"error_code":14,"error_msg":"Captcha needed","redirect_uri":"https://id.vk.ru/not_robot_captcha?session_token=PRIVATE_SESSION"}}`
		}
	case "/fb.do":
		if form.Get("method") == "auth.anonymLogin" {
			body = `{"session_key":"PRIVATE_SESSION_KEY"}`
		} else {
			body = `{"turn_server":{"username":"PRIVATE_USER","credential":"PRIVATE_PASSWORD","urls":["turn:127.0.0.1:3478?transport=udp"]}}`
		}
	}
	return authTestResponse(200, body), nil
}
func validChainProof(t *testing.T) string {
	t.Helper()
	var hash string
	nonce := 0
	for {
		sum := sha256.Sum256([]byte("ST9BEClStK0wSdo4" + strconv.Itoa(nonce)))
		hash = hex.EncodeToString(sum[:])
		if strings.HasPrefix(hash, "00") {
			break
		}
		nonce++
	}
	telemetry := `{"ua":{"result":{"userAgent":"Fixture WebView"}}}`
	tel := sha256.Sum256([]byte(telemetry))
	raw := `{"hash":"` + hash + `","nonce":` + strconv.Itoa(nonce) + `,"duration_ms":1,"telemetry":` + telemetry + `,"tel_hash":"` + hex.EncodeToString(tel[:]) + `"}`
	return "v2." + base64.StdEncoding.EncodeToString([]byte(raw))
}
func TestAdvancedFullCredentialChainWithFixtures(t *testing.T) {
	html, err := os.ReadFile("../captcha/testdata/not_robot_captcha.html")
	if err != nil {
		t.Fatal(err)
	}
	proof := validChainProof(t)
	for _, tc := range []struct {
		name                     string
		captureValue             string
		captureErr               error
		manual                   bool
		wantCaptures, wantChecks int
	}{
		{"browser continuation", proof, nil, false, 1, 1},
		{"unavailable host legacy fallback", "", errors.New("host unavailable"), false, 1, 1},
		{"mismatched proof legacy fallback", "v2.invalid", nil, false, 1, 1},
		{"manual priority", proof, nil, true, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			captures, manual := 0, 0
			client := &advancedChainClient{html: string(html)}
			c := New(Config{AdvancedCaptcha: true, ManualOnly: tc.manual})
			c.powCapture = func(context.Context, string, net.Dialer, browserprofile.Profile) (string, error) {
				captures++
				return tc.captureValue, tc.captureErr
			}
			c.manualSolve = func(context.Context, *captcha.Error, net.Dialer, browserprofile.Profile) (string, error) {
				manual++
				return "PRIVATE_MANUAL", nil
			}
			user, pass, addrs, err := c.getTokenChainWithClient(context.Background(), "fixture", 1, VKCredentials{ClientID: "fixture"}, c.currentPersona(), client)
			if err != nil || user != "PRIVATE_USER" || pass != "PRIVATE_PASSWORD" || len(addrs) != 1 || addrs[0] != "127.0.0.1:3478" {
				t.Fatalf("credential chain failed: %v", err)
			}
			if captures != tc.wantCaptures || client.checks != tc.wantChecks || client.submissions != 1 {
				t.Fatalf("captures=%d checks=%d submissions=%d", captures, client.checks, client.submissions)
			}
			if tc.name == "browser continuation" && client.checkedProof != proof {
				t.Fatal("browser proof was not preserved through check")
			}
			if tc.manual && manual != 1 {
				t.Fatal("manual-only path did not invoke manual solver")
			}
		})
	}
}
func TestAdvancedCaptureRefusalNeverFallsBack(t *testing.T) {
	for _, refusal := range []error{captcha.ErrRateLimited, captcha.ErrUnavailable, context.Canceled} {
		c := New(Config{AdvancedCaptcha: true})
		ctx, cancel := context.WithCancel(context.Background())
		c.powCapture = func(context.Context, string, net.Dialer, browserprofile.Profile) (string, error) {
			if refusal == context.Canceled {
				cancel()
			}
			return "", refusal
		}
		_, err := c.defaultAutoSolve(ctx, testCaptchaErr(), 1, nil, c.currentPersona())
		cancel()
		if !errors.Is(err, refusal) {
			t.Fatalf("capture refusal ignored: %v", err)
		}
	}
}
