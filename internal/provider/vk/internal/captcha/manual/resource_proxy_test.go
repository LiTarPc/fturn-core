package manual

import (
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

type resourceFixtureTransport func(*http.Request) (*http.Response, error)

func (f resourceFixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func mustResourceURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, e := url.Parse(raw)
	if e != nil {
		t.Fatal(e)
	}
	return u
}

func TestResourceWebpackPublicPathKeepsCDNDirectory(t *testing.T) {
	entry := "https://st.vk.ru/vkid/vkid-bff/dist/projects/notRobotCaptcha-web/entrypoints/entry.243b7a49.js"
	local := mustResourceURL(t, "http://localhost:8765"+localResourceURL(mustResourceURL(t, entry)))
	// Webpack strips query/fragment/file, then appends ../ to currentScript.src.
	base := mustResourceURL(t, regexp.MustCompile(`/[^/]+$`).ReplaceAllString(local.String(), "/")+"../")
	for _, relative := range []string{"chunks/js/iui_subapp.a79f2d53.js?cache-bust=true&retry-attempt=2", "chunks/js/394.e400a060.js", "chunks/css/iui_subapp.f2b1747b.css"} {
		loaded := base.ResolveReference(mustResourceURL(t, relative))
		upstream, e := upstreamResourceURL(loaded)
		if e != nil {
			t.Fatal(e)
		}
		want := "https://st.vk.ru/vkid/vkid-bff/dist/projects/notRobotCaptcha-web/" + relative
		if upstream.String() != want {
			t.Fatalf("asset=%s, want=%s", upstream, want)
		}
	}
	css := base.ResolveReference(mustResourceURL(t, "chunks/css/main.css"))
	font := css.ResolveReference(mustResourceURL(t, "../../fonts/400latin.woff2"))
	u, e := upstreamResourceURL(font)
	if e != nil || u.String() != "https://st.vk.ru/vkid/vkid-bff/dist/projects/notRobotCaptcha-web/fonts/400latin.woff2" {
		t.Fatal(u, e)
	}
}
func TestResourceHTTPPreservesPathQueryMIMEAndErrorStatus(t *testing.T) {
	requested := []string{}
	transport := resourceFixtureTransport(func(r *http.Request) (*http.Response, error) {
		requested = append(requested, r.URL.String())
		content := "application/javascript"
		body := "window.fixtureLoaded=true;"
		status := 200
		switch {
		case strings.HasSuffix(r.URL.Path, ".css"):
			content = "text/css"
			body = ".captcha{display:block}"
		case strings.HasSuffix(r.URL.Path, ".woff2"):
			content = "font/woff2"
			body = "wOF2"
		case strings.Contains(r.URL.Path, "missing"):
			content = "text/html"
			body = "<h1>Not Found</h1>"
			status = 404
		}
		return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{content}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})
	handler := externalResourceHandler(transport, false, make(chan string, 1), nil)
	server := httptest.NewServer(handler)
	defer server.Close()
	for _, item := range []struct {
		path, mime string
		status     int
	}{{"chunks/js/394.e400a060.js?retry-attempt=2", "application/javascript", 200}, {"chunks/css/main.css", "text/css", 200}, {"fonts/400latin.woff2", "font/woff2", 200}, {"chunks/js/missing.js", "text/html", 404}, {"chunks/js/a%2Fb%20c.js?v=1%2F2&retry-attempt=2", "application/javascript", 200}} {
		target := "https://st.vk.ru/vkid/vkid-bff/dist/projects/notRobotCaptcha-web/" + item.path
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+localResourceURL(mustResourceURL(t, target)), nil)
		if err != nil {
			t.Fatal(err)
		}
		res, e := server.Client().Do(req)
		if e != nil {
			t.Fatal(e)
		}
		_ = res.Body.Close()
		if res.StatusCode != item.status || res.Header.Get("Content-Type") != item.mime {
			t.Fatal(res.StatusCode, res.Header)
		}
		if requested[len(requested)-1] != target {
			t.Fatal(requested)
		}
	}
	before := len(requested)
	for _, raw := range []string{"https://ad.mail.ru/static/sync-loader.js", "https://127.0.0.1/private", "https://st.vk.ru.evil.invalid/script.js"} {
		w := httptest.NewRecorder()
		handler(w, httptest.NewRequestWithContext(t.Context(), "GET", localResourceURL(mustResourceURL(t, raw)), nil))
		if w.Code != 403 {
			t.Fatal(raw, w.Code)
		}
	}
	if len(requested) != before {
		t.Fatal("forbidden origin reached transport")
	}
}
func TestResourceRoundTripAndInvalidOrigins(t *testing.T) {
	raw := "https://st.vk.ru/path/a%2Fb/font%20name.woff2?v=1%2F2&x=3"
	local := mustResourceURL(t, localResourceURL(mustResourceURL(t, raw)))
	up, e := upstreamResourceURL(local)
	if e != nil || up.String() != raw {
		t.Fatal(up, e)
	}
	for _, origin := range []string{"file://st.vk.ru", "https://user:pass@st.vk.ru", "https://st.vk.ru/other", "https://st.vk.ru?proxy=1"} {
		key := base64.RawURLEncoding.EncodeToString([]byte(origin))
		if _, e := upstreamResourceURL(mustResourceURL(t, resourceProxyPrefix+key+"/a.js")); e == nil {
			t.Fatal("invalid origin accepted", origin)
		}
	}
}
func TestResourceHTMLAndCaptureProtectionUseNewNamespace(t *testing.T) {
	target := mustResourceURL(t, "https://id.vk.ru/not_robot_captcha")
	html := rewriteHTMLAttrsServerSide(`<script src="https://st.vk.ru/vkid/p/entrypoints/entry.js"></script><link href="https://st.vk.ru/vkid/p/chunks/css/main.css">`, target)
	if strings.Contains(html, "generic_proxy?") || strings.Count(html, resourceProxyPrefix) != 2 {
		t.Fatal(html)
	}
	for _, method := range []string{"captchaNotRobot.check", "captchaNotRobot.componentDone", "captchaNotRobot.leaveCaptcha", "captchaNotRobot.endSession"} {
		raw := "https://api.vk.ru/method/" + method
		for _, local := range []string{localResourceURL(mustResourceURL(t, raw)), "/generic_proxy?proxy_url=" + url.QueryEscape(raw)} {
			if got := captchaRequestPath(mustResourceURL(t, local)); got != "/method/"+method {
				t.Fatal(got)
			}
		}
	}
}

func TestResourceCaptureGuardBlocksVerificationOnEveryRoute(t *testing.T) {
	forwarded := 0
	transport := resourceFixtureTransport(func(r *http.Request) (*http.Response, error) {
		forwarded++
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("fixture")), Request: r}, nil
	})
	handler := captureOnlyHandler(externalResourceHandler(transport, true, make(chan string, 1), nil))
	for _, method := range []string{"captchaNotRobot.check", "captchaNotRobot.componentDone", "captchaNotRobot.leaveCaptcha", "captchaNotRobot.endSession"} {
		for _, path := range []string{"/method/" + method, "/method/" + strings.Replace(method, ".", "%2e", 1)} {
			raw := "https://api.vk.ru" + path
			for _, route := range []string{path, localResourceURL(mustResourceURL(t, raw)), "/generic_proxy?proxy_url=" + url.QueryEscape(raw)} {
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodPost, route, strings.NewReader("fixture=value")))
				if w.Code != http.StatusConflict {
					t.Fatalf("route %s: status %d", route, w.Code)
				}
			}
		}
	}
	if forwarded != 0 {
		t.Fatal("capture-only verification reached transport")
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, localResourceURL(mustResourceURL(t, "https://st.vk.ru/chunks/js/fixture.js")), nil))
	if w.Code != http.StatusOK || forwarded != 1 {
		t.Fatal("capture-only mode blocked a static resource")
	}
}

func TestResourceInvalidTargetsNeverReachTransport(t *testing.T) {
	transport := resourceFixtureTransport(func(_ *http.Request) (*http.Response, error) {
		t.Error("invalid target reached transport")
		return nil, errors.New("unexpected request")
	})
	handler := externalResourceHandler(transport, false, make(chan string, 1), nil)
	for _, origin := range []string{"file://st.vk.ru", "ftp://st.vk.ru", "https://user:pass@st.vk.ru", "https://st.vk.ru/path", "https://st.vk.ru?x=1", "https://st.vk.ru?", "https://st.vk.ru#fragment", "https://127.0.0.1", "https://ad.mail.ru", "https://ads.vk.ru", "https://st.vk.ru.evil.invalid"} {
		key := base64.RawURLEncoding.EncodeToString([]byte(origin))
		routes := []string{resourceProxyPrefix + key + "/a.js"}
		if !strings.ContainsAny(origin, "?#") && !strings.HasSuffix(origin, "/path") {
			routes = append(routes, "/generic_proxy?proxy_url="+url.QueryEscape(origin+"/a.js"))
		}
		for _, route := range routes {
			w := httptest.NewRecorder()
			handler(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, route, nil))
			if w.Code != http.StatusBadRequest && w.Code != http.StatusForbidden {
				t.Fatalf("origin %s: status %d", origin, w.Code)
			}
		}
	}
	for _, route := range []string{resourceProxyPrefix + "!invalid/a.js", resourceProxyPrefix + "missing-path", "/generic_proxy?proxy_url=broken"} {
		w := httptest.NewRecorder()
		handler(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, route, nil))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("route %s: status %d", route, w.Code)
		}
	}
}

func TestResourceLegacyAndNamespacedRequestsPreservePostAndToken(t *testing.T) {
	raw := "https://api.vk.ru/method/captchaNotRobot.check?fixture=1%2F2"
	for _, route := range []string{localResourceURL(mustResourceURL(t, raw)), "/generic_proxy?proxy_url=" + url.QueryEscape(raw)} {
		keys := make(chan string, 1)
		transport := resourceFixtureTransport(func(r *http.Request) (*http.Response, error) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			if r.URL.String() != raw || r.Method != http.MethodPost || r.Header.Get("X-Fixture") != "preserved" || string(body) != "fixture=value" {
				t.Fatal("POST changed in proxy")
			}
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"response":{"success_token":"offline-fixture-token"}}`)), Request: r}, nil
		})
		handler := externalResourceHandler(transport, false, keys, nil)
		request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, route, strings.NewReader("fixture=value"))
		request.Header.Set("X-Fixture", "preserved")
		w := httptest.NewRecorder()
		handler(w, request)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "offline-fixture-token") {
			t.Fatal("token response changed")
		}
		select {
		case token := <-keys:
			if token != "offline-fixture-token" {
				t.Fatal("incorrect token")
			}
		default:
			t.Fatal("manual token was not delivered")
		}
	}
}

type resourceBrokenBody struct{}

func (resourceBrokenBody) Read(_ []byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (resourceBrokenBody) Close() error               { return nil }

func TestResourceErrorsUseSanitizedHandler(t *testing.T) {
	for _, bodyFailure := range []bool{false, true} {
		transport := resourceFixtureTransport(func(r *http.Request) (*http.Response, error) {
			if !bodyFailure {
				return nil, errors.New("fixture transport failure")
			}
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: resourceBrokenBody{}, Request: r}, nil
		})
		called := false
		handler := externalResourceHandler(transport, false, make(chan string, 1), func(w http.ResponseWriter, _ *http.Request, _ error) {
			called = true
			http.Error(w, "proxy request failed", http.StatusBadGateway)
		})
		w := httptest.NewRecorder()
		handler(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, localResourceURL(mustResourceURL(t, "https://api.vk.ru/method/captchaNotRobot.check?session_token=private-fixture")), nil))
		if !called || w.Code != http.StatusBadGateway || strings.Contains(w.Body.String(), "private-fixture") {
			t.Fatal("sanitized error handler was not used")
		}
	}
}
