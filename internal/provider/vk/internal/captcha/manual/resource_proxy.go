package manual

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

// Keep the upstream directory tree in the browser-visible pathname. Webpack,
// relative imports and CSS url() cannot derive a CDN base from a query parameter.
const resourceProxyPrefix = "/local-captcha-resource/"

func localResourceURL(target *url.URL) string {
	origin := target.Scheme + "://" + target.Host
	key := base64.RawURLEncoding.EncodeToString([]byte(origin))
	pathname := target.Path
	if pathname == "" {
		pathname = "/"
	}
	local := &url.URL{Path: resourceProxyPrefix + key + pathname, RawQuery: target.RawQuery, Fragment: target.Fragment}
	if target.RawPath != "" {
		local.RawPath = resourceProxyPrefix + key + target.EscapedPath()
	}
	return local.String()
}

func upstreamResourceURL(local *url.URL) (*url.URL, error) {
	if !strings.HasPrefix(local.Path, resourceProxyPrefix) {
		return nil, errors.New("invalid resource path")
	}
	key, escaped, found := strings.Cut(strings.TrimPrefix(local.EscapedPath(), resourceProxyPrefix), "/")
	if !found || key == "" {
		return nil, errors.New("invalid resource path")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil {
		return nil, errors.New("invalid resource origin")
	}
	target, err := url.Parse(string(decoded))
	if err != nil || (target.Scheme != "https" && target.Scheme != "http") || target.Host == "" || target.User != nil || target.Path != "" || target.RawQuery != "" || target.ForceQuery || target.Fragment != "" || target.Opaque != "" {
		return nil, errors.New("invalid resource origin")
	}
	pathname, err := url.PathUnescape("/" + escaped)
	if err != nil {
		return nil, errors.New("invalid resource path")
	}
	target.Path = pathname
	target.RawPath = "/" + escaped
	target.RawQuery = local.RawQuery
	return target, nil
}

func captchaRequestPath(local *url.URL) string {
	if local.Path == "/generic_proxy" {
		if target, err := url.Parse(local.Query().Get("proxy_url")); err == nil {
			return target.Path
		}
	}
	if strings.HasPrefix(local.Path, resourceProxyPrefix) {
		if target, err := upstreamResourceURL(local); err == nil {
			return target.Path
		}
	}
	return local.Path
}

// Decode the actual upstream path before applying capture-only restrictions.
// Checking only the local namespace would let verification calls bypass them.
func captureOnlyHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested := captchaRequestPath(r.URL)
		for _, method := range []string{"captchaNotRobot.check", "captchaNotRobot.componentDone", "captchaNotRobot.leaveCaptcha", "captchaNotRobot.endSession"} {
			if strings.Contains(requested, method) {
				http.Error(w, "verification deferred to solver", http.StatusConflict)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// Both legacy query URLs and path-preserving asset URLs retain the same host
// allowlist and transport. Error responses keep their real status and MIME type.
func externalResourceHandler(transport http.RoundTripper, capturePow bool, keyCh chan<- string, onError func(http.ResponseWriter, *http.Request, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		targetAuthURL := r.URL.Query().Get("proxy_url")
		if strings.HasPrefix(r.URL.Path, resourceProxyPrefix) {
			target, err := upstreamResourceURL(r.URL)
			if err != nil {
				http.Error(w, "Bad resource URL", http.StatusBadRequest)
				return
			}
			targetAuthURL = target.String()
		}

		targetParsed, err := url.Parse(targetAuthURL)
		if err != nil || targetParsed.Host == "" || targetParsed.User != nil || (targetParsed.Scheme != "https" && targetParsed.Scheme != "http") {
			http.Error(w, "Bad URL", http.StatusBadRequest)
			return
		}
		if !isAllowedProxyHost(targetParsed.Hostname()) {
			http.Error(w, "Forbidden host", http.StatusForbidden)
			return
		}
		genericReverse := &httputil.ReverseProxy{
			Transport:    transport,
			ErrorHandler: onError,
			Rewrite: func(req *httputil.ProxyRequest) {
				req.Out.URL.Path = targetParsed.Path
				req.Out.URL.RawPath = targetParsed.RawPath
				req.Out.URL.RawQuery = targetParsed.RawQuery
				rewriteProxyRequest(req.Out, targetParsed)
			},
			ModifyResponse: func(res *http.Response) error {
				// убираем security-заголовки, блокирующие cross-origin загрузку
				// статики (JS/CSS) при проксировании.
				for _, h := range []string{
					"Content-Security-Policy",
					"Content-Security-Policy-Report-Only",
					"X-Content-Security-Policy",
					"X-WebKit-CSP",
					"Cross-Origin-Opener-Policy",
					"Cross-Origin-Embedder-Policy",
					"Cross-Origin-Resource-Policy",
					"X-Frame-Options",
					"Strict-Transport-Security",
				} {
					res.Header.Del(h)
				}
				// разрешаем cross-origin доступ к ресурсу
				res.Header.Set("Access-Control-Allow-Origin", "*")

				// captchaNotRobot.check идёт через /generic_proxy на api.vk.com/api.vk.ru.
				if strings.Contains(targetParsed.Path, "captchaNotRobot.check") {
					bodyBytes, readErr := io.ReadAll(res.Body)
					if readErr != nil {
						return readErr
					}
					if err := res.Body.Close(); err != nil {
						return err
					}
					res.Body = io.NopCloser(bytes.NewReader(bodyBytes))
					res.ContentLength = int64(len(bodyBytes))
					res.Header.Set("Content-Length", fmt.Sprint(len(bodyBytes)))
					if !capturePow {
						notifyKey(keyCh, extractSuccessToken(bodyBytes))
					}
				}

				return nil
			},
		}
		genericReverse.ServeHTTP(w, r)
	}
}
