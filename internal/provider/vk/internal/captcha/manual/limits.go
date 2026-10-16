package manual

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/LiTarPc/fturn-core/internal/provider/vk/internal/captcha"
)

// limitTransport shares one stop signal between both proxy routes.
type limitTransport struct {
	rt     http.RoundTripper
	errors chan<- error
	mu     sync.Mutex
	limit  error
}

func (t *limitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	stopped := t.limit
	t.mu.Unlock()
	if stopped != nil {
		return nil, stopped
	}
	resp, err := t.rt.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	var refusal error
	source := captcha.SafeURL(req.URL.String())
	if err := captcha.ResponseError(source, resp.StatusCode, resp.Header.Get("Retry-After"), nil); err != nil {
		refusal = err
	} else if strings.Contains(req.URL.Path, "captchaNotRobot.") {
		body, readErr := io.ReadAll(resp.Body)
		closeErr := resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(body))
		if readErr != nil || closeErr != nil {
			_ = resp.Body.Close()
			if readErr != nil {
				return nil, readErr
			}
			return nil, closeErr
		}
		payload := body
		if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
			if reader, gzipErr := gzip.NewReader(bytes.NewReader(body)); gzipErr == nil {
				decoded, decodeErr := io.ReadAll(reader)
				_ = reader.Close()
				if decodeErr == nil {
					payload = decoded
				}
			}
		}
		var raw map[string]any
		if json.Unmarshal(payload, &raw) == nil {
			err := captcha.ResponseError(source, resp.StatusCode, resp.Header.Get("Retry-After"), raw)
			if errors.Is(err, captcha.ErrRateLimited) || errors.Is(err, captcha.ErrUnavailable) {
				refusal = err
			}
		}
	}
	if refusal != nil {
		t.mu.Lock()
		if t.limit == nil {
			t.limit = refusal
			select {
			case t.errors <- refusal:
			default:
			}
		}
		t.mu.Unlock()
	}
	return resp, nil
}
