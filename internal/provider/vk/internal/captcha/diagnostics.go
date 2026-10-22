package captcha

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

const diagnosticLimit = 16 * 1024
const diagnosticRedacted = "<redacted>"

var diagnosticURL = regexp.MustCompile(`https?://[^\s"<>]+`)
var diagnosticAssignment = regexp.MustCompile(`(?i)((?:[a-z_]*token|[a-z_]*secret|password|authorization|cookie|session_key|captcha_sid|captcha_key|browser_fp|hash)\s*[=:]\s*)([^\s,;&"<>]+)`)

// SafeResponse preserves provider diagnostics, including unknown fields, while
// masking credentials, echoed request secrets and URL query values. It never
// mutates the response used by the protocol parsers.
func SafeResponse(raw any) string {
	r := diagnosticRedactor{}
	clean := r.clean(raw)
	// Secrets can be echoed in error_msg before their named field is visited.
	sort.Slice(r.secrets, func(i, j int) bool { return len(r.secrets[i]) > len(r.secrets[j]) })
	r.ready = true
	clean = r.clean(clean)
	b, err := json.Marshal(clean)
	if err != nil {
		return "<response unavailable>"
	}
	return diagnosticClip(string(b), diagnosticLimit)
}

// WithResponse adds diagnostics without changing errors.Is/errors.As behavior.
func WithResponse(err error, raw any) error {
	if err == nil || raw == nil {
		return err
	}
	details := SafeResponse(raw)
	if details == "null" {
		return err
	}
	return fmt.Errorf("%w; response=%s", err, details)
}

// WithResponseBody also handles HTTP failures before the success JSON parser.
// Non-JSON pages are described by size rather than dumping arbitrary HTML.
func WithResponseBody(err error, body []byte) error {
	var raw any
	if json.Unmarshal(body, &raw) != nil {
		raw = map[string]any{"body_format": "non-JSON", "body_bytes": len(body)}
	}
	return WithResponse(err, raw)
}

type diagnosticRedactor struct {
	secrets []string
	ready   bool
}

func diagnosticSensitive(name string) bool {
	name = strings.ToLower(strings.NewReplacer("_", "", "-", "", ".", "").Replace(name))
	for _, part := range []string{"token", "secret", "password", "cookie", "authorization", "fingerprint"} {
		if strings.Contains(name, part) {
			return true
		}
	}
	switch name {
	case "key", "username", "session", "sessionkey", "settingskey", "captchakey", "captchasid", "browserfp", "hash", "vkjoinlink", "joinkey", "image", "device", "captchasettings":
		return true
	}
	return false
}

func (r *diagnosticRedactor) remember(v any) {
	switch value := v.(type) {
	case string:
		if len(value) >= 6 && value != diagnosticRedacted {
			r.secrets = append(r.secrets, value)
		}
	case map[string]any:
		for _, item := range value {
			r.remember(item)
		}
	case []any:
		for _, item := range value {
			r.remember(item)
		}
	}
}

func (r *diagnosticRedactor) params(v any) any {
	params, ok := v.([]any)
	if !ok {
		r.remember(v)
		return diagnosticRedacted
	}
	out := make([]any, len(params))
	for i, item := range params {
		if _, ok := item.(map[string]any); ok {
			out[i] = r.clean(item)
		} else {
			r.remember(item)
			out[i] = diagnosticRedacted
		}
	}
	return out
}

func (r *diagnosticRedactor) clean(v any) any {
	switch value := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(value))
		paramName, named := value["key"].(string)
		_, hasValue := value["value"]
		for key, item := range value {
			switch {
			case key == "request_params":
				out[key] = r.params(item)
			case key == "key" && named && hasValue:
				out[key] = paramName
			case key == "value" && (!named || diagnosticSensitive(paramName)):
				r.remember(item)
				out[key] = diagnosticRedacted
			case diagnosticSensitive(key):
				r.remember(item)
				out[key] = diagnosticRedacted
			default:
				out[key] = r.clean(item)
			}
		}
		return out
	case []any:
		out := make([]any, len(value))
		for i, item := range value {
			out[i] = r.clean(item)
		}
		return out
	case string:
		if !r.ready {
			return value
		}
		for _, secret := range r.secrets {
			value = strings.ReplaceAll(value, secret, diagnosticRedacted)
		}
		value = diagnosticURL.ReplaceAllStringFunc(value, func(raw string) string {
			if strings.Contains(raw, "/call/join/") {
				return "<redacted-call-url>"
			}
			return SafeURL(raw)
		})
		value = diagnosticAssignment.ReplaceAllString(value, "${1}"+diagnosticRedacted)
		return diagnosticClip(value, 4096)
	default:
		return v
	}
}

func diagnosticClip(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	for !utf8.ValidString(value[:limit]) {
		limit--
	}
	return value[:limit] + "...<truncated>"
}
