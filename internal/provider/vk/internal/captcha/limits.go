package captcha

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// RateLimitError preserves the provider's retry time across the auth chain.
type RateLimitError struct {
	Source  string
	RetryAt time.Time
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("%s: %s", ErrRateLimited, e.Source)
}

func (*RateLimitError) Unwrap() error { return ErrRateLimited }

// NewRateLimitError accepts HTTP-date and delay-seconds Retry-After values.
func NewRateLimitError(source, retryAfter string) *RateLimitError {
	return &RateLimitError{Source: source, RetryAt: parseRetryAfter(retryAfter, time.Now())}
}

func parseRetryAfter(value string, now time.Time) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	numeric := true
	for _, char := range value {
		if char < '0' || char > '9' {
			numeric = false
			break
		}
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); numeric && err == nil {
		if seconds >= 0 && seconds <= int64((1<<63-1)/time.Second) {
			return now.Add(time.Duration(seconds) * time.Second)
		}
		return time.Time{}
	}
	if date, err := http.ParseTime(value); err == nil && date.After(now) {
		return date
	}
	return time.Time{}
}

// LimitedResponse recognizes explicit provider refusal without retrying it.
func LimitedResponse(raw map[string]any) bool {
	if r, ok := raw["response"].(map[string]any); ok {
		if strings.EqualFold(captchaStringifyAny(r["status"]), "error_limit") || strings.EqualFold(captchaStringifyAny(r["show_captcha_type"]), "error_limit") {
			return true
		}
	}
	if e, ok := raw["error"].(map[string]any); ok {
		c := captchaStringifyAny(e["error_code"])
		return c == "6" || c == "29"
	}
	return false
}
