package captcha

import (
	"errors"
	"fmt"
	"strconv"
	"time"
)

// APIError describes a provider error without retaining echoed request secrets.
type APIError struct {
	Source  string
	Code    int
	Subcode int
	RetryAt time.Time
}

func (e *APIError) Error() string {
	return fmt.Sprintf("VK API error: source=%s code=%d subcode=%d", e.Source, e.Code, e.Subcode)
}

func (e *APIError) Is(target error) bool     { return e.Code == 10 && target == ErrUnavailable }
func (e *APIError) RetryDeadline() time.Time { return e.RetryAt }

// ServiceError represents a temporary HTTP service failure.
type ServiceError struct {
	Source  string
	Status  int
	RetryAt time.Time
}

func (e *ServiceError) Error() string {
	return fmt.Sprintf("%s: source=%s HTTP %d", ErrUnavailable, e.Source, e.Status)
}
func (*ServiceError) Unwrap() error                { return ErrUnavailable }
func (e *ServiceError) RetryDeadline() time.Time   { return e.RetryAt }
func (e *RateLimitError) RetryDeadline() time.Time { return e.RetryAt }

// RetryDeadline returns the provider deadline, including through wrapped errors.
func RetryDeadline(err error) time.Time {
	var deadline interface{ RetryDeadline() time.Time }
	if errors.As(err, &deadline) {
		return deadline.RetryDeadline()
	}
	return time.Time{}
}

// ResponseError classifies HTTP and API failures before parsing a success body.
func ResponseError(source string, status int, retryAfter string, raw map[string]any) error {
	if status == 429 || LimitedResponse(raw) {
		return WithResponse(NewRateLimitError(source, retryAfter), raw)
	}
	if status >= 500 && status <= 599 {
		return WithResponse(&ServiceError{Source: source, Status: status, RetryAt: parseRetryAfter(retryAfter, time.Now())}, raw)
	}
	if payload, ok := raw["error"].(map[string]any); ok {
		code, _ := strconv.Atoi(captchaStringifyAny(payload["error_code"]))
		subcode, _ := strconv.Atoi(captchaStringifyAny(payload["subcode"]))
		return WithResponse(&APIError{Source: source, Code: code, Subcode: subcode, RetryAt: parseRetryAfter(retryAfter, time.Now())}, raw)
	}
	return nil
}
