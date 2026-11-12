package captcha

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
)

func TestTransportErrorRedactsURLWithoutLosingCause(t *testing.T) {
	cause := &url.Error{Op: "Get", URL: "https://id.vk.ru/captcha?session_token=PRIVATE_SESSION&hash=PRIVATE_HASH", Err: context.DeadlineExceeded}
	err := SafeError(cause)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("deadline classification lost")
	}
	var typed *url.Error
	if !errors.As(err, &typed) || typed != cause {
		t.Fatal("typed cause lost")
	}
	if strings.Contains(err.Error(), "PRIVATE_") || !strings.Contains(err.Error(), "id.vk.ru/captcha?hash,session_token") {
		t.Fatal("transport error did not redact URL")
	}
	if SafeError(nil) != nil {
		t.Fatal("nil error changed")
	}
}
