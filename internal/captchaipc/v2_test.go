package captchaipc

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func v2Server(t *testing.T) (*Server, *eventBuffer) {
	t.Helper()
	out := &eventBuffer{}
	s, err := New(context.Background(), Config{Token: testBearer, Generation: "test_generation_2", Output: out, Protocol: 2, BrowserTimeout: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, out
}
func TestV2CaptureTerminalDoesNotAuthorize(t *testing.T) {
	for _, status := range []string{"captured", "unavailable", "manual_requested", "expired", "cancelled"} {
		t.Run(status, func(t *testing.T) {
			s, out := v2Server(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			var aborted atomic.Bool
			id, err := s.BeginCapture(ctx, "http://localhost:8765/not_robot?session_token=PRIVATE_CAPTURE", func() { aborted.Store(true) })
			if err != nil {
				t.Fatal(err)
			}
			code, b := ipcRequest(t, s, "GET", "/v1/captcha/"+id, "", testBearer, s.cfg.Generation, "", "")
			var desc Challenge
			if err = json.Unmarshal(b, &desc); err != nil {
				t.Fatal(err)
			}
			if code != 200 || desc.Purpose != "pow_capture" || desc.Mode != "browser" || time.Until(time.UnixMilli(desc.ExpiresAtMS)) > 12*time.Second {
				t.Fatal("invalid capture descriptor")
			}
			s.Authorized()
			if strings.Contains(out.String(), `"phase":"authorized"`) {
				t.Fatal("pending capture authorized")
			}
			if status == "unavailable" || status == "manual_requested" {
				code, _ = ipcRequest(t, s, "POST", "/v1/captcha/"+id+"/host", `{"generation":"test_generation_2","status":"`+status+`","reason":"host_unavailable"}`, testBearer, s.cfg.Generation, "", "")
				if code != 204 {
					t.Fatal(code)
				}
			} else {
				s.End(id, status)
			}
			s.End(id, "resolved")
			code, _ = ipcRequest(t, s, "GET", "/v1/captcha/"+id, "", testBearer, s.cfg.Generation, "", "")
			if code != 410 {
				t.Fatal("terminal challenge retained")
			}
			events := out.String()
			if strings.Contains(events, "PRIVATE_") || strings.Contains(events, `"phase":"resolved"`) || strings.Contains(events, `"phase":"authorized"`) || strings.Contains(events, `"mode":"manual"`) {
				t.Fatal("capture leaked data or changed solve/auth state")
			}
			lines := strings.Split(strings.TrimSpace(events), "\n")
			if len(lines) != 2 {
				t.Fatalf("unexpected event count: %d", len(lines))
			}
			for _, line := range lines {
				var event Event
				if err = json.Unmarshal([]byte(strings.TrimPrefix(line, Prefix)), &event); err != nil {
					t.Fatal(err)
				}
				if event.V != 2 || event.Purpose != "pow_capture" {
					t.Fatal("wrong v2 event")
				}
			}
			if !aborted.Load() {
				t.Fatal("terminal capture did not close local host")
			}
		})
	}
}
func TestV2CaptureTTLAndSeparateManual(t *testing.T) {
	s, out := v2Server(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	id, err := s.BeginCapture(ctx, "http://localhost:8765/capture", func() { close(done) })
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("capture did not expire")
	}
	if strings.Contains(out.String(), `"mode":"manual"`) || !strings.Contains(out.String(), `"phase":"expired"`) {
		t.Fatal("capture timeout promoted to manual")
	}
	manualCtx, manualCancel := context.WithTimeout(context.Background(), time.Second)
	defer manualCancel()
	next, err := s.Begin(manualCtx, "http://localhost:8765/fresh", "manual")
	if err != nil || next == id {
		t.Fatal("manual did not create a separate task")
	}
	s.End(next, "resolved")
	s.Authorized()
	if !strings.Contains(out.String(), `"purpose":"solve"`) || !strings.Contains(out.String(), `"phase":"authorized"`) {
		t.Fatal("fresh authorization notification missing")
	}
	s.Pause()
	s.Authorized()
	if strings.Count(out.String(), `"phase":"authorized"`) != 1 {
		t.Fatal("authorization cleared a newer pause")
	}
}
func TestV1WireHasNoPurpose(t *testing.T) {
	s, out := ipcServer(t)
	id, _ := beginIPC(t, s, "manual")
	code, b := ipcRequest(t, s, "GET", "/v1/captcha/"+id, "", testBearer, s.cfg.Generation, "", "")
	if code != 200 || strings.Contains(string(b), "purpose") || strings.Contains(out.String(), "purpose") || !strings.Contains(out.String(), `"v":1`) {
		t.Fatal("v1 wire changed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := s.BeginCapture(ctx, "http://localhost:8765/capture", cancel); err == nil {
		t.Fatal("v1 accepted advanced capture")
	}
}
func TestIPCEnvironmentAliasesAndConflict(t *testing.T) {
	for _, prefix := range []string{"FREETURN_", "FREETURN_TURN_", "FREETURN_RAW_"} {
		for _, key := range []string{"CAPTCHA_TOKEN", "CAPTCHA_GENERATION", "CAPTCHA_PROTOCOL"} {
			t.Setenv(prefix+key, "")
		}
	}
	t.Setenv("FREETURN_RAW_CAPTCHA_TOKEN", testBearer)
	t.Setenv("FREETURN_RAW_CAPTCHA_GENERATION", "test_generation_2")
	t.Setenv("FREETURN_RAW_CAPTCHA_PROTOCOL", "2")
	token, gen, version, err := environment()
	if err != nil || token != testBearer || gen != "test_generation_2" || version != 2 {
		t.Fatal("shared RAW alias failed")
	}
	t.Setenv("FREETURN_TURN_CAPTCHA_PROTOCOL", "1")
	if _, _, _, err = environment(); err == nil {
		t.Fatal("conflicting aliases accepted")
	}
}
