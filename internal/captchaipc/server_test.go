package captchaipc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type eventBuffer struct {
	sync.Mutex
	b bytes.Buffer
}

func (b *eventBuffer) Write(p []byte) (int, error) { b.Lock(); defer b.Unlock(); return b.b.Write(p) }
func (b *eventBuffer) String() string              { b.Lock(); defer b.Unlock(); return b.b.String() }

const testBearer = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func ipcServer(t *testing.T) (*Server, *eventBuffer) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	out := &eventBuffer{}
	s, e := New(ctx, Config{Token: testBearer, Generation: "test_generation_1", Output: out, BrowserTimeout: 50 * time.Millisecond})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { cancel(); _ = s.Close() })
	return s, out
}
func ipcRequest(t *testing.T, s *Server, method, path, body, token, generation, host, origin string) (int, []byte) {
	t.Helper()
	r, e := http.NewRequestWithContext(context.Background(), method, "http://"+s.listener.Addr().String()+path, strings.NewReader(body))
	if e != nil {
		t.Fatal(e)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if generation != "" {
		r.Header.Set("X-Fturn-Generation", generation)
	}
	if host != "" {
		r.Host = host
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	response, e := (&http.Client{Timeout: time.Second}).Do(r)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = response.Body.Close() }()
	b, e := io.ReadAll(response.Body)
	if e != nil {
		t.Fatal(e)
	}
	return response.StatusCode, b
}
func beginIPC(t *testing.T, s *Server, mode string) (string, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	id, e := s.Begin(ctx, "http://localhost:8765/not_robot?session_token=PRIVATE_URL_TOKEN", mode)
	if e != nil {
		cancel()
		t.Fatal(e)
	}
	t.Cleanup(cancel)
	return id, cancel
}
func TestIPCPrivateChallengeLifecycle(t *testing.T) {
	s, out := ipcServer(t)
	id, _ := beginIPC(t, s, "browser")
	path := "/v1/captcha/" + id
	code, b := ipcRequest(t, s, "GET", path, "", testBearer, s.cfg.Generation, "", "")
	if code != 200 {
		t.Fatalf("GET %d", code)
	}
	var task Challenge
	if json.Unmarshal(b, &task) != nil || task.URL != "http://localhost:8765/not_robot?session_token=PRIVATE_URL_TOKEN" || task.RequestID != id || task.Mode != "browser" {
		t.Fatalf("bad private state: %s", b)
	}
	if strings.Contains(out.String(), "PRIVATE_URL_TOKEN") || strings.Contains(out.String(), testBearer) || strings.Contains(out.String(), "localhost:8765") {
		t.Fatal("private data escaped into stdout")
	}
	s.End(id, "resolved")
	code, _ = ipcRequest(t, s, "GET", path, "", testBearer, s.cfg.Generation, "", "")
	if code != 410 {
		t.Fatalf("completed task retained: %d", code)
	}
	if strings.Count(out.String(), `"phase":"resolved"`) != 1 {
		t.Fatal("missing completion event")
	}
}
func TestIPCRejectsUnauthorizedAndStaleRequests(t *testing.T) {
	s, _ := ipcServer(t)
	id, _ := beginIPC(t, s, "manual")
	path := "/v1/captcha/" + id
	for _, tc := range []struct {
		token, gen, host, origin string
		want                     int
	}{
		{"", s.cfg.Generation, "", "", 401}, {"wrong", s.cfg.Generation, "", "", 401},
		{testBearer, "old_generation", "", "", 409}, {testBearer, s.cfg.Generation, "evil.invalid", "", 403},
		{testBearer, s.cfg.Generation, "", "http://localhost:8765", 403},
	} {
		code, _ := ipcRequest(t, s, "GET", path, "", tc.token, tc.gen, tc.host, tc.origin)
		if code != tc.want {
			t.Fatalf("security response %d want %d", code, tc.want)
		}
	}
	code, _ := ipcRequest(t, s, "GET", path+"?token=x", "", testBearer, s.cfg.Generation, "", "")
	if code != 400 {
		t.Fatal("query accepted")
	}
	code, _ = ipcRequest(t, s, "POST", path+"/host", `{"generation":"old_generation","status":"available"}`, testBearer, s.cfg.Generation, "", "")
	if code != 409 {
		t.Fatal("stale body accepted")
	}
	code, _ = ipcRequest(t, s, "POST", path+"/host", `{"generation":"test_generation_1","status":"available","url":"evil"}`, testBearer, s.cfg.Generation, "", "")
	if code != 400 {
		t.Fatal("unknown field accepted")
	}
}
func TestIPCBrowserToManualRetainsTask(t *testing.T) {
	s, out := ipcServer(t)
	id, _ := beginIPC(t, s, "browser")
	path := "/v1/captcha/" + id
	code, _ := ipcRequest(t, s, "POST", path+"/host", `{"generation":"test_generation_1","status":"unavailable","reason":"renderer_gone"}`, testBearer, s.cfg.Generation, "", "")
	if code != 204 {
		t.Fatal(code)
	}
	code, b := ipcRequest(t, s, "GET", path, "", testBearer, s.cfg.Generation, "", "")
	var state Challenge
	if err := json.Unmarshal(b, &state); err != nil {
		t.Fatal(err)
	}
	if code != 200 || state.RequestID != id || state.Mode != "manual" {
		t.Fatalf("fallback replaced task: %s", b)
	}
	if strings.Count(out.String(), `"phase":"pending"`) != 2 {
		t.Fatal("manual fallback event missing")
	}
	s.End(id, "cancelled")
	code, _ = ipcRequest(t, s, "POST", path+"/host", `{"generation":"test_generation_1","status":"available"}`, testBearer, s.cfg.Generation, "", "")
	if code != 410 {
		t.Fatal("obsolete status accepted")
	}
}
func TestIPCBrowserTimeoutPromotesAndTTLExpires(t *testing.T) {
	s, out := ipcServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Millisecond)
	defer cancel()
	id, e := s.Begin(ctx, "http://127.0.0.1:8765/", "browser")
	if e != nil {
		t.Fatal(e)
	}
	until := time.Now().Add(time.Second)
	for !strings.Contains(out.String(), `"mode":"manual"`) && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if !strings.Contains(out.String(), `"mode":"manual"`) {
		t.Fatal("no automatic/manual fallback")
	}
	<-ctx.Done()
	code, _ := ipcRequest(t, s, "GET", "/v1/captcha/"+id, "", testBearer, s.cfg.Generation, "", "")
	if code != 410 {
		t.Fatal("expired URL served")
	}
	for !strings.Contains(out.String(), `"phase":"expired"`) && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if !strings.Contains(out.String(), `"phase":"expired"`) {
		t.Fatal("expiry event missing")
	}
}
func TestIPCExplicitResumeAndCancelledWait(t *testing.T) {
	s, out := ipcServer(t)
	s.Pause()
	s.Pause()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Wait(ctx) }()
	select {
	case <-done:
		t.Fatal("waiting auth resumed automatically")
	case <-time.After(20 * time.Millisecond):
	}
	code, _ := ipcRequest(t, s, "POST", "/v1/auth/resume", "", testBearer, "old_generation", "", "")
	if code != 409 {
		t.Fatal("old process resumed auth")
	}
	code, _ = ipcRequest(t, s, "POST", "/v1/auth/resume", "", testBearer, s.cfg.Generation, "", "")
	if code != 204 {
		t.Fatal(code)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("user resume did not unblock auth")
	}
	s.Resume()
	if strings.Count(out.String(), `"phase":"waiting_user"`) != 1 || strings.Count(out.String(), `"phase":"resuming"`) != 1 {
		t.Fatal("resume was not idempotent")
	}
	s.Pause()
	cancel()
	if s.Wait(ctx) == nil {
		t.Fatal("cancelled wait succeeded")
	}
}
func TestIPCURLAndConfigValidation(t *testing.T) {
	for _, cfg := range []Config{{Token: "short", Generation: "good_generation"}, {Token: testBearer, Generation: "bad\nvalue"}} {
		if s, e := New(context.Background(), cfg); e == nil {
			_ = s.Close()
			t.Fatal("invalid credentials accepted")
		}
	}
	s, _ := ipcServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, raw := range []string{"https://vk.ru/", "http://127.0.0.1:9999/", "http://user@localhost:8765/", "http://localhost:8765/#token"} {
		if _, e := s.Begin(ctx, raw, "browser"); e == nil {
			t.Fatal("untrusted URL accepted")
		}
	}
}

type blockedStatusBody struct {
	reader  *strings.Reader
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockedStatusBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.started); <-b.release })
	return b.reader.Read(p)
}
func (*blockedStatusBody) Close() error { return nil }

func TestIPCDelayedHostStatusCannotChangeSuccessor(t *testing.T) {
	s, _ := ipcServer(t)
	s.cfg.BrowserTimeout = time.Hour
	old, _ := beginIPC(t, s, "browser")
	body := &blockedStatusBody{reader: strings.NewReader(`{"generation":"test_generation_1","status":"unavailable","reason":"renderer_gone"}`), started: make(chan struct{}), release: make(chan struct{})}
	r := httptest.NewRequestWithContext(context.Background(), "POST", "http://"+s.listener.Addr().String()+"/v1/captcha/"+old+"/host", body)
	r.Header.Set("Authorization", "Bearer "+testBearer)
	r.Header.Set("X-Fturn-Generation", s.cfg.Generation)
	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { s.ServeHTTP(response, r); close(done) }()
	select {
	case <-body.started:
	case <-time.After(time.Second):
		t.Fatal("status body not reached")
	}
	s.End(old, "cancelled")
	current, _ := beginIPC(t, s, "browser")
	close(body.release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("late status blocked")
	}
	if response.Code != 410 {
		t.Fatalf("late status=%d", response.Code)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current == nil || s.current.RequestID != current || s.current.Mode != "browser" {
		t.Fatal("late status mutated successor")
	}
}
func TestIPCShutdownCancelsQueuedSolverAndRejectsNewTask(t *testing.T) {
	s, _ := ipcServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Acquire(ctx) }()
	_ = s.Close()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("shutdown err=%v", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("queued solver ignored process shutdown")
	}
	s.Release()
	if _, err := s.Begin(ctx, "http://localhost:8765/not_robot", "browser"); !errors.Is(err, context.Canceled) {
		t.Fatalf("closed server accepted new task: %v", err)
	}
}

func TestIPCResumeWithoutNewChallengeCompletesAndDoesNotClearPending(t *testing.T) {
	s, out := ipcServer(t)
	s.cfg.BrowserTimeout = time.Hour
	s.Authorized()
	if strings.Contains(out.String(), `"phase":"authorized"`) {
		t.Fatal("unsolicited completion")
	}
	s.Pause()
	s.Authorized()
	if strings.Contains(out.String(), `"phase":"authorized"`) {
		t.Fatal("success cleared user wait")
	}
	s.Resume()
	pending, _ := beginIPC(t, s, "browser")
	s.Authorized()
	if strings.Contains(out.String(), `"phase":"authorized"`) {
		t.Fatal("success cleared active challenge")
	}
	s.End(pending, "resolved")
	s.Authorized()
	s.Authorized()
	if strings.Count(out.String(), `"phase":"authorized"`) != 1 {
		t.Fatal("resumed success must emit once")
	}
	s.Pause()
	s.Resume()
	s.Authorized()
	if strings.Count(out.String(), `"phase":"authorized"`) != 2 {
		t.Fatal("no-captcha resume stuck in resuming")
	}
}
