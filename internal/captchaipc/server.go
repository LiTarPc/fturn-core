// Package captchaipc carries challenge metadata and private URLs between a RAW
// subprocess and its Android host. Verification results stay in the captcha proxy.
package captchaipc

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

const Prefix = "FTURN_EVENT "

var validGeneration = regexp.MustCompile(`^[A-Za-z0-9_-]{8,128}$`)

type Event struct {
	V           int    `json:"v"`
	Type        string `json:"type"`
	Generation  string `json:"generation"`
	RequestID   string `json:"request_id,omitempty"`
	Mode        string `json:"mode,omitempty"`
	Purpose     string `json:"purpose,omitempty"`
	Phase       string `json:"phase"`
	ExpiresAtMS int64  `json:"expires_at_ms,omitempty"`
	IPCPort     int    `json:"ipc_port"`
}
type Challenge struct {
	Generation  string `json:"generation"`
	RequestID   string `json:"request_id"`
	Mode        string `json:"mode"`
	Purpose     string `json:"purpose,omitempty"`
	ExpiresAtMS int64  `json:"expires_at_ms"`
	URL         string `json:"url"`
}
type task struct {
	Challenge
	finished chan struct{}
	abort    context.CancelFunc
}
type Config struct {
	Token, Generation string
	Output            io.Writer
	BrowserTimeout    time.Duration
	Protocol          int
}
type Server struct {
	cfg      Config
	ctx      context.Context
	cancel   context.CancelFunc
	listener net.Listener
	http     *http.Server
	mu       sync.Mutex
	outMu    sync.Mutex
	current  *task
	paused   bool
	resuming bool
	resume   chan struct{}
	serial   chan struct{}
}

// FromEnvironment is opt-in. Supplying only one credential is a startup error.
func FromEnvironment(ctx context.Context) (*Server, error) {
	token, generation, protocol, err := environment()
	if err != nil {
		return nil, err
	}
	if token == "" && generation == "" {
		return nil, nil
	}
	return New(ctx, Config{Token: token, Generation: generation, Protocol: protocol, Output: os.Stdout})
}
func New(ctx context.Context, cfg Config) (*Server, error) {
	if cfg.Protocol == 0 {
		cfg.Protocol = 1
	}
	if cfg.Protocol != 1 && cfg.Protocol != 2 {
		return nil, errors.New("unsupported captcha IPC protocol")
	}
	token, e := hex.DecodeString(cfg.Token)
	if e != nil || len(token) != 32 || !validGeneration.MatchString(cfg.Generation) {
		return nil, errors.New("invalid captcha IPC credentials")
	}
	if cfg.Output == nil {
		cfg.Output = io.Discard
	}
	if cfg.BrowserTimeout <= 0 {
		cfg.BrowserTimeout = 45 * time.Second
	}
	lc := net.ListenConfig{}
	listener, e := lc.Listen(ctx, "tcp4", "127.0.0.1:0")
	if e != nil {
		return nil, e
	}
	ownedCtx, cancel := context.WithCancel(ctx)
	s := &Server{cfg: cfg, ctx: ownedCtx, cancel: cancel, listener: listener, resume: make(chan struct{}), serial: make(chan struct{}, 1)}
	s.http = &http.Server{Handler: s, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 8192}
	go func() { _ = s.http.Serve(listener) }()
	go func() { <-ownedCtx.Done(); _ = s.http.Close() }()
	return s, nil
}
func (s *Server) Protocol() int { return s.cfg.Protocol }
func (s *Server) Port() int     { addr, _ := s.listener.Addr().(*net.TCPAddr); return addr.Port }
func (s *Server) Close() error  { s.cancel(); return s.http.Close() }
func (s *Server) emit(e Event) {
	e.V = s.cfg.Protocol
	e.Generation = s.cfg.Generation
	e.IPCPort = s.Port()
	b, _ := json.Marshal(e)
	s.outMu.Lock()
	defer s.outMu.Unlock()
	_, _ = fmt.Fprintf(s.cfg.Output, "%s%s\n", Prefix, b)
}
func (s *Server) event(t *task, phase string) {
	s.emit(Event{Type: "captcha", RequestID: t.RequestID, Mode: t.Mode, Purpose: t.Purpose, Phase: phase, ExpiresAtMS: t.ExpiresAtMS})
}

// Acquire is context-aware and checks the gate again after waiting for another
// provider's challenge. Already cached credentials do not call this gate.
func (s *Server) Acquire(ctx context.Context) error {
	select {
	case s.serial <- struct{}{}:
	case <-s.ctx.Done():
		return s.ctx.Err()
	case <-ctx.Done():
		return ctx.Err()
	}
	if e := s.Wait(ctx); e != nil {
		<-s.serial
		return e
	}
	return nil
}
func (s *Server) Release() { <-s.serial }
func (s *Server) Wait(ctx context.Context) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if s.ctx.Err() != nil {
			return s.ctx.Err()
		}
		s.mu.Lock()
		paused, resume := s.paused, s.resume
		s.mu.Unlock()
		if !paused {
			return nil
		}
		select {
		case <-resume:
		case <-ctx.Done():
			return ctx.Err()
		case <-s.ctx.Done():
			return s.ctx.Err()
		}
	}
}
func (s *Server) Pause() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.paused {
		return
	}
	s.paused = true
	s.resuming = false
	s.emit(Event{Type: "auth", Phase: "waiting_user"})
}
func (s *Server) Resume() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.paused {
		return
	}
	s.paused = false
	s.resuming = true
	close(s.resume)
	s.resume = make(chan struct{})
	s.emit(Event{Type: "auth", Phase: "resuming"})
}

// Authorized completes a resumed authorization after fresh credentials were
// fetched. Cached groups must not clear a pause or an active challenge.
func (s *Server) Authorized() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if (s.cfg.Protocol == 1 && !s.resuming) || s.paused || s.current != nil {
		return
	}
	s.resuming = false
	s.emit(Event{Type: "auth", Phase: "authorized"})
}

// Begin accepts only the local verification proxy, never a URL delivered by an
// untrusted caller. The secret-bearing URL is returned only over authenticated IPC.
func (s *Server) Begin(ctx context.Context, raw, mode string) (string, error) {
	return s.begin(ctx, raw, mode, "solve", nil)
}
func (s *Server) BeginCapture(ctx context.Context, raw string, abort context.CancelFunc) (string, error) {
	if s.cfg.Protocol != 2 {
		return "", errors.New("browser PoW requires captcha IPC v2")
	}
	return s.begin(ctx, raw, "browser", "pow_capture", abort)
}
func (s *Server) begin(ctx context.Context, raw, mode, purpose string, abort context.CancelFunc) (string, error) {
	if err := s.ctx.Err(); err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "http" || u.User != nil || u.Fragment != "" || u.Port() != "8765" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost") {
		return "", errors.New("invalid captcha proxy URL")
	}
	if mode != "browser" && mode != "manual" {
		return "", errors.New("invalid captcha mode")
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return "", errors.New("captcha deadline required")
	}
	if !deadline.After(time.Now()) {
		return "", context.DeadlineExceeded
	}
	if purpose == "pow_capture" && time.Until(deadline) > 12*time.Second {
		deadline = time.Now().Add(12 * time.Second)
	}
	id := make([]byte, 16)
	if _, e = rand.Read(id); e != nil {
		return "", e
	}
	if s.cfg.Protocol == 1 {
		purpose = ""
	}
	t := &task{Challenge: Challenge{Generation: s.cfg.Generation, RequestID: hex.EncodeToString(id), Mode: mode, Purpose: purpose, ExpiresAtMS: deadline.UnixMilli(), URL: raw}, finished: make(chan struct{}), abort: abort}
	s.mu.Lock()
	if s.current != nil {
		s.mu.Unlock()
		return "", errors.New("captcha challenge already pending")
	}
	s.current = t
	s.event(t, "pending")
	s.mu.Unlock()
	go func() {
		timeout := s.cfg.BrowserTimeout
		if purpose == "pow_capture" {
			timeout = time.Until(deadline)
		}
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		for {
			select {
			case <-t.finished:
				return
			case <-s.ctx.Done():
				s.End(t.RequestID, "cancelled")
				return
			case <-ctx.Done():
				phase := "cancelled"
				if errors.Is(ctx.Err(), context.DeadlineExceeded) {
					phase = "expired"
				}
				s.End(t.RequestID, phase)
				return
			case <-timer.C:
				if purpose == "pow_capture" {
					s.End(t.RequestID, "expired")
				} else {
					s.manual(t.RequestID)
				}
			}
		}
	}()
	return t.RequestID, nil
}
func (s *Server) End(id, phase string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.current
	if t == nil || t.RequestID != id {
		return
	}
	s.current = nil
	if t.Purpose == "pow_capture" && phase == "resolved" {
		phase = "captured"
	}
	close(t.finished)
	if t.abort != nil {
		t.abort()
	}
	s.event(t, phase)
}
func (s *Server) manual(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.current
	if t == nil || t.RequestID != id || t.Mode == "manual" || t.Purpose == "pow_capture" {
		return
	}
	t.Mode = "manual"
	s.event(t, "pending")
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	wantHost := s.listener.Addr().String()
	if r.Host != wantHost || r.Header.Get("Origin") != "" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	auth := r.Header.Get("Authorization")
	if subtle.ConstantTimeCompare([]byte(auth), []byte("Bearer "+s.cfg.Token)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Header.Get("X-Fturn-Generation") != s.cfg.Generation {
		http.Error(w, "stale generation", http.StatusConflict)
		return
	}
	if r.URL.RawQuery != "" {
		http.Error(w, "query not supported", http.StatusBadRequest)
		return
	}
	if r.URL.Path == "/v1/auth/resume" {
		if r.Method != "POST" {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		s.Resume()
		w.WriteHeader(http.StatusNoContent)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/v1/captcha/")
	if path == r.URL.Path {
		http.NotFound(w, r)
		return
	}
	id, operation, extra := strings.Cut(path, "/")
	if extra && operation != "host" {
		http.NotFound(w, r)
		return
	}
	s.mu.Lock()
	t := s.current
	if t == nil || t.RequestID != id || time.Now().UnixMilli() >= t.ExpiresAtMS {
		s.mu.Unlock()
		http.Error(w, "expired challenge", http.StatusGone)
		return
	}
	current := t.Challenge
	s.mu.Unlock()
	if !extra && r.Method == "GET" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(current)
		return
	}
	if !extra || r.Method != "POST" {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Generation string `json:"generation"`
		Status     string `json:"status"`
		Reason     string `json:"reason"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&body) != nil {
		http.Error(w, "bad status", http.StatusBadRequest)
		return
	}
	var tail any
	if decoder.Decode(&tail) != io.EOF {
		http.Error(w, "trailing body", http.StatusBadRequest)
		return
	}
	if body.Generation != s.cfg.Generation {
		http.Error(w, "stale generation", http.StatusConflict)
		return
	}
	switch body.Reason {
	case "", "host_unavailable", "renderer_gone", "load_failed", "challenge_expired", "user_requested":
	default:
		http.Error(w, "bad reason", http.StatusBadRequest)
		return
	}
	if body.Status != "available" && body.Status != "unavailable" && body.Status != "manual_requested" {
		http.Error(w, "bad status", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	t = s.current
	if t == nil || t.RequestID != id || time.Now().UnixMilli() >= t.ExpiresAtMS {
		s.mu.Unlock()
		http.Error(w, "expired challenge", http.StatusGone)
		return
	}
	if body.Status != "available" && t.Purpose == "pow_capture" {
		s.current = nil
		close(t.finished)
		s.event(t, "unavailable")
		if t.abort != nil {
			t.abort()
		}
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if body.Status != "available" && t.Mode != "manual" {
		t.Mode = "manual"
		s.event(t, "pending")
	}
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) Active() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.paused || s.current != nil }

// Shared names and explicit TURN/RAW aliases are accepted; conflicts fail closed.
func environment() (token, generation string, protocol int, err error) {
	read := func(suffix string) (string, error) {
		value := ""
		for _, prefix := range []string{"FREETURN_", "FREETURN_TURN_", "FREETURN_RAW_"} {
			v := os.Getenv(prefix + suffix)
			if v != "" {
				if value != "" && value != v {
					return "", errors.New("conflicting captcha IPC environment aliases")
				}
				value = v
			}
		}
		return value, nil
	}
	token, err = read("CAPTCHA_TOKEN")
	if err != nil {
		return
	}
	generation, err = read("CAPTCHA_GENERATION")
	if err != nil {
		return
	}
	v, e := read("CAPTCHA_PROTOCOL")
	if e != nil {
		err = e
		return
	}
	protocol = 1
	if v != "" {
		if v == "2" {
			protocol = 2
		} else if v != "1" {
			err = errors.New("unsupported captcha IPC protocol")
			return
		}
	}
	if token == "" && generation == "" && v != "" {
		err = errors.New("captcha IPC credentials required")
	}
	return
}
