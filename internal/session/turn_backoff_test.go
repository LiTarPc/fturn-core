package session

import (
	"context"
	"testing"
	"time"
)

func TestTURNBackoffPreservesStartupWindow(t *testing.T) {
	s := newTestSession(t, Options{ConnectTimeout: 20 * time.Millisecond, StatusInterval: time.Millisecond}, nil)
	// Unix-second deadlines deliberately exceed the short startup timeout.
	until := time.Now().Add(2 * time.Second)
	s.noteTURNBackoff(until)
	s.noteTURNBackoff(time.Now())
	if s.turnBackoffUntil.Load() != until.Unix() {
		t.Fatal("shorter pause replaced the deadline")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.watch(ctx, cancel, s.turnBackoffUntil.Load) }()
	select {
	case e := <-done:
		t.Fatalf("startup timed out inside TURN cooldown: %v", e)
	case <-time.After(70 * time.Millisecond):
	}
	cancel()
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}
