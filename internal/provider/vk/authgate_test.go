package vk

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestAuthGateExplicitResumeAndCancellation(t *testing.T) {
	g := NewAuthGate()
	g.Pause()
	g.Authorized()
	if !g.Active() {
		t.Fatal("success cleared a newer pause")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := g.Acquire(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("paused authorization proceeded")
	}
	g.Resume()
	g.Resume()
	if g.Active() {
		t.Fatal("resume did not release gate")
	}
	if err := g.Acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel2()
	if err := g.Acquire(ctx2); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("concurrent fresh authorization was not serialized")
	}
	g.Release()
	if err := g.Acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	g.Release()
}
