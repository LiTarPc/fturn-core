package vk

import (
	"context"
	"sync"
)

// AuthGate keeps failed advanced authorization paused until explicit resume.
// Cached credentials remain usable because only fresh fetches acquire the gate.
type AuthGate struct {
	mu     sync.Mutex
	paused bool
	resume chan struct{}
	serial chan struct{}
}

func NewAuthGate() *AuthGate {
	return &AuthGate{resume: make(chan struct{}), serial: make(chan struct{}, 1)}
}
func (g *AuthGate) Acquire(ctx context.Context) error {
	select {
	case g.serial <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	for {
		if err := ctx.Err(); err != nil {
			g.Release()
			return err
		}
		g.mu.Lock()
		paused, ch := g.paused, g.resume
		g.mu.Unlock()
		if !paused {
			return nil
		}
		select {
		case <-ch:
		case <-ctx.Done():
			g.Release()
			return ctx.Err()
		}
	}
}
func (g *AuthGate) Release() { <-g.serial }
func (g *AuthGate) Pause()   { g.mu.Lock(); defer g.mu.Unlock(); g.paused = true }
func (g *AuthGate) Resume() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.paused {
		g.paused = false
		close(g.resume)
		g.resume = make(chan struct{})
	}
}
func (g *AuthGate) Active() bool { g.mu.Lock(); defer g.mu.Unlock(); return g.paused }
func (*AuthGate) Authorized()    {}
