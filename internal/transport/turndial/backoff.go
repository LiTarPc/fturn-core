package turndial

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/pion/stun/v3"
)

const quotaCooldown = time.Minute
const candidateInterval = 200 * time.Millisecond

// BackoffError reports an intentional TURN pause, independent of VK auth pauses.
type BackoffError struct {
	Until time.Time
	Code  stun.ErrorCode
	Cause error
}

func (e *BackoffError) Error() string {
	return fmt.Sprintf("TURN cooldown code=%d retry_after=%s", e.Code, max(time.Until(e.Until), 0).Round(time.Millisecond))
}
func (e *BackoffError) Unwrap() error { return e.Cause }

// RetryAfter also handles wrapped/joined errors without matching log text.
func RetryAfter(err error) time.Duration {
	if err == nil {
		return 0
	}
	if e, ok := err.(*BackoffError); ok {
		return max(time.Until(e.Until), 0)
	}
	if e, ok := err.(*stun.TurnError); ok {
		if e.ErrorCodeAttr.Code == stun.CodeAllocQuotaReached || e.ErrorCodeAttr.Code == stun.CodeInsufficientCapacity {
			return quotaCooldown
		}
	}
	var result time.Duration
	if many, ok := err.(interface{ Unwrap() []error }); ok {
		for _, e := range many.Unwrap() {
			result = max(result, RetryAfter(e))
		}
	} else if one, ok := err.(interface{ Unwrap() error }); ok {
		return RetryAfter(one.Unwrap())
	}
	return result
}

type allocationPermit struct {
	held       chan struct{}
	next, last time.Time
}
type allocationGate struct {
	mu                 sync.Mutex
	users              map[[32]byte]*allocationPermit
	userPauses         map[[32]byte]*BackoffError
	serverPauses       map[string]*BackoffError
	interval, cooldown time.Duration
}

func newAllocationGate(interval, cooldown time.Duration) *allocationGate {
	return &allocationGate{users: make(map[[32]byte]*allocationPermit), userPauses: make(map[[32]byte]*BackoffError), serverPauses: make(map[string]*BackoffError), interval: interval, cooldown: cooldown}
}

// Keep pauses across a client reconnect. Never retain plaintext credentials.
var turnAllocations = newAllocationGate(candidateInterval, quotaCooldown)

// acquire serializes Allocate for one username, including candidate fallback.
// Waiting workers recheck quota after the preceding attempt has completed.
func (g *allocationGate) acquire(ctx context.Context, server, user string) (func(error), error) {
	key := sha256.Sum256([]byte(user))
	g.mu.Lock()
	now := time.Now()
	if len(g.users) > 1024 {
		for k, e := range g.users {
			if len(e.held) == 0 && now.Sub(e.last) > 10*time.Minute {
				delete(g.users, k)
				delete(g.userPauses, k)
			}
		}
	}
	for s, p := range g.serverPauses {
		if !p.Until.After(now) {
			delete(g.serverPauses, s)
		}
	}
	entry := g.users[key]
	if entry == nil {
		entry = &allocationPermit{held: make(chan struct{}, 1)}
		g.users[key] = entry
	}
	entry.last = now
	g.mu.Unlock()
	select {
	case entry.held <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	unlock := func() { <-entry.held }
	g.mu.Lock()
	pause := g.pauseLocked(key, server)
	wait := time.Until(entry.next)
	g.mu.Unlock()
	if pause != nil {
		unlock()
		return nil, pause
	}
	if wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			unlock()
			return nil, ctx.Err()
		}
	}
	if err := ctx.Err(); err != nil {
		unlock()
		return nil, err
	}
	g.mu.Lock()
	pause = g.pauseLocked(key, server)
	entry.next = time.Now().Add(g.interval)
	g.mu.Unlock()
	if pause != nil {
		unlock()
		return nil, pause
	}
	var once sync.Once
	return func(err error) {
		once.Do(func() {
			var turnErr *stun.TurnError
			if errors.As(err, &turnErr) {
				g.mu.Lock()
				until := time.Now().Add(g.cooldown)
				p := &BackoffError{Until: until, Code: turnErr.ErrorCodeAttr.Code, Cause: turnErr}
				switch p.Code {
				case stun.CodeAllocQuotaReached:
					g.userPauses[key] = p
				case stun.CodeInsufficientCapacity:
					g.serverPauses[server] = p
				}
				g.mu.Unlock()
			}
			unlock()
		})
	}, nil
}
func (g *allocationGate) pauseLocked(key [32]byte, server string) *BackoffError {
	now := time.Now()
	user := g.userPauses[key]
	if user != nil && !user.Until.After(now) {
		delete(g.userPauses, key)
		user = nil
	}
	endpoint := g.serverPauses[server]
	if endpoint != nil && !endpoint.Until.After(now) {
		delete(g.serverPauses, server)
		endpoint = nil
	}
	if endpoint != nil && (user == nil || endpoint.Until.After(user.Until)) {
		return endpoint
	}
	return user
}
