package turndial

import (
	"context"
	"errors"
	"fmt"
	"github.com/pion/stun/v3"
	"testing"
	"time"
)

func quotaError(code stun.ErrorCode) error {
	return &stun.TurnError{ErrorCodeAttr: stun.ErrorCodeAttribute{Code: code}}
}
func TestQuotaPausesAllCandidatesForUsername(t *testing.T) {
	g := newAllocationGate(0, time.Minute)
	release, e := g.acquire(context.Background(), "a:3478", "same-user")
	if e != nil {
		t.Fatal(e)
	}
	release(quotaError(stun.CodeAllocQuotaReached))
	for _, server := range []string{"a:3478", "b:3478"} {
		_, e = g.acquire(context.Background(), server, "same-user")
		var wait *BackoffError
		if !errors.As(e, &wait) || RetryAfter(e) < 59*time.Second {
			t.Fatalf("candidate %s: %v", server, e)
		}
	}
	other, e := g.acquire(context.Background(), "a:3478", "different-user")
	if e != nil {
		t.Fatal(e)
	}
	other(nil)
}
func TestCapacityPauseIsSharedByEndpoint(t *testing.T) {
	g := newAllocationGate(0, time.Minute)
	release, e := g.acquire(context.Background(), "full:3478", "u1")
	if e != nil {
		t.Fatal(e)
	}
	release(quotaError(stun.CodeInsufficientCapacity))
	if _, e = g.acquire(context.Background(), "full:3478", "u2"); RetryAfter(e) < 59*time.Second {
		t.Fatalf("capacity pause: %v", e)
	}
	release, e = g.acquire(context.Background(), "other:3478", "u2")
	if e != nil {
		t.Fatal(e)
	}
	release(nil)
}
func TestQueuedAllocateRechecksQuota(t *testing.T) {
	g := newAllocationGate(0, time.Minute)
	release, e := g.acquire(context.Background(), "a", "u")
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() {
		next, e := g.acquire(context.Background(), "b", "u")
		if next != nil {
			next(nil)
		}
		done <- e
	}()
	select {
	case <-done:
		t.Fatal("concurrent Allocate escaped serialization")
	case <-time.After(20 * time.Millisecond):
	}
	release(quotaError(stun.CodeAllocQuotaReached))
	select {
	case e := <-done:
		if RetryAfter(e) < 59*time.Second {
			t.Fatalf("queued waiter: %v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("waiter stuck")
	}
}
func TestAllocateGateWaitHonorsCancelAndExpiry(t *testing.T) {
	g := newAllocationGate(0, 25*time.Millisecond)
	release, e := g.acquire(context.Background(), "a", "u")
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = g.acquire(ctx, "a", "u"); !errors.Is(e, context.Canceled) {
		t.Fatalf("cancel: %v", e)
	}
	release(quotaError(stun.CodeAllocQuotaReached))
	time.Sleep(35 * time.Millisecond)
	release, e = g.acquire(context.Background(), "a", "u")
	if e != nil {
		t.Fatal(e)
	}
	release(nil)
}
func TestRetryAfterJoinedErrors(t *testing.T) {
	e := errors.Join(errors.New("network"), fmt.Errorf("candidate: %w", quotaError(stun.CodeAllocQuotaReached)))
	if RetryAfter(e) != time.Minute {
		t.Fatalf("joined delay=%s", RetryAfter(e))
	}
	if RetryAfter(errors.New("486 is text, not a typed TURN error")) != 0 {
		t.Fatal("matched text as quota")
	}
}
