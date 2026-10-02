package client

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/stun/v3"
	"github.com/pion/turn/v5/internal/proto"
)

func testRefreshAllocation(response *stun.Message) *allocation {
	return &allocation{
		client: &mockClient{performTransaction: func(*stun.Message, net.Addr, bool) (TransactionResult, error) {
			return TransactionResult{Msg: response}, nil
		}},
		username: stun.NewUsername("user"), realm: stun.NewRealm("realm"),
		integrity: stun.NewLongTermIntegrity("user", "realm", "pass"),
		_nonce:    stun.NewNonce("old"), _lifetime: 10 * time.Minute,
		log:               logging.NewDefaultLoggerFactory().NewLogger("test"),
		refreshAllocTimer: NewPeriodicTimer(0, func(int) {}, 5*time.Minute),
	}
}

func TestRefreshRejectsErrorResponses(t *testing.T) {
	for _, code := range []stun.ErrorCode{stun.CodeBadRequest, stun.CodeAllocMismatch, stun.CodeForbidden} {
		res := stun.MustBuild(stun.NewType(stun.MethodRefresh, stun.ClassErrorResponse), code)
		a := testRefreshAllocation(res)
		err := a.refreshAllocation(10*time.Minute, false)
		var turnErr *stun.TurnError
		if !errors.As(err, &turnErr) || turnErr.ErrorCodeAttr.Code != code {
			t.Fatalf("code=%d err=%v, want TURN error", code, err)
		}
		if a.lifetime() != 10*time.Minute {
			t.Fatal("failure changed lifetime")
		}
	}
}

func TestRefreshRejectsInvalidSuccess(t *testing.T) {
	for _, res := range []*stun.Message{
		nil,
		stun.MustBuild(stun.NewType(stun.MethodChannelBind, stun.ClassSuccessResponse)),
		stun.MustBuild(stun.NewType(stun.MethodRefresh, stun.ClassIndication), proto.Lifetime{Duration: time.Minute}),
		stun.MustBuild(stun.NewType(stun.MethodRefresh, stun.ClassSuccessResponse)),
		stun.MustBuild(stun.NewType(stun.MethodRefresh, stun.ClassSuccessResponse), proto.Lifetime{Duration: 0}),
	} {
		a := testRefreshAllocation(res)
		if err := a.refreshAllocation(10*time.Minute, false); err == nil {
			t.Fatal("invalid response accepted")
		}
		if a.lifetime() != 10*time.Minute {
			t.Fatal("invalid response changed lifetime")
		}
	}
}

func TestRefreshRetriesStaleNonceAndUpdatesTimer(t *testing.T) {
	a := testRefreshAllocation(nil)
	calls := 0
	a.client = &mockClient{performTransaction: func(msg *stun.Message, _ net.Addr, _ bool) (TransactionResult, error) {
		calls++
		if calls == 1 {
			return TransactionResult{Msg: stun.MustBuild(stun.NewType(stun.MethodRefresh, stun.ClassErrorResponse), stun.CodeStaleNonce, stun.NewNonce("fresh"))}, nil
		}
		var nonce stun.Nonce
		if err := nonce.GetFrom(msg); err != nil || string(nonce) != "fresh" {
			t.Errorf("retry nonce=%s err=%v", nonce, err)
		}
		return TransactionResult{Msg: stun.MustBuild(stun.NewType(stun.MethodRefresh, stun.ClassSuccessResponse), proto.Lifetime{Duration: 2 * time.Minute})}, nil
	}}
	a.onRefreshTimers(timerIDRefreshAlloc)
	if calls != 2 || a.lifetime() != 2*time.Minute || a.refreshAllocTimer.interval != time.Minute {
		t.Fatalf("calls=%d lifetime=%s timer=%s", calls, a.lifetime(), a.refreshAllocTimer.interval)
	}
}

func TestRefreshFailureRetriesSoon(t *testing.T) {
	a := testRefreshAllocation(stun.MustBuild(stun.NewType(stun.MethodRefresh, stun.ClassErrorResponse), stun.CodeForbidden))
	a.onRefreshTimers(timerIDRefreshAlloc)
	if a.refreshAllocTimer.interval != 5*time.Second {
		t.Fatalf("retry delay=%s", a.refreshAllocTimer.interval)
	}
}

func TestChannelRefreshHasPermissionMargin(t *testing.T) {
	if defaultBindingRefreshInterval+defaultBindingCheckInterval+2*30*time.Second >= 5*time.Minute {
		t.Fatal("no margin for channel retries before permission expiry")
	}
	conn := &UDPConn{bindingRefreshInterval: defaultBindingRefreshInterval}
	bound := newBindingManager().create(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9})
	bound.setState(bindingStateReady)
	bound.setRefreshedAt(time.Now().Add(-3 * time.Minute))
	if state, ok := conn.startBinding(bound); !ok || state != bindingStateReady || bound.state() != bindingStateRefresh {
		t.Fatal("three-minute-old permission was not selected for refresh")
	}
}

func TestIdleChannelIsRefreshedByTimer(t *testing.T) {
	refreshed := make(chan struct{}, 1)
	conn := NewUDPConn(&AllocationConfig{
		Client: &mockClient{performTransaction: func(msg *stun.Message, _ net.Addr, dontWait bool) (TransactionResult, error) {
			if dontWait {
				return TransactionResult{}, nil
			}
			if msg.Type.Method == stun.MethodChannelBind {
				select {
				case refreshed <- struct{}{}:
				default:
				}
				return TransactionResult{Msg: stun.MustBuild(stun.NewType(stun.MethodChannelBind, stun.ClassSuccessResponse))}, nil
			}
			return TransactionResult{}, errors.New("unexpected transaction")
		}},
		Username: stun.NewUsername("user"), Realm: stun.NewRealm("realm"),
		Integrity: stun.NewLongTermIntegrity("user", "realm", "pass"), Nonce: stun.NewNonce("nonce"),
		Lifetime: time.Hour, PermissionRefreshInterval: time.Hour,
		BindingRefreshInterval: 20 * time.Millisecond, BindingCheckInterval: 5 * time.Millisecond,
		Log: logging.NewDefaultLoggerFactory().NewLogger("test"),
	})
	defer func() { _ = conn.Close() }()
	bound := conn.bindingMgr.create(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9})
	bound.setRefreshedAt(time.Now())
	bound.setState(bindingStateReady)
	select {
	case <-refreshed:
	case <-time.After(time.Second):
		t.Fatal("idle channel was not refreshed")
	}
}

func TestPeriodicTimerUsesUpdatedInterval(t *testing.T) {
	done := make(chan time.Duration, 1)
	var timer *PeriodicTimer
	var first time.Time
	timer = NewPeriodicTimer(0, func(int) {
		if first.IsZero() {
			first = time.Now()
			timer.SetInterval(30 * time.Millisecond)
			return
		}
		timer.Stop()
		done <- time.Since(first)
	}, time.Millisecond)
	timer.Start()
	defer timer.Stop()
	select {
	case elapsed := <-done:
		if elapsed < 25*time.Millisecond {
			t.Fatalf("timer kept old interval: %s", elapsed)
		}
	case <-time.After(time.Second):
		t.Fatal("updated timer did not fire")
	}
}
