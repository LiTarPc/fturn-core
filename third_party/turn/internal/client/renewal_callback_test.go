package client

import (
	"github.com/pion/logging"
	"github.com/pion/stun/v3"
	"github.com/pion/turn/v5/internal/proto"
	"net"
	"testing"
	"time"
)

func TestUDPConnForwardsTypedRenewalResults(t *testing.T) {
	refreshed := make(chan error, 1)
	bound := make(chan error, 1)
	conn := NewUDPConn(&AllocationConfig{Client: &mockClient{performTransaction: func(msg *stun.Message, _ net.Addr, _ bool) (TransactionResult, error) {
		if msg.Type.Method == stun.MethodRefresh {
			return TransactionResult{Msg: stun.MustBuild(stun.NewType(stun.MethodRefresh, stun.ClassSuccessResponse), proto.Lifetime{Duration: time.Hour})}, nil
		}
		return TransactionResult{Msg: stun.MustBuild(stun.NewType(stun.MethodChannelBind, stun.ClassSuccessResponse))}, nil
	}}, RelayedAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9000}, ServerAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 3478}, Username: stun.NewUsername("u"), Realm: stun.NewRealm("r"), Nonce: stun.NewNonce("n"), Integrity: stun.NewShortTermIntegrity("p"), Lifetime: time.Hour, Log: logging.NewDefaultLoggerFactory().NewLogger("test"), OnAllocationRefresh: func(e error) { refreshed <- e }, OnChannelBind: func(e error) { bound <- e }})
	defer func() { _ = conn.Close() }()
	conn.onRefreshTimers(timerIDRefreshAlloc)
	select {
	case e := <-refreshed:
		if e != nil {
			t.Fatal(e)
		}
	default:
		t.Fatal("allocation callback was lost")
	}
	binding := conn.bindingMgr.create(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345})
	conn.bindChannel(binding, bindingStateIdle)
	select {
	case e := <-bound:
		if e != nil {
			t.Fatal(e)
		}
	default:
		t.Fatal("channel callback was lost")
	}
}
