package client

import (
	"github.com/pion/logging"
	"github.com/pion/stun/v3"
	"github.com/pion/turn/v5/internal/proto"
	"net"
	"testing"
	"time"
)

func TestUDPConnConfirmedCloseValidatesServerReply(t *testing.T) {
	for _, tc := range []struct {
		name      string
		reply     *stun.Message
		wantError bool
	}{
		{"deleted", stun.MustBuild(stun.NewType(stun.MethodRefresh, stun.ClassSuccessResponse), proto.Lifetime{Duration: 0}), false},
		{"not_deleted", stun.MustBuild(stun.NewType(stun.MethodRefresh, stun.ClassSuccessResponse), proto.Lifetime{Duration: time.Minute}), true},
		{"missing_reply", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			waited := false
			c := NewUDPConn(&AllocationConfig{Client: &mockClient{performTransaction: func(msg *stun.Message, _ net.Addr, dontWait bool) (TransactionResult, error) {
				waited = !dontWait
				return TransactionResult{Msg: tc.reply}, nil
			}}, RelayedAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9000}, ServerAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 3478}, Username: stun.NewUsername("u"), Realm: stun.NewRealm("r"), Nonce: stun.NewNonce("n"), Integrity: stun.NewShortTermIntegrity("p"), Lifetime: time.Hour, Log: logging.NewDefaultLoggerFactory().NewLogger("test")})
			err := c.CloseWithConfirmation()
			if !waited {
				t.Fatal("deletion did not wait")
			}
			if (err != nil) != tc.wantError {
				t.Fatalf("CloseWithConfirmation=%v", err)
			}
		})
	}
}
