//go:build integration

package tcprelay

import (
	"context"
	"errors"
	"github.com/LiTarPc/fturn-core/internal/logx"
	"github.com/LiTarPc/fturn-core/internal/proxy/udprelay"
	"github.com/LiTarPc/fturn-core/internal/transport/turndial"
	"github.com/pion/stun/v3"
	"github.com/pion/turn/v5"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Drop deletion requests after a successful Allocate, as a lossy TURN path would.
type refreshDropConn struct {
	net.PacketConn
	drop atomic.Bool
}

func (c *refreshDropConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, a, e := c.PacketConn.ReadFrom(b)
		if e != nil {
			return n, a, e
		}
		if c.drop.Load() && stun.IsMessage(b[:n]) {
			m := &stun.Message{Raw: append([]byte(nil), b[:n]...)}
			if m.Decode() == nil && m.Type.Method == stun.MethodRefresh {
				continue
			}
		}
		return n, a, nil
	}
}
func lifecycleTURN(t *testing.T, user string, quota turn.QuotaHandler) (*turn.Server, *refreshDropConn) {
	t.Helper()
	socket, e := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	pc := &refreshDropConn{PacketConn: socket}
	const realm = "lifecycle-test"
	s, e := turn.NewServer(turn.ServerConfig{Realm: realm, AuthHandler: func(a *turn.RequestAttributes) (string, []byte, bool) {
		return user, turn.GenerateAuthKey(user, realm, "password"), a.Username == user
	}, QuotaHandler: quota, PacketConnConfigs: []turn.PacketConnConfig{{PacketConn: pc, RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{RelayAddress: net.IPv4(127, 0, 0, 1), Address: "127.0.0.1"}}}})
	if e != nil {
		_ = pc.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = s.Close(); _ = pc.Close() })
	return s, pc
}
func TestTURNQuotaStopsConcurrentCandidateStorm(t *testing.T) {
	user := "quota-storm-regression-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	var requests atomic.Int32
	_, first := lifecycleTURN(t, user, func(string, string, net.Addr) bool { requests.Add(1); return false })
	_, second := lifecycleTURN(t, user, func(string, string, net.Addr) bool { requests.Add(1); return false })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	get := func(ctx context.Context, _ int) (string, string, []string, error) {
		if err := ctx.Err(); err != nil {
			return "", "", nil, err
		}
		return user, "password", []string{first.LocalAddr().String(), second.LocalAddr().String()}, nil
	}
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for id := 1; id <= 20; id++ {
		wg.Go(func() {
			stream, e := udprelay.DialTURN(ctx, "", "", true, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}, id, get, logx.Nop())
			if stream != nil {
				_ = stream.Close()
			}
			errs <- e
		})
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if turndial.RetryAfter(e) < 50*time.Second {
			t.Errorf("missing shared quota pause: %v", e)
		}
	}
	if n := requests.Load(); n != 1 {
		t.Fatalf("quota checked %d times, want one for 20 workers and two candidates", n)
	}
}
func TestTURNDeletionConfirmationAndTimeout(t *testing.T) {
	for _, drop := range []bool{false, true} {
		name := "confirmed"
		if drop {
			name = "lost_delete"
		}
		t.Run(name, func(t *testing.T) {
			server, pc := lifecycleTURN(t, "delete-regression-"+name, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			stream, e := turndial.Open(ctx, turndial.Config{TransportUDP: true, Log: logx.Nop()}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}, "delete-regression-"+name, "password", pc.LocalAddr().String())
			if e != nil {
				t.Fatal(e)
			}
			if server.AllocationCount() != 1 {
				t.Fatal("allocation was not created")
			}
			pc.drop.Store(drop)
			started := time.Now()
			e = stream.Close()
			elapsed := time.Since(started)
			if drop {
				if e == nil || stream.DeletionStatus() != "unconfirmed" {
					t.Fatalf("lost delete reported success: %v %s", e, stream.DeletionStatus())
				}
				if elapsed > 2*time.Second {
					t.Fatalf("delete blocked shutdown for %s", elapsed)
				}
			} else if e != nil || stream.DeletionStatus() != "confirmed" || server.AllocationCount() != 0 {
				t.Fatalf("delete: error=%v status=%s count=%d", e, stream.DeletionStatus(), server.AllocationCount())
			}
			if !errors.Is(stream.Close(), e) {
				t.Fatal("repeated Close changed the deletion result")
			}
		})
	}
}
