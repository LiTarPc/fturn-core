package tcprelay

import (
	"bytes"
	"context"
	"github.com/LiTarPc/fturn-core/internal/logx"
	"github.com/LiTarPc/fturn-core/internal/stats"
	"github.com/LiTarPc/fturn-core/internal/transport/kcpmux"
	"github.com/pion/stun/v3"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func auditEOFBackend(t *testing.T) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				b, e := io.ReadAll(c)
				if e != nil {
					return
				}
				time.Sleep(30 * time.Millisecond)
				_, _ = c.Write(append([]byte("response:"), b...))
			}()
		}
	}()
	return ln.Addr().String()
}
func TestRegressionTCPHalfCloseControl(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sess := pairedSession(t, ctx, auditEOFBackend(t))
	s, e := sess.OpenStream()
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = s.Close() }()
	_ = s.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = s.Write([]byte("request"))
	if e = s.CloseWrite(); e != nil {
		t.Fatal(e)
	}
	got, e := io.ReadAll(s)
	if e != nil {
		t.Fatal(e)
	}
	if string(got) != "response:request" {
		t.Fatalf("got %q", got)
	}
}
func TestRegressionTCPHalfCloseThroughClient(t *testing.T) {
	for _, counted := range []bool{false, true} {
		t.Run(map[bool]string{false: "without_stats", true: "with_stats"}[counted], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var active atomic.Int32
			p := newSessionPool(&active)
			var counters *stats.Stats
			if counted {
				counters = stats.New(true)
			}
			ps := p.Add(1, pairedSession(t, ctx, auditEOFBackend(t)), counters)
			ln, e := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer func() { _ = ln.Close() }()
			c, e := (&net.Dialer{}).DialContext(t.Context(), "tcp", ln.Addr().String())
			if e != nil {
				t.Fatal(e)
			}
			defer func() { _ = c.Close() }()
			relay, e := ln.Accept()
			if e != nil {
				t.Fatal(e)
			}
			done := make(chan struct{})
			go func() { defer close(done); proxyConn(ctx, logx.Nop(), relay, p, ps, p.NextConnID()) }()
			_ = c.SetDeadline(time.Now().Add(3 * time.Second))
			_, _ = c.Write([]byte("request"))
			tcp, ok := c.(*net.TCPConn)
			if !ok {
				t.Fatal("expected TCP connection")
			}
			if e = tcp.CloseWrite(); e != nil {
				t.Fatal(e)
			}
			got, e := io.ReadAll(c)
			if e != nil {
				t.Fatalf("read reply: %v", e)
			}
			if !bytes.Equal(got, []byte("response:request")) {
				t.Errorf("reply after CloseWrite lost: got %q, want response:request", got)
			}
			cancel()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("proxy leaked")
			}
		})
	}
}
func TestRegressionQuota486HasCooldown(t *testing.T) {
	err := &stun.TurnError{StunMessageType: stun.NewType(stun.MethodAllocate, stun.ClassErrorResponse), ErrorCodeAttr: stun.ErrorCodeAttribute{Code: stun.CodeAllocQuotaReached}}
	got := retryDelay(nopAuth{}, err)
	if got < time.Minute {
		t.Errorf("486 retry=%s; want at least 1 minute cooldown", got)
	}
}
func TestRegressionPanickedSessionWorkerIsReported(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	var active atomic.Int32
	params := &Params{Profile: "none", KCPProfile: kcpmux.DefaultProfile(), GetCreds: func(context.Context, int) (string, string, []string, error) {
		calls.Add(1)
		panic("audit injected credential worker panic")
	}}
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, &Deps{Log: logx.Nop(), ConnectedStreams: &active}, params, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}, "127.0.0.1:0", 1)
	}()
	limit := time.Now().Add(time.Second)
	for calls.Load() == 0 && time.Now().Before(limit) {
		time.Sleep(time.Millisecond)
	}
	if calls.Load() == 0 {
		t.Fatal("worker did not start")
	}
	finished := false
	select {
	case err := <-done:
		finished = true
		if err == nil {
			t.Error("panic lost: Run returned nil")
		}
	case <-time.After(100 * time.Millisecond):
		if calls.Load() < 2 {
			t.Error("worker panic neither reported nor restarted; listener remains running with zero workers")
		}
	}
	cancel()
	if !finished {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("Run did not stop")
		}
	}
}
