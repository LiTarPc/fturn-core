package turndial

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestOpen_BadAddress(t *testing.T) {
	peer := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 1}
	_, err := Open(context.Background(), Config{}, peer, "u", "p", "not-a-host-port")
	if err == nil {
		t.Fatal("expected error for malformed addr")
	}
	if !strings.Contains(err.Error(), "parse TURN addr") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOpen_HostOverrideApplied(t *testing.T) {
	peer := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 1}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_, err := Open(ctx, Config{HostOverride: "127.0.0.1", PortOverride: "1", TransportUDP: false, DialTimeout: 200 * time.Millisecond}, peer, "u", "p", "8.8.8.8:443")
	if err == nil {
		t.Fatal("expected dial error against unreachable :1")
	}
	if !strings.Contains(err.Error(), "dial TURN") {
		t.Fatalf("expected dial error, got: %v", err)
	}
}

type countingCloseConn struct {
	net.PacketConn
	closes atomic.Int32
	err    error
}

func (c *countingCloseConn) Close() error {
	c.closes.Add(1)
	return c.err
}

func TestRelayClosePreservesDeallocationResultAcrossOwners(t *testing.T) {
	for _, deallocateErr := range []error{nil, errors.New("deallocation write failed")} {
		raw := &countingCloseConn{err: deallocateErr}
		relay := &closeOncePacketConn{PacketConn: raw}
		var wg sync.WaitGroup
		// DTLS shutdown and session cleanup can race. Both must observe the original
		// deallocation result, not an artificial "already closed" error.
		for range 16 {
			wg.Go(func() {
				if err := relay.Close(); !errors.Is(err, deallocateErr) {
					t.Errorf("Close = %v, want original result %v", err, deallocateErr)
				}
			})
		}
		wg.Wait()
		if got := raw.closes.Load(); got != 1 {
			t.Fatalf("deallocation count = %d, want 1", got)
		}
	}
}
