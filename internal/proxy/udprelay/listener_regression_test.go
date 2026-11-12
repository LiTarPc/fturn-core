package udprelay

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestRegressionUDPListenerSurvivesOversizedDatagram(t *testing.T) {
	pc, e := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = pc.Close() }()
	sender, e := (&net.Dialer{}).DialContext(t.Context(), "udp", pc.LocalAddr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = sender.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var peer atomic.Value
	q := make(chan *Packet, 8)
	done := make(chan struct{})
	go func() { defer close(done); _ = runListener(ctx, pc, &peer, q) }()
	_, e = sender.Write(make([]byte, 4096))
	if e != nil {
		t.Fatal(e)
	}
	select {
	case <-done:
		t.Fatal("UDP listener exited permanently after a single 4096-byte datagram")
	case <-time.After(50 * time.Millisecond):
	}
	_, e = sender.Write([]byte("ok"))
	if e != nil {
		t.Fatal(e)
	}
	deadline := time.After(time.Second)
	for {
		select {
		case p := <-q:
			ok := string(p.Data[:p.N]) == "ok"
			packetPool.Put(p)
			if ok {
				return
			}
		case <-done:
			t.Fatal("listener stopped")
		case <-deadline:
			t.Fatal("valid datagram after oversized one was not delivered")
		}
	}
}
