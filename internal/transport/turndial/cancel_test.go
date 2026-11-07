package turndial

import (
	"context"
	"errors"
	"github.com/LiTarPc/fturn-core/internal/logx"
	"net"
	"testing"
	"time"
)

func TestOpenCancelsPendingAllocate(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan net.Conn, 1)
	request := make(chan struct{})
	go func() {
		c, e := ln.Accept()
		if e != nil {
			return
		}
		accepted <- c
		var buf [4096]byte
		_, _ = c.Read(buf[:])
		close(request)
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		s, e := Open(ctx, Config{Log: logx.Nop()}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}, "cancel-test", "audit", ln.Addr().String())
		if s != nil {
			_ = s.Close()
		}
		done <- e
	}()
	var conn net.Conn
	select {
	case conn = <-accepted:
		defer func() { _ = conn.Close() }()
	case <-time.After(3 * time.Second):
		t.Fatal("not connected")
	}
	select {
	case <-request:
	case <-time.After(3 * time.Second):
		t.Fatal("no Allocate request")
	}
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatalf("got %v, want cancellation", e)
		}
	case <-time.After(time.Second):
		t.Fatal("Allocate ignored cancellation")
	}
}
