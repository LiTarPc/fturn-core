package netconn

import (
	"errors"
	"net"
	"testing"
	"time"
)

func TestPacketPipePeerCloseUnblocksReader(t *testing.T) {
	a, b := PacketPipe(1600, 1)
	defer func() { _ = a.Close(); _ = b.Close() }()
	done := make(chan error, 1)
	go func() { var buf [1600]byte; _, _, e := b.ReadFrom(buf[:]); done <- e }()
	_ = a.Close()
	select {
	case e := <-done:
		if !errors.Is(e, net.ErrClosed) {
			t.Fatalf("ReadFrom=%v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("peer reader remained blocked")
	}
}
