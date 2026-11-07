package smux

import (
	"errors"
	"net"
	"testing"
	"time"
)

func TestTransportFailureIsReportedImmediately(t *testing.T) {
	a, b := net.Pipe()
	cfg := DefaultConfig()
	cfg.KeepAliveDisabled = true
	session, e := Client(a, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer session.Close()
	_ = b.Close()
	select {
	case <-session.ErrorChan():
		if session.Err() == nil || !session.IsClosed() {
			t.Fatal("failure not visible")
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for keepalive instead of transport failure")
	}
	cause := session.Err()
	_ = session.Close()
	if !errors.Is(session.Err(), cause) {
		t.Fatal("cleanup replaced first error")
	}
}
