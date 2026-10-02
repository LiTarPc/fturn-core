package main

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestSessionReplacementUnblocksOldAndPreservesNew(t *testing.T) {
	var r sessionRegistry
	key := sessionKey{clientID: "client", mode: 1, streamID: 3}
	oldConn, peer := net.Pipe()
	defer func() { _ = oldConn.Close(); _ = peer.Close() }()
	oldCtx, cancelOld := context.WithCancel(context.Background())
	defer cancelOld()
	old := &serverSession{cancel: cancelOld, conn: oldConn}
	if r.replace(key, old) != nil {
		t.Fatal("first session replaced an entry")
	}
	readDone := make(chan error, 1)
	go func() { _, err := oldConn.Read(make([]byte, 1)); readDone <- err }()
	newConn, newPeer := net.Pipe()
	defer func() { _ = newConn.Close(); _ = newPeer.Close() }()
	newCtx, cancelNew := context.WithCancel(context.Background())
	defer cancelNew()
	next := &serverSession{cancel: cancelNew, conn: newConn}
	if got := r.replace(key, next); got != old {
		t.Fatal("did not replace old session")
	}
	if oldCtx.Err() == nil {
		t.Fatal("old handler was not cancelled")
	}
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("old read succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("old DTLS transport read stayed blocked")
	}
	r.remove(key, old)
	if r.active[key] != next || newCtx.Err() != nil {
		t.Fatal("old cleanup removed or cancelled replacement")
	}
	r.remove(key, next)
	if len(r.active) != 0 {
		t.Fatal("replacement was not removed")
	}
}

func TestSessionsKeepParallelStreamsAndLegacyClients(t *testing.T) {
	var r sessionRegistry
	conn, peer := net.Pipe()
	defer func() { _ = conn.Close(); _ = peer.Close() }()
	keys := []sessionKey{
		{clientID: "client", mode: 1, streamID: 2},
		{clientID: "client", mode: 1, streamID: 4},
		{clientID: "other", mode: 1, streamID: 2},
		{clientID: "client", mode: 2, streamID: 2},
		{clientID: "client", mode: 1, streamID: 0},
		{clientID: "", mode: 1, streamID: 2},
	}
	for _, key := range keys {
		if old := r.replace(key, &serverSession{conn: conn, cancel: func() { t.Error("independent session cancelled") }}); old != nil {
			t.Fatal("independent session replaced")
		}
	}
	if len(r.active) != 4 {
		t.Fatalf("registry size=%d, want 4 identifiable streams", len(r.active))
	}
}
