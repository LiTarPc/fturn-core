package main

import (
	"context"
	"net"
	"sync"
	"time"
)

type sessionKey struct {
	clientID string
	mode     byte
	streamID uint32
}

type serverSession struct {
	cancel context.CancelFunc
	conn   net.Conn
}

type sessionRegistry struct {
	mu     sync.Mutex
	active map[sessionKey]*serverSession
}

func (r *sessionRegistry) replace(key sessionKey, next *serverSession) *serverSession {
	// Older clients have no stream identity. Replacing by client ID alone
	// would tear down their other parallel connections.
	if key.clientID == "" || key.streamID == 0 {
		return nil
	}
	r.mu.Lock()
	if r.active == nil {
		r.active = make(map[sessionKey]*serverSession)
	}
	old := r.active[key]
	r.active[key] = next
	r.mu.Unlock()
	if old != nil {
		old.cancel()
		// Unblock the old DTLS reader/writer immediately, including before
		// the proxy's cancellation hook has been registered.
		_ = old.conn.SetDeadline(time.Now())
	}
	return old
}

func (r *sessionRegistry) remove(key sessionKey, entry *serverSession) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// A displaced handler can finish after its replacement starts.
	if r.active[key] == entry {
		delete(r.active, key)
	}
}
