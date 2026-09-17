//go:build integration

package tcprelay

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/turn/v5"
	"github.com/samosvalishe/free-turn-proxy/internal/clientsdb"
	"github.com/samosvalishe/free-turn-proxy/internal/logx"
	"github.com/samosvalishe/free-turn-proxy/internal/proxy/tcpserver"
	"github.com/samosvalishe/free-turn-proxy/internal/transport/dtlsdial"
	"github.com/samosvalishe/free-turn-proxy/internal/transport/kcpmux"
	"github.com/samosvalishe/free-turn-proxy/internal/wire"
)

const integrationWait = 45 * time.Second

type trackingTURNListener struct {
	net.Listener
	mu    sync.Mutex
	conns []net.Conn
}

func (l *trackingTURNListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	l.conns = append(l.conns, conn)
	l.mu.Unlock()
	return conn, nil
}

func (l *trackingTURNListener) conn(index int) net.Conn {
	l.mu.Lock()
	defer l.mu.Unlock()
	if index < 0 || index >= len(l.conns) {
		return nil
	}
	return l.conns[index]
}

func (l *trackingTURNListener) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.conns)
}

func eventually(t *testing.T, timeout time.Duration, desc string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", desc)
}

func startIntegrationTURN(t *testing.T) (*trackingTURNListener, string, string, string) {
	t.Helper()
	base, err := net.Listen("tcp4", "127.0.0.1:0") //nolint:noctx // integration harness
	if err != nil {
		t.Fatalf("TURN listen: %v", err)
	}
	tracked := &trackingTURNListener{Listener: base}

	const (
		realm = "fturn-integration"
		user  = "integration-user"
		pass  = "integration-pass"
	)
	key := turn.GenerateAuthKey(user, realm, pass)
	server, err := turn.NewServer(turn.ServerConfig{
		Realm: realm,
		AuthHandler: func(ra *turn.RequestAttributes) (string, []byte, bool) {
			if ra.Username != user {
				return "", nil, false
			}
			return user, key, true
		},
		ListenerConfigs: []turn.ListenerConfig{{
			Listener: tracked,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
				RelayAddress: net.ParseIP("127.0.0.1"),
				Address:      "127.0.0.1",
			},
		}},
	})
	if err != nil {
		_ = base.Close()
		t.Fatalf("TURN server: %v", err)
	}
	t.Cleanup(func() {
		_ = server.Close()
		_ = base.Close()
	})
	return tracked, base.Addr().String(), user, pass
}

func startIntegrationBackend(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0") //nolint:noctx // integration harness
	if err != nil {
		t.Fatalf("backend listen: %v", err)
	}
	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			wg.Go(func() {
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(conn, conn)
			})
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
		wg.Wait()
	})
	return ln.Addr().String()
}

func startIntegrationTCPServer(t *testing.T, ctx context.Context, backend string) *net.UDPAddr {
	t.Helper()
	cert, err := dtlsdial.GenerateSelfSignedCert()
	if err != nil {
		t.Fatalf("server certificate: %v", err)
	}
	listener, err := dtls.ListenWithOptions(
		"udp4",
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0},
		dtls.WithCertificates(cert),
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
		dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
		dtls.WithConnectionIDGenerator(dtls.RandomCIDGenerator(8)),
	)
	if err != nil {
		t.Fatalf("DTLS listen: %v", err)
	}

	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, aerr := listener.Accept()
			if aerr != nil {
				return
			}
			wg.Go(func() {
				defer func() { _ = conn.Close() }()
				dtlsConn, ok := conn.(*dtls.Conn)
				if !ok {
					return
				}
				hsCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
				defer cancel()
				if herr := dtlsConn.HandshakeContext(hsCtx); herr != nil {
					return
				}
				_, mode, rerr := clientsdb.ReadClientID(dtlsConn)
				if rerr != nil || mode != clientsdb.ModeTCP {
					return
				}
				tcpserver.Handle(ctx, logx.Nop(), dtlsConn, backend, kcpmux.DefaultProfile())
			})
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
		wg.Wait()
	})

	addr, ok := listener.Addr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("DTLS listener addr type = %T", listener.Addr())
	}
	return addr
}

func sessionByID(pool *sessionPool, id int) *pooledSession {
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	for _, ps := range pool.sessions {
		if ps.id == id {
			return ps
		}
	}
	return nil
}

func assertIntegrationEcho(t *testing.T, addr string, payload []byte) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("local TCP dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if err = conn.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Write(payload); err != nil {
		t.Fatalf("local TCP write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, got); err != nil {
		t.Fatalf("local TCP read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("echo payload mismatch")
	}
}

func forceRST(t *testing.T, conn net.Conn) {
	t.Helper()
	if conn == nil {
		t.Fatal("TURN transport connection is nil")
	}
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatalf("TURN transport type = %T, want *net.TCPConn", conn)
	}
	if err := tcp.SetLinger(0); err != nil {
		t.Fatalf("SetLinger(0): %v", err)
	}
	if err := tcp.Close(); err != nil {
		t.Fatalf("RST close: %v", err)
	}
}

func waitSessionTransportFailure(t *testing.T, ps *pooledSession) {
	t.Helper()
	deadline := time.Now().Add(integrationWait)
	for time.Now().Before(deadline) {
		if ps.sess.IsClosed() {
			return
		}
		stream, err := ps.sess.OpenStream()
		if err != nil {
			return
		}
		_ = stream.Close()
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatal("smux session did not observe TURN/TCP transport failure")
}

func TestTURNOverTCPRecoveryEndToEnd(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	backend := startIntegrationBackend(t)
	peer := startIntegrationTCPServer(t, ctx, backend)
	turnListener, turnAddr, user, pass := startIntegrationTURN(t)

	var active atomic.Int32
	pool := newSessionPool(&active)
	deps := &Deps{
		DTLSDialer:       &dtlsdial.Dialer{HandshakeTimeout: 15 * time.Second},
		Log:              logx.Nop(),
		ConnectedStreams: &active,
	}
	params := &Params{
		TransportUDP: false,
		Profile:      wire.ProfileNone,
		GetCreds: func(context.Context, int) (string, string, []string, error) {
			return user, pass, []string{turnAddr}, nil
		},
		KCPProfile: kcpmux.DefaultProfile(),
		ClientID:   "tcp-integration-client",
	}

	fatalCh := make(chan error, 2)
	var maintainWG sync.WaitGroup
	startMaintainer := func(id int) {
		maintainWG.Go(func() {
			maintainSession(ctx, deps, params, peer, id, pool, nil, func(err error) {
				select {
				case fatalCh <- err:
				default:
				}
			})
		})
	}
	startMaintainer(1)
	eventually(t, integrationWait, "session 1", func() bool { return pool.Count() == 1 && turnListener.count() >= 1 })
	ps1 := sessionByID(pool, 1)
	if ps1 == nil {
		t.Fatal("session 1 missing from pool")
	}
	turnConn1 := turnListener.conn(0)

	startMaintainer(2)
	eventually(t, integrationWait, "session 2", func() bool { return pool.Count() == 2 && turnListener.count() >= 2 })

	localListener, err := net.Listen("tcp4", "127.0.0.1:0") //nolint:noctx // integration harness
	if err != nil {
		t.Fatalf("tcprelay listen: %v", err)
	}
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		acceptLoop(ctx, deps, localListener, pool)
	}()

	payload := bytes.Repeat([]byte("full-stack-turn-tcp-"), 2048)
	assertIntegrationEcho(t, localListener.Addr().String(), payload)

	// Simulate the real-world case where the remote TURN endpoint resets a pooled
	// TCP transport. SetLinger(0)+Close on the accepted server-side socket emits RST.
	forceRST(t, turnConn1)
	waitSessionTransportFailure(t, ps1)

	// Force one already-accepted local TCP connection to start on the stale pooled
	// session. proxyConn must invalidate it and retry the same local connection once
	// on another healthy session before any user bytes have been consumed.
	local, relay := net.Pipe()
	failoverDone := make(chan struct{})
	go func() {
		defer close(failoverDone)
		proxyConn(ctx, logx.Nop(), relay, pool, ps1, pool.NextConnID())
	}()
	if err = local.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatal(err)
	}
	failoverPayload := bytes.Repeat([]byte("same-local-connection-survives-"), 1024)
	writeDone := make(chan error, 1)
	go func() {
		_, werr := local.Write(failoverPayload)
		writeDone <- werr
	}()
	got := make([]byte, len(failoverPayload))
	if _, err = io.ReadFull(local, got); err != nil {
		t.Fatalf("read after stale-session fallback: %v", err)
	}
	if err = <-writeDone; err != nil {
		t.Fatalf("write after stale-session fallback: %v", err)
	}
	if !bytes.Equal(got, failoverPayload) {
		t.Fatal("fallback payload mismatch")
	}
	_ = local.Close()
	select {
	case <-failoverDone:
	case <-time.After(20 * time.Second):
		t.Fatal("fallback proxyConn did not return")
	}

	// maintainSession must notice the dead transport and restore the pool to 2/2.
	eventually(t, integrationWait, "session 1 reconnect", func() bool {
		return pool.Count() == 2 && turnListener.count() >= 3 && sessionByID(pool, 1) != ps1
	})
	assertIntegrationEcho(t, localListener.Addr().String(), []byte("post-reconnect-ok"))

	select {
	case ferr := <-fatalCh:
		t.Fatalf("session maintainer fatal error: %v", ferr)
	default:
	}

	cancel()
	_ = localListener.Close()
	select {
	case <-acceptDone:
	case <-time.After(20 * time.Second):
		t.Fatal("acceptLoop did not stop")
	}
	maintainWG.Wait()

	if active.Load() != 0 {
		t.Fatalf("active sessions after shutdown = %d, want 0", active.Load())
	}
	t.Logf("TURN/TCP recovery verified: initial transport reset, same-connection fallback, pool reconnect")
	_ = fmt.Sprintf("turn=%s peer=%s", turnAddr, peer.String()) // keep addresses easy to expose while debugging
}
