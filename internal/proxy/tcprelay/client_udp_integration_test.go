//go:build integration

package tcprelay

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LiTarPc/fturn-core/internal/clientsdb"
	"github.com/LiTarPc/fturn-core/internal/logx"
	"github.com/LiTarPc/fturn-core/internal/proxy/udprelay"
	"github.com/LiTarPc/fturn-core/internal/proxy/udpserver"
	"github.com/LiTarPc/fturn-core/internal/transport/dtlsdial"
	"github.com/LiTarPc/fturn-core/internal/transport/limits"
	"github.com/LiTarPc/fturn-core/internal/wire"
	"github.com/pion/dtls/v3"
	"github.com/pion/turn/v5"
)

// These INFO messages are consumed by existing Windows and Android wrappers.
type clientLogRecorder struct {
	logx.Logger
	mu    sync.Mutex
	lines []string
}

func (l *clientLogRecorder) Infof(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}
func (l *clientLogRecorder) Warnf(format string, args ...any) { l.Infof(format, args...) }

func (l *clientLogRecorder) contains(text string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, line := range l.lines {
		if strings.Contains(line, text) {
			return true
		}
	}
	return false
}

func startClientUDPTURN(t *testing.T) (string, string, string) {
	t.Helper()
	pc, e := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	const realm = "udp-integration"
	const user = "udp-integration-user"
	const pass = "udp-integration-password"
	server, e := turn.NewServer(turn.ServerConfig{Realm: realm, AuthHandler: func(a *turn.RequestAttributes) (string, []byte, bool) {
		return user, turn.GenerateAuthKey(user, realm, pass), a.Username == user
	}, PacketConnConfigs: []turn.PacketConnConfig{{PacketConn: pc, RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{RelayAddress: net.IPv4(127, 0, 0, 1), Address: "127.0.0.1"}}}})
	if e != nil {
		_ = pc.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = server.Close(); _ = pc.Close() })
	return pc.LocalAddr().String(), user, pass
}

func startClientUDPPeer(t *testing.T, ctx context.Context, profile string, key []byte) *net.UDPAddr {
	t.Helper()
	backend, e := (&net.ListenConfig{}).ListenPacket(ctx, "udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, readErr := backend.ReadFrom(buf)
			if readErr != nil {
				return
			}
			_, _ = backend.WriteTo(buf[:n], addr)
		}
	}()
	cert, e := dtlsdial.GenerateSelfSignedCert()
	if e != nil {
		t.Fatal(e)
	}
	opts := []dtls.ServerOption{dtls.WithCertificates(cert), dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret), dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)}
	address := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	var listener net.Listener
	if profile == wire.ProfileNone {
		listener, e = dtls.ListenWithOptions("udp4", address, opts...)
	} else {
		wrapped, err := wire.Listen(profile, address, key)
		if err != nil {
			t.Fatal(err)
		}
		listener, e = dtls.NewListenerWithOptions(wrapped, opts...)
	}
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	acceptedDone := make(chan struct{})
	go func() {
		defer close(acceptedDone)
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			wg.Go(func() {
				defer func() { _ = c.Close() }()
				stop := context.AfterFunc(ctx, func() { _ = c.Close() })
				defer stop()
				hs, cancel := context.WithTimeout(ctx, 5*time.Second)
				defer cancel()
				dtlsConn, ok := c.(*dtls.Conn)
				if !ok {
					return
				}
				if e := dtlsConn.HandshakeContext(hs); e != nil {
					return
				}
				_, mode, e := clientsdb.ReadClientID(c)
				if e != nil || mode != clientsdb.ModeUDP {
					return
				}
				udpserver.Handle(ctx, logx.Nop(), c, backend.LocalAddr().String())
			})
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); _ = backend.Close(); <-acceptedDone; wg.Wait() })
	addressValue, ok := listener.Addr().(*net.UDPAddr)
	if !ok {
		t.Fatal("expected UDP listener address")
	}
	return addressValue
}

func TestUDPClientEndToEndProfilesAndTransports(t *testing.T) {
	for _, udp := range []bool{false, true} {
		transport := "tcp"
		if udp {
			transport = "udp"
		}
		for _, profile := range []string{wire.ProfileNone, wire.ProfileRTPOpus, wire.ProfileRTPOpus2, wire.ProfileRTPOpus3} {
			t.Run(transport+"/"+profile, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				address, user, pass := "", "", ""
				if udp {
					address, user, pass = startClientUDPTURN(t)
				} else {
					_, address, user, pass = startIntegrationTURN(t)
				}
				key := bytes.Repeat([]byte{0x42}, 32)
				peer := startClientUDPPeer(t, ctx, profile, key)
				listener, e := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
				if e != nil {
					t.Fatal(e)
				}
				defer func() { _ = listener.Close() }()
				params := &udprelay.Params{TransportUDP: udp, Profile: profile, ObfKey: key, ClientID: "udp-client-regression", GetCreds: func(context.Context, int) (string, string, []string, error) {
					return user, pass, []string{address}, nil
				}}
				var active atomic.Int32
				log := &clientLogRecorder{Logger: logx.Nop()}
				done := make(chan error, 1)
				go func() {
					done <- udprelay.Run(ctx, &dtlsdial.Dialer{HandshakeTimeout: 5 * time.Second}, nopAuth{}, log, &active, nil, params, peer, listener, 2)
				}()
				eventually(t, 8*time.Second, "both UDP channels ready", func() bool { return active.Load() == 2 })
				if !log.contains("Established DTLS connection") || !log.contains("TURN server IP:") {
					t.Fatal("legacy UI readiness/route messages missing")
				}
				sender, e := (&net.Dialer{}).DialContext(t.Context(), "udp4", listener.LocalAddr().String())
				if e != nil {
					t.Fatal(e)
				}
				defer func() { _ = sender.Close() }()
				_ = sender.SetDeadline(time.Now().Add(5 * time.Second))
				// An unsupported datagram must not poison the following valid packets.
				if _, e = sender.Write(make([]byte, 4096)); e != nil {
					t.Fatal(e)
				}
				for _, size := range []int{1, 1280, limits.UDPApplication, 17} {
					t.Logf("sending payload size=%d", size)
					want := bytes.Repeat([]byte{0x42}, size)
					if _, e = sender.Write(want); e != nil {
						t.Fatal(e)
					}
					got := make([]byte, 65535)
					n, readErr := sender.Read(got)
					if readErr != nil {
						t.Fatalf("payload size %d: %v", size, readErr)
					}
					if !bytes.Equal(got[:n], want) {
						t.Fatalf("datagram corruption at size %d: %d bytes", size, n)
					}
				}
				cancel()
				select {
				case e = <-done:
					if e != nil {
						t.Fatal(e)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("UDP client did not stop")
				}
				if !log.contains("Closed DTLS connection") {
					t.Error("legacy UI close message missing")
				}
				if active.Load() != 0 {
					t.Fatal("ready count leaked after shutdown")
				}
			})
		}
	}
}

func TestUDPClientDoesNotCountAllocationAsReady(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, addr, user, pass := startIntegrationTURN(t)
	blackhole, e := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = blackhole.Close() }()
	received := make(chan struct{})
	go func() { var b [4096]byte; _, _, _ = blackhole.ReadFrom(b[:]); close(received) }()
	listener, e := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = listener.Close() }()
	params := &udprelay.Params{Profile: wire.ProfileNone, GetCreds: func(context.Context, int) (string, string, []string, error) { return user, pass, []string{addr}, nil }}
	var active atomic.Int32
	done := make(chan error, 1)
	peer, ok := blackhole.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatal("expected UDP peer")
	}
	go func() {
		done <- udprelay.Run(ctx, &dtlsdial.Dialer{HandshakeTimeout: 3 * time.Second}, nopAuth{}, logx.Nop(), &active, nil, params, peer, listener, 1)
	}()
	select {
	case <-received:
	case <-time.After(5 * time.Second):
		t.Fatal("no DTLS ClientHello reached blackhole through TURN")
	}
	if active.Load() != 0 {
		t.Error("Allocate was counted as a ready DTLS channel")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("blackholed handshake did not stop")
	}
}

// Authorization (including a browser-PoW wait) is not DTLS handshake time.
// The working peer becomes reachable only after the delayed credentials arrive.
func TestUDPHandshakeBudgetStartsAfterCredentials(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, address, user, pass := startIntegrationTURN(t)
	peer := startClientUDPPeer(t, ctx, wire.ProfileNone, nil)
	local, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = local.Close() }()
	const handshakeBudget = time.Second
	started := make(chan struct{})
	release := make(chan struct{})
	var fetches atomic.Int32
	params := &udprelay.Params{Profile: wire.ProfileNone, ClientID: "delayed-authorization-fixture", GetCreds: func(ctx context.Context, _ int) (string, string, []string, error) {
		if fetches.Add(1) == 1 {
			close(started)
		}
		select {
		case <-release:
			return user, pass, []string{address}, nil
		case <-ctx.Done():
			return "", "", nil, ctx.Err()
		}
	}}
	var active atomic.Int32
	logger := &clientLogRecorder{Logger: logx.Nop()}
	done := make(chan error, 1)
	go func() {
		done <- udprelay.Run(ctx, &dtlsdial.Dialer{HandshakeTimeout: handshakeBudget, HandshakeSem: make(chan struct{}, 3)}, nopAuth{}, logger, &active, nil, params, peer, local, 1)
	}()
	defer func() {
		cancel()
		select {
		case runErr := <-done:
			if runErr != nil {
				t.Error(runErr)
			}
		case <-time.After(3 * time.Second):
			t.Error("cancel did not tear down the client")
		}
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("authorization wait was not entered")
	}
	timer := time.NewTimer(2 * handshakeBudget)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if active.Load() != 0 {
		t.Fatal("authorization wait reported ready")
	}
	close(release)
	eventually(t, 3*time.Second, "DTLS ready after delayed credentials without a retry backoff", func() bool { return active.Load() == 1 })
	if fetches.Load() != 1 {
		t.Fatalf("authorization was retried after local handshake budget expired: %d", fetches.Load())
	}
	sender, err := (&net.Dialer{}).DialContext(t.Context(), "udp4", local.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sender.Close() }()
	if err = sender.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	want := []byte("delayed-credentials-roundtrip")
	if _, err = sender.Write(want); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 128)
	n, err := sender.Read(b)
	if err != nil || !bytes.Equal(b[:n], want) {
		t.Fatalf("payload roundtrip failed after delayed credentials: %v", err)
	}
}

func TestUDPHandshakeFailureKeepsPrimaryCause(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, address, user, pass := startIntegrationTURN(t)
	blackhole, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blackhole.Close() }()
	peer, ok := blackhole.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatal("expected UDP address")
	}
	local, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = local.Close() }()
	params := &udprelay.Params{Profile: wire.ProfileNone, ClientID: "handshake-cause-fixture", GetCreds: func(context.Context, int) (string, string, []string, error) {
		return user, pass, []string{address}, nil
	}}
	logger := &clientLogRecorder{Logger: logx.Nop()}
	var active atomic.Int32
	done := make(chan error, 1)
	go func() {
		done <- udprelay.Run(ctx, &dtlsdial.Dialer{HandshakeTimeout: 200 * time.Millisecond}, nopAuth{}, logger, &active, nil, params, peer, local, 1)
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("handshake failure did not tear down")
		}
	}()
	eventually(t, 3*time.Second, "primary DTLS timeout retained by TURN cycle", func() bool {
		return logger.contains("cause=DTLS session: failed to connect DTLS:") && logger.contains("deadline exceeded")
	})
	if active.Load() != 0 {
		t.Fatal("failed handshake reported ready")
	}
	if !logger.contains("relay_mode=udp turn_transport=tcp") {
		t.Fatal("relay mode and TURN transport are ambiguous")
	}
}

func TestUDPDelayedCredentialGroupsKeepHandshakeSlotsFree(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, address, user, pass := startIntegrationTURN(t)
	peer := startClientUDPPeer(t, ctx, wire.ProfileNone, nil)
	local, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = local.Close() }()
	waiting := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	params := &udprelay.Params{Profile: wire.ProfileNone, ClientID: "two-credential-groups-fixture", GetCreds: func(ctx context.Context, id int) (string, string, []string, error) {
		if id > 6 {
			once.Do(func() { close(waiting) })
			select {
			case <-release:
			case <-ctx.Done():
				return "", "", nil, ctx.Err()
			}
		}
		return user, pass, []string{address}, nil
	}}
	var active atomic.Int32
	sem := make(chan struct{}, 3)
	done := make(chan error, 1)
	go func() {
		done <- udprelay.Run(ctx, &dtlsdial.Dialer{HandshakeTimeout: time.Second, HandshakeSem: sem}, nopAuth{}, logx.Nop(), &active, nil, params, peer, local, 12)
	}()
	defer func() {
		cancel()
		select {
		case runErr := <-done:
			if runErr != nil {
				t.Error(runErr)
			}
		case <-time.After(3 * time.Second):
			t.Error("multi-group client did not stop")
		}
	}()
	select {
	case <-waiting:
	case <-time.After(3 * time.Second):
		t.Fatal("second credential group did not wait")
	}
	select {
	case <-time.After(2 * time.Second):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if active.Load() != 6 {
		t.Fatalf("first credential group was blocked by pending authorization: ready=%d", active.Load())
	}
	if len(sem) != 0 {
		t.Fatal("pending credential group consumed handshake slots")
	}
	close(release)
	eventually(t, 5*time.Second, "all 12 streams ready after second credential group", func() bool { return active.Load() == 12 })
}
func TestUDPCancelDuringCredentialsStopsWithoutHandshake(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	waiting := make(chan struct{})
	var once sync.Once
	local, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = local.Close() }()
	params := &udprelay.Params{GetCreds: func(ctx context.Context, _ int) (string, string, []string, error) {
		once.Do(func() { close(waiting) })
		<-ctx.Done()
		return "", "", nil, ctx.Err()
	}}
	sem := make(chan struct{}, 3)
	var active atomic.Int32
	done := make(chan error, 1)
	go func() {
		done <- udprelay.Run(ctx, &dtlsdial.Dialer{HandshakeTimeout: time.Second, HandshakeSem: sem}, nopAuth{}, logx.Nop(), &active, nil, params, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}, local, 12)
	}()
	select {
	case <-waiting:
	case <-time.After(2 * time.Second):
		t.Fatal("credential wait not entered")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancel during credentials hung")
	}
	if len(sem) != 0 || active.Load() != 0 {
		t.Fatal("handshake slot or ready state leaked")
	}
}
