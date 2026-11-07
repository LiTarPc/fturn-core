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
