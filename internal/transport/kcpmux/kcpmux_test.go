package kcpmux

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/samosvalishe/free-turn-proxy/internal/netconn"
	"github.com/xtaci/smux"
)

// datagramConn подаёт пары PacketPipe как net.Conn с сохранением границ датаграмм;
// dropEvery роняет каждую N-ю отправку, чтобы проверить ARQ.
type datagramConn struct {
	net.PacketConn
	remote    net.Addr
	dropEvery uint64
	sent      atomic.Uint64
}

func (c *datagramConn) Read(b []byte) (int, error) {
	n, _, err := c.ReadFrom(b)
	return n, err
}

func (c *datagramConn) Write(b []byte) (int, error) {
	if c.dropEvery > 0 && c.sent.Add(1)%c.dropEvery == 0 {
		return len(b), nil
	}
	return c.WriteTo(b, c.remote)
}

func (c *datagramConn) RemoteAddr() net.Addr { return c.remote }

func pipePair(dropEvery uint64) (*datagramConn, *datagramConn) {
	a, b := netconn.PacketPipe(2048, 1024)
	return &datagramConn{PacketConn: a, remote: b.LocalAddr(), dropEvery: dropEvery},
		&datagramConn{PacketConn: b, remote: a.LocalAddr()}
}

func TestServerSmuxProfiles(t *testing.T) {
	t.Parallel()

	client := SmuxConfig()
	cases := []struct {
		profile SmuxProfile
		want    int
	}{
		{SmuxProfileLow, 8 * 1024},
		{SmuxProfileMedium, 16 * 1024},
		{SmuxProfileHigh, 32 * 1024},
	}
	for _, tc := range cases {
		t.Run(string(tc.profile), func(t *testing.T) {
			server := ServerSmuxConfig(tc.profile)
			if server.MaxFrameSize != tc.want {
				t.Fatalf("server MaxFrameSize=%d, want %d", server.MaxFrameSize, tc.want)
			}
			if server.MaxFrameSize > client.MaxFrameSize {
				t.Fatalf("server MaxFrameSize=%d exceeds client default=%d", server.MaxFrameSize, client.MaxFrameSize)
			}
			if server.MaxReceiveBuffer != client.MaxReceiveBuffer || server.MaxStreamBuffer != client.MaxStreamBuffer {
				t.Fatal("server smux config unexpectedly changed receive buffers")
			}
		})
	}
	if DefaultSmuxProfile() != SmuxProfileMedium {
		t.Fatalf("default smux profile=%q, want medium", DefaultSmuxProfile())
	}
}

func TestValidateSmuxProfile(t *testing.T) {
	t.Parallel()
	for _, profile := range []SmuxProfile{SmuxProfileLow, SmuxProfileMedium, SmuxProfileHigh} {
		if err := ValidateSmuxProfile(profile); err != nil {
			t.Fatalf("profile %q: %v", profile, err)
		}
	}
	if err := ValidateSmuxProfile("turbo"); err == nil {
		t.Fatal("expected invalid smux profile error")
	}
}

func TestRoundTripAllServerSmuxProfiles(t *testing.T) {
	for _, profile := range []SmuxProfile{SmuxProfileLow, SmuxProfileMedium, SmuxProfileHigh} {
		t.Run(string(profile), func(t *testing.T) {
			runRoundTrip(t, 0, profile)
		})
	}
}

func TestRoundTripWithLoss(t *testing.T) {
	t.Parallel()
	runRoundTrip(t, 7, SmuxProfileMedium)
}

func runRoundTrip(t *testing.T, dropEvery uint64, smuxProfile SmuxProfile) {
	t.Helper()

	clientConn, serverConn := pipePair(dropEvery)
	profile := DefaultProfile()

	accepted := make(chan *smux.Session, 1)
	serverErr := make(chan error, 1)
	go func() {
		kcpSess, err := Accept(serverConn, profile)
		if err != nil {
			serverErr <- err
			return
		}
		smuxSess, err := smux.Server(kcpSess, ServerSmuxConfig(smuxProfile))
		if err != nil {
			serverErr <- err
			return
		}
		accepted <- smuxSess
	}()

	kcpClient, err := Dial(clientConn, profile)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = kcpClient.Close() }()

	// Клиент остаётся на обычном конфиге (32 KiB frame), а сервер перебирает 8/16/32 KiB.
	// Так тест проверяет wire-совместимость старого клиента со всеми серверными профилями.
	smuxClient, err := smux.Client(kcpClient, SmuxConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = smuxClient.Close() }()

	stream, err := smuxClient.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stream.Close() }()

	payload := make([]byte, 256*1024)
	if _, rerr := rand.Read(payload); rerr != nil {
		t.Fatal(rerr)
	}
	writeErr := make(chan error, 1)
	go func() { _, werr := stream.Write(payload); writeErr <- werr }()

	var smuxServer *smux.Session
	select {
	case smuxServer = <-accepted:
	case serr := <-serverErr:
		t.Fatal(serr)
	case <-time.After(30 * time.Second):
		t.Fatal("server accept timeout")
	}
	defer func() { _ = smuxServer.Close() }()

	srvStream, err := smuxServer.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srvStream.Close() }()

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(srvStream, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload mismatch client->server")
	}
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}

	// Ответ больше 32 KiB, поэтому low/medium гарантированно фрагментируют его,
	// а high использует стандартный 32 KiB quantum. Клиент должен собрать все варианты.
	back := payload[:64*1024]
	go func() { _, _ = srvStream.Write(back) }()
	echo := make([]byte, len(back))
	if err := stream.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(stream, echo); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(echo, back) {
		t.Fatal("payload mismatch server->client")
	}
}
