package udprelay

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LiTarPc/fturn-core/internal/transport/dtlsdial"
)

func newPairDeps(t *testing.T) (*Deps, net.PacketConn) {
	t.Helper()
	listenConn, err := net.ListenPacket("udp", "127.0.0.1:0") //nolint:noctx // тестовый сокет
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listenConn.Close() })

	var activeLocalPeer atomic.Value
	var connected atomic.Int32

	return &Deps{
		DTLSDialer:       &dtlsdial.Dialer{HandshakeTimeout: 30 * time.Second},
		ActiveLocalPeer:  &activeLocalPeer,
		ConnectedStreams: &connected,
	}, listenConn
}

// Отмена пары со стороны TURN обязана свернуть DTLS: аллокация с новым relayed-адресом
// не адресуема сервером в старой DTLS-сессии.
func TestOneDTLSPairCancelRecycles(t *testing.T) {
	t.Parallel()
	deps, listenConn := newPairDeps(t)

	connchan := make(chan streamPair, 1)
	done := make(chan error, 1)
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}

	go func() {
		done <- oneDTLS(context.Background(), deps, &Params{}, peer, listenConn,
			make(chan *Packet), connchan, nil, 1)
	}()

	var pair streamPair
	select {
	case pair = <-connchan:
	case <-time.After(5 * time.Second):
		t.Fatal("pair was not published")
	}
	if pair.pipe == nil || pair.cancel == nil {
		t.Fatal("incomplete pair")
	}

	pair.cancel()

	select {
	case err := <-done:
		if !errors.Is(err, errPairRecycled) {
			t.Fatalf("err = %v, want errPairRecycled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("oneDTLS did not exit after pair cancel")
	}
}

// Пара отдаётся ровно один раз: повторная публикация посадила бы следующую аллокацию
// на DTLS, который уже сворачивают.
func TestOneDTLSPublishesPairOnce(t *testing.T) {
	t.Parallel()
	deps, listenConn := newPairDeps(t)

	connchan := make(chan streamPair, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}

	done := make(chan error, 1)
	go func() {
		done <- oneDTLS(ctx, deps, &Params{}, peer, listenConn, make(chan *Packet), connchan, nil, 1)
	}()

	select {
	case <-connchan:
	case <-time.After(5 * time.Second):
		t.Fatal("pair was not published")
	}

	select {
	case <-connchan:
		t.Fatal("pair published more than once")
	case <-time.After(500 * time.Millisecond):
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("oneDTLS did not exit after ctx cancel")
	}
}

// Отмена всей сессии - не рецикл пары: наверх должна уйти причина отмены, иначе
// DTLSLoop крутил бы бесконечные попытки на умирающем relay.
func TestOneDTLSSessionCancelIsNotRecycle(t *testing.T) {
	t.Parallel()
	deps, listenConn := newPairDeps(t)

	connchan := make(chan streamPair, 1)
	ctx, cancel := context.WithCancel(context.Background())
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}

	done := make(chan error, 1)
	go func() {
		done <- oneDTLS(ctx, deps, &Params{}, peer, listenConn, make(chan *Packet), connchan, nil, 1)
	}()

	select {
	case <-connchan:
	case <-time.After(5 * time.Second):
		t.Fatal("pair was not published")
	}
	cancel()

	select {
	case err := <-done:
		if errors.Is(err, errPairRecycled) {
			t.Fatal("session cancel reported as pair recycle")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("oneDTLS did not exit after ctx cancel")
	}
}

func TestOneDTLSWaitsForTURNBeforeHandshakeSlot(t *testing.T) {
	deps, listen := newPairDeps(t)
	sem := make(chan struct{}, 1)
	deps.DTLSDialer.HandshakeSem = sem
	pairs := make(chan streamPair, 1)
	done := make(chan error, 1)
	go func() {
		done <- oneDTLS(context.Background(), deps, &Params{}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}, listen, make(chan *Packet), pairs, nil, 1)
	}()
	var pair streamPair
	select {
	case pair = <-pairs:
	case <-time.After(2 * time.Second):
		t.Fatal("pair not published")
	}
	defer pair.cancel()
	if pair.ready == nil || pair.result == nil {
		t.Fatal("missing readiness/result handshake")
	}
	select {
	case <-time.After(100 * time.Millisecond):
	case err := <-done:
		t.Fatalf("DTLS ended before allocation was ready: %v", err)
	}
	if len(sem) != 0 {
		t.Fatal("credential wait occupied a handshake slot")
	}
	pair.cancel()
	select {
	case err := <-done:
		if !errors.Is(err, errPairRecycled) {
			t.Fatalf("pair cancellation lost: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("waiting pair did not stop")
	}
	select {
	case err := <-pair.result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("raw DTLS cause lost: %v", err)
		}
	default:
		t.Fatal("missing DTLS result")
	}
}
