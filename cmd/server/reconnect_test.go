package main

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/samosvalishe/free-turn-proxy/internal/clientsdb"
	"github.com/samosvalishe/free-turn-proxy/internal/config"
	"github.com/samosvalishe/free-turn-proxy/internal/logx"
	"github.com/samosvalishe/free-turn-proxy/internal/transport/dtlsdial"
)

func TestDTLSReconnectReplacesOnlyMatchingStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var lc net.ListenConfig
	backend, err := lc.ListenPacket(ctx, "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = backend.Close() }()
	go func() {
		buf := make([]byte, 1600)
		for {
			n, addr, err := backend.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = backend.WriteTo(buf[:n], addr)
		}
	}()
	cert, err := dtlsdial.GenerateSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := dtls.ListenWithOptions("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")},
		dtls.WithCertificates(cert), dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
		dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
		dtls.WithConnectionIDGenerator(dtls.RandomCIDGenerator(8)))
	if err != nil {
		t.Fatal(err)
	}
	var sessions sessionRegistry
	cfg := &config.Server{Proxy: config.ProxyOpts{Mode: config.ProxyModeUDP, Connect: backend.LocalAddr().String()}}
	accepted := make(chan chan struct{}, 3)
	var wg sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			done := make(chan struct{})
			accepted <- done
			wg.Go(func() {
				defer close(done)
				handleAccepted(ctx, logx.Nop(), nil, conn, cfg, &sessions)
			})
		}
	}()
	t.Cleanup(func() { cancel(); _ = listener.Close(); <-acceptDone; wg.Wait() })
	peer, ok := listener.Addr().(*net.UDPAddr)
	if !ok {
		t.Fatal("expected UDP listener")
	}
	dial := func(stream uint32) (net.Conn, <-chan struct{}) {
		t.Helper()
		pc, err := lc.ListenPacket(ctx, "udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		dialer := &dtlsdial.Dialer{HandshakeTimeout: 3 * time.Second}
		conn, err := dialer.Dial(ctx, pc, peer)
		if err != nil {
			_ = pc.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close(); _ = pc.Close() })
		if err := clientsdb.WriteClientHello(conn, "reconnect-client", clientsdb.ModeUDP, stream); err != nil {
			t.Fatal(err)
		}
		select {
		case done := <-accepted:
			return conn, done
		case <-ctx.Done():
			t.Fatal("accept timeout")
			return nil, nil
		}
	}
	echo := func(conn net.Conn, payload string) {
		t.Helper()
		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write([]byte(payload)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 1600)
		n, err := conn.Read(buf)
		if err != nil || string(buf[:n]) != payload {
			t.Fatalf("echo=%q err=%v", buf[:n], err)
		}
		_ = conn.SetDeadline(time.Time{})
	}
	old, oldDone := dial(3)
	echo(old, "old-path")
	parallel, parallelDone := dial(4)
	echo(parallel, "parallel-path")
	next, _ := dial(3)
	echo(next, "new-relay-path")
	select {
	case <-oldDone:
	case <-ctx.Done():
		t.Fatal("old server handler stayed alive")
	}
	select {
	case <-parallelDone:
		t.Fatal("parallel stream was displaced")
	default:
	}
	echo(parallel, "parallel-still-live")
	echo(next, "new-still-live")
}
