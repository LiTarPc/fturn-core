// Package turndial manages bounded, cancellable TURN client connections.
package turndial

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/LiTarPc/fturn-core/internal/logx"
	"github.com/LiTarPc/fturn-core/internal/netconn"
	"github.com/LiTarPc/fturn-core/internal/netctl"
	"github.com/LiTarPc/fturn-core/internal/randx"
	"github.com/pion/turn/v5"
)

type Config struct {
	HostOverride, PortOverride string
	TransportUDP               bool
	DialTimeout                time.Duration
	Log                        logx.Logger
	StreamID                   int
}
type Stream struct {
	Relay         net.PacketConn
	ServerUDPAddr *net.UDPAddr
	PermDead      <-chan struct{}
	close         func() error
	cause         func() error
	deletion      func() string
}

func (s *Stream) Close() error {
	if s == nil || s.close == nil {
		return nil
	}
	return s.close()
}
func (s *Stream) Err() error {
	if s == nil || s.cause == nil {
		return nil
	}
	return s.cause()
}
func (s *Stream) DeletionStatus() string {
	if s == nil || s.deletion == nil {
		return "unknown"
	}
	return s.deletion()
}

type closeOncePacketConn struct {
	net.PacketConn
	once      sync.Once
	err       error
	closeFunc func() error
}

func (c *closeOncePacketConn) Close() error {
	c.once.Do(func() {
		if c.closeFunc != nil {
			c.err = c.closeFunc()
		} else {
			c.err = c.PacketConn.Close()
		}
	})
	return c.err
}

const setupTimeout = 20 * time.Second
const deletionTimeout = 900 * time.Millisecond

func Open(ctx context.Context, cfg Config, peer *net.UDPAddr, user, pass, rawAddr string) (_ *Stream, err error) {
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	setupCtx, cancel := context.WithTimeout(ctx, setupTimeout)
	defer cancel()
	host, port, err := net.SplitHostPort(rawAddr)
	if err != nil {
		return nil, fmt.Errorf("parse TURN addr: %w", err)
	}
	if cfg.HostOverride != "" {
		host = cfg.HostOverride
	}
	if cfg.PortOverride != "" {
		port = cfg.PortOverride
	}
	endpoint := net.JoinHostPort(host, port)
	release, err := turnAllocations.acquire(setupCtx, endpoint, user)
	if err != nil {
		return nil, err
	}
	defer func() { release(err) }()
	ip := net.ParseIP(host)
	if ip == nil {
		addresses, e := net.DefaultResolver.LookupIPAddr(setupCtx, host)
		if e != nil {
			return nil, fmt.Errorf("resolve TURN addr: %w", e)
		}
		if len(addresses) == 0 {
			return nil, fmt.Errorf("resolve TURN addr: no addresses")
		}
		ip = addresses[0].IP
	}
	numeric := net.JoinHostPort(ip.String(), port)
	serverAddr, err := net.ResolveUDPAddr("udp", numeric)
	if err != nil {
		return nil, fmt.Errorf("resolve TURN addr: %w", err)
	}
	dialTimeout := cfg.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = 5 * time.Second
	}
	dialCtx, dialCancel := context.WithTimeout(setupCtx, dialTimeout)
	defer dialCancel()
	transport := "tcp"
	if cfg.TransportUDP {
		transport = "udp"
	}
	raw, err := (&net.Dialer{Control: netctl.Apply}).DialContext(dialCtx, transport, numeric)
	if err != nil {
		return nil, fmt.Errorf("dial TURN (%s): %w", transport, err)
	}
	var pc net.PacketConn
	if cfg.TransportUDP {
		c, ok := raw.(*net.UDPConn)
		if !ok {
			_ = raw.Close()
			return nil, fmt.Errorf("TURN: expected UDP socket")
		}
		pc = &netconn.ConnectedUDPConn{UDPConn: c}
	} else {
		pc = turn.NewSTUNConn(&netconn.SplitFirstWriteConn{Conn: raw, SplitAt: 5 + randx.Intn(3), Delay: 20 * time.Millisecond})
	}
	var socketOnce sync.Once
	closeSocket := func() { socketOnce.Do(func() { _ = raw.Close() }) }
	var closing atomic.Bool
	var deadOnce sync.Once
	dead := make(chan struct{})
	var failure atomic.Pointer[error]
	markDead := func(e error) {
		if e != nil {
			failure.CompareAndSwap(nil, &e)
		}
		deadOnce.Do(func() { close(dead) })
	}
	renewal := &renewalWatch{onDead: markDead}
	af := turn.RequestedAddressFamilyIPv6
	if peer.IP.To4() != nil {
		af = turn.RequestedAddressFamilyIPv4
	}
	log := logx.OrNop(cfg.Log)
	client, err := turn.NewClient(&turn.ClientConfig{STUNServerAddr: numeric, TURNServerAddr: numeric, Conn: pc, Net: netconn.New(), Username: user, Password: pass, RequestedAddressFamily: af,
		PermissionRefreshInterval: 24 * time.Hour, BindingRefreshInterval: 2 * time.Minute, BindingCheckInterval: 10 * time.Second,
		LoggerFactory:       &logxFactory{log: log, stream: cfg.StreamID},
		OnAllocationRefresh: func(e error) { renewal.result(false, e) }, OnChannelBind: func(e error) { renewal.result(true, e) },
		OnListenerError: func(e error) {
			if !closing.Load() {
				markDead(fmt.Errorf("TURN receiver: %w", e))
				log.Warnf("[STREAM %d] TURN receiver stopped: server=%s transport=%s error=%v", cfg.StreamID, numeric, transport, e)
			}
		},
	})
	if err != nil {
		closeSocket()
		return nil, fmt.Errorf("create TURN client: %w", err)
	}
	abort := func() { closing.Store(true); closeSocket(); client.Close() }
	hookDone := make(chan struct{})
	stop := context.AfterFunc(setupCtx, func() { defer close(hookDone); abort() })
	transferred := false
	finishSetup := sync.OnceFunc(func() {
		if !stop() {
			<-hookDone
		}
	})
	defer func() {
		finishSetup()
		if !transferred {
			abort()
		}
	}()
	if err = client.Listen(); err != nil {
		return nil, fmt.Errorf("TURN listen: %w", err)
	}
	relay, err := client.Allocate()
	if err != nil {
		if setupCtx.Err() != nil {
			return nil, fmt.Errorf("TURN allocate: %w", setupCtx.Err())
		}
		return nil, fmt.Errorf("TURN allocate: %w", err)
	}
	if setupCtx.Err() != nil {
		_ = relay.Close()
		return nil, setupCtx.Err()
	}
	// Complete ownership transfer before cancelling the setup-only context.
	finishSetup()
	if setupCtx.Err() != nil {
		_ = relay.Close()
		return nil, setupCtx.Err()
	}
	var confirmed atomic.Bool
	shared := &closeOncePacketConn{PacketConn: relay}
	shared.closeFunc = func() error {
		closing.Store(true)
		closer, ok := relay.(interface{ CloseWithConfirmation() error })
		if !ok {
			return fmt.Errorf("TURN relay cannot confirm deletion")
		}
		deleteCtx, deleteCancel := context.WithTimeout(context.WithoutCancel(ctx), deletionTimeout)
		defer deleteCancel()
		finished := make(chan struct{})
		stopDelete := context.AfterFunc(deleteCtx, func() { defer close(finished); abort() })
		e := closer.CloseWithConfirmation()
		if !stopDelete() {
			<-finished
		}
		if deleteCtx.Err() != nil {
			return fmt.Errorf("TURN deletion unconfirmed: %w", deleteCtx.Err())
		}
		if e == nil {
			confirmed.Store(true)
		}
		return e
	}
	var closeOnce sync.Once
	var closeErr error
	stream := &Stream{Relay: shared, ServerUDPAddr: serverAddr, PermDead: dead, cause: func() error {
		if p := failure.Load(); p != nil {
			return *p
		}
		return nil
	}, deletion: func() string {
		if confirmed.Load() {
			return "confirmed"
		}
		return "unconfirmed"
	}}
	stream.close = func() error { closeOnce.Do(func() { closeErr = shared.Close(); abort() }); return closeErr }
	log.Infof("[STREAM %d] TURN server IP: %s", cfg.StreamID, serverAddr.IP)
	transferred = true
	return stream, nil
}
