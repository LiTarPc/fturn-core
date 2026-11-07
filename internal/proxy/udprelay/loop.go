package udprelay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/LiTarPc/fturn-core/internal/clientsdb"
	"github.com/LiTarPc/fturn-core/internal/netconn"
	"github.com/LiTarPc/fturn-core/internal/provider"
	"github.com/LiTarPc/fturn-core/internal/randx"
	"github.com/LiTarPc/fturn-core/internal/transport/limits"
	"github.com/LiTarPc/fturn-core/internal/transport/turndial"
	"github.com/LiTarPc/fturn-core/internal/wire"
	"github.com/LiTarPc/fturn-core/internal/wire/shape"
)

// errPairRecycled - пару свернул TURN-цикл (аллокация мертва), а не сеть: сетевой
// backoff тут только удлиняет простой.
var errPairRecycled = errors.New("udprelay: stream pair recycled")

// streamPair связывает DTLS-сессию с аллокацией, поверх которой она поднята. Смерть
// аллокации обязана ронять DTLS: у новой аллокации другой relayed-адрес, а миграция
// адреса по DTLS Connection ID под obf-профилем на сервере не работает - сервер примет
// такие записи за новую сессию и будет ждать от них handshake.
type streamPair struct {
	pipe   net.PacketConn
	cancel context.CancelFunc
}

// DTLSLoop поддерживает и перезапускает DTLS-соединение для указанного streamID.
func DTLSLoop(ctx context.Context, deps *Deps, params *Params, peer *net.UDPAddr, listenConn net.PacketConn, inboundChan <-chan *Packet, connchan chan<- streamPair, okchan chan<- struct{}, streamID int) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			err := oneDTLS(ctx, deps, params, peer, listenConn, inboundChan, connchan, okchan, streamID)
			// Пара пересоздаётся под новую аллокацию - TURN-цикл уже держит свою паузу.
			if errors.Is(err, errPairRecycled) {
				continue
			}
			if err != nil && time.Now().Unix() < deps.auth().BackoffUntilUnix() && errors.Is(err, context.DeadlineExceeded) {
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Duration(1+randx.Intn(2)) * time.Second):
				}
				continue
			}
			if err != nil {
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Duration(10+randx.Intn(20)) * time.Second):
				}
			}
		}
	}
}

// TURNLoop управляет жизненным циклом одной TURN-аллокации.
func TURNLoop(ctx context.Context, deps *Deps, params *Params, peer *net.UDPAddr, connchan <-chan streamPair, streamID int) {
	for {
		var pair streamPair
		select {
		case <-ctx.Done():
			return
		case pair = <-connchan:
		}
		if !deps.allocPace.Wait(ctx) {
			pair.cancel()
			return
		}
		err := oneTURN(ctx, deps, params, peer, pair.pipe, streamID)
		pair.cancel()
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, provider.ErrFatalNoStreams) {
			deps.fatal(err)
			return
		}
		delay := 2 * time.Second
		if d := turndial.RetryAfter(err); d > 0 {
			delay = d + time.Duration(randx.Intn(2000))*time.Millisecond
			if params.OnBackoff != nil {
				params.OnBackoff(time.Now().Add(delay))
			}
		}
		if errors.Is(err, provider.ErrBackoffActive) {
			delay = 60 * time.Second
			if until := deps.auth().BackoffUntilUnix(); until > 0 {
				delay = max(time.Until(time.Unix(until, 0)), 5*time.Second)
			}
		}
		deps.log().Warnf("[STREAM %d] UDP TURN cycle ended: cause=%v retry_in=%s", streamID, err, delay)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func oneDTLS(ctx context.Context, deps *Deps, params *Params, peer *net.UDPAddr, listenConn net.PacketConn, inboundChan <-chan *Packet, connchan chan<- streamPair, okchan chan<- struct{}, streamID int) error {
	dtlsctx, dtlscancel := context.WithCancel(ctx)
	defer dtlscancel()

	err := dtlsSession(dtlsctx, dtlscancel, deps, params, peer, listenConn, inboundChan, connchan, okchan, streamID)
	// Отменена именно пара, а не вся сессия - значит её свернул TURN-цикл.
	if err != nil && ctx.Err() == nil && dtlsctx.Err() != nil {
		return errPairRecycled
	}
	return err
}

func dtlsSession(dtlsctx context.Context, dtlscancel context.CancelFunc, deps *Deps, params *Params, peer *net.UDPAddr, listenConn net.PacketConn, inboundChan <-chan *Packet, connchan chan<- streamPair, okchan chan<- struct{}, streamID int) error {
	select {
	case <-time.After(time.Duration(randx.Intn(400)+100) * time.Millisecond):
	case <-dtlsctx.Done():
		return dtlsctx.Err()
	}

	conn1, conn2 := netconn.PacketPipe(limits.Datagram, 256)
	stopPipe := context.AfterFunc(dtlsctx, func() { _ = conn1.Close(); _ = conn2.Close() })
	defer stopPipe()
	defer func() { _ = conn1.Close() }()
	defer func() { _ = conn2.Close() }()
	// Ровно один раз: пара строго 1:1, иначе следующая аллокация села бы на DTLS, который
	// уже сворачивают. Отдаём до handshake - его пакеты идут через эту же аллокацию.
	select {
	case connchan <- streamPair{pipe: conn2, cancel: dtlscancel}:
	case <-dtlsctx.Done():
		return dtlsctx.Err()
	}
	dtlsRaw, err1 := deps.DTLSDialer.Dial(dtlsctx, conn1, peer)
	if err1 != nil {
		return fmt.Errorf("failed to connect DTLS: %w", err1)
	}
	var dtlsConn net.Conn = dtlsRaw
	defer func() {
		_ = dtlsConn.Close()
		deps.log().Infof("[STREAM %d] Closed DTLS connection", streamID)
	}()

	if err := clientsdb.WriteClientStream(dtlsConn, params.ClientID, clientsdb.ModeUDP, streamID); err != nil {
		return fmt.Errorf("failed to write client ID: %w", err)
	}
	if deps.ConnectedStreams != nil {
		deps.ConnectedStreams.Add(1)
		defer deps.ConnectedStreams.Add(-1)
	}
	deps.auth().ResetErrors(streamID)
	deps.log().Infof("[STREAM %d] Established DTLS connection: client hello sent; stream is ready", streamID)
	if okchan != nil {
		select {
		case okchan <- struct{}{}:
		default:
		}
	}

	forwardDone := make(chan struct{})
	forwardError := make(chan error, 1)
	defer func() { _ = dtlsConn.Close(); <-forwardDone }()
	go func() {
		defer close(forwardDone)
		var buf [2048]byte
		for {
			n, err := dtlsConn.Read(buf[:])
			if err != nil {
				forwardError <- fmt.Errorf("DTLS receive: %w", err)
				return
			}
			addr := deps.ActiveLocalPeer.Load()
			if addr == nil {
				continue
			}
			netAddr, ok := addr.(net.Addr)
			if !ok {
				continue
			}
			_, writeErr := listenConn.WriteTo(buf[:n], netAddr)
			if writeErr != nil {
				forwardError <- fmt.Errorf("local UDP write: %w", writeErr)
				return
			}
		}
	}()

	for {
		select {
		case <-dtlsctx.Done():
			return dtlsctx.Err()
		case <-forwardDone:
			select {
			case err := <-forwardError:
				return err
			default:
				return errors.New("DTLS receiver stopped")
			}
		case pkt := <-inboundChan:
			_, err := dtlsConn.Write(pkt.Data[:pkt.N])
			packetPool.Put(pkt)
			if err != nil {
				return fmt.Errorf("failed to forward packet to DTLS: %w", err)
			}
		}
	}
}

// oneTURN owns all forwarding goroutines until they have stopped and the
// allocation has received a bounded deletion attempt.
func oneTURN(ctx context.Context, deps *Deps, params *Params, peer *net.UDPAddr, pipe net.PacketConn, streamID int) (err error) {
	stream, err := DialTURN(ctx, params.Host, params.Port, params.TransportUDP, peer, streamID, params.GetCreds, deps.log())
	if err != nil {
		if deps.auth().IsAuthError(err) {
			deps.auth().HandleAuthError(streamID)
		}
		return fmt.Errorf("connect to TURN: %w", err)
	}
	relay := stream.Relay
	if deps.OnTURNServer != nil {
		deps.OnTURNServer(stream.ServerUDPAddr.IP)
	}
	if params.ObfTiming > 0 {
		relay = shape.WrapPacketConn(relay, params.ObfTiming)
	}
	address := relay.LocalAddr().String()
	started := time.Now()
	deps.log().Infof("[STREAM %d] TURN allocated: relayed=%s server=%s; waiting for DTLS", streamID, address, stream.ServerUDPAddr)
	defer func() {
		closeErr := stream.Close()
		deps.log().Infof("[STREAM %d] TURN closed: relayed=%s age=%s cause=%v delete_status=%s delete_error=%v", streamID, address, time.Since(started).Round(time.Millisecond), err, stream.DeletionStatus(), closeErr)
	}()
	codec, err := wire.NewClientCodec(params.Profile, params.ObfKey)
	if err != nil {
		return fmt.Errorf("obf init: %w", err)
	}
	turnCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	hookDone := make(chan struct{})
	stop := context.AfterFunc(turnCtx, func() { defer close(hookDone); _ = relay.SetDeadline(time.Now()); _ = pipe.SetDeadline(time.Now()) })
	defer func() {
		if !stop() {
			<-hookDone
		}
		_ = relay.SetDeadline(time.Time{})
		_ = pipe.SetDeadline(time.Time{})
	}()
	fail := func(stage string, e error) {
		if e != nil {
			cancel(fmt.Errorf("%s: %w", stage, e))
		}
	}
	var internalPeer atomic.Value
	var wg sync.WaitGroup
	wg.Go(func() {
		select {
		case <-turnCtx.Done():
		case <-stream.PermDead:
			e := stream.Err()
			if e == nil {
				e = errors.New("TURN renewal failed")
			}
			fail("TURN lifecycle", e)
		}
	})
	wg.Go(func() {
		defer cancel(errors.New("TURN outbound worker stopped"))
		size := limits.Datagram
		if codec != nil {
			size = codec.MaxWire(limits.Datagram)
		}
		buf := make([]byte, size)
		slot := buf
		if codec != nil {
			slot = buf[codec.HeaderLen() : codec.HeaderLen()+limits.Datagram]
		}
		for turnCtx.Err() == nil {
			n, addr, e := pipe.ReadFrom(slot)
			if e != nil {
				fail("DTLS-to-TURN read", e)
				return
			}
			if internalPeer.Load() == nil {
				internalPeer.Store(addr)
			}
			packet := slot[:n]
			if codec != nil {
				n, e = codec.WrapInPlace(buf, n)
				if e != nil {
					fail("obf wrap", e)
					return
				}
				packet = buf[:n]
			}
			n, e = relay.WriteTo(packet, peer)
			if params.TrafficStats != nil {
				params.TrafficStats.AddTx(n)
			}
			if e != nil {
				fail("TURN write", e)
				return
			}
		}
	})
	wg.Go(func() {
		defer cancel(errors.New("TURN inbound worker stopped"))
		size := limits.Datagram
		if codec != nil {
			size = codec.MaxWire(size)
		}
		buf := make([]byte, size)
		for turnCtx.Err() == nil {
			n, _, e := relay.ReadFrom(buf)
			if e != nil {
				fail("TURN read", e)
				return
			}
			addr := internalPeer.Load()
			if addr == nil {
				continue
			}
			packet := buf[:n]
			if codec != nil {
				packet, e = codec.UnwrapInPlace(packet)
				if e != nil {
					deps.log().Debugf("[STREAM %d] Dropping invalid obf datagram: %v", streamID, e)
					continue
				}
			}
			if params.TrafficStats != nil {
				params.TrafficStats.AddRx(len(packet))
			}
			destination, ok := addr.(net.Addr)
			if !ok {
				fail("TURN-to-DTLS address", errors.New("invalid pipe address"))
				return
			}
			if _, e = pipe.WriteTo(packet, destination); e != nil {
				fail("TURN-to-DTLS write", e)
				return
			}
		}
	})
	wg.Wait()
	return context.Cause(turnCtx)
}
