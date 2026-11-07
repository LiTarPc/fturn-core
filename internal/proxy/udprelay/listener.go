package udprelay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/LiTarPc/fturn-core/internal/logx"
	"github.com/LiTarPc/fturn-core/internal/transport/limits"
)

const inboundQueueCap = 2000

type Packet struct {
	Data []byte
	N    int
}

var packetPool = sync.Pool{New: func() any { return &Packet{Data: make([]byte, limits.UDPApplication)} }}

// Read a complete UDP datagram before enforcing the relay limit. On Windows,
// reading an oversized datagram into a small buffer otherwise returns WSAEMSGSIZE.
func runListener(ctx context.Context, conn net.PacketConn, active *atomic.Value, queue chan<- *Packet, logs ...logx.Logger) error {
	log := logx.Nop()
	if len(logs) > 0 {
		log = logx.OrNop(logs[0])
	}
	buf := make([]byte, 65535)
	var last string
	var dropped uint64
	noteDrop := func(reason string) {
		dropped++
		if dropped == 1 || dropped&(dropped-1) == 0 {
			log.Warnf("UDP listener: dropped=%d reason=%s max_payload=%d", dropped, reason, limits.UDPApplication)
		}
	}
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, syscall.EMSGSIZE) {
				noteDrop("oversized datagram")
				continue
			}
			return fmt.Errorf("UDP listener read: %w", err)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if n > limits.UDPApplication {
			noteDrop("oversized datagram")
			continue
		}
		if addr == nil {
			continue
		}
		if s := addr.String(); s != last {
			active.Store(addr)
			last = s
		}
		pkt := packetPool.Get().(*Packet)
		pkt.N = copy(pkt.Data, buf[:n])
		select {
		case queue <- pkt:
		default:
			packetPool.Put(pkt)
			noteDrop("inbound queue full")
		}
	}
}
