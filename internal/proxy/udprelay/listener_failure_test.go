package udprelay

import (
	"context"
	"errors"
	"github.com/LiTarPc/fturn-core/internal/logx"
	"github.com/LiTarPc/fturn-core/internal/transport/dtlsdial"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type failedListener struct {
	net.PacketConn
	err error
}

func (c *failedListener) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, c.err }
func (*failedListener) SetReadDeadline(time.Time) error          { return nil }
func TestRunSurfacesUnexpectedListenerFailure(t *testing.T) {
	failure := errors.New("simulated UDP read failure")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var active atomic.Int32
	params := &Params{Profile: "none", GetCreds: func(ctx context.Context, _ int) (string, string, []string, error) {
		<-ctx.Done()
		return "", "", nil, ctx.Err()
	}}
	err := Run(ctx, &dtlsdial.Dialer{HandshakeTimeout: time.Second}, nil, logx.Nop(), &active, nil, params, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}, &failedListener{err: failure}, 1)
	if !errors.Is(err, failure) || !errors.Is(err, ErrFatal) {
		t.Fatalf("listener failure was hidden: %v", err)
	}
}
