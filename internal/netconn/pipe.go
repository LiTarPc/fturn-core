package netconn

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// BiCopy preserves TCP half-close: EOF ends only the opposite write direction.
// Connections without CloseWrite retain the previous full-cancellation behavior.
func BiCopy(ctx context.Context, c1, c2 net.Conn, errf func(string, ...any)) (int64, int64) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	setDeadline := func(t time.Time) {
		for _, c := range []net.Conn{c1, c2} {
			if err := c.SetDeadline(t); err != nil && errf != nil {
				errf("BiCopy: deadline: %v", err)
			}
		}
	}
	hookDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(hookDone); setDeadline(time.Now()) })
	copySide := func(dst, src net.Conn) int64 {
		n, err := io.Copy(dst, src)
		if err != nil && !errors.Is(err, io.EOF) {
			if errf != nil {
				errf("BiCopy: copy: %v", err)
			}
			cancel()
			return n
		}
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			if err = cw.CloseWrite(); err == nil {
				return n
			}
			if errf != nil {
				errf("BiCopy: CloseWrite: %v", err)
			}
		}
		cancel()
		return n
	}
	var wg sync.WaitGroup
	var a, b int64
	wg.Go(func() { a = copySide(c1, c2) })
	wg.Go(func() { b = copySide(c2, c1) })
	wg.Wait()
	if !stop() {
		<-hookDone
	}
	setDeadline(time.Time{})
	return a, b
}
