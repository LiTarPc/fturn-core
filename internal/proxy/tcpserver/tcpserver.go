// Package tcpserver - серверная сторона tcp-режима: KCP+smux поверх DTLS, каждый
// smux-поток форвардится в локальный TCP backend.
package tcpserver

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/samosvalishe/free-turn-proxy/internal/logx"
	"github.com/samosvalishe/free-turn-proxy/internal/transport/kcpmux"
	"github.com/xtaci/smux"
)

const backendDialTimeout = 10 * time.Second

// Handle блокирует вызывающую горутину до закрытия сессии клиентом или ctx.
func Handle(ctx context.Context, logger logx.Logger, dtlsConn net.Conn, connectAddr string, profile kcpmux.Profile) {
	kcpSess, err := kcpmux.Accept(dtlsConn, profile)
	if err != nil {
		logger.Errorf("tcpserver: %s", err)
		return
	}
	defer func() {
		if closeErr := kcpSess.Close(); closeErr != nil {
			logger.Warnf("tcpserver: close KCP session: %v", closeErr)
		}
	}()

	smuxSess, err := smux.Server(kcpSess, kcpmux.ServerSmuxConfig())
	if err != nil {
		logger.Errorf("tcpserver: smux server: %s", err)
		return
	}
	defer func() {
		if closeErr := smuxSess.Close(); closeErr != nil {
			logger.Warnf("tcpserver: close smux session: %v", closeErr)
		}
	}()
	logger.Debugf("tcpserver: smux session established")

	// ctx живёт всё время процесса - без stop() хук копился бы на каждую сессию.
	stopOnCancel := context.AfterFunc(ctx, func() { _ = smuxSess.Close() })
	defer stopOnCancel()

	var wg sync.WaitGroup
	for {
		stream, err := smuxSess.AcceptStream()
		if err != nil {
			if ctx.Err() == nil {
				logger.Debugf("tcpserver: smux accept: %s", err)
			}
			break
		}
		wg.Go(func() { handleStream(ctx, logger, stream, connectAddr) })
	}
	wg.Wait()
}

func handleStream(ctx context.Context, logger logx.Logger, s *smux.Stream, connectAddr string) {
	defer func() {
		if err := s.Close(); err != nil && err != smux.ErrGoAway {
			logger.Warnf("tcpserver: close smux stream: %v", err)
		}
	}()

	backend, err := (&net.Dialer{Timeout: backendDialTimeout}).DialContext(ctx, "tcp", connectAddr)
	if err != nil {
		logger.Errorf("tcpserver: backend dial %s: %s", connectAddr, err)
		return
	}
	defer func() {
		if closeErr := backend.Close(); closeErr != nil {
			logger.Warnf("tcpserver: close backend connection: %v", closeErr)
		}
	}()

	// Go включает TCP_NODELAY для TCP-сокетов по умолчанию; фиксируем это явно как
	// требование low-latency server->backend пути, чтобы оно не зависело от dialer/обёрток.
	if tcp, ok := backend.(*net.TCPConn); ok {
		if nerr := tcp.SetNoDelay(true); nerr != nil {
			logger.Debugf("tcpserver: backend TCP_NODELAY: %v", nerr)
		}
	}

	relayHalfClose(ctx, s, backend, logger.Debugf)
}

// relayHalfClose копирует TCP-поток в обе стороны, сохраняя семантику half-close.
// EOF в одном направлении означает FIN только для записи противоположной стороны;
// второе направление продолжает работать и может доставить поздний ответ backend.
// При реальной ошибке или отмене ctx оба copy принудительно будятся дедлайном.
func relayHalfClose(ctx context.Context, left, right net.Conn, errf func(format string, v ...any)) {
	setDeadline := func(t time.Time, what string) {
		if err := left.SetDeadline(t); err != nil && errf != nil {
			errf("tcpserver: left %s: %v", what, err)
		}
		if err := right.SetDeadline(t); err != nil && errf != nil {
			errf("tcpserver: right %s: %v", what, err)
		}
	}

	var abortOnce sync.Once
	abort := func() {
		abortOnce.Do(func() { setDeadline(time.Now(), "abort deadline") })
	}

	hookDone := make(chan struct{})
	stopOnCancel := context.AfterFunc(ctx, func() {
		defer close(hookDone)
		abort()
	})

	copySide := func(dst, src net.Conn, direction string) {
		_, err := io.Copy(dst, src)
		if err != nil {
			if ctx.Err() == nil && errf != nil {
				errf("tcpserver: %s copy: %v", direction, err)
			}
			abort()
			return
		}

		closer, ok := dst.(interface{ CloseWrite() error })
		if !ok {
			if errf != nil {
				errf("tcpserver: %s destination %T has no CloseWrite", direction, dst)
			}
			abort()
			return
		}
		if err := closer.CloseWrite(); err != nil {
			if ctx.Err() == nil && errf != nil {
				errf("tcpserver: %s CloseWrite: %v", direction, err)
			}
			abort()
		}
	}

	var wg sync.WaitGroup
	wg.Go(func() { copySide(left, right, "stream<-backend") })
	wg.Go(func() { copySide(right, left, "backend<-stream") })
	wg.Wait()

	if !stopOnCancel() {
		<-hookDone
	}
	setDeadline(time.Time{}, "clear deadline")
}
