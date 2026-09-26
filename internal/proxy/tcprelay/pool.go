// Package tcprelay реализует tcp-режим клиента: локальный TCP-listener, а каждое
// принятое соединение уходит отдельным smux-потоком в одну из сессий пула
// TURN+DTLS+KCP+smux (round-robin).
package tcprelay

import (
	"sync"
	"sync/atomic"

	"github.com/samosvalishe/free-turn-proxy/internal/stats"
	"github.com/xtaci/smux"
)

// muxSession - минимальный контракт smux-сессии, который нужен пулу и proxyConn.
// Интерфейс оставляет production-типом *smux.Session, но позволяет детерминированно
// тестировать stale session: IsClosed ещё false, а OpenStream уже возвращает ошибку.
type muxSession interface {
	OpenStream() (*smux.Stream, error)
	IsClosed() bool
	Close() error
}

// pooledSession - одна сессия TURN+DTLS+KCP+smux.
type pooledSession struct {
	id      int
	sess    muxSession
	traffic *stats.Stats
	active  atomic.Int32
}

// sessionPool - конкурентно-безопасный round-robin пул живых сессий.
type sessionPool struct {
	mu       sync.RWMutex
	sessions []*pooledSession
	counter  atomic.Uint64
	connID   atomic.Uint64

	// active - зеркало числа живых сессий для UI (те же "N/M", что и в udp-режиме).
	active *atomic.Int32

	readyOnce sync.Once
	ready     chan struct{}
}

func newSessionPool(active *atomic.Int32) *sessionPool {
	return &sessionPool{active: active, ready: make(chan struct{})}
}

// publishActive вызывать под p.mu.
func (p *sessionPool) publishActive() {
	if p.active != nil {
		p.active.Store(int32(len(p.sessions))) //nolint:gosec // сессий десятки, int32 не переполнить
	}
}

// Ready закрывается на первой поднявшейся сессии.
func (p *sessionPool) Ready() <-chan struct{} { return p.ready }

func (p *sessionPool) Add(id int, s muxSession, traffic *stats.Stats) *pooledSession {
	ps := &pooledSession{id: id, sess: s, traffic: traffic}
	p.mu.Lock()
	p.sessions = append(p.sessions, ps)
	p.publishActive()
	p.mu.Unlock()
	p.readyOnce.Do(func() { close(p.ready) })
	return ps
}

// Remove no-op, если ps не найден.
func (p *sessionPool) Remove(ps *pooledSession) {
	p.mu.Lock()
	for i, s := range p.sessions {
		if s == ps {
			p.sessions = append(p.sessions[:i], p.sessions[i+1:]...)
			break
		}
	}
	p.publishActive()
	p.mu.Unlock()
}

// Invalidate немедленно выводит сессию из ротации и закрывает её. Это важно для
// stale socket: smux.IsClosed может ещё быть false, хотя OpenStream уже получил RST.
// maintainSession позднее увидит закрытие и поднимет свежий TURN стек.
func (p *sessionPool) Invalidate(ps *pooledSession) bool {
	if ps == nil {
		return false
	}

	removed := false
	p.mu.Lock()
	for i, s := range p.sessions {
		if s == ps {
			p.sessions = append(p.sessions[:i], p.sessions[i+1:]...)
			removed = true
			break
		}
	}
	p.publishActive()
	p.mu.Unlock()

	_ = ps.sess.Close()
	return removed
}

// Pick - nil, если живых сессий нет.
func (p *sessionPool) Pick() *pooledSession {
	p.mu.RLock()
	defer p.mu.RUnlock()
	n := len(p.sessions)
	if n == 0 {
		return nil
	}
	for range n {
		ps := p.sessions[(p.counter.Add(1)-1)%uint64(n)]
		if !ps.sess.IsClosed() {
			return ps
		}
	}
	return nil
}

func (p *sessionPool) NextConnID() uint64 { return p.connID.Add(1) }

func (p *sessionPool) Count() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.sessions)
}

// CloseAll рвёт сессии, не трогая listener: рецикл не должен ронять локальный порт.
func (p *sessionPool) CloseAll() {
	p.mu.RLock()
	snapshot := make([]*pooledSession, len(p.sessions))
	copy(snapshot, p.sessions)
	p.mu.RUnlock()
	for _, ps := range snapshot {
		_ = ps.sess.Close()
	}
}
