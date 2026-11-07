// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package client

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPeriodicTimer(t *testing.T) {
	t.Run("basic", func(t *testing.T) {
		timerID := 3
		var nCbs uint64
		rt := NewPeriodicTimer(timerID, func(id int) {
			atomic.AddUint64(&nCbs, 1)
			assert.Equal(t, timerID, id)
		}, 50*time.Millisecond)

		assert.False(t, rt.IsRunning(), "should not be running yet")

		ok := rt.Start()
		assert.True(t, ok, "should be true")
		assert.True(t, rt.IsRunning(), "should be running")

		time.Sleep(100 * time.Millisecond)

		ok = rt.Start()
		assert.False(t, ok, "start again is noop")

		// Scheduling under load may delay ticks; verify behavior without assuming
		// that exactly four wall-clock ticks have run after a fixed sleep.
		assert.Eventually(t, func() bool { return atomic.LoadUint64(&nCbs) >= 4 }, 2*time.Second, 10*time.Millisecond)
		rt.Stop()
		assert.False(t, rt.IsRunning(), "should not be running")
		stopped := atomic.LoadUint64(&nCbs)
		time.Sleep(120 * time.Millisecond)
		assert.Equal(t, stopped, atomic.LoadUint64(&nCbs), "callbacks continued after Stop")
	})

	t.Run("stop inside handler", func(t *testing.T) {
		timerID := 4
		var rt *PeriodicTimer
		rt = NewPeriodicTimer(timerID, func(id int) {
			assert.Equal(t, timerID, id)
			rt.Stop()
		}, 20*time.Millisecond)

		assert.False(t, rt.IsRunning(), "should not be running yet")

		ok := rt.Start()
		assert.True(t, ok, "should be true")
		assert.True(t, rt.IsRunning(), "should be running")
		time.Sleep(30 * time.Millisecond)
		assert.False(t, rt.IsRunning(), "should not be running")
	})
}
