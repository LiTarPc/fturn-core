package turndial

import (
	"fmt"
	"sync"
)

// renewalWatch consumes typed Pion outcomes, independent of logger wording.
type renewalWatch struct {
	mu                  sync.Mutex
	allocation, binding int
	fired               bool
	onDead              func(error)
}

func (w *renewalWatch) result(binding bool, err error) {
	w.mu.Lock()
	count := &w.allocation
	stage := "allocation_refresh"
	if binding {
		count = &w.binding
		stage = "channel_bind"
	}
	if err == nil {
		*count = 0
	} else {
		*count++
	}
	fire := !w.fired && *count >= permFailThreshold
	if fire {
		w.fired = true
	}
	w.mu.Unlock()
	if fire && w.onDead != nil {
		w.onDead(fmt.Errorf("TURN %s failed repeatedly: %w", stage, err))
	}
}
