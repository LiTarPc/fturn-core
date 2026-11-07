package mobile

import (
	"strings"
	"testing"
)

func TestStartRefusesUnfinishedPreviousGeneration(t *testing.T) {
	Stop()
	old := &live{done: make(chan struct{})}
	finishing.Store(old)
	defer finishing.Store(nil)
	err := Start(DefaultConfigJSON())
	if err == nil || !strings.Contains(err.Error(), "still stopping") {
		t.Fatalf("Start=%v", err)
	}
	close(old.done)
	// Once stopped, configuration validation must be reached instead of the fence.
	err = Start(`{}`)
	if err == nil || strings.Contains(err.Error(), "still stopping") {
		t.Fatalf("finished generation still fences Start: %v", err)
	}
}
