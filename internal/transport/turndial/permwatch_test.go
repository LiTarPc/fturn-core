package turndial

import (
	"sync/atomic"
	"testing"

	"github.com/pion/logging"
)

func newTestWatch(threshold int) (*permWatchFactory, *atomic.Int32) {
	var fired atomic.Int32
	f := &permWatchFactory{
		inner:     logging.NewDefaultLoggerFactory(),
		threshold: threshold,
		onDead:    func() { fired.Add(1) },
	}
	return f, &fired
}

func TestPermWatchFiresAfterThreshold(t *testing.T) {
	f, fired := newTestWatch(2)
	log := f.NewLogger(turncScope)

	log.Warnf(permFailMarker+": %s", "boom")
	if fired.Load() != 0 {
		t.Fatalf("fired too early after 1 fail: %d", fired.Load())
	}
	log.Warnf(permFailMarker+": %s", "boom")
	if fired.Load() != 1 {
		t.Fatalf("expected 1 fire after threshold, got %d", fired.Load())
	}
	log.Warnf(permFailMarker+": %s", "boom")
	if fired.Load() != 1 {
		t.Fatalf("fired more than once: %d", fired.Load())
	}
}

func TestPermWatchRecyclesAfterRepeatedSavedBinding400(t *testing.T) {
	f, fired := newTestWatch(2)
	log := f.NewLogger(turncScope)

	msg := permSavedBind400Marker + " %s on channel %d; keeping binding ready"
	log.Warnf(msg, "192.0.2.1:56660", 16384)
	if fired.Load() != 0 {
		t.Fatalf("fired too early after first 400: %d", fired.Load())
	}
	log.Warnf(msg, "192.0.2.1:56660", 16384)
	if fired.Load() != 1 {
		t.Fatalf("expected recycle after repeated 400, got %d", fired.Load())
	}
	log.Warnf(msg, "192.0.2.1:56660", 16384)
	if fired.Load() != 1 {
		t.Fatalf("recycled more than once: %d", fired.Load())
	}
}

func TestPermWatchResetOnSuccess(t *testing.T) {
	f, fired := newTestWatch(2)
	log := f.NewLogger(turncScope)

	log.Warnf(permFailMarker + ": x")
	log.Debug(permOKMarker)
	log.Warnf(permFailMarker + ": x")
	if fired.Load() != 0 {
		t.Fatalf("reset failed: fired=%d (fail/ok/fail не должно фаерить)", fired.Load())
	}
}

func TestPermWatchIgnoresOtherScopes(t *testing.T) {
	f, fired := newTestWatch(1)
	log := f.NewLogger("other")
	if _, ok := log.(*permWatchLogger); ok {
		t.Fatal("non-turnc scope must not be wrapped")
	}
	log.Warnf(permFailMarker)
	if fired.Load() != 0 {
		t.Fatalf("fired on non-turnc scope: %d", fired.Load())
	}
}

func TestPermWatchIgnoresUnrelatedMessages(t *testing.T) {
	f, fired := newTestWatch(1)
	log := f.NewLogger(turncScope)
	log.Debug("Started refresh permission timer")
	log.Debug("No permission to refresh")
	log.Warnf("Unrelated allocation warning: %s", "x")
	if fired.Load() != 0 {
		t.Fatalf("fired on unrelated message: %d", fired.Load())
	}
}

func TestAllocationRefreshFailuresAreIndependent(t *testing.T) {
	f, fired := newTestWatch(2)
	log := f.NewLogger(turncScope)
	log.Warnf("%s: %s", "Failed to refresh allocation", "437")
	log.Debug(permOKMarker) // ChannelBind success cannot restore the allocation.
	log.Warnf("Failed to refresh allocation: %s", "437")
	if fired.Load() != 1 {
		t.Fatalf("allocation failures did not recycle: %d", fired.Load())
	}
}

func TestAllocationRefreshSuccessResetsFailures(t *testing.T) {
	f, fired := newTestWatch(2)
	log := f.NewLogger(turncScope)
	log.Warn("Failed to refresh allocation: timeout")
	log.Debugf("Updated lifetime: %d seconds", 600)
	log.Warn("Failed to refresh allocation: timeout")
	if fired.Load() != 0 {
		t.Fatalf("successful refresh did not reset failures: %d", fired.Load())
	}
}
