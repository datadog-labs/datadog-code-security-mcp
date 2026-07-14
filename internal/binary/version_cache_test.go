package binary

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestBinaryVersionCacheCollectsAllVersionsConcurrently(t *testing.T) {
	release := make(chan struct{})
	started := make(chan BinaryType, len(BinaryConfigs))
	cache := newBinaryVersionCache(func(_ context.Context, binaryType BinaryType) string {
		started <- binaryType
		<-release
		return "1.2.3"
	})
	t.Cleanup(cache.Close)

	cache.Refresh()
	for range BinaryConfigs {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("version probes did not start concurrently")
		}
	}
	close(release)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	snapshot := cache.SnapshotAfterInitial(ctx)
	for _, config := range BinaryConfigs {
		if got := snapshot[config.TelemetryKey]; got != "1.2.3" {
			t.Errorf("%s = %q, want 1.2.3", config.TelemetryKey, got)
		}
	}
}

func TestBinaryVersionCacheProbesOnlyOnce(t *testing.T) {
	var calls atomic.Int32
	cache := newBinaryVersionCache(func(context.Context, BinaryType) string {
		calls.Add(1)
		return "1.2.3"
	})
	t.Cleanup(cache.Close)

	cache.Refresh()
	cache.Refresh()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cache.SnapshotAfterInitial(ctx)
	cache.Refresh()

	if got, want := int(calls.Load()), len(BinaryConfigs); got != want {
		t.Fatalf("probe calls = %d, want %d", got, want)
	}
}

func TestBinaryVersionCacheSnapshotIsCompleteAndDefensive(t *testing.T) {
	cache := newBinaryVersionCache(func(ctx context.Context, _ BinaryType) string {
		<-ctx.Done()
		return "unknown"
	})
	t.Cleanup(cache.Close)
	cache.Refresh()

	first := cache.Snapshot()
	for _, config := range BinaryConfigs {
		if got := first[config.TelemetryKey]; got != "unknown" {
			t.Errorf("%s = %q, want unknown while probe is pending", config.TelemetryKey, got)
		}
	}
	for key := range first {
		first[key] = "mutated"
	}
	second := cache.Snapshot()
	for key, got := range second {
		if got == "mutated" {
			t.Errorf("snapshot mutation leaked for %s", key)
		}
	}
}

func TestBinaryVersionCacheCloseCancelsProbes(t *testing.T) {
	started := make(chan struct{}, len(BinaryConfigs))
	cache := newBinaryVersionCache(func(ctx context.Context, _ BinaryType) string {
		started <- struct{}{}
		<-ctx.Done()
		return "unknown"
	})
	cache.Refresh()
	for range BinaryConfigs {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("version probe did not start")
		}
	}

	done := make(chan struct{})
	go func() {
		cache.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel active probes")
	}
}
