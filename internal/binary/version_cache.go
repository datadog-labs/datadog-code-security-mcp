package binary

import (
	"context"
	"sync"
	"time"
)

const versionProbeTimeout = 2 * time.Second

type binaryVersionTarget struct {
	name       string
	binaryType BinaryType
}

func binaryVersionTargets() []binaryVersionTarget {
	targets := make([]binaryVersionTarget, 0, len(BinaryConfigs))
	for binaryType, config := range BinaryConfigs {
		targets = append(targets, binaryVersionTarget{
			name:       config.TelemetryKey,
			binaryType: binaryType,
		})
	}
	return targets
}

type binaryVersionGetter func(context.Context, BinaryType) string

// BinaryVersionCache collects scanner versions once per process. Probes run in
// parallel and are bounded independently so telemetry never delays normal work
// by more than the caller's wait timeout.
type BinaryVersionCache struct {
	ctx    context.Context
	cancel context.CancelFunc

	mu       sync.RWMutex
	versions map[string]string
	started  bool
	closed   bool
	done     chan struct{}
	wg       sync.WaitGroup

	getVersion binaryVersionGetter
}

func NewBinaryVersionCache() *BinaryVersionCache {
	return newBinaryVersionCache(func(ctx context.Context, binaryType BinaryType) string {
		return NewManager(binaryType).GetVersion(ctx)
	})
}

func newBinaryVersionCache(getVersion binaryVersionGetter) *BinaryVersionCache {
	ctx, cancel := context.WithCancel(context.Background())
	return &BinaryVersionCache{
		ctx:        ctx,
		cancel:     cancel,
		versions:   make(map[string]string),
		done:       make(chan struct{}),
		getVersion: getVersion,
	}
}

// Refresh starts the process-local probe batch. Repeated calls are no-ops.
func (c *BinaryVersionCache) Refresh() {
	if c == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.started || c.closed {
		return
	}
	c.started = true

	for _, target := range binaryVersionTargets() {
		c.wg.Add(1)
		go c.probe(target)
	}
	// A single waiter closes done once every probe finishes; wg is the only
	// completion signal, so there is no separate counter to keep in sync.
	go func() {
		c.wg.Wait()
		close(c.done)
	}()
}

func (c *BinaryVersionCache) probe(target binaryVersionTarget) {
	defer c.wg.Done()

	ctx, cancel := context.WithTimeout(c.ctx, versionProbeTimeout)
	defer cancel()
	version := c.getVersion(ctx, target.binaryType)
	if version == "" {
		version = "unknown"
	}

	c.mu.Lock()
	if !c.closed {
		c.versions[target.name] = version
	}
	c.mu.Unlock()
}

// Snapshot returns every scanner key. Probes still in flight are "unknown".
func (c *BinaryVersionCache) Snapshot() map[string]string {
	if c == nil {
		return map[string]string{}
	}
	c.mu.RLock()
	defer c.mu.RUnlock()

	versions := make(map[string]string, len(BinaryConfigs))
	for _, target := range binaryVersionTargets() {
		versions[target.name] = "unknown"
	}
	for name, version := range c.versions {
		versions[name] = version
	}
	return versions
}

// SnapshotAfterInitial waits for the probe batch or context cancellation.
func (c *BinaryVersionCache) SnapshotAfterInitial(ctx context.Context) map[string]string {
	if c == nil {
		return map[string]string{}
	}
	c.Refresh()
	select {
	case <-c.done:
	case <-ctx.Done():
	}
	return c.Snapshot()
}

// Close cancels active probes and waits for their child processes to exit.
func (c *BinaryVersionCache) Close() {
	if c == nil {
		return
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	if !c.started {
		c.started = true
		close(c.done)
	}
	c.cancel()
	c.mu.Unlock()
	c.wg.Wait()
}
