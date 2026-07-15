package main

import (
	"context"
	"time"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/binary"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/telemetry"
)

// versionWaitTimeout bounds how long an event will wait for the once-per-process
// scanner version probes to finish. Both CLI and MCP paths wait: probes start at
// process boot, so by the time a scan completes they are almost always done and
// the wait returns immediately. The bound only matters for events emitted very
// early (e.g. server_start), where it caps the delay rather than shipping
// "unknown" versions.
const versionWaitTimeout = 2500 * time.Millisecond

// scannerVersionCache is owned by the process command lifecycle.
var scannerVersionCache *binary.BinaryVersionCache

func binaryVersionsForEvent(ctx context.Context) map[string]string {
	if scannerVersionCache == nil {
		return map[string]string{}
	}
	waitCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), versionWaitTimeout)
	defer cancel()
	return scannerVersionCache.SnapshotAfterInitial(waitCtx)
}

// trackScan stamps the once-per-process scanner versions onto a scan event and
// dispatches it. Callers set event.Interface (CLI vs MCP) in the struct literal
// at the call site, which already knows which surface it is.
func trackScan(ctx context.Context, event telemetry.ScanEvent) {
	event.BinaryVersions = binaryVersionsForEvent(ctx)
	telemetryClient.TrackScan(ctx, event)
}

// trackOperation is the OperationEvent counterpart of trackScan.
func trackOperation(ctx context.Context, event telemetry.OperationEvent) {
	event.BinaryVersions = binaryVersionsForEvent(ctx)
	telemetryClient.TrackOperation(ctx, event)
}
