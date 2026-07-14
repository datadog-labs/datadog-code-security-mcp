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

func trackCLIScan(ctx context.Context, event telemetry.ScanEvent) {
	event.Interface = telemetry.InterfaceCLI
	event.BinaryVersions = binaryVersionsForEvent(ctx)
	telemetryClient.TrackScan(ctx, event)
}

func trackMCPScan(ctx context.Context, event telemetry.ScanEvent) {
	event.Interface = telemetry.InterfaceMCP
	event.BinaryVersions = binaryVersionsForEvent(ctx)
	telemetryClient.TrackScan(ctx, event)
}

func trackMCPEvent(ctx context.Context, event telemetry.OperationEvent) {
	event.Interface = telemetry.InterfaceMCP
	event.BinaryVersions = binaryVersionsForEvent(ctx)
	telemetryClient.TrackOperation(ctx, event)
}

func trackCLIOperation(ctx context.Context, event telemetry.OperationEvent) {
	event.Interface = telemetry.InterfaceCLI
	event.BinaryVersions = binaryVersionsForEvent(ctx)
	telemetryClient.TrackOperation(ctx, event)
}
