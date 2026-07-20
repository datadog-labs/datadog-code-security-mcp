package main

import (
	"context"
	"testing"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/binary"
)

func TestVersionCommandTracksAllBinaryVersions(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	srv, ch := captureCmdServer(t)
	telemetryClient = newCmdTestTelemetryClient(t, srv)
	scannerVersionCache = binary.NewBinaryVersionCache()
	scannerVersionCache.Refresh()
	t.Cleanup(func() {
		scannerVersionCache.Close()
		scannerVersionCache = nil
		telemetryClient = nil
	})

	cmd := newVersionCmd()
	cmd.SetArgs([]string{})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("version command failed: %v", err)
	}
	flushTelemetry()

	event := waitCmdEvent(t, ch)
	if event["operation"] != "version" {
		t.Errorf("operation = %v, want version", event["operation"])
	}
	if event["interface"] != "cli" {
		t.Errorf("interface = %v, want cli", event["interface"])
	}
	versions, ok := event["binary_versions"].(map[string]any)
	if !ok {
		t.Fatalf("binary_versions has wrong type: %T", event["binary_versions"])
	}
	for _, config := range binary.BinaryConfigs {
		if _, ok := versions[config.TelemetryKey]; !ok {
			t.Errorf("binary_versions missing %q: %v", config.TelemetryKey, versions)
		}
	}
}
