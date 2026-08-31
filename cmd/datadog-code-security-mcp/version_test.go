package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

func TestDetailedVersionReportsEveryScannerIndependently(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test uses executable shell scripts")
	}

	binDir := t.TempDir()
	binaries := map[string]string{
		"datadog-static-analyzer": "--version",
		"datadog-security-cli":    "version",
	}
	for name, expectedArg := range binaries {
		script := "#!/bin/sh\n" +
			"test \"$1\" = \"" + expectedArg + "\" || exit 1\n" +
			"printf 'Version: 1.2.3\\n'\n"
		if err := os.WriteFile(filepath.Join(binDir, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", binDir)

	var output bytes.Buffer
	if err := printVersion(context.Background(), &output, true); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, binaryType := range binary.OrderedBinaryTypes() {
		name := binary.BinaryConfigs[binaryType].BinaryName
		if strings.Count(text, "  "+name+":") != 1 {
			t.Errorf("%s status count = %d, output:\n%s", name, strings.Count(text, "  "+name+":"), text)
		}
	}
	for _, name := range []string{"datadog-static-analyzer", "datadog-security-cli"} {
		if !strings.Contains(text, "  "+name+": ✅ INSTALLED") {
			t.Errorf("%s not reported installed:\n%s", name, text)
		}
	}
	for _, name := range []string{"datadog-sbom-generator", "datadog-iac-scanner"} {
		if !strings.Contains(text, "  "+name+": ❌ NOT INSTALLED") {
			t.Errorf("%s not reported missing:\n%s", name, text)
		}
	}
}
