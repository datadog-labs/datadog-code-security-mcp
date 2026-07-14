package binary

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGetVersionUsesBinaryVersionArgs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test uses executable shell scripts")
	}

	binDir := t.TempDir()
	binaries := map[string]string{
		"datadog-security-cli":    "version",
		"datadog-static-analyzer": "--version",
	}
	for name, expectedArg := range binaries {
		script := "#!/bin/sh\n" +
			"test \"$1\" = \"" + expectedArg + "\" || exit 1\n" +
			"printf 'Version: v1.2.3\\n'\n"
		if err := os.WriteFile(filepath.Join(binDir, name), []byte(script), 0o755); err != nil {
			t.Fatalf("write fake %s: %v", name, err)
		}
	}
	t.Setenv("PATH", binDir)

	tests := []struct {
		name       string
		binaryType BinaryType
	}{
		{name: "security CLI subcommand", binaryType: BinaryTypeSecurity},
		{name: "default version flag", binaryType: BinaryTypeStaticAnalyzer},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := NewManager(test.binaryType).GetVersion(context.Background()); got != "1.2.3" {
				t.Fatalf("GetVersion() = %q, want 1.2.3", got)
			}
		})
	}
}
