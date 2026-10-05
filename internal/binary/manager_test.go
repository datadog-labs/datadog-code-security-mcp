package binary

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestOrderedBinaryTypesMatchesConfigs(t *testing.T) {
	ordered := OrderedBinaryTypes()
	if len(ordered) != len(BinaryConfigs) {
		t.Fatalf("OrderedBinaryTypes() has %d entries, BinaryConfigs has %d", len(ordered), len(BinaryConfigs))
	}

	seen := make(map[BinaryType]bool, len(ordered))
	for _, binaryType := range ordered {
		if _, ok := BinaryConfigs[binaryType]; !ok {
			t.Errorf("OrderedBinaryTypes() contains unconfigured binary %q", binaryType)
		}
		if seen[binaryType] {
			t.Errorf("OrderedBinaryTypes() contains duplicate binary %q", binaryType)
		}
		seen[binaryType] = true
	}
	for binaryType := range BinaryConfigs {
		if !seen[binaryType] {
			t.Errorf("OrderedBinaryTypes() is missing configured binary %q", binaryType)
		}
	}
}

func TestScanTypeBinaryMapping(t *testing.T) {
	tests := []struct {
		scanType     string
		wantBinaries []BinaryType
		wantKeys     []string
	}{
		{"sast", []BinaryType{BinaryTypeStaticAnalyzer}, []string{"static_analyzer"}},
		{"secrets", []BinaryType{BinaryTypeStaticAnalyzer}, []string{"static_analyzer"}},
		{"sca", []BinaryType{BinaryTypeSBOMGenerator, BinaryTypeSecurity}, []string{"sbom_generator", "security_cli"}},
		{"iac", []BinaryType{BinaryTypeIaC}, []string{"iac_scanner"}},
		{"sbom", []BinaryType{BinaryTypeSBOMGenerator}, []string{"sbom_generator"}},
		{"unknown", nil, []string{}},
	}
	for _, tc := range tests {
		t.Run(tc.scanType, func(t *testing.T) {
			if got := BinariesForScanType(tc.scanType); !reflect.DeepEqual(got, tc.wantBinaries) {
				t.Errorf("BinariesForScanType(%q) = %v, want %v", tc.scanType, got, tc.wantBinaries)
			}
			if got := TelemetryKeysForScanType(tc.scanType); !reflect.DeepEqual(got, tc.wantKeys) {
				t.Errorf("TelemetryKeysForScanType(%q) = %v, want %v", tc.scanType, got, tc.wantKeys)
			}
		})
	}
}

func TestSBOMGeneratorWindowsInstallInstructions(t *testing.T) {
	tests := []struct {
		arch     string
		wantFile string
	}{
		{"amd64", "datadog-sbom-generator_windows_amd64.zip"},
		{"arm64", "datadog-sbom-generator_windows_arm64.zip"},
	}
	for _, tc := range tests {
		t.Run(tc.arch, func(t *testing.T) {
			got := NewSBOMGeneratorManager().installInstructionsFor("windows", tc.arch)
			wantURL := "https://github.com/DataDog/datadog-sbom-generator/releases/latest/download/" + tc.wantFile
			if !strings.Contains(got, wantURL) {
				t.Errorf("instructions missing %q:\n%s", wantURL, got)
			}
			if strings.Contains(got, "Binary not available") {
				t.Errorf("instructions report windows/%s as unavailable:\n%s", tc.arch, got)
			}
		})
	}
}

func TestSecurityCLIUnavailableOnWindows(t *testing.T) {
	got := NewManager(BinaryTypeSecurity).installInstructionsFor("windows", "amd64")
	if !strings.Contains(got, "only available for Linux and macOS") {
		t.Errorf("expected Linux/macOS-only notice, got:\n%s", got)
	}
}

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
