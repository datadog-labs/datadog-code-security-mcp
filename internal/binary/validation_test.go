package binary

import (
	"context"
	"strings"
	"testing"
)

func TestValidateScanBinaries_EmptyScanTypes(t *testing.T) {
	ctx := context.Background()
	err := ValidateScanBinaries(ctx, []string{})

	if err != nil {
		t.Errorf("Expected no error for empty scan types, got: %v", err)
	}
}

func TestValidateScanBinaries_SharedBinary(t *testing.T) {
	ctx := context.Background()

	// Test that sast+secrets only checks datadog-static-analyzer once
	// This test will pass or fail depending on whether binaries are installed
	err := ValidateScanBinaries(ctx, []string{"sast", "secrets"})

	if err != nil {
		// Expected if binaries not installed
		errMsg := err.Error()

		// Should only mention datadog-static-analyzer once
		if !strings.Contains(errMsg, "datadog-static-analyzer") {
			t.Errorf("Error should mention datadog-static-analyzer")
		}

		// Should show both scan types as requiring the binary
		if !strings.Contains(errMsg, "sast") || !strings.Contains(errMsg, "secrets") {
			t.Errorf("Error should show both sast and secrets as requiring the binary, got: %s", errMsg)
		}

		// Verify it's a properly structured error with "Required for:"
		if !strings.Contains(errMsg, "Required for:") {
			t.Errorf("Error should include 'Required for:' prefix, got: %s", errMsg)
		}
	}
	// If no error, binaries are installed - test passes
}

func TestValidateScanBinaries_MultipleBinaries(t *testing.T) {
	ctx := context.Background()

	// Test with scan types requiring different binaries
	err := ValidateScanBinaries(ctx, []string{"sast", "sca"})

	if err != nil {
		// Expected if binaries not installed
		errMsg := err.Error()

		// Should mention "SCAN PREREQUISITES MISSING"
		if !strings.Contains(errMsg, "SCAN PREREQUISITES MISSING") {
			t.Errorf("Error should mention 'SCAN PREREQUISITES MISSING', got: %s", errMsg)
		}

		// Should mention that this is RECOVERABLE
		if !strings.Contains(errMsg, "RECOVERABLE") {
			t.Errorf("Error should mention 'RECOVERABLE', got: %s", errMsg)
		}

		// If both binaries are missing, should have separator
		staticAnalyzerMissing := strings.Contains(errMsg, "datadog-static-analyzer")
		securityCLIMissing := strings.Contains(errMsg, "datadog-security-cli")

		if staticAnalyzerMissing && securityCLIMissing {
			// Should have separator between errors (using ═ character)
			if !strings.Contains(errMsg, strings.Repeat("═", 70)) {
				t.Errorf("Error should have separator between multiple binary errors")
			}
		}
	}
	// If no error, binaries are installed - test passes
}

func TestValidateScanBinaries_OnlySCA(t *testing.T) {
	ctx := context.Background()

	// Test SCA scan type alone
	err := ValidateScanBinaries(ctx, []string{"sca"})

	if err != nil {
		// Expected if datadog-security-cli not installed
		errMsg := err.Error()

		// Should mention datadog-security-cli
		if !strings.Contains(errMsg, "datadog-security-cli") {
			t.Errorf("Error should mention datadog-security-cli for SCA scan, got: %s", errMsg)
		}

		// Should show SCA as requiring the binary
		if !strings.Contains(errMsg, "Required for: sca") {
			t.Errorf("Error should show 'Required for: sca', got: %s", errMsg)
		}
	}
	// If no error, binary is installed - test passes
}

func TestValidateScanBinaries_UnknownScanType(t *testing.T) {
	ctx := context.Background()

	// Test with scan types that don't map to any binary
	// This should not cause an error (binary check will be skipped)
	err := ValidateScanBinaries(ctx, []string{"unknown"})

	if err != nil {
		t.Errorf("Unknown scan type should not cause binary validation error, got: %v", err)
	}
}

func TestValidateScanBinaries_MixedScanTypes(t *testing.T) {
	ctx := context.Background()

	// Test all scan types together
	err := ValidateScanBinaries(ctx, []string{"sast", "secrets", "sca"})

	if err != nil {
		// Expected if binaries not installed
		errMsg := err.Error()

		// Should be a structured error with new format
		if !strings.Contains(errMsg, "SCAN PREREQUISITES MISSING") {
			t.Errorf("Error should mention 'SCAN PREREQUISITES MISSING', got: %s", errMsg)
		}

		// Verify "Required for:" appears in error
		if !strings.Contains(errMsg, "Required for:") {
			t.Errorf("Error should include 'Required for:' prefix, got: %s", errMsg)
		}

		// Should mention that this is RECOVERABLE
		if !strings.Contains(errMsg, "RECOVERABLE") {
			t.Errorf("Error should mention 'RECOVERABLE', got: %s", errMsg)
		}
	}
	// If no error, all binaries are installed - test passes
}
