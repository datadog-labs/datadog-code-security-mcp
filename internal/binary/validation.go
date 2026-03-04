package binary

import (
	"context"
	"fmt"
	"strings"
)

// ValidateScanBinaries validates that all required binaries for the given scan types are available.
// Returns an error with installation instructions if any binaries are missing.
func ValidateScanBinaries(ctx context.Context, scanTypes []string) error {
	// Map scan types to binary managers (with deduplication)
	binaryChecks := make(map[BinaryType]struct {
		manager   *BinaryManager
		scanTypes []string
	})

	for _, scanType := range scanTypes {
		switch scanType {
		case "sast", "secrets":
			// Both use datadog-static-analyzer
			entry := binaryChecks[BinaryTypeStaticAnalyzer]
			if entry.manager == nil {
				entry.manager = NewManager(BinaryTypeStaticAnalyzer)
			}
			entry.scanTypes = append(entry.scanTypes, scanType)
			binaryChecks[BinaryTypeStaticAnalyzer] = entry

		case "sca":
			// Uses datadog-security-cli for vulnerability scanning
			binaryChecks[BinaryTypeSecurity] = struct {
				manager   *BinaryManager
				scanTypes []string
			}{
				manager:   NewManager(BinaryTypeSecurity),
				scanTypes: []string{"sca"},
			}
			// Also requires datadog-sbom-generator for SBOM generation (step 1 of SCA)
			binaryChecks[BinaryTypeSBOMGenerator] = struct {
				manager   *BinaryManager
				scanTypes []string
			}{
				manager:   NewManager(BinaryTypeSBOMGenerator),
				scanTypes: []string{"sca"},
			}
		}
	}

	// Check each unique binary
	var errors []string
	for _, check := range binaryChecks {
		// GetBinaryPath already returns full error with installation instructions
		if _, err := check.manager.GetBinaryPath(ctx); err != nil {
			// Add which scan types need this binary
			errorWithContext := fmt.Sprintf("Required for: %s\n%s",
				strings.Join(check.scanTypes, ", "),
				err.Error())
			errors = append(errors, errorWithContext)
		}
	}

	// Return aggregated error if any binaries are missing
	if len(errors) > 0 {
		separator := "\n" + strings.Repeat("═", 70) + "\n"
		headerSeparator := strings.Repeat("━", 70)

		header := "⚠️  SCAN PREREQUISITES MISSING\n\n" +
			"The following binaries must be installed before scanning:\n\n"

		footer := "\n\n" + headerSeparator + "\n" +
			"IMPORTANT: Install all missing binaries above, then retry the scan.\n" +
			"This is a RECOVERABLE error - binaries can be installed and scan retried.\n" +
			headerSeparator

		return fmt.Errorf("%s%s%s",
			header,
			strings.Join(errors, separator),
			footer)
	}

	return nil
}
