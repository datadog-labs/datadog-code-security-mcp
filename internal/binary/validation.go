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
		// scanTypeBinaries (in manager.go) is the single source of truth for the
		// scan-type→binary mapping; dedup shared binaries (e.g. static-analyzer
		// for sast+secrets) via the map key.
		for _, binaryType := range BinariesForScanType(scanType) {
			entry := binaryChecks[binaryType]
			if entry.manager == nil {
				entry.manager = NewManager(binaryType)
			}
			entry.scanTypes = append(entry.scanTypes, scanType)
			binaryChecks[binaryType] = entry
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
