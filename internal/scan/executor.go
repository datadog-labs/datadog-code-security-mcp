package scan

import (
	"context"
	"fmt"
	"sync"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/binary"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/types"
)

type Scanner interface {
	Execute(ctx context.Context, args ScanArgs) ([]types.Violation, error)
}

// ExecuteParallelScans runs multiple scan types in parallel
// Returns partial results if some scans fail but others succeed
func ExecuteParallelScans(ctx context.Context, args ScanArgs, binaryMgr *binary.BinaryManager) (*ScanResult, error) {
	// Result channel
	type scanResult struct {
		scanType string
		findings []types.Violation
		err      error
	}

	// Buffered channel sized to number of scan types
	// This ensures goroutines never block on send, even if collection is slow
	results := make(chan scanResult, len(args.ScanTypes))
	var wg sync.WaitGroup

	// Launch all scans in parallel
	// Each scan type runs independently to maximize throughput
	// Failures in one scan don't block others (resilient design)
	for _, scanType := range args.ScanTypes {
		wg.Add(1)
		go func(st string) {
			defer wg.Done()

			scannerInst := getScannerFor(st, binaryMgr)
			if scannerInst == nil {
				results <- scanResult{st, nil, fmt.Errorf("unknown scan type: %s", st)}
				return
			}

			// Execute scan (may take several seconds)
			findings, err := scannerInst.Execute(ctx, args)
			results <- scanResult{st, findings, err}
		}(scanType)
	}

	// Close results channel when all scans complete
	// This allows the collection loop below to terminate
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect all results (even if some failed)
	// This enables partial success: if SAST fails but Secrets succeeds,
	// we still return the Secrets findings with an error for SAST
	allFindings := make([]types.Violation, 0)
	resultsByType := make(map[types.DetectionType][]types.Violation)
	var errors []ScanError

	for result := range results {
		if result.err != nil {
			errors = append(errors, ScanError{
				DetectionType: result.scanType,
				Error:         result.err.Error(),
			})
		} else {
			allFindings = append(allFindings, result.findings...)
			// Convert string to DetectionType
			detectionType := types.DetectionType(result.scanType)
			resultsByType[detectionType] = result.findings
		}
	}

	// Build summary
	summary := buildSummary(allFindings)

	return &ScanResult{
		Summary:       summary,
		Results:       resultsByType,
		Errors:        errors,
		PartialResult: len(errors) > 0 && len(allFindings) > 0,
	}, nil
}

// getScannerFor returns the appropriate scanner for the given scan type
// Returns nil for unknown scan types
func getScannerFor(scanType string, binMgr *binary.BinaryManager) Scanner {
	switch scanType {
	case "sast":
		return NewSASTScanner(binMgr)
	case "secrets":
		return NewSecretsScanner(binMgr)
	case "sca":
		// SCA uses different binary (datadog-security-cli)
		scaBinMgr := binary.NewManager(binary.BinaryTypeSecurity)
		return NewSCAScanner(scaBinMgr)
	default:
		return nil
	}
}

// buildSummary aggregates findings by severity
func buildSummary(findings []types.Violation) ScanSummary {
	summary := ScanSummary{
		BySeverity:      make(map[string]int),
		ByDetectionType: make(map[string]int),
	}

	for _, f := range findings {
		summary.Total++

		// Count by severity
		switch f.Severity {
		case types.SeverityCritical:
			summary.Critical++
		case types.SeverityHigh:
			summary.High++
		case types.SeverityMedium:
			summary.Medium++
		case types.SeverityLow:
			summary.Low++
		}
		summary.BySeverity[f.Severity]++

		// Count by detection type
		detType := string(f.DetectionType)
		summary.ByDetectionType[detType]++
	}

	return summary
}
