package scan

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/binary"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/types"
)

type Scanner interface {
	Execute(ctx context.Context, args ScanArgs) ([]types.Violation, error)
}

// noticeProvider is an optional interface a Scanner may implement to surface
// a non-fatal, informational note about its own execution (e.g. "no
// components detected") without it being treated as an error. Kept separate
// from Scanner so scanners without this concept don't need a no-op method.
type noticeProvider interface {
	LastNotice() *types.ScanNotice
}

// ExecuteParallelScans runs multiple scan types in parallel
// Returns partial results if some scans fail but others succeed
func ExecuteParallelScans(ctx context.Context, args ScanArgs, binaryMgr *binary.BinaryManager) *ScanOutcome {
	// Buffered channel sized to number of scan types
	// This ensures goroutines never block on send, even if collection is slow
	results := make(chan ScanExecution, len(args.ScanTypes))
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
				results <- ScanExecution{
					DetectionType: types.DetectionType(st),
					Err:           fmt.Errorf("unknown scan type: %s", st),
				}
				return
			}

			// Execute scan (may take several seconds) and record wall time
			scanStart := time.Now()
			findings, err := scannerInst.Execute(ctx, args)
			var notice *types.ScanNotice
			if np, ok := scannerInst.(noticeProvider); ok {
				notice = np.LastNotice()
			}
			results <- ScanExecution{
				DetectionType: types.DetectionType(st),
				Findings:      findings,
				Err:           err,
				Duration:      time.Since(scanStart),
				Notice:        notice,
			}
		}(scanType)
	}

	// Close results channel when all scans complete
	// This allows the collection loop below to terminate
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect all results (even if some failed). The channel completes in
	// nondeterministic order, so store by type and project in request order below.
	collected := make(map[string]ScanExecution, len(args.ScanTypes))
	for result := range results {
		collected[string(result.DetectionType)] = result
	}

	return assembleOutcome(args.ScanTypes, collected)
}

// assembleOutcome preserves request order after concurrent scanner completion.
func assembleOutcome(scanTypes []string, collected map[string]ScanExecution) *ScanOutcome {
	executions := make([]ScanExecution, 0, len(scanTypes))
	for _, scanType := range scanTypes {
		executions = append(executions, collected[scanType])
	}
	return NewCompletedOutcome(executions)
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
	case "iac":
		iacBinMgr := binary.NewManager(binary.BinaryTypeIaC)
		return NewIaCScanner(iacBinMgr)
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
