// Package scan provides orchestration for security scanning operations.
//
// Type definitions are centralized in internal/types and re-exported here
// to maintain clean API boundaries. The scan package serves as the public
// API for security scanning, while internal/types contains shared type definitions.
//
// See: internal/types/types.go, internal/types/detection.go, internal/types/severity.go
package scan

import (
	"time"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/types"
)

// Re-export types as part of the scan package's public API
type (
	ScanArgs         = types.ScanArgs
	ScanSummary      = types.ScanSummary
	ScanResult       = types.ScanResult
	ScanError        = types.ScanError
	GenerateSBOMArgs = types.SBOMArgs
	SBOMSummary      = types.SBOMSummary
	SBOMResult       = types.SBOMResult
	SCAArgs          = types.SCAArgs
	SCASummary       = types.SCASummary
	SCAResult        = types.SCAResult
)

// ScanExecution is the canonical record for one scanner invocation.
type ScanExecution struct {
	DetectionType types.DetectionType
	Findings      []types.Violation
	Duration      time.Duration
	Err           error
}

// ScanOutcome owns the complete state of a scan invocation. Public results,
// summaries, and invocation errors are projections of this state.
type ScanOutcome struct {
	scanTypes     []types.DetectionType
	executions    []ScanExecution
	invocationErr error
}

// NewFailedOutcome records a failure that prevented scanner execution.
func NewFailedOutcome(scanTypes []string, err error) *ScanOutcome {
	requested := make([]types.DetectionType, len(scanTypes))
	for i, scanType := range scanTypes {
		requested[i] = types.DetectionType(scanType)
	}
	return &ScanOutcome{
		scanTypes:     requested,
		invocationErr: err,
	}
}

// NewCompletedOutcome records scanner executions in deterministic request order.
// Requested scan types are derived from those records so the two cannot drift.
func NewCompletedOutcome(executions []ScanExecution) *ScanOutcome {
	outcome := &ScanOutcome{
		scanTypes:  make([]types.DetectionType, len(executions)),
		executions: make([]ScanExecution, len(executions)),
	}
	for i, execution := range executions {
		outcome.scanTypes[i] = execution.DetectionType
		outcome.executions[i] = cloneExecution(execution)
	}
	return outcome
}

func cloneExecution(execution ScanExecution) ScanExecution {
	execution.Findings = append([]types.Violation(nil), execution.Findings...)
	return execution
}

// ScanTypes returns the requested scan types in deterministic request order.
func (o *ScanOutcome) ScanTypes() []string {
	if o == nil {
		return nil
	}
	scanTypes := make([]string, len(o.scanTypes))
	for i, scanType := range o.scanTypes {
		scanTypes[i] = string(scanType)
	}
	return scanTypes
}

// Executions returns a defensive copy of the canonical execution records.
func (o *ScanOutcome) Executions() []ScanExecution {
	if o == nil {
		return nil
	}
	executions := make([]ScanExecution, len(o.executions))
	for i, execution := range o.executions {
		executions[i] = cloneExecution(execution)
	}
	return executions
}

// Execution returns the execution metadata for scanType.
func (o *ScanOutcome) Execution(scanType string) (ScanExecution, bool) {
	if o == nil {
		return ScanExecution{}, false
	}
	for _, execution := range o.executions {
		if string(execution.DetectionType) == scanType {
			return cloneExecution(execution), true
		}
	}
	return ScanExecution{}, false
}

// HasSuccessfulExecution reports whether at least one requested scanner
// completed successfully, even when it found no violations.
func (o *ScanOutcome) HasSuccessfulExecution() bool {
	if o == nil {
		return false
	}
	for _, execution := range o.executions {
		if execution.Err == nil {
			return true
		}
	}
	return false
}

// HasFailedExecution reports whether at least one requested scanner failed.
func (o *ScanOutcome) HasFailedExecution() bool {
	if o == nil {
		return false
	}
	for _, execution := range o.executions {
		if execution.Err != nil {
			return true
		}
	}
	return false
}

// Err returns the invocation-level failure. Scanner failures become fatal only
// when every requested scanner failed.
func (o *ScanOutcome) Err() error {
	if o == nil {
		return nil
	}
	if o.invocationErr != nil {
		return o.invocationErr
	}
	if o.HasSuccessfulExecution() || !o.HasFailedExecution() {
		return nil
	}
	return allScansFailedError(o.scanErrors())
}

// scanErrors collects per-scanner failures without projecting the full result.
func (o *ScanOutcome) scanErrors() []ScanError {
	errors := make([]ScanError, 0)
	for _, execution := range o.executions {
		if execution.Err != nil {
			errors = append(errors, ScanError{
				DetectionType: string(execution.DetectionType),
				Error:         execution.Err.Error(),
			})
		}
	}
	return errors
}

// Result projects the user-facing result from the canonical execution records.
func (o *ScanOutcome) Result() *ScanResult {
	if o == nil || len(o.executions) == 0 {
		return nil
	}

	allFindings := make([]types.Violation, 0)
	resultsByType := make(map[types.DetectionType][]types.Violation)
	for _, execution := range o.executions {
		if execution.Err != nil {
			continue
		}
		allFindings = append(allFindings, execution.Findings...)
		resultsByType[execution.DetectionType] = append([]types.Violation(nil), execution.Findings...)
	}

	return &ScanResult{
		Summary:       buildSummary(allFindings),
		Results:       resultsByType,
		Errors:        o.scanErrors(),
		PartialResult: o.HasSuccessfulExecution() && o.HasFailedExecution(),
	}
}

// Re-export constants as part of the scan package's public API
const (
	SupportedPackageManagers = types.SupportedPackageManagers
	ManualSBOMSuggestion     = types.ManualSBOMSuggestion
)
