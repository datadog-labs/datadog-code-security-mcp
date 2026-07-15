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
	ScanNotice       = types.ScanNotice
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
	// Notice is a non-fatal, informational note about the execution (e.g. no
	// components detected by the SBOM generator). It is orthogonal to Err:
	// a successful execution (Err == nil) may still carry a Notice.
	Notice *types.ScanNotice
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
	// Notice is a pointer, so copy the pointee too; otherwise the "defensive
	// copy" contract would leak a shared pointer into (and out of) the outcome.
	if execution.Notice != nil {
		notice := *execution.Notice
		execution.Notice = &notice
	}
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

// EachExecution calls fn for every execution in request order. The execution is
// passed by value but shares the underlying Findings slice, so fn must treat it
// as read-only. This lets read-only consumers (e.g. telemetry) iterate without
// paying the defensive deep-copy that Executions() makes.
func (o *ScanOutcome) EachExecution(fn func(ScanExecution)) {
	if o == nil {
		return
	}
	for _, execution := range o.executions {
		fn(execution)
	}
}

// executionStates reports success/failure presence in a single pass.
func (o *ScanOutcome) executionStates() (hasSuccess, hasFailure bool) {
	for i := range o.executions {
		if o.executions[i].Err != nil {
			hasFailure = true
		} else {
			hasSuccess = true
		}
	}
	return hasSuccess, hasFailure
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
	hasSuccess, hasFailure := o.executionStates()
	if hasSuccess || !hasFailure {
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
				DetectionType: execution.DetectionType,
				Error:         execution.Err.Error(),
			})
		}
	}
	return errors
}

// scanNotices collects per-scanner non-fatal notices without projecting the
// full result. Unlike scanErrors, these come from successful executions.
func (o *ScanOutcome) scanNotices() []ScanNotice {
	notices := make([]ScanNotice, 0)
	for _, execution := range o.executions {
		if execution.Notice != nil {
			notices = append(notices, *execution.Notice)
		}
	}
	return notices
}

// OutcomeBreakdowns holds per-detection-type reductions over the executions,
// keyed by detection type. All three maps are built in a single pass without
// cloning findings.
type OutcomeBreakdowns struct {
	Durations  map[string]int64  // wall time in ms per detection type
	ErrorKinds map[string]string // categorized failure kind per failed type
	Notices    map[string]string // curated notice message per type that has one
}

// AggregateBreakdowns reduces the executions into telemetry-friendly maps in a
// single pass. errorKind categorizes a scanner error into a stable kind; it is
// injected so this package need not depend on the telemetry classifier. Maps
// are always non-nil; callers should gate emission on len().
func (o *ScanOutcome) AggregateBreakdowns(errorKind func(error) string) OutcomeBreakdowns {
	breakdowns := OutcomeBreakdowns{
		Durations:  make(map[string]int64),
		ErrorKinds: make(map[string]string),
		Notices:    make(map[string]string),
	}
	if o == nil {
		return breakdowns
	}
	for i := range o.executions {
		execution := &o.executions[i]
		detectionType := string(execution.DetectionType)
		breakdowns.Durations[detectionType] = execution.Duration.Milliseconds()
		if execution.Err != nil && errorKind != nil {
			breakdowns.ErrorKinds[detectionType] = errorKind(execution.Err)
		}
		if execution.Notice != nil {
			breakdowns.Notices[detectionType] = execution.Notice.Message
		}
	}
	return breakdowns
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

	hasSuccess, hasFailure := o.executionStates()
	return &ScanResult{
		Summary:       buildSummary(allFindings),
		Results:       resultsByType,
		Errors:        o.scanErrors(),
		Notices:       o.scanNotices(),
		PartialResult: hasSuccess && hasFailure,
	}
}

// Re-export constants as part of the scan package's public API
const (
	SupportedPackageManagers = types.SupportedPackageManagers
	ManualSBOMSuggestion     = types.ManualSBOMSuggestion
)
