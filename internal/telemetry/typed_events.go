package telemetry

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/scan"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/types"
)

type Interface string

const (
	InterfaceCLI Interface = "cli"
	InterfaceMCP Interface = "mcp"
)

type OutputFormat string

const (
	OutputFormatHuman OutputFormat = "human"
	OutputFormatJSON  OutputFormat = "json"
)

// ScanEvent describes one scan invocation. Outcome is the single canonical
// source for requested types, findings, durations, and failures — including
// pre-execution failures, which callers record via scan.NewFailedOutcome so
// there is never a second, competing source of truth on this struct.
type ScanEvent struct {
	Interface      Interface
	Outcome        *scan.ScanOutcome
	StartedAt      time.Time
	PathsCount     int
	OutputFormat   OutputFormat
	WorkingDir     string
	AuthMethod     string
	BinaryVersions map[string]string
}

func (e ScanEvent) scanTypes() []string {
	return e.Outcome.ScanTypes()
}

func (e ScanEvent) err() error {
	return e.Outcome.Err()
}

// TrackScan emits the aggregate and per-scanner events for an invocation.
func (c *Client) TrackScan(ctx context.Context, event ScanEvent) {
	if c == nil || !c.Enabled() {
		return
	}

	scanTypes := event.scanTypes()
	base := c.scanBaseAttrs(event)
	invocationErr := event.err()
	if len(scanTypes) == 1 {
		report := perScanReport{
			scanType:   scanTypes[0],
			standalone: true,
			duration:   time.Since(event.StartedAt),
			err:        invocationErr,
		}
		if execution, ok := event.Outcome.Execution(scanTypes[0]); ok {
			report.executed = true
			report.duration = execution.Duration
			report.err = execution.Err
			report.findings = execution.Findings
		}
		c.trackPerScan(ctx, event.Interface, base, report)
		return
	}

	batchID := uuid.New().String()
	operation := scanOperation(scanTypes)
	result := event.Outcome.Result()
	attrs := baseOperationAttrs(operation, event.Interface, time.Since(event.StartedAt), invocationErr)
	attrs["scan_types"] = strings.Join(scanTypes, ",")
	attrs["batch_id"] = batchID
	addScanBaseAttrs(attrs, base)
	if result != nil {
		attrs["findings_count"] = result.Summary.Total
		attrs["scan_types_breakdown"] = result.Summary.ByDetectionType
		attrs["severity_breakdown"] = result.Summary.BySeverity
		attrs["partial_errors_count"] = len(result.Errors)
		if durations := scanDurationBreakdown(event.Outcome); len(durations) > 0 {
			attrs["scan_durations_breakdown"] = durations
		}
		if failures := scanErrorKindBreakdown(event.Outcome); len(failures) > 0 {
			attrs["partial_errors_breakdown"] = failures
		}
	}
	c.trackOperationResult(ctx, operation, attrs, invocationErr)

	if event.Outcome == nil {
		return
	}
	base.batchID = batchID
	for _, execution := range event.Outcome.Executions() {
		c.trackPerScan(ctx, event.Interface, base, perScanReport{
			scanType:   string(execution.DetectionType),
			standalone: false,
			duration:   execution.Duration,
			findings:   execution.Findings,
			executed:   true,
			err:        execution.Err,
		})
	}
}

type scanBaseAttributes struct {
	pathsCount     int
	authMethod     string
	binaryVersions map[string]string
	firstRun       bool
	outputFormat   OutputFormat
	isGitRepo      bool
	isWorktree     bool
	batchID        string
}

func (c *Client) scanBaseAttrs(event ScanEvent) scanBaseAttributes {
	workingDir := event.WorkingDir
	if workingDir == "" {
		workingDir = "."
	}
	workspace := DetectWorkspace(workingDir)
	return scanBaseAttributes{
		pathsCount:     event.PathsCount,
		authMethod:     event.AuthMethod,
		binaryVersions: event.BinaryVersions,
		firstRun:       c.IsFirstRun(),
		outputFormat:   event.OutputFormat,
		isGitRepo:      workspace.IsGitRepo,
		isWorktree:     workspace.IsWorktree,
	}
}

// baseOperationAttrs builds the common operation envelope shared by every
// operation-result event: the CommonAttrs base plus operation, interface,
// duration, and success. Callers layer any event-specific attributes on top.
func baseOperationAttrs(operation string, iface Interface, duration time.Duration, err error) map[string]any {
	attrs := CommonAttrs()
	attrs["operation"] = operation
	attrs["interface"] = string(iface)
	attrs["duration_ms"] = duration.Milliseconds()
	attrs["success"] = err == nil
	return attrs
}

func addScanBaseAttrs(attrs map[string]any, base scanBaseAttributes) {
	attrs["paths_count"] = base.pathsCount
	attrs["auth_method"] = base.authMethod
	attrs["binary_versions"] = base.binaryVersions
	attrs["first_run"] = base.firstRun
	attrs["is_git_repo"] = base.isGitRepo
	attrs["is_worktree"] = base.isWorktree
	if base.outputFormat != "" {
		attrs["output_format"] = string(base.outputFormat)
	}
	if base.batchID != "" {
		attrs["batch_id"] = base.batchID
	}
}

// perScanReport is the per-scanner slice of a scan invocation. executed
// distinguishes a scanner that ran and found nothing from an event that never
// reached execution (e.g. a pre-execution failure or an empty outcome).
type perScanReport struct {
	scanType   string
	standalone bool
	duration   time.Duration
	findings   []types.Violation
	executed   bool
	err        error
}

func (c *Client) trackPerScan(ctx context.Context, iface Interface, base scanBaseAttributes, report perScanReport) {
	operation := report.scanType + "_scan"
	attrs := baseOperationAttrs(operation, iface, report.duration, report.err)
	attrs["standalone"] = report.standalone
	addScanBaseAttrs(attrs, base)
	if report.executed && report.err == nil {
		attrs["findings_count"] = len(report.findings)
		attrs["severity_breakdown"] = severityBreakdown(report.findings)
	}
	c.trackOperationResult(ctx, operation, attrs, report.err)
}

func scanOperation(scanTypes []string) string {
	if len(scanTypes) == 1 {
		return scanTypes[0] + "_scan"
	}
	return "code_security_scan"
}

func scanDurationBreakdown(outcome *scan.ScanOutcome) map[string]int64 {
	durations := make(map[string]int64)
	for _, execution := range outcome.Executions() {
		durations[string(execution.DetectionType)] = execution.Duration.Milliseconds()
	}
	return durations
}

func scanErrorKindBreakdown(outcome *scan.ScanOutcome) map[string]string {
	failures := make(map[string]string)
	for _, execution := range outcome.Executions() {
		if execution.Err != nil {
			failures[string(execution.DetectionType)] = CategorizeError(execution.Err)
		}
	}
	return failures
}

func severityBreakdown(findings []types.Violation) map[string]int {
	counts := make(map[string]int)
	for _, finding := range findings {
		counts[finding.Severity]++
	}
	return counts
}

// OperationEvent is the typed schema for non-scan command and MCP operations.
type OperationEvent struct {
	Operation       string
	Interface       Interface
	StartedAt       time.Time
	Failure         error
	BinaryVersions  map[string]string
	IncludeFirstRun bool
	AuthMethod      string
	FindingsCount   *int
	LibrariesCount  *int
	Detailed        *bool
}

func (c *Client) TrackOperation(ctx context.Context, event OperationEvent) {
	if c == nil {
		return
	}
	attrs := baseOperationAttrs(event.Operation, event.Interface, time.Since(event.StartedAt), event.Failure)
	attrs["binary_versions"] = event.BinaryVersions
	if event.IncludeFirstRun {
		attrs["first_run"] = c.IsFirstRun()
	}
	if event.AuthMethod != "" {
		attrs["auth_method"] = event.AuthMethod
	}
	if event.FindingsCount != nil {
		attrs["findings_count"] = *event.FindingsCount
	}
	if event.LibrariesCount != nil {
		attrs["libraries_count"] = *event.LibrariesCount
	}
	if event.Detailed != nil {
		attrs["detailed"] = *event.Detailed
	}
	c.trackOperationResult(ctx, event.Operation, attrs, event.Failure)
}

// ServerStartEvent is the typed schema for the once-per-process MCP start event.
type ServerStartEvent struct {
	AuthConfigured bool
	BinaryVersions map[string]string
}

func (c *Client) TrackServerStart(ctx context.Context, event ServerStartEvent) {
	if c == nil {
		return
	}
	attrs := CommonAttrs()
	attrs["operation"] = "server_start"
	attrs["interface"] = string(InterfaceMCP)
	attrs["auth_configured"] = event.AuthConfigured
	attrs["binary_versions"] = event.BinaryVersions
	c.TrackInfo(ctx, "mcp server started", attrs)
}

func (c *Client) trackOperationResult(ctx context.Context, operation string, attrs map[string]any, err error) {
	if err != nil {
		c.TrackError(ctx, err, operation+" failed", attrs)
		return
	}
	c.TrackInfo(ctx, operation+" completed", attrs)
}
