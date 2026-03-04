package scan

import (
	"context"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/binary"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/types"
)

// SASTScanner implements SAST (Static Application Security Testing) scanning
type SASTScanner struct {
	base         *BaseStaticAnalyzerScanner
	filterConfig FilterConfig
}

// FilterConfig controls severity filtering for findings
type FilterConfig struct {
	MinSeverity string // Use types.Severity* constants (LOW, MEDIUM, HIGH, CRITICAL)
	Enabled     bool
}

// Default configuration values
const (
	DefaultMinSeverity   = types.SeverityMedium
	DefaultFilterEnabled = true
)

// NewSASTScanner creates a new SAST scanner with default configuration
func NewSASTScanner(binMgr *binary.BinaryManager) *SASTScanner {
	return &SASTScanner{
		base: &BaseStaticAnalyzerScanner{
			binaryMgr: binMgr,
			config: StaticAnalyzerConfig{
				ScanType:         "sast",
				TempDirPrefix:    "sast-scan-",
				EnableSAST:       true,
				EnableSecrets:    false,
				DefaultDetection: types.DetectionTypeSAST,
			},
		},
		filterConfig: FilterConfig{
			MinSeverity: DefaultMinSeverity, // Default: filter out LOW severity
			Enabled:     DefaultFilterEnabled,
		},
	}
}

// Execute runs SAST scan with severity filtering
func (s *SASTScanner) Execute(ctx context.Context, args ScanArgs) ([]types.Violation, error) {
	// Delegate to base for detection and parsing
	findings, err := s.base.Execute(ctx, args)
	if err != nil {
		return nil, err
	}

	// Apply SAST-specific severity filtering
	if s.filterConfig.Enabled {
		findings = s.filterBySeverity(findings, s.filterConfig.MinSeverity)
	}

	return findings, nil
}

// filterBySeverity removes findings below the threshold
func (s *SASTScanner) filterBySeverity(findings []types.Violation, minSeverity string) []types.Violation {
	minLevel := types.SeverityOrder[minSeverity]
	filtered := make([]types.Violation, 0, len(findings))

	for _, f := range findings {
		if types.SeverityOrder[f.Severity] >= minLevel {
			filtered = append(filtered, f)
		}
	}

	return filtered
}
