package processing

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/owenrumney/go-sarif/v2/sarif"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/types"
)

const (
	MaxSARIFSize = 50 * 1024 * 1024 // 50MB
)

// SARIF severity levels
const (
	SARIFLevelError   = "error"
	SARIFLevelWarning = "warning"
	SARIFLevelNote    = "note"
)

// ParseSARIF extracts essential violation information from SARIF output
// This is a shared utility that both SAST and Secrets scanners can use
func ParseSARIF(data []byte, workingDir string, defaultDetectionType types.DetectionType) ([]types.Violation, error) {
	if len(data) > MaxSARIFSize {
		return nil, fmt.Errorf("SARIF output too large: %d bytes (max: %d bytes)", len(data), MaxSARIFSize)
	}

	report, err := sarif.FromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SARIF: %w", err)
	}

	if len(report.Runs) == 0 {
		return []types.Violation{}, nil
	}

	var violations []types.Violation

	for _, run := range report.Runs {
		if run == nil || run.Tool.Driver == nil {
			continue
		}

		// Build rules lookup
		rulesById := make(map[string]*sarif.ReportingDescriptor)
		if run.Tool.Driver.Rules != nil {
			for _, rule := range run.Tool.Driver.Rules {
				if rule != nil && rule.ID != "" {
					rulesById[rule.ID] = rule
				}
			}
		}

		// Extract violations
		for _, result := range run.Results {
			if result == nil || result.RuleID == nil {
				continue
			}

			// Skip suppressed
			if len(result.Suppressions) > 0 {
				continue
			}

			rule := rulesById[*result.RuleID]

			violation := types.Violation{
				Severity:      mapSeverity(result, rule),
				Rule:          *result.RuleID,
				RuleURL:       extractRuleURL(rule),
				Message:       extractMessage(result),
				DetectionType: extractDetectionType(rule, defaultDetectionType),
			}

			// Extract location
			if len(result.Locations) > 0 && result.Locations[0] != nil {
				loc := result.Locations[0].PhysicalLocation
				if loc != nil && loc.ArtifactLocation != nil && loc.ArtifactLocation.URI != nil {
					violation.File = cleanFilePath(*loc.ArtifactLocation.URI, workingDir)
					if loc.Region != nil && loc.Region.StartLine != nil {
						violation.Line = *loc.Region.StartLine
					}
				}
			}

			violations = append(violations, violation)
		}
	}

	return violations, nil
}

func mapSeverity(result *sarif.Result, rule *sarif.ReportingDescriptor) string {
	// Get level from result or rule
	var level string
	if result.Level != nil {
		level = *result.Level
	} else if rule != nil && rule.DefaultConfiguration != nil {
		level = rule.DefaultConfiguration.Level
	}

	// Map SARIF level to severity
	switch strings.ToLower(level) {
	case SARIFLevelError:
		return types.SeverityHigh
	case SARIFLevelWarning:
		return types.SeverityMedium
	case SARIFLevelNote:
		return types.SeverityLow
	default:
		return types.SeverityMedium
	}
}

func extractMessage(result *sarif.Result) string {
	if result.Message.Text != nil {
		return *result.Message.Text
	}
	if result.Message.Markdown != nil {
		return *result.Message.Markdown
	}
	return ""
}

func extractRuleURL(rule *sarif.ReportingDescriptor) string {
	if rule != nil && rule.HelpURI != nil {
		return *rule.HelpURI
	}
	return ""
}

func cleanFilePath(uri string, workingDir string) string {
	// Remove file:// prefix
	path := strings.TrimPrefix(uri, "file://")

	// Make relative to working dir if possible
	if workingDir != "" {
		if relPath, err := filepath.Rel(workingDir, path); err == nil {
			return relPath
		}
	}

	return path
}

func extractDetectionType(rule *sarif.ReportingDescriptor, defaultType types.DetectionType) types.DetectionType {
	if rule == nil || len(rule.Properties) == 0 {
		return defaultType
	}

	for _, val := range rule.Properties {
		strVal, ok := val.(string)
		if !ok {
			continue
		}

		// Check if it's the rule type property in format "DATADOG_RULE_TYPE:SECRET"
		if strings.HasPrefix(strVal, "DATADOG_RULE_TYPE:") {
			ruleType := strings.TrimPrefix(strVal, "DATADOG_RULE_TYPE:")
			if ruleType == "SECRET" {
				return types.DetectionTypeSecrets
			}
			return types.DetectionTypeSAST
		}
	}

	return defaultType // Use the default if not found
}
