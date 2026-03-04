package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/binary"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/processing"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/sbom"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/types"
)

type SCAScanner struct {
	binaryMgr *binary.BinaryManager // Uses BinaryTypeSecurity for datadog-security-cli
}

func NewSCAScanner(binMgr *binary.BinaryManager) *SCAScanner {
	return &SCAScanner{
		binaryMgr: binMgr,
	}
}

// Execute runs SCA scan
// Takes directories as input (like SAST/Secrets), generates SBOM internally, then scans.
// Working directory resolution is handled by ExecuteScan before this is called.
func (s *SCAScanner) Execute(ctx context.Context, args ScanArgs) ([]types.Violation, error) {
	sbomFile, err := s.generateSBOM(ctx, args.FilePaths, args.WorkingDir)
	if err != nil {
		return nil, fmt.Errorf("SBOM generation failed: %w", err)
	}
	defer os.Remove(sbomFile)

	if err := s.validateSBOMFile(sbomFile); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	rawOutput, err := s.runDetection(ctx, sbomFile, args.WorkingDir)
	if err != nil {
		return nil, fmt.Errorf("detection failed: %w", err)
	}

	vulnerabilities, err := processing.ParseSCAJSON(rawOutput)
	if err != nil {
		return nil, fmt.Errorf("parsing failed: %w", err)
	}

	return s.convertToViolations(vulnerabilities), nil
}

// generateSBOM creates SBOM from directories using sbom.Generator.
// When multiple paths are provided, an SBOM is generated per path and
// the components are merged (deduplicated by PackageURL) so that a
// single vulnerability detection pass covers all requested targets.
func (s *SCAScanner) generateSBOM(ctx context.Context, filePaths []string, workingDir string) (string, error) {
	// Normalize: if no paths provided, default to "."
	paths := filePaths
	if len(paths) == 0 {
		paths = []string{"."}
	}

	var allComponents []types.Library
	generator := sbom.NewGenerator()

	for _, p := range paths {
		if p == "" {
			p = "."
		}
		result, err := generator.Generate(ctx, types.SBOMArgs{
			Path:       p,
			WorkingDir: workingDir,
		})
		if err != nil {
			return "", fmt.Errorf("failed to generate SBOM for path %q: %w", p, err)
		}
		if result.Error != nil {
			return "", fmt.Errorf("SBOM generation error for path %q: %s", p, result.Error.Error)
		}
		allComponents = append(allComponents, result.Components...)
	}

	// Deduplicate components by PackageURL
	allComponents = deduplicateComponents(allComponents)

	if len(allComponents) == 0 {
		return "", fmt.Errorf("no components found in SBOM")
	}

	// Build merged result and write to temp file
	mergedResult := &types.SBOMResult{Components: allComponents}
	sbomFile, err := s.writeSBOMToTempFile(mergedResult)
	if err != nil {
		return "", fmt.Errorf("failed to write SBOM: %w", err)
	}

	return sbomFile, nil
}

// deduplicateComponents removes duplicate libraries by PackageURL.
// Components without a PackageURL are always kept.
func deduplicateComponents(components []types.Library) []types.Library {
	seen := make(map[string]struct{}, len(components))
	result := make([]types.Library, 0, len(components))
	for _, c := range components {
		if c.PackageURL != "" {
			if _, exists := seen[c.PackageURL]; exists {
				continue
			}
			seen[c.PackageURL] = struct{}{}
		}
		result = append(result, c)
	}
	return result
}

// writeSBOMToTempFile converts result to CycloneDX and writes to temp file
func (s *SCAScanner) writeSBOMToTempFile(result *types.SBOMResult) (string, error) {
	// Create temp file
	tempFile, err := os.CreateTemp("", "sbom-*.json")
	if err != nil {
		return "", err
	}
	defer tempFile.Close()

	// Convert to CycloneDX format
	cycloneDX := convertToCycloneDX(result)

	// Write JSON
	encoder := json.NewEncoder(tempFile)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(cycloneDX); err != nil {
		os.Remove(tempFile.Name())
		return "", err
	}

	return tempFile.Name(), nil
}

// convertToCycloneDX converts GeneratorResult to CycloneDX 1.5 format
func convertToCycloneDX(result *types.SBOMResult) map[string]any {
	components := make([]map[string]any, 0, len(result.Components))

	for _, comp := range result.Components {
		component := map[string]any{
			"name":    comp.Name,
			"version": comp.Version,
			"type":    comp.Type,
		}

		if comp.PackageURL != "" {
			component["purl"] = comp.PackageURL
		}

		if comp.Language != "" {
			component["properties"] = []map[string]string{
				{"name": "language", "value": comp.Language},
			}
		}

		components = append(components, component)
	}

	return map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"version":     1,
		"components":  components,
	}
}

// validateSBOMFile ensures SBOM file exists and is valid
func (s *SCAScanner) validateSBOMFile(sbomFile string) error {
	info, err := os.Stat(sbomFile)
	if err != nil {
		return fmt.Errorf("SBOM file not accessible: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("SBOM file path is a directory")
	}
	return nil
}

// runDetection calls datadog-security-cli to scan SBOM
func (s *SCAScanner) runDetection(ctx context.Context, sbomFile, workingDir string) ([]byte, error) {
	// Get binary path
	cliPath, err := s.binaryMgr.GetBinaryPath(ctx)
	if err != nil {
		return nil, err
	}

	// Build command arguments
	args := []string{
		"sbom",
		sbomFile,
		"--output-format", "json",
		"--no-persist",
		"--resource-type", "repository",
		"--resource-id", workingDir,
	}

	// Execute command
	cmd := exec.CommandContext(ctx, cliPath, args...)
	cmd.Dir = workingDir

	output, err := cmd.Output()
	if err != nil {
		// Exit code 2 means vulnerabilities found (expected)
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 2 {
				return output, nil
			}
			// Include stderr in error message for actionable diagnostics
			if len(exitErr.Stderr) > 0 {
				return nil, fmt.Errorf("scanner execution failed: %s", strings.TrimSpace(string(exitErr.Stderr)))
			}
		}
		return nil, fmt.Errorf("scanner execution failed: %w", err)
	}

	return output, nil
}

// convertToViolations converts Vulnerability to Violation for consistent handling
func (s *SCAScanner) convertToViolations(vulnerabilities []types.Vulnerability) []types.Violation {
	violations := make([]types.Violation, 0, len(vulnerabilities))

	for _, vuln := range vulnerabilities {
		violation := types.Violation{
			Severity:      vuln.Severity,
			Rule:          vuln.CVE,
			RuleURL:       "", // Could extract from References if available
			File:          fmt.Sprintf("%s@%s", vuln.Component, vuln.Version),
			Line:          0, // N/A for vulnerabilities
			Message:       vuln.Description,
			DetectionType: types.DetectionTypeSCA,
		}
		violations = append(violations, violation)
	}

	return violations
}
