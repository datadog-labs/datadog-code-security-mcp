package sbom

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/binary"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/types"
)

const (
	DefaultSBOMTimeout = 10 * time.Minute
)

// Generator manages SBOM generation using datadog-sbom-generator
type Generator struct {
	binaryMgr *binary.BinaryManager
	executor  *binary.CommandExecutor
}

// NewGenerator creates a new SBOM generator
func NewGenerator() *Generator {
	return &Generator{
		binaryMgr: binary.NewSBOMGeneratorManager(),
		executor:  binary.NewCommandExecutor(),
	}
}

// Generate creates a Software Bill of Materials for the specified path
func (g *Generator) Generate(ctx context.Context, args types.SBOMArgs) (*types.SBOMResult, error) {
	// Validate and set defaults
	if err := validateArgs(&args); err != nil {
		return nil, err
	}

	scanCtx, cancel := createContext(ctx)
	if cancel != nil {
		defer cancel()
	}

	// Get binary path
	binaryPath, err := g.binaryMgr.GetBinaryPath(scanCtx)
	if err != nil {
		return &types.SBOMResult{
			Error: &types.ScanError{
				DetectionType: string(types.DetectionTypeSBOM),
				Error:         err.Error(),
				Hint:          "Install datadog-sbom-generator using the instructions above",
			},
		}, nil
	}

	// Create secure temp directory (mode 0700)
	tempDir, err := os.MkdirTemp("", "sbom-generator-")
	if err != nil {
		return &types.SBOMResult{
			Error: &types.ScanError{
				DetectionType: string(types.DetectionTypeSBOM),
				Error:         fmt.Sprintf("failed to create temp directory: %v", err),
			},
		}, nil
	}
	defer os.RemoveAll(tempDir)

	// Create output file inside the secure directory
	outputPath := filepath.Join(tempDir, "sbom.json")

	// Build args for SBOM generation
	// The tool expects: datadog-sbom-generator scan [options] <path>
	// Supported formats: json, cyclonedx-1-5
	cmdArgs := []string{
		"scan",
		"--format", "cyclonedx-1-5",
		"--output", outputPath,
	}

	// Add the path to scan
	scanPath := args.Path
	if !filepath.IsAbs(scanPath) {
		// Make path absolute if relative
		scanPath = filepath.Join(args.WorkingDir, scanPath)
	}
	cmdArgs = append(cmdArgs, scanPath)

	// Execute SBOM generation
	output, err := g.executor.Execute(scanCtx, binaryPath, cmdArgs, args.WorkingDir, outputPath)
	if err != nil {
		return &types.SBOMResult{
			Error: &types.ScanError{
				DetectionType: string(types.DetectionTypeSBOM),
				Error:         err.Error(),
				Hint:          retryHintFromError(err),
			},
		}, nil
	}

	// Parse SBOM results
	libraries, err := g.parseCycloneDXJSON(output, args.WorkingDir)
	if err != nil {
		return &types.SBOMResult{
			Error: &types.ScanError{
				DetectionType: string(types.DetectionTypeSBOM),
				Error:         fmt.Sprintf("failed to parse SBOM results: %v", err),
			},
		}, nil
	}

	// Build summary
	summary := buildSummary(libraries)

	// Build result
	result := &types.SBOMResult{
		Summary:    summary,
		Components: libraries,
	}

	// Add hint if no components found
	if len(libraries) == 0 {
		result.Error = &types.ScanError{
			DetectionType: string(types.DetectionTypeSBOM),
			Error:         "No components detected by datadog-sbom-generator",
			Hint:          getManualSBOMSuggestion(),
		}
	}

	return result, nil
}

func validateArgs(args *types.SBOMArgs) error {
	if err := ensureWorkingDir(args); err != nil {
		return err
	}
	if err := ensurePath(args); err != nil {
		return err
	}
	return nil
}

func ensureWorkingDir(args *types.SBOMArgs) error {
	if args.WorkingDir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("sbom: failed to get working directory: %w", err)
		}
		args.WorkingDir = wd
		return nil
	}

	info, err := os.Stat(args.WorkingDir)
	if err != nil {
		return fmt.Errorf("sbom: working_dir '%s' does not exist or is not accessible", args.WorkingDir)
	}
	if !info.IsDir() {
		return fmt.Errorf("sbom: working_dir '%s' is not a directory", args.WorkingDir)
	}
	return nil
}

func ensurePath(args *types.SBOMArgs) error {
	if args.Path == "" {
		args.Path = "."
		return nil
	}

	// Resolve path relative to working directory
	fullPath := args.Path
	if !filepath.IsAbs(args.Path) {
		fullPath = filepath.Join(args.WorkingDir, args.Path)
	}

	info, err := os.Stat(fullPath)
	if err != nil {
		return fmt.Errorf("sbom: path '%s' does not exist or is not accessible (resolved to: %s)", args.Path, fullPath)
	}
	if !info.IsDir() {
		return fmt.Errorf("sbom: path '%s' must be a directory", args.Path)
	}

	return nil
}

func createContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, hasDeadline := ctx.Deadline(); hasDeadline {
		return ctx, nil
	}
	return context.WithTimeout(ctx, DefaultSBOMTimeout)
}

func buildSummary(libraries []types.Library) types.SBOMSummary {
	summary := types.SBOMSummary{
		TotalComponents: len(libraries),
		ByLanguage:      make(map[string]int),
		ByType:          make(map[string]int),
	}

	for _, lib := range libraries {
		// Count by language/package manager
		if lib.Language != "" {
			summary.ByLanguage[lib.Language]++
		}

		// Count by type
		if lib.Type != "" {
			summary.ByType[lib.Type]++
		}
	}

	return summary
}

func retryHintFromError(err error) string {
	errMsg := err.Error()

	// Check if it's a binary not found error
	if strings.Contains(errMsg, "not found in PATH") {
		return "Install datadog-sbom-generator using the instructions above"
	}

	// Check if it's a permission error
	if strings.Contains(errMsg, "permission denied") {
		return "Check file permissions and ensure you have access to the scan path"
	}

	// Default hint
	return ""
}

func getManualSBOMSuggestion() string {
	return "The package manager may not be supported. Supported: .NET (NuGet), C++ (Conan), Go (modules), Java (Gradle/Maven), JavaScript (NPM/PNPM/Yarn), PHP (Composer), Python (pdm/pipenv/poetry/requirements/uv), Ruby (Bundler), Rust (Cargo). " +
		"Claude should perform manual SBOM generation by reading lock files (package.json, requirements.txt, go.mod, pom.xml, Gemfile.lock, Cargo.lock, composer.lock, etc.) and extracting dependencies."
}

// CycloneDX structs for parsing SBOM output

// cycloneDXOutput represents the CycloneDX JSON format structure
type cycloneDXOutput struct {
	BOMFormat   string `json:"bomFormat"`
	SpecVersion string `json:"specVersion"`
	Version     int    `json:"version"`
	Metadata    struct {
		Component struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Type    string `json:"type"`
		} `json:"component"`
	} `json:"metadata"`
	Components []cycloneDXComponent `json:"components"`
}

// cycloneDXComponent represents a component in CycloneDX format
type cycloneDXComponent struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Type     string `json:"type"`
	Purl     string `json:"purl,omitempty"`
	Licenses []struct {
		License struct {
			ID   string `json:"id,omitempty"`
			Name string `json:"name,omitempty"`
		} `json:"license,omitempty"`
	} `json:"licenses,omitempty"`
	Properties []cycloneDXProperty `json:"properties,omitempty"`
}

// cycloneDXProperty represents a property in CycloneDX format
type cycloneDXProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// parseCycloneDXJSON parses CycloneDX SBOM JSON output and returns Library results
func (g *Generator) parseCycloneDXJSON(data []byte, workingDir string) ([]types.Library, error) {
	if len(data) == 0 {
		return []types.Library{}, nil
	}

	var output cycloneDXOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("failed to parse SBOM output as CycloneDX JSON: %w", err)
	}

	libraries := make([]types.Library, 0, len(output.Components))
	for _, comp := range output.Components {
		// Extract language/package manager from purl or properties
		language := extractLanguageFromPurl(comp.Purl)
		if language == "" {
			language = extractLanguageFromProperties(comp.Properties)
		}

		// Extract file location from properties if available
		file := workingDir
		for _, prop := range comp.Properties {
			if prop.Name == "file" || prop.Name == "location" {
				file = prop.Value
				break
			}
		}

		lib := types.Library{
			Name:       comp.Name,
			Version:    comp.Version,
			Type:       comp.Type,
			PackageURL: comp.Purl,
			Language:   language,
			File:       file,
		}
		libraries = append(libraries, lib)
	}

	return libraries, nil
}

// extractLanguageFromPurl extracts the package manager/language from a Package URL
// Example: pkg:npm/lodash@4.17.21 -> npm
// Example: pkg:pypi/requests@2.28.0 -> pypi
func extractLanguageFromPurl(purl string) string {
	if purl == "" {
		return ""
	}
	// Purl format: pkg:<type>/...
	if len(purl) < 5 || purl[:4] != "pkg:" {
		return ""
	}
	// Find the first slash
	for i := 4; i < len(purl); i++ {
		if purl[i] == '/' {
			return purl[4:i]
		}
	}
	return ""
}

// extractLanguageFromProperties extracts language from CycloneDX properties
func extractLanguageFromProperties(properties []cycloneDXProperty) string {
	for _, prop := range properties {
		// Check for osv-scanner properties (generated by datadog-sbom-generator)
		if prop.Name == "osv-scanner:package-manager" {
			return prop.Value
		}
		// Also check for standard properties
		if prop.Name == "language" || prop.Name == "package_manager" {
			return prop.Value
		}
	}
	return ""
}
