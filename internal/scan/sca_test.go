package scan

import (
	"context"
	"os"
	"testing"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/binary"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/types"
)

func TestSCAScanner_ConvertToViolations(t *testing.T) {
	s := &SCAScanner{}

	vulns := []types.Vulnerability{
		{
			CVE:       "CVE-2021-44228",
			Severity:  "CRITICAL",
			Component: "log4j-core",
			Version:   "2.14.1",
			Description: "Remote code execution via JNDI lookups",
		},
		{
			CVE:       "CVE-2023-1234",
			Severity:  "HIGH",
			Component: "some-lib",
			Version:   "1.0.0",
			Description: "Buffer overflow",
		},
	}

	violations := s.convertToViolations(vulns)

	if len(violations) != 2 {
		t.Fatalf("Expected 2 violations, got %d", len(violations))
	}

	v := violations[0]
	if v.Rule != "CVE-2021-44228" {
		t.Errorf("Expected Rule=CVE-2021-44228, got %s", v.Rule)
	}
	if v.Severity != "CRITICAL" {
		t.Errorf("Expected Severity=CRITICAL, got %s", v.Severity)
	}
	if v.File != "log4j-core@2.14.1" {
		t.Errorf("Expected File=log4j-core@2.14.1, got %s", v.File)
	}
	if v.Message != "Remote code execution via JNDI lookups" {
		t.Errorf("Unexpected Message: %s", v.Message)
	}
	if v.DetectionType != types.DetectionTypeSCA {
		t.Errorf("Expected DetectionType=sca, got %s", v.DetectionType)
	}
	if v.Line != 0 {
		t.Errorf("Expected Line=0 for vulnerability, got %d", v.Line)
	}
}

func TestSCAScanner_ConvertToViolations_Empty(t *testing.T) {
	s := &SCAScanner{}

	violations := s.convertToViolations([]types.Vulnerability{})
	if len(violations) != 0 {
		t.Errorf("Expected 0 violations for empty input, got %d", len(violations))
	}
}

func TestConvertToCycloneDX(t *testing.T) {
	result := &types.SBOMResult{
		Components: []types.Library{
			{
				Name:       "lodash",
				Version:    "4.17.21",
				Type:       "library",
				PackageURL: "pkg:npm/lodash@4.17.21",
				Language:   "javascript",
			},
			{
				Name:    "fmt",
				Version: "0.0.0",
				Type:    "library",
			},
		},
	}

	cdx := convertToCycloneDX(result)

	if cdx["bomFormat"] != "CycloneDX" {
		t.Errorf("Expected bomFormat=CycloneDX, got %v", cdx["bomFormat"])
	}
	if cdx["specVersion"] != "1.5" {
		t.Errorf("Expected specVersion=1.5, got %v", cdx["specVersion"])
	}

	components, ok := cdx["components"].([]map[string]any)
	if !ok {
		t.Fatalf("Expected components to be []map[string]any")
	}
	if len(components) != 2 {
		t.Fatalf("Expected 2 components, got %d", len(components))
	}

	c0 := components[0]
	if c0["name"] != "lodash" {
		t.Errorf("Expected name=lodash, got %v", c0["name"])
	}
	if c0["purl"] != "pkg:npm/lodash@4.17.21" {
		t.Errorf("Expected purl set, got %v", c0["purl"])
	}
	if c0["properties"] == nil {
		t.Error("Expected properties set for component with language")
	}

	c1 := components[1]
	if c1["purl"] != nil {
		t.Error("Expected no purl for component without PackageURL")
	}
	if c1["properties"] != nil {
		t.Error("Expected no properties for component without language")
	}
}

func TestSCAScanner_ValidateSBOMFile(t *testing.T) {
	s := &SCAScanner{}

	t.Run("valid file", func(t *testing.T) {
		f, err := os.CreateTemp("", "test-sbom-*.json")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(f.Name())
		f.Close()

		if err := s.validateSBOMFile(f.Name()); err != nil {
			t.Errorf("Expected no error for valid file, got: %v", err)
		}
	})

	t.Run("directory instead of file", func(t *testing.T) {
		dir, err := os.MkdirTemp("", "test-sbom-dir-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)

		if err := s.validateSBOMFile(dir); err == nil {
			t.Error("Expected error for directory, got nil")
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		if err := s.validateSBOMFile("/nonexistent/path/sbom.json"); err == nil {
			t.Error("Expected error for nonexistent file, got nil")
		}
	})
}

func TestDeduplicateComponents(t *testing.T) {
	tests := []struct {
		name     string
		input    []types.Library
		expected int
	}{
		{
			name:     "empty input",
			input:    nil,
			expected: 0,
		},
		{
			name: "no duplicates",
			input: []types.Library{
				{Name: "a", PackageURL: "pkg:npm/a@1.0"},
				{Name: "b", PackageURL: "pkg:npm/b@2.0"},
			},
			expected: 2,
		},
		{
			name: "duplicate by purl",
			input: []types.Library{
				{Name: "a", PackageURL: "pkg:npm/a@1.0"},
				{Name: "a", PackageURL: "pkg:npm/a@1.0"},
				{Name: "b", PackageURL: "pkg:npm/b@2.0"},
			},
			expected: 2,
		},
		{
			name: "components without purl are always kept",
			input: []types.Library{
				{Name: "a"},
				{Name: "a"},
				{Name: "b", PackageURL: "pkg:npm/b@1.0"},
			},
			expected: 3,
		},
		{
			name: "mixed duplicates and unique",
			input: []types.Library{
				{Name: "a", PackageURL: "pkg:npm/a@1.0"},
				{Name: "b", PackageURL: "pkg:npm/b@2.0"},
				{Name: "a", PackageURL: "pkg:npm/a@1.0"},
				{Name: "c"},
				{Name: "b", PackageURL: "pkg:npm/b@2.0"},
			},
			expected: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := deduplicateComponents(tt.input)
			if len(result) != tt.expected {
				t.Errorf("expected %d components, got %d", tt.expected, len(result))
			}
		})
	}
}

func TestDeduplicateComponents_PreservesOrder(t *testing.T) {
	input := []types.Library{
		{Name: "first", PackageURL: "pkg:npm/first@1.0"},
		{Name: "second", PackageURL: "pkg:npm/second@1.0"},
		{Name: "first-dup", PackageURL: "pkg:npm/first@1.0"},
		{Name: "third", PackageURL: "pkg:npm/third@1.0"},
	}
	result := deduplicateComponents(input)
	if len(result) != 3 {
		t.Fatalf("expected 3 components, got %d", len(result))
	}
	if result[0].Name != "first" {
		t.Errorf("expected first component to be 'first', got %q", result[0].Name)
	}
	if result[1].Name != "second" {
		t.Errorf("expected second component to be 'second', got %q", result[1].Name)
	}
	if result[2].Name != "third" {
		t.Errorf("expected third component to be 'third', got %q", result[2].Name)
	}
}

func TestSCAScanner_Execute_ContextCancellation(t *testing.T) {
	binMgr := binary.NewManager(binary.BinaryTypeSecurity)
	s := NewSCAScanner(binMgr)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	args := ScanArgs{
		FilePaths:  []string{"."},
		WorkingDir: ".",
	}

	_, err := s.Execute(ctx, args)
	if err == nil {
		t.Error("Expected an error due to context cancellation, got nil")
	}
}
