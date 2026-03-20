package main

import (
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/libraryscan"
)

// extractResultText joins all TextContent blocks from a CallToolResult into one string.
func extractResultText(result *mcp.CallToolResult) string {
	var sb strings.Builder
	for _, c := range result.Content {
		if tc, ok := c.(mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String()
}

func TestFormatLibraryScanResult_NoFindings(t *testing.T) {
	result := &libraryscan.ScanResult{}
	toolResult := formatLibraryScanResult(result)

	if toolResult == nil {
		t.Fatal("expected non-nil result")
	}
	if toolResult.IsError {
		t.Error("expected non-error result for empty findings")
	}
	text := extractResultText(toolResult)
	if strings.Contains(text, "%s") {
		t.Error("result contains an unformatted format verb placeholder")
	}
	if !strings.Contains(text, "No vulnerabilities found") {
		t.Errorf("expected 'No vulnerabilities found' in output, got: %q", text)
	}
}

func TestFormatLibraryScanResult_SingleFinding(t *testing.T) {
	exploitTrue := true
	result := &libraryscan.ScanResult{
		Libraries: []libraryscan.LibraryInfo{
			{
				Name:      "lodash",
				Version:   "4.17.20",
				Ecosystem: "npm",
				Relation:  "direct",
				Vulnerabilities: []libraryscan.VulnerabilityDetail{
					{
						GHSAID:            "GHSA-test-1234-5678",
						CVE:               "CVE-2024-1234",
						Severity:          "High",
						CVSSScore:         8.1,
						DatadogScore:      7.5,
						Summary:           "Prototype pollution",
						ClosestFixVersion: "4.17.21",
						LatestFixVersion:  "4.17.21",
						ExploitAvailable:  &exploitTrue,
					},
				},
			},
		},
	}

	toolResult := formatLibraryScanResult(result)
	if toolResult.IsError {
		t.Error("expected non-error result")
	}
	text := extractResultText(toolResult)

	checks := []string{
		"GHSA-test-1234-5678",
		"CVE-2024-1234",
		"lodash",
		"4.17.20",
		"High",
		"8.1",
		"7.5",
		"Prototype pollution",
		"4.17.21",
		"Exploit available",
	}
	for _, want := range checks {
		if !strings.Contains(text, want) {
			t.Errorf("expected %q in output", want)
		}
	}
}

func TestFormatLibraryScanResult_SeveritySummary(t *testing.T) {
	result := &libraryscan.ScanResult{
		Libraries: []libraryscan.LibraryInfo{
			{
				Name: "lib-a", Version: "1.0",
				Vulnerabilities: []libraryscan.VulnerabilityDetail{
					{GHSAID: "GHSA-1", Severity: "Critical"},
					{GHSAID: "GHSA-2", Severity: "Critical"},
				},
			},
			{
				Name: "lib-b", Version: "1.0",
				Vulnerabilities: []libraryscan.VulnerabilityDetail{
					{GHSAID: "GHSA-3", Severity: "High"},
					{GHSAID: "GHSA-4", Severity: "Low"},
				},
			},
		},
	}

	toolResult := formatLibraryScanResult(result)
	text := extractResultText(toolResult)

	if !strings.Contains(text, "Critical") {
		t.Error("expected Critical in summary")
	}
	if !strings.Contains(text, "High") {
		t.Error("expected High in summary")
	}
	if !strings.Contains(text, "Low") {
		t.Error("expected Low in summary")
	}
	// Total should be 4
	if !strings.Contains(text, "**4**") {
		t.Errorf("expected bold total count **4** in output, got: %s", text)
	}
}

func TestFormatLibraryScanResult_NoUnformattedPlaceholders(t *testing.T) {
	// Regression: ensure no %s/%d/%v placeholders leak into output.
	exploitFalse := false
	cases := []*libraryscan.ScanResult{
		{},
		{
			Libraries: []libraryscan.LibraryInfo{
				{
					Name:      "pkg",
					Version:   "1.0",
					Ecosystem: "npm",
					Relation:  "direct",
					Vulnerabilities: []libraryscan.VulnerabilityDetail{
						{
							GHSAID:           "GHSA-x",
							CVE:              "CVE-2024-0001",
							Severity:         "Medium",
							ExploitAvailable: &exploitFalse,
						},
					},
				},
			},
		},
	}
	for _, result := range cases {
		toolResult := formatLibraryScanResult(result)
		text := extractResultText(toolResult)
		for _, placeholder := range []string{"%s", "%d", "%v", "%w"} {
			if strings.Contains(text, placeholder) {
				t.Errorf("output contains unformatted placeholder %q", placeholder)
			}
		}
	}
}

func TestFormatLibraryScanResult_UnsupportedVersion_ShowsRaw(t *testing.T) {
	raw := `{"version": 99, "libraries": {}, "vulnerabilities": {}}`
	result := &libraryscan.ScanResult{
		UnsupportedVersion: 99,
		RawResponse:        raw,
	}

	toolResult := formatLibraryScanResult(result)
	if toolResult.IsError {
		t.Error("expected non-error result")
	}
	text := extractResultText(toolResult)

	if !strings.Contains(text, "Unsupported response version 99") {
		t.Error("expected unsupported version warning in output")
	}
	if !strings.Contains(text, raw) {
		t.Error("expected raw JSON to be included in output")
	}
	if strings.Contains(text, "No vulnerabilities found") {
		t.Error("should not show clean-scan message for unsupported version")
	}
}

func TestFormatLibraryScanResult_LibrariesTableShownWhenNoFindings(t *testing.T) {
	eolDate := "2025-01-01"
	result := &libraryscan.ScanResult{
		Libraries: []libraryscan.LibraryInfo{
			{
				Name:          "express",
				Version:       "4.18.0",
				Ecosystem:     "npm",
				LicenseID:     "MIT",
				LatestVersion: "5.0.0",
				Relation:      "direct",
			},
			{
				Name:      "old-pkg",
				Version:   "1.0.0",
				Ecosystem: "npm",
				LicenseID: "ISC",
				Relation:  "transitive",
				EolDate:   &eolDate,
			},
		},
	}

	text := extractResultText(formatLibraryScanResult(result))

	if !strings.Contains(text, "No vulnerabilities found") {
		t.Error("expected 'No vulnerabilities found' message")
	}
	if !strings.Contains(text, "Libraries Scanned (2)") {
		t.Error("expected library table header")
	}
	if !strings.Contains(text, "express") {
		t.Error("expected express in library table")
	}
	if !strings.Contains(text, "4.18.0") {
		t.Error("expected version 4.18.0 in library table")
	}
	if !strings.Contains(text, "5.0.0") {
		t.Error("expected latest version 5.0.0 in library table")
	}
	if !strings.Contains(text, "MIT") {
		t.Error("expected MIT license in library table")
	}
	if !strings.Contains(text, "EOL: 2025-01-01") {
		t.Error("expected EOL date for old-pkg")
	}
}

func TestFormatLibraryScanResult_LibrariesTableShownWithFindings(t *testing.T) {
	result := &libraryscan.ScanResult{
		Libraries: []libraryscan.LibraryInfo{
			{
				Name:      "vuln-lib",
				Version:   "1.0",
				Ecosystem: "npm",
				Relation:  "direct",
				Vulnerabilities: []libraryscan.VulnerabilityDetail{
					{GHSAID: "GHSA-x", Severity: "High"},
				},
			},
			{Name: "safe-lib", Version: "2.0", Ecosystem: "npm", Relation: "transitive"},
		},
	}

	text := extractResultText(formatLibraryScanResult(result))

	if !strings.Contains(text, "Libraries Scanned (2)") {
		t.Error("expected library table header")
	}
	if !strings.Contains(text, "vuln-lib") {
		t.Error("expected vuln-lib in output")
	}
	if !strings.Contains(text, "safe-lib") {
		t.Error("expected safe-lib in output")
	}
	// Library table should appear before the per-library vulnerability section
	libIdx := strings.Index(text, "Libraries Scanned")
	vulnIdx := strings.Index(text, "vuln-lib @ 1.0")
	if libIdx == -1 || vulnIdx == -1 || libIdx > vulnIdx {
		t.Error("expected Libraries Scanned section to appear before vulnerability details")
	}
}

func TestFormatLibraryScanResult_ExploitPoCShown(t *testing.T) {
	exploitTrue := true
	result := &libraryscan.ScanResult{
		Libraries: []libraryscan.LibraryInfo{
			{
				Name:    "vuln-lib",
				Version: "1.0",
				Vulnerabilities: []libraryscan.VulnerabilityDetail{
					{
						GHSAID:           "GHSA-poc",
						Severity:         "Critical",
						ExploitAvailable: &exploitTrue,
						ExploitPoC:       &exploitTrue,
					},
				},
			},
		},
	}

	text := extractResultText(formatLibraryScanResult(result))
	if !strings.Contains(text, "PoC exists") {
		t.Error("expected 'PoC exists' in output when ExploitPoC is true")
	}
}
