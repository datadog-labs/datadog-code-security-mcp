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
	result := &libraryscan.ScanResult{Findings: nil}
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
	result := &libraryscan.ScanResult{
		Findings: []libraryscan.VulnerabilityFinding{
			{
				GHSAID:            "GHSA-test-1234-5678",
				CVEAliases:        []string{"CVE-2024-1234"},
				LibraryName:       "lodash",
				LibraryVersion:    "4.17.20",
				Severity:          "High",
				CVSSScore:         8.1,
				Summary:           "Prototype pollution",
				Remediation:       "Upgrade to 4.17.21",
				ClosestFixVersion: "4.17.21",
				LatestFixVersion:  "4.17.21",
				ExploitAvailable:  true,
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
		"Prototype pollution",
		"Upgrade to 4.17.21",
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
		Findings: []libraryscan.VulnerabilityFinding{
			{GHSAID: "GHSA-1", Severity: "Critical", LibraryName: "a", LibraryVersion: "1.0"},
			{GHSAID: "GHSA-2", Severity: "Critical", LibraryName: "b", LibraryVersion: "1.0"},
			{GHSAID: "GHSA-3", Severity: "High", LibraryName: "c", LibraryVersion: "1.0"},
			{GHSAID: "GHSA-4", Severity: "Low", LibraryName: "d", LibraryVersion: "1.0"},
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
	cases := []*libraryscan.ScanResult{
		{Findings: nil},
		{Findings: []libraryscan.VulnerabilityFinding{
			{GHSAID: "GHSA-x", Severity: "Medium", LibraryName: "pkg", LibraryVersion: "1.0"},
		}},
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
