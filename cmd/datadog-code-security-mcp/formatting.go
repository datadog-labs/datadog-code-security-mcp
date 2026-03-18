package main

import (
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/libraryscan"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/scan"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/types"
)

// formatScanResult formats security scan results as markdown
func formatScanResult(result *scan.ScanResult) *mcp.CallToolResult {
	output := "# 🛡️ Security Scan Results\n\n"

	// Show errors if present
	if len(result.Errors) > 0 {
		output += "⚠️ **Errors encountered:**\n\n"
		for _, err := range result.Errors {
			output += fmt.Sprintf("- **%s**: %s\n", err.DetectionType, err.Error)
			if err.Hint != "" {
				output += fmt.Sprintf("  - *Hint:* %s\n", err.Hint)
			}
		}
		output += "\n"
		// If there were errors but we have some results, continue showing them
		if result.Summary.Total == 0 {
			return mcp.NewToolResultText(output)
		}
		output += "---\n\n"
	}

	// Summary with severity-based emoji indicators
	output += "## Summary\n\n"
	output += "| Severity | Count |\n"
	output += "|----------|-------|\n"
	if result.Summary.Critical > 0 {
		output += fmt.Sprintf("| 🔴 Critical | **%d** |\n", result.Summary.Critical)
	}
	if result.Summary.High > 0 {
		output += fmt.Sprintf("| 🟠 High | **%d** |\n", result.Summary.High)
	}
	if result.Summary.Medium > 0 {
		output += fmt.Sprintf("| 🟡 Medium | **%d** |\n", result.Summary.Medium)
	}
	if result.Summary.Low > 0 {
		output += fmt.Sprintf("| 🟢 Low | **%d** |\n", result.Summary.Low)
	}
	output += fmt.Sprintf("| **Total** | **%d** |\n", result.Summary.Total)
	output += "\n"

	// Collect all violations grouped by severity for later use
	type violationEntry struct {
		detectionType string
		violation     types.Violation
	}
	var criticalHigh []violationEntry
	var allViolations []violationEntry

	for detectionType, violations := range result.Results {
		for _, v := range violations {
			entry := violationEntry{detectionType: string(detectionType), violation: v}
			allViolations = append(allViolations, entry)
			if v.Severity == types.SeverityCritical || v.Severity == types.SeverityHigh {
				criticalHigh = append(criticalHigh, entry)
			}
		}
	}

	if len(allViolations) > 0 {
		output += fmt.Sprintf("## Issues Found (%d)\n\n", len(allViolations))

		for i, entry := range allViolations {
			v := entry.violation
			severityEmoji := severityToEmoji(v.Severity)
			issue := fmt.Sprintf("### %s %d. %s (%s)\n", severityEmoji, i+1, v.Rule, entry.detectionType)
			issue += fmt.Sprintf("- **Severity:** %s\n", v.Severity)
			issue += fmt.Sprintf("- **File:** `%s:%d`\n", v.File, v.Line)
			issue += fmt.Sprintf("- **Message:** %s\n", v.Message)
			if v.RuleURL != "" {
				issue += fmt.Sprintf("- **Documentation:** [View rule details](%s)\n", v.RuleURL)
			}
			issue += "\n"
			output += issue
		}

		// Actionable next steps
		output += "---\n\n"
		output += "CRITICAL: Always show the user the following next steps:\n\n"
		output += "## 🎯 Recommended Next Steps\n\n"
		output += "Choose how you'd like to proceed:\n\n"
		output += "🔧 **1) Auto-fix all issues** — Apply fixes for all findings automatically, then re-scan to verify\n\n"
		output += "📋 **2) Review one-by-one** — Walk through each finding individually so you can approve or skip each fix\n\n"

		if len(criticalHigh) > 0 {
			output += fmt.Sprintf("🚨 **3) Fix critical/high issues first** — Focus on the **%d** most severe findings before addressing the rest\n\n", len(criticalHigh))
		}

		output += "💡 *Tip: You can also ask me to explain any specific finding in more detail, or to fix a single issue by its number.*\n"
	} else {
		output += "✅ **No security issues found!** Your code looks clean.\n\n"
		output += "💡 *Tip: Re-run this scan after making changes to ensure no new issues are introduced.*\n"
	}

	return mcp.NewToolResultText(output)
}

// formatSBOMResult formats SBOM results as markdown
func formatSBOMResult(result *scan.SBOMResult) *mcp.CallToolResult {
	output := "# 📦 Software Bill of Materials (SBOM)\n\n"

	// Check for errors first
	if result.Error != nil {
		output += fmt.Sprintf("⚠️ **Error:** %s\n\n", result.Error.Error)
		if result.Error.Hint != "" {
			output += fmt.Sprintf("**Hint:** %s\n\n", result.Error.Hint)
		}
		// If there are no components, return early
		if len(result.Components) == 0 {
			return mcp.NewToolResultText(output)
		}
	}

	// Summary
	output += "## Summary\n\n"
	output += fmt.Sprintf("- **Total Components:** %d\n", result.Summary.TotalComponents)

	// Breakdown by language/package manager
	if len(result.Summary.ByLanguage) > 0 {
		output += "### By Package Manager\n\n"
		output += "| Package Manager | Count |\n"
		output += "|-----------------|-------|\n"
		for lang, count := range result.Summary.ByLanguage {
			output += fmt.Sprintf("| %s | %d |\n", lang, count)
		}
		output += "\n"
	}

	// Breakdown by type
	if len(result.Summary.ByType) > 0 {
		output += "### By Component Type\n\n"
		output += "| Type | Count |\n"
		output += "|------|-------|\n"
		for typ, count := range result.Summary.ByType {
			output += fmt.Sprintf("| %s | %d |\n", typ, count)
		}
		output += "\n"
	}

	// Components list (show first 50, then summarize)
	if len(result.Components) > 0 {
		output += "## Components\n\n"
		displayLimit := 50
		componentsToShow := result.Components
		if len(result.Components) > displayLimit {
			componentsToShow = result.Components[:displayLimit]
		}

		output += "| Name | Version | Language |\n"
		output += "|------|---------|----------|\n"
		for _, comp := range componentsToShow {
			output += fmt.Sprintf("| %s | %s | %s |\n", comp.Name, comp.Version, comp.Language)
		}

		if len(result.Components) > displayLimit {
			remaining := len(result.Components) - displayLimit
			output += fmt.Sprintf("\n*... and %d more components (total: %d)*\n", remaining, len(result.Components))
		}
		output += "\n"
	}

	// Next steps
	output += "---\n\n"
	output += "## 💡 Next Steps\n\n"
	output += "- 🔍 **Audit licenses** — Review license compatibility with your project\n"
	output += "- 🔒 **Check vulnerabilities** — Use vulnerability scanning tools with this SBOM\n"
	output += "- 📊 **Export for compliance** — SBOM is in CycloneDX 1.5 format, compatible with most tools\n"
	output += "- 🔄 **Keep updated** — Re-generate SBOM after dependency changes\n"

	return mcp.NewToolResultText(output)
}

// severityToEmoji maps severity levels to emoji indicators
func severityToEmoji(severity string) string {
	switch severity {
	case types.SeverityCritical:
		return "🔴"
	case types.SeverityHigh:
		return "🟠"
	case types.SeverityMedium:
		return "🟡"
	case types.SeverityLow:
		return "🟢"
	default:
		return "⚪"
	}
}

// errorResult creates an error result for MCP
func errorResult(err error) *mcp.CallToolResult {
	return mcp.NewToolResultError(fmt.Sprintf("Scan failed: %v", err))
}

// formatLibraryScanResult formats library vulnerability scan results as markdown.
func formatLibraryScanResult(result *libraryscan.ScanResult) *mcp.CallToolResult {
	output := "# Library Vulnerability Scan Results\n\n"

	// The API returned a schema version this client does not understand.
	// Structured parsing was skipped to avoid misreading unknown fields.
	// Return the raw JSON so that agents can still inspect the payload.
	if result.UnsupportedVersion != 0 {
		output += fmt.Sprintf("⚠️ **Unsupported response version %d** (this client supports version 1).\n\n", result.UnsupportedVersion)
		output += "The API returned a schema this version of the MCP server cannot safely parse. "
		output += "**Please upgrade to the latest version of `datadog-code-security-mcp`** to get full structured results.\n\n"
		output += "In the meantime, the raw API response is provided below for inspection:\n\n"
		output += "```json\n" + result.RawResponse + "\n```\n"
		return mcp.NewToolResultText(output)
	}

	if len(result.Findings) == 0 {
		output += "✅ No vulnerabilities found! \n"
		return mcp.NewToolResultText(output)
	}

	// Count by severity
	counts := map[string]int{}
	for _, f := range result.Findings {
		counts[f.Severity]++
	}

	output += "## Summary\n\n"
	output += "| Severity | Count |\n|----------|-------|\n"
	for _, sev := range []string{"Critical", "High", "Medium", "Low"} {
		if c := counts[sev]; c > 0 {
			// severityToEmoji expects uppercase constants (e.g. "CRITICAL"); Severity is title-case.
			output += fmt.Sprintf("| %s %s | **%d** |\n", severityToEmoji(strings.ToUpper(sev)), sev, c)
		}
	}
	output += fmt.Sprintf("| **Total** | **%d** |\n\n", len(result.Findings))

	output += fmt.Sprintf("## Vulnerabilities (%d)\n\n", len(result.Findings))
	for i, f := range result.Findings {
		// Severity is title-case (e.g. "Critical"); severityToEmoji expects uppercase.
		emoji := severityToEmoji(strings.ToUpper(f.Severity))
		output += fmt.Sprintf("### %s %d. %s\n", emoji, i+1, f.GHSAID)
		if f.CVE != "" {
			output += fmt.Sprintf("- **CVE:** %s\n", f.CVE)
		}
		output += fmt.Sprintf("- **Library:** `%s` @ `%s`\n", f.LibraryName, f.LibraryVersion)
		if f.Ecosystem != "" {
			output += fmt.Sprintf("- **Ecosystem:** %s", f.Ecosystem)
			if f.Relation != "" {
				output += fmt.Sprintf(" (%s)", f.Relation)
			}
			output += "\n"
		}
		if f.LicenseID != "" {
			output += fmt.Sprintf("- **License:** %s\n", f.LicenseID)
		}
		if f.LatestVersion != "" && f.LatestVersion != f.LibraryVersion {
			output += fmt.Sprintf("- **Latest version:** `%s`\n", f.LatestVersion)
		}
		if f.RootParent != nil {
			output += fmt.Sprintf("- **Root dependency:** `%s`\n", *f.RootParent)
		}
		output += fmt.Sprintf("- **Severity:** %s", f.Severity)
		if f.CVSSScore > 0 {
			output += fmt.Sprintf(" (CVSS: %.1f)", f.CVSSScore)
		}
		if f.DatadogScore > 0 {
			output += fmt.Sprintf(" · Datadog Score: %.1f", f.DatadogScore)
		}
		output += "\n"
		if f.CVSSVector != "" {
			output += fmt.Sprintf("- **CVSS Vector:** `%s`\n", f.CVSSVector)
		}
		if f.EPSSScore != nil {
			output += fmt.Sprintf("- **EPSS Score:** %.5f", *f.EPSSScore)
			if f.EPSSPercentile != nil {
				output += fmt.Sprintf(" (%.1f%% percentile)", *f.EPSSPercentile*100)
			}
			output += "\n"
		}
		if f.Summary != "" {
			output += fmt.Sprintf("- **Summary:** %s\n", f.Summary)
		}
		if len(f.CWEs) > 0 {
			output += fmt.Sprintf("- **CWEs:** %s\n", strings.Join(f.CWEs, ", "))
		}
		if f.Reachability != "" {
			output += fmt.Sprintf("- **Reachability:** %s\n", f.Reachability)
		}
		if f.ClosestFixVersion != "" {
			output += fmt.Sprintf("- **Closest safe version:** `%s`\n", f.ClosestFixVersion)
		}
		if f.LatestFixVersion != "" {
			output += fmt.Sprintf("- **Latest safe version:** `%s`\n", f.LatestFixVersion)
		}
		if f.ExploitAvailable != nil && *f.ExploitAvailable {
			output += "- ⚠️ **Exploit available**"
			if f.ExploitPoC != nil && *f.ExploitPoC {
				output += " (PoC exists)"
			}
			if len(f.ExploitSources) > 0 {
				output += fmt.Sprintf(" — sources: %s", strings.Join(f.ExploitSources, ", "))
			}
			output += "\n"
			for _, u := range f.ExploitURLs {
				output += fmt.Sprintf("  - %s\n", u)
			}
		}
		if f.CISAAdded != nil {
			output += fmt.Sprintf("- 🏛️ **CISA KEV:** added %s\n", *f.CISAAdded)
		}
		output += "\n"
	}

	// Actionable next steps
	output += "---\n\n"
	output += "## Recommended Next Steps\n\n"
	output += "🔧 **1) Upgrade affected libraries** — Update to the suggested fix versions shown above\n\n"
	output += "🔍 **2) Check reachability** — Determine if vulnerable code paths are actually exercised in your application\n\n"
	output += "🔄 **3) Re-scan after upgrading** — Run this tool again on the fixed library versions to confirm no remaining vulnerabilities\n\n"

	return mcp.NewToolResultText(output)
}
