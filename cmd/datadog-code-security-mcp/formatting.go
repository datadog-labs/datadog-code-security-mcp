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

	// Collect all violations for display
	type violationEntry struct {
		detectionType string
		violation     types.Violation
	}
	var allViolations []violationEntry

	for detectionType, violations := range result.Results {
		for _, v := range violations {
			allViolations = append(allViolations, violationEntry{detectionType: string(detectionType), violation: v})
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

// formatLibrariesTable renders a markdown table of all scanned libraries.
// Returns an empty string when the slice is empty.
func formatLibrariesTable(libraries []libraryscan.LibraryInfo) string {
	if len(libraries) == 0 {
		return ""
	}

	out := fmt.Sprintf("## Libraries Scanned (%d)\n\n", len(libraries))
	out += "| Library | Version | Latest | Ecosystem | License | Popularity | Relation | Root Parent | Risks | Vulnerabilities |\n"
	out += "|---------|---------|--------|-----------|---------|------------|----------|-------------|-------|-----------------|\n"

	for _, lib := range libraries {
		latest := lib.LatestVersion
		if latest == "" || latest == lib.Version {
			latest = "—"
		}
		license := lib.LicenseID
		if license == "" {
			license = "—"
		}
		popularity := lib.Popularity
		if popularity == "" {
			popularity = "—"
		}
		relation := lib.Relation
		if relation == "" {
			relation = "—"
		}
		rootParent := "—"
		if lib.RootParent != nil && *lib.RootParent != "" {
			rootParent = *lib.RootParent
		}
		risks := "—"
		if len(lib.Risks) > 0 {
			risks = strings.Join(lib.Risks, ", ")
		}
		vulnCount := len(lib.Vulnerabilities)
		vulnCell := "✅ 0"
		if vulnCount > 0 {
			vulnCell = fmt.Sprintf("⚠️ %d", vulnCount)
		}
		name := lib.Name
		if lib.EolDate != nil {
			name = fmt.Sprintf("%s *(EOL: %s)*", lib.Name, *lib.EolDate)
		}
		out += fmt.Sprintf("| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
			name, lib.Version, latest, lib.Ecosystem, license, popularity, relation, rootParent, risks, vulnCell)
	}
	out += "\n"
	return out
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

	// Count total vulnerabilities and by severity across all libraries
	totalVulns := 0
	counts := map[string]int{}
	for _, lib := range result.Libraries {
		for _, v := range lib.Vulnerabilities {
			totalVulns++
			counts[v.Severity]++
		}
	}

	if totalVulns == 0 {
		output += "✅ No vulnerabilities found!\n\n"
		output += formatLibrariesTable(result.Libraries)
		return mcp.NewToolResultText(output)
	}

	output += "## Summary\n\n"
	output += "| Severity | Count |\n|----------|-------|\n"
	for _, sev := range []string{"Critical", "High", "Medium", "Low"} {
		if c := counts[sev]; c > 0 {
			// severityToEmoji expects uppercase constants (e.g. "CRITICAL"); Severity is title-case.
			output += fmt.Sprintf("| %s %s | **%d** |\n", severityToEmoji(strings.ToUpper(sev)), sev, c)
		}
	}
	output += fmt.Sprintf("| **Total** | **%d** |\n\n", totalVulns)

	output += formatLibrariesTable(result.Libraries)

	// Vulnerabilities grouped by library
	vulnIdx := 1
	for _, lib := range result.Libraries {
		if len(lib.Vulnerabilities) == 0 {
			continue
		}
		vulnWord := "vulnerability"
		if len(lib.Vulnerabilities) != 1 {
			vulnWord = "vulnerabilities"
		}
		output += fmt.Sprintf("## 📦 %s @ %s (%d %s)\n\n", lib.Name, lib.Version, len(lib.Vulnerabilities), vulnWord)
		if len(lib.Risks) > 0 {
			output += fmt.Sprintf("- **Risks:** %s\n\n", strings.Join(lib.Risks, ", "))
		}

		for _, v := range lib.Vulnerabilities {
			emoji := severityToEmoji(strings.ToUpper(v.Severity))
			output += fmt.Sprintf("### %s %d. %s\n", emoji, vulnIdx, v.GHSAID)
			vulnIdx++
			if v.CVE != "" {
				output += fmt.Sprintf("- **CVE:** %s\n", v.CVE)
			}
			output += fmt.Sprintf("- **Severity:** %s", v.Severity)
			if v.CVSSScore > 0 {
				output += fmt.Sprintf(" (CVSS: %.1f)", v.CVSSScore)
			}
			if v.DatadogScore > 0 {
				output += fmt.Sprintf(" · Datadog Score: %.1f", v.DatadogScore)
			}
			output += "\n"
			if v.CVSSVector != "" {
				output += fmt.Sprintf("- **CVSS Vector:** `%s`\n", v.CVSSVector)
			}
			if v.EPSSScore != nil {
				output += fmt.Sprintf("- **EPSS Score:** %.5f", *v.EPSSScore)
				if v.EPSSPercentile != nil {
					output += fmt.Sprintf(" (%.1f%% percentile)", *v.EPSSPercentile*100)
				}
				output += "\n"
			}
			if v.Summary != "" {
				output += fmt.Sprintf("- **Summary:** %s\n", v.Summary)
			}
			if len(v.CWEs) > 0 {
				output += fmt.Sprintf("- **CWEs:** %s\n", strings.Join(v.CWEs, ", "))
			}
			if v.Reachability != "" {
				output += fmt.Sprintf("- **Reachability:** %s\n", v.Reachability)
			}
			if v.ClosestFixVersion != "" {
				output += fmt.Sprintf("- **Closest safe version:** `%s`\n", v.ClosestFixVersion)
			}
			if v.LatestFixVersion != "" {
				output += fmt.Sprintf("- **Latest safe version:** `%s`\n", v.LatestFixVersion)
			}
			if v.ExploitAvailable != nil && *v.ExploitAvailable {
				output += "- ⚠️ **Exploit available**"
				if v.ExploitPoC != nil && *v.ExploitPoC {
					output += " (PoC exists)"
				}
				if len(v.ExploitSources) > 0 {
					output += fmt.Sprintf(" — sources: %s", strings.Join(v.ExploitSources, ", "))
				}
				output += "\n"
				for _, u := range v.ExploitURLs {
					output += fmt.Sprintf("  - %s\n", u)
				}
			}
			if v.CISAAdded != nil {
				output += fmt.Sprintf("- 🏛️ **CISA KEV:** added %s\n", *v.CISAAdded)
			}
			output += "\n"
		}
	}

	return mcp.NewToolResultText(output)
}
