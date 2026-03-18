package libraryscan

import (
	"encoding/json"
	"fmt"
)

// mcpScanResult is the top-level structure of the MCP-optimized scan result response (version 1).
// Libraries are keyed by PURL; vulnerabilities are keyed by advisory ID and deduplicated
// across all libraries.
type mcpScanResult struct {
	Version         int                            `json:"version"`
	Libraries       map[string]mcpLibraryResult    `json:"libraries"`
	Vulnerabilities map[string]mcpVulnerabilityDef `json:"vulnerabilities"`
}

type mcpLibraryResult struct {
	Name            string       `json:"name"`
	Version         string       `json:"version"`
	Ecosystem       string       `json:"ecosystem"`
	Relation        string       `json:"relation"`
	Vulnerabilities []mcpVulnRef `json:"vulnerabilities"`
}

type mcpVulnRef struct {
	AdvisoryID       string           `json:"advisoryId"`
	FixVersion       string           `json:"fixVersion"`
	HasRemediation   bool             `json:"hasRemediation"`
	FixType          string           `json:"fixType"`
	Remediations     []mcpRemediation `json:"remediations"`
	Reachability     string           `json:"reachability"`
	DatadogScore     float64          `json:"datadogScore"`
	ExploitAvailable *bool            `json:"exploitAvailable"`
	ExploitPoC       *bool            `json:"exploitPoC"`
}

type mcpRemediation struct {
	LibraryName    string `json:"libraryName"`
	LibraryVersion string `json:"libraryVersion"`
	Type           string `json:"type"`
}

type mcpVulnerabilityDef struct {
	ID       string   `json:"id"`
	CVE      string   `json:"cve"`
	Summary  string   `json:"summary"`
	Severity string   `json:"severity"`
	CVSSScore float64 `json:"cvssScore"`
	CWEs     []string `json:"cwes"`
}

// parseResponse parses the MCP-optimized JSON response from the poll endpoint.
func parseResponse(body []byte) (*ScanResult, error) {
	var raw mcpScanResult
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse scan result: %w", err)
	}

	if len(raw.Libraries) == 0 {
		return &ScanResult{RawResponse: string(body)}, nil
	}

	var findings []VulnerabilityFinding
	for purl, lib := range raw.Libraries {
		for _, vulnRef := range lib.Vulnerabilities {
			finding := VulnerabilityFinding{
				GHSAID:           vulnRef.AdvisoryID,
				LibraryPURL:      purl,
				LibraryName:      lib.Name,
				LibraryVersion:   lib.Version,
				Ecosystem:        lib.Ecosystem,
				Relation:         lib.Relation,
				DatadogScore:     vulnRef.DatadogScore,
				Reachability:     vulnRef.Reachability,
				ExploitAvailable: vulnRef.ExploitAvailable,
				ExploitPoC:       vulnRef.ExploitPoC,
				FixVersion:       vulnRef.FixVersion,
				HasRemediation:   vulnRef.HasRemediation,
				FixType:          vulnRef.FixType,
			}

			// Enrich from deduplicated vulnerability definition
			if vulnDef, ok := raw.Vulnerabilities[vulnRef.AdvisoryID]; ok {
				finding.CVE = vulnDef.CVE
				finding.Summary = vulnDef.Summary
				finding.Severity = vulnDef.Severity
				finding.CVSSScore = vulnDef.CVSSScore
				finding.CWEs = vulnDef.CWEs
			}

			// Extract closest and latest fix versions from structured remediations
			for _, r := range vulnRef.Remediations {
				switch r.Type {
				case "closest_no_vulnerabilities":
					finding.ClosestFixVersion = r.LibraryVersion
				case "latest_no_vulnerabilities":
					finding.LatestFixVersion = r.LibraryVersion
				}
			}

			findings = append(findings, finding)
		}
	}

	return &ScanResult{Findings: findings, RawResponse: string(body)}, nil
}
