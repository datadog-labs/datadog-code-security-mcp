package libraryscan

import (
	"encoding/json"
	"fmt"
	"sort"
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
	Name          string       `json:"name"`
	Version       string       `json:"version"`
	Ecosystem     string       `json:"ecosystem"`
	LicenseID     string       `json:"licenseId"`
	OpenSSFLevel  string       `json:"openssfLevel"`
	Popularity    string       `json:"popularity"`
	LatestVersion string       `json:"latestVersion"`
	EolDate       *string      `json:"eolDate"`
	Relation      string       `json:"relation"`
	RootParent    *string      `json:"rootParent"`
	TraversalPath *string      `json:"traversalPath"`
	Risks         []string     `json:"risks"`
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
	CVE            string   `json:"cve"`
	Summary        string   `json:"summary"`
	Severity       string   `json:"severity"`
	CVSSScore      float64  `json:"cvssScore"`
	CVSSVector     string   `json:"cvssVector"`
	CWEs           []string `json:"cwes"`
	EPSSScore      *float64 `json:"epssScore"`
	EPSSPercentile *float64 `json:"epssPercentile"`
	ExploitSources []string `json:"exploitSources"`
	ExploitURLs    []string `json:"exploitUrls"`
	CISAAdded      *string  `json:"cisaAdded"`
}

// supportedVersion is the only McpScanResult schema version this client can safely parse.
// Per the schema contract: if the response version is higher than expected, the consumer
// must reject structured parsing and degrade gracefully rather than misread unknown fields.
const supportedVersion = 1

// parseResponse parses the MCP-optimized JSON response from the poll endpoint.
// If the response carries an unsupported schema version, structured parsing is skipped
// and only the raw JSON is returned so that agents can still inspect the payload directly.
func parseResponse(body []byte) (*ScanResult, error) {
	var raw mcpScanResult
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse scan result: %w", err)
	}

	// Version 0 means the field is absent (legacy/pre-versioned response) — treat as no data.
	// Any version above what we support must not be structurally parsed.
	if raw.Version != 0 && raw.Version != supportedVersion {
		return &ScanResult{RawResponse: string(body), UnsupportedVersion: raw.Version}, nil
	}

	if len(raw.Libraries) == 0 {
		return &ScanResult{}, nil
	}

	var libraries []LibraryInfo
	for purl, lib := range raw.Libraries {
		var vulns []VulnerabilityDetail
		for _, vulnRef := range lib.Vulnerabilities {
			detail := VulnerabilityDetail{
				GHSAID:           vulnRef.AdvisoryID,
				DatadogScore:     vulnRef.DatadogScore,
				Reachability:     vulnRef.Reachability,
				ExploitAvailable: vulnRef.ExploitAvailable,
				ExploitPoC:       vulnRef.ExploitPoC,
				FixVersion:       vulnRef.FixVersion,
				HasRemediation:   vulnRef.HasRemediation,
				FixType:          vulnRef.FixType,
			}

			// Enrich from the deduplicated advisory definition
			if vulnDef, ok := raw.Vulnerabilities[vulnRef.AdvisoryID]; ok {
				detail.CVE = vulnDef.CVE
				detail.Summary = vulnDef.Summary
				detail.Severity = vulnDef.Severity
				detail.CVSSScore = vulnDef.CVSSScore
				detail.CVSSVector = vulnDef.CVSSVector
				detail.CWEs = vulnDef.CWEs
				detail.EPSSScore = vulnDef.EPSSScore
				detail.EPSSPercentile = vulnDef.EPSSPercentile
				detail.ExploitSources = vulnDef.ExploitSources
				detail.ExploitURLs = vulnDef.ExploitURLs
				detail.CISAAdded = vulnDef.CISAAdded
			}

			// Extract closest and latest fix versions from structured remediations
			for _, r := range vulnRef.Remediations {
				switch r.Type {
				case "closest_no_vulnerabilities":
					detail.ClosestFixVersion = r.LibraryVersion
				case "latest_no_vulnerabilities":
					detail.LatestFixVersion = r.LibraryVersion
				}
			}

			vulns = append(vulns, detail)
		}

		libraries = append(libraries, LibraryInfo{
			PURL:            purl,
			Name:            lib.Name,
			Version:         lib.Version,
			Ecosystem:       lib.Ecosystem,
			LicenseID:       lib.LicenseID,
			OpenSSFLevel:    lib.OpenSSFLevel,
			Popularity:      lib.Popularity,
			LatestVersion:   lib.LatestVersion,
			EolDate:         lib.EolDate,
			Relation:        lib.Relation,
			RootParent:      lib.RootParent,
			TraversalPath:   lib.TraversalPath,
			Risks:           lib.Risks,
			Vulnerabilities: vulns,
		})
	}

	// Sort libraries: most vulnerabilities first, then alphabetically for deterministic output.
	sort.Slice(libraries, func(i, j int) bool {
		if len(libraries[i].Vulnerabilities) != len(libraries[j].Vulnerabilities) {
			return len(libraries[i].Vulnerabilities) > len(libraries[j].Vulnerabilities)
		}
		return libraries[i].Name < libraries[j].Name
	})

	return &ScanResult{Libraries: libraries}, nil
}
