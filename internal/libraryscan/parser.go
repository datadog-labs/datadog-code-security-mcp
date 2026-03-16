package libraryscan

import (
	"encoding/json"
	"fmt"
)

// enrichedResult is the top-level structure of the GET scan result response.
// Only the fields we actually use are decoded; the rest are ignored.
type enrichedResult struct {
	VulnerabilityDetection *vulnerabilityDetection `json:"VULNERABILITY_DETECTION"`
	ScoreEnricher          *scoreEnricher          `json:"SCORE_ENRICHER"`
	RemediationEnricher    *remediationEnricher    `json:"REMEDIATION_ENRICHER"`
}

type vulnerabilityDetection struct {
	Advisories []advisory `json:"advisories"`
}

type advisory struct {
	ComponentInput componentInput `json:"componentInput"`
	OsvAdvisory    osvAdvisory    `json:"osvAdvisory"`
	Remediation    string         `json:"remediation"`
	Hash           string         `json:"hash"`
}

type componentInput struct {
	ComponentName    string `json:"componentName"`
	ComponentVersion string `json:"componentVersion"`
	Purl             string `json:"purl"`
}

type osvAdvisory struct {
	ID               string     `json:"id"`
	Aliases          []string   `json:"aliases"`
	Summary          string     `json:"summary"`
	Details          string     `json:"details"`
	DatabaseSpecific dbSpecific `json:"databaseSpecific"`
}

type dbSpecific struct {
	Severity string `json:"severity"`
}

type scoreEnricher struct {
	VulnerabilityHashToDatadogScore map[string]datadogScoreEntry `json:"vulnerabilityHashToDatadogScore"`
}

type datadogScoreEntry struct {
	Score            scoreDetails `json:"score"`
	ExploitAvailable bool         `json:"exploitAvailable"`
}

type scoreDetails struct {
	Score    float64 `json:"score"`
	Severity string  `json:"severity"`
}

type remediationEnricher struct {
	VulnerabilityHashToRemediations map[string][]remediationEntry `json:"vulnerabilityHashToRemediations"`
}

type remediationEntry struct {
	Remediation remediationDetails `json:"remediation"`
}

type remediationDetails struct {
	Type           string `json:"type"`
	LibraryVersion string `json:"library_version"`
}

// parseResponse parses the enriched JSON response from the poll endpoint.
func parseResponse(body []byte) (*ScanResult, error) {
	var raw enrichedResult
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse scan result: %w", err)
	}

	if raw.VulnerabilityDetection == nil {
		return &ScanResult{RawResponse: string(body)}, nil
	}

	findings := make([]VulnerabilityFinding, 0, len(raw.VulnerabilityDetection.Advisories))
	for _, adv := range raw.VulnerabilityDetection.Advisories {
		finding := VulnerabilityFinding{
			GHSAID:         adv.OsvAdvisory.ID,
			CVEAliases:     adv.OsvAdvisory.Aliases,
			Summary:        adv.OsvAdvisory.Summary,
			Details:        adv.OsvAdvisory.Details,
			LibraryPURL:    adv.ComponentInput.Purl,
			LibraryName:    adv.ComponentInput.ComponentName,
			LibraryVersion: adv.ComponentInput.ComponentVersion,
			Severity:       adv.OsvAdvisory.DatabaseSpecific.Severity,
			Remediation:    adv.Remediation,
		}

		// SCORE_ENRICHER overrides severity with Datadog's enriched score
		if raw.ScoreEnricher != nil {
			if entry, ok := raw.ScoreEnricher.VulnerabilityHashToDatadogScore[adv.Hash]; ok {
				finding.Severity = entry.Score.Severity
				finding.CVSSScore = entry.Score.Score
				finding.ExploitAvailable = entry.ExploitAvailable
			}
		}

		// REMEDIATION_ENRICHER provides closest and latest safe versions
		if raw.RemediationEnricher != nil {
			for _, r := range raw.RemediationEnricher.VulnerabilityHashToRemediations[adv.Hash] {
				switch r.Remediation.Type {
				case "closest_no_vulnerabilities":
					finding.ClosestFixVersion = r.Remediation.LibraryVersion
				case "latest_no_vulnerabilities":
					finding.LatestFixVersion = r.Remediation.LibraryVersion
				}
			}
		}

		findings = append(findings, finding)
	}

	return &ScanResult{Findings: findings, RawResponse: string(body)}, nil
}
