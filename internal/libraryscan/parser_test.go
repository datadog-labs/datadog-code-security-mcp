package libraryscan

import (
	"testing"
)

func TestParseResponse_Empty(t *testing.T) {
	result, err := parseResponse([]byte(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings))
	}
}

func TestParseResponse_RawResponseIsPreserved(t *testing.T) {
	body := []byte(`{"VULNERABILITY_DETECTION": null}`)
	result, err := parseResponse(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RawResponse != string(body) {
		t.Errorf("expected RawResponse to equal input body, got %q", result.RawResponse)
	}
}

func TestParseResponse_InvalidJSON(t *testing.T) {
	_, err := parseResponse([]byte(`not json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseResponse_TwoAdvisories(t *testing.T) {
	body := []byte(`{
		"VULNERABILITY_DETECTION": {
			"advisories": [
				{
					"componentInput": {
						"componentName": "com.cronutils:cron-utils",
						"componentVersion": "9.1.2",
						"purl": "pkg:maven/com.cronutils/cron-utils@9.1.2"
					},
					"osvAdvisory": {
						"id": "GHSA-p9m8-27x8-rg87",
						"aliases": ["CVE-2021-41269"],
						"summary": "Critical vulnerability found in cron-utils",
						"details": "Template injection",
						"databaseSpecific": {"severity": "CRITICAL"},
						"severity": []
					},
					"remediation": "Upgrade to a version >= 9.1.6",
					"hash": "hash1"
				},
				{
					"componentInput": {
						"componentName": "com.cronutils:cron-utils",
						"componentVersion": "9.1.2",
						"purl": "pkg:maven/com.cronutils/cron-utils@9.1.2"
					},
					"osvAdvisory": {
						"id": "GHSA-pfj3-56hm-jwq5",
						"aliases": ["CVE-2020-26238"],
						"summary": "Template injection in cron-utils",
						"details": "Template injection",
						"databaseSpecific": {"severity": "HIGH"},
						"severity": []
					},
					"remediation": "Upgrade to a version >= 9.1.3",
					"hash": "hash2"
				}
			]
		}
	}`)

	result, err := parseResponse(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(result.Findings))
	}
	if result.Findings[0].GHSAID != "GHSA-p9m8-27x8-rg87" {
		t.Errorf("expected GHSA-p9m8-27x8-rg87, got %s", result.Findings[0].GHSAID)
	}
	if len(result.Findings[0].CVEAliases) != 1 || result.Findings[0].CVEAliases[0] != "CVE-2021-41269" {
		t.Errorf("unexpected CVE aliases: %v", result.Findings[0].CVEAliases)
	}
	if result.Findings[0].LibraryName != "com.cronutils:cron-utils" {
		t.Errorf("unexpected library name: %s", result.Findings[0].LibraryName)
	}
	if result.Findings[0].LibraryVersion != "9.1.2" {
		t.Errorf("expected LibraryVersion 9.1.2, got %s", result.Findings[0].LibraryVersion)
	}
	if result.Findings[0].Remediation != "Upgrade to a version >= 9.1.6" {
		t.Errorf("unexpected remediation: %s", result.Findings[0].Remediation)
	}
	if result.Findings[1].GHSAID != "GHSA-pfj3-56hm-jwq5" {
		t.Errorf("expected GHSA-pfj3-56hm-jwq5, got %s", result.Findings[1].GHSAID)
	}
	if len(result.Findings[1].CVEAliases) != 1 || result.Findings[1].CVEAliases[0] != "CVE-2020-26238" {
		t.Errorf("unexpected CVE aliases for finding[1]: %v", result.Findings[1].CVEAliases)
	}
}

func TestParseResponse_ScoreEnricherOverridesSeverity(t *testing.T) {
	body := []byte(`{
		"VULNERABILITY_DETECTION": {
			"advisories": [{
				"componentInput": {"componentName": "lib", "componentVersion": "1.0", "purl": "pkg:npm/lib@1.0"},
				"osvAdvisory": {"id": "GHSA-xxxx", "aliases": [], "summary": "test", "details": "", "databaseSpecific": {"severity": "LOW"}, "severity": []},
				"remediation": "Upgrade",
				"hash": "h1"
			}]
		},
		"SCORE_ENRICHER": {
			"vulnerabilityHashToDatadogScore": {
				"h1": {
					"score": {"score": 9.8, "severity": "Critical"},
					"exploitAvailable": true
				}
			}
		}
	}`)

	result, err := parseResponse(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Findings[0].Severity != "Critical" {
		t.Errorf("expected SCORE_ENRICHER to override severity to Critical, got %s", result.Findings[0].Severity)
	}
	if result.Findings[0].CVSSScore != 9.8 {
		t.Errorf("expected CVSSScore 9.8, got %f", result.Findings[0].CVSSScore)
	}
	if !result.Findings[0].ExploitAvailable {
		t.Error("expected ExploitAvailable to be true")
	}
}

func TestParseResponse_RemediationEnricher(t *testing.T) {
	body := []byte(`{
		"VULNERABILITY_DETECTION": {
			"advisories": [{
				"componentInput": {"componentName": "lib", "componentVersion": "1.0", "purl": "pkg:npm/lib@1.0"},
				"osvAdvisory": {"id": "GHSA-xxxx", "aliases": [], "summary": "test", "details": "", "databaseSpecific": {"severity": "HIGH"}, "severity": []},
				"remediation": "Upgrade",
				"hash": "h1"
			}]
		},
		"REMEDIATION_ENRICHER": {
			"vulnerabilityHashToRemediations": {
				"h1": [
					{"remediation": {"type": "closest_no_vulnerabilities", "library_version": "1.0.5"}},
					{"remediation": {"type": "latest_no_vulnerabilities", "library_version": "2.0.0"}}
				]
			}
		}
	}`)

	result, err := parseResponse(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Findings[0].ClosestFixVersion != "1.0.5" {
		t.Errorf("expected ClosestFixVersion 1.0.5, got %s", result.Findings[0].ClosestFixVersion)
	}
	if result.Findings[0].LatestFixVersion != "2.0.0" {
		t.Errorf("expected LatestFixVersion 2.0.0, got %s", result.Findings[0].LatestFixVersion)
	}
}
