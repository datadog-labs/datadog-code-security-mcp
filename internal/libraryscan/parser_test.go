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

func TestParseResponse_UnsupportedVersionRawResponseIsPreserved(t *testing.T) {
	body := []byte(`{"version": 99, "libraries": {}, "vulnerabilities": {}}`)
	result, err := parseResponse(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RawResponse != string(body) {
		t.Errorf("expected RawResponse to equal input body for unsupported version, got %q", result.RawResponse)
	}
}

func TestParseResponse_InvalidJSON(t *testing.T) {
	_, err := parseResponse([]byte(`not json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseResponse_TwoLibrariesWithVulns(t *testing.T) {
	body := []byte(`{
		"version": 1,
		"libraries": {
			"pkg:maven/com.cronutils/cron-utils@9.1.2": {
				"name": "com.cronutils:cron-utils",
				"version": "9.1.2",
				"ecosystem": "Maven",
				"relation": "direct",
				"vulnerabilities": [
					{
						"advisoryId": "GHSA-p9m8-27x8-rg87",
						"fixVersion": "9.1.6",
						"hasRemediation": true,
						"fixType": "VULNERABLE_PACKAGE",
						"remediations": [
							{"libraryName": "com.cronutils:cron-utils", "libraryVersion": "9.1.6", "type": "closest_no_vulnerabilities"},
							{"libraryName": "com.cronutils:cron-utils", "libraryVersion": "9.2.0", "type": "latest_no_vulnerabilities"}
						],
						"reachability": "UNDETERMINED",
						"datadogScore": 9.8,
						"exploitAvailable": true,
						"exploitPoC": false
					}
				]
			},
			"pkg:maven/com.cronutils/cron-utils-deps@1.0.0": {
				"name": "com.cronutils:cron-utils-deps",
				"version": "1.0.0",
				"ecosystem": "Maven",
				"relation": "transitive",
				"vulnerabilities": [
					{
						"advisoryId": "GHSA-pfj3-56hm-jwq5",
						"fixVersion": "1.1.0",
						"hasRemediation": true,
						"fixType": "VULNERABLE_PACKAGE",
						"remediations": [],
						"reachability": "UNDETERMINED",
						"datadogScore": 7.5,
						"exploitAvailable": null,
						"exploitPoC": null
					}
				]
			}
		},
		"vulnerabilities": {
			"GHSA-p9m8-27x8-rg87": {
				"id": "GHSA-p9m8-27x8-rg87",
				"cve": "CVE-2021-41269",
				"summary": "Critical vulnerability found in cron-utils",
				"severity": "Critical",
				"cvssScore": 9.8,
				"cwes": ["CWE-94"]
			},
			"GHSA-pfj3-56hm-jwq5": {
				"id": "GHSA-pfj3-56hm-jwq5",
				"cve": "CVE-2020-26238",
				"summary": "Template injection in cron-utils",
				"severity": "High",
				"cvssScore": 7.5,
				"cwes": ["CWE-74"]
			}
		}
	}`)

	result, err := parseResponse(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(result.Findings))
	}

	// Index findings by advisory ID for deterministic assertions
	byID := map[string]VulnerabilityFinding{}
	for _, f := range result.Findings {
		byID[f.GHSAID] = f
	}

	f1, ok := byID["GHSA-p9m8-27x8-rg87"]
	if !ok {
		t.Fatal("expected finding for GHSA-p9m8-27x8-rg87")
	}
	if f1.CVE != "CVE-2021-41269" {
		t.Errorf("expected CVE-2021-41269, got %s", f1.CVE)
	}
	if f1.LibraryName != "com.cronutils:cron-utils" {
		t.Errorf("unexpected library name: %s", f1.LibraryName)
	}
	if f1.LibraryVersion != "9.1.2" {
		t.Errorf("expected LibraryVersion 9.1.2, got %s", f1.LibraryVersion)
	}
	if f1.Severity != "Critical" {
		t.Errorf("expected Severity Critical, got %s", f1.Severity)
	}
	if f1.CVSSScore != 9.8 {
		t.Errorf("expected CVSSScore 9.8, got %f", f1.CVSSScore)
	}
	if f1.Relation != "direct" {
		t.Errorf("expected Relation direct, got %s", f1.Relation)
	}
	if f1.Ecosystem != "Maven" {
		t.Errorf("expected Ecosystem Maven, got %s", f1.Ecosystem)
	}
	if f1.ClosestFixVersion != "9.1.6" {
		t.Errorf("expected ClosestFixVersion 9.1.6, got %s", f1.ClosestFixVersion)
	}
	if f1.LatestFixVersion != "9.2.0" {
		t.Errorf("expected LatestFixVersion 9.2.0, got %s", f1.LatestFixVersion)
	}
	if f1.ExploitAvailable == nil || !*f1.ExploitAvailable {
		t.Error("expected ExploitAvailable to be true")
	}

	f2, ok := byID["GHSA-pfj3-56hm-jwq5"]
	if !ok {
		t.Fatal("expected finding for GHSA-pfj3-56hm-jwq5")
	}
	if f2.CVE != "CVE-2020-26238" {
		t.Errorf("expected CVE-2020-26238, got %s", f2.CVE)
	}
	if f2.Relation != "transitive" {
		t.Errorf("expected Relation transitive, got %s", f2.Relation)
	}
	if f2.ExploitAvailable != nil {
		t.Errorf("expected ExploitAvailable to be nil, got %v", *f2.ExploitAvailable)
	}
}

func TestParseResponse_VulnDefinitionEnrichesFields(t *testing.T) {
	body := []byte(`{
		"version": 1,
		"libraries": {
			"pkg:npm/lib@1.0": {
				"name": "lib",
				"version": "1.0",
				"ecosystem": "npm",
				"relation": "direct",
				"vulnerabilities": [{
					"advisoryId": "GHSA-xxxx",
					"fixVersion": "2.0.0",
					"hasRemediation": true,
					"fixType": "VULNERABLE_PACKAGE",
					"remediations": [],
					"reachability": "REACHABLE",
					"datadogScore": 9.5,
					"exploitAvailable": true,
					"exploitPoC": true
				}]
			}
		},
		"vulnerabilities": {
			"GHSA-xxxx": {
				"id": "GHSA-xxxx",
				"cve": "CVE-2024-9999",
				"summary": "Test vulnerability",
				"severity": "Critical",
				"cvssScore": 9.5,
				"cwes": ["CWE-502", "CWE-184"]
			}
		}
	}`)

	result, err := parseResponse(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if f.GHSAID != "GHSA-xxxx" {
		t.Errorf("expected GHSA-xxxx, got %s", f.GHSAID)
	}
	if f.CVE != "CVE-2024-9999" {
		t.Errorf("expected CVE-2024-9999, got %s", f.CVE)
	}
	if f.Summary != "Test vulnerability" {
		t.Errorf("unexpected summary: %s", f.Summary)
	}
	if f.Severity != "Critical" {
		t.Errorf("expected Critical, got %s", f.Severity)
	}
	if f.CVSSScore != 9.5 {
		t.Errorf("expected CVSSScore 9.5, got %f", f.CVSSScore)
	}
	if len(f.CWEs) != 2 || f.CWEs[0] != "CWE-502" {
		t.Errorf("unexpected CWEs: %v", f.CWEs)
	}
	if f.DatadogScore != 9.5 {
		t.Errorf("expected DatadogScore 9.5, got %f", f.DatadogScore)
	}
	if f.Reachability != "REACHABLE" {
		t.Errorf("expected Reachability REACHABLE, got %s", f.Reachability)
	}
	if f.ExploitAvailable == nil || !*f.ExploitAvailable {
		t.Error("expected ExploitAvailable to be true")
	}
	if f.ExploitPoC == nil || !*f.ExploitPoC {
		t.Error("expected ExploitPoC to be true")
	}
}

func TestParseResponse_RemediationFromVulnRef(t *testing.T) {
	body := []byte(`{
		"version": 1,
		"libraries": {
			"pkg:npm/lib@1.0": {
				"name": "lib",
				"version": "1.0",
				"ecosystem": "npm",
				"relation": "direct",
				"vulnerabilities": [{
					"advisoryId": "GHSA-remed",
					"fixVersion": "2.0.0",
					"hasRemediation": true,
					"fixType": "VULNERABLE_PACKAGE",
					"remediations": [
						{"libraryName": "lib", "libraryVersion": "1.0.5", "type": "closest_no_vulnerabilities"},
						{"libraryName": "lib", "libraryVersion": "2.0.0", "type": "latest_no_vulnerabilities"},
						{"libraryName": "lib", "libraryVersion": "1.0.3", "type": "closest_no_critical"}
					],
					"reachability": "UNDETERMINED",
					"datadogScore": 7.0,
					"exploitAvailable": false,
					"exploitPoC": null
				}]
			}
		},
		"vulnerabilities": {}
	}`)

	result, err := parseResponse(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	f := result.Findings[0]
	if f.ClosestFixVersion != "1.0.5" {
		t.Errorf("expected ClosestFixVersion 1.0.5, got %s", f.ClosestFixVersion)
	}
	if f.LatestFixVersion != "2.0.0" {
		t.Errorf("expected LatestFixVersion 2.0.0, got %s", f.LatestFixVersion)
	}
	if f.HasRemediation != true {
		t.Error("expected HasRemediation to be true")
	}
	if f.ExploitAvailable == nil || *f.ExploitAvailable {
		t.Error("expected ExploitAvailable to be false (non-nil pointer to false)")
	}
	if f.ExploitPoC != nil {
		t.Error("expected ExploitPoC to be nil")
	}
}

func TestParseResponse_UnsupportedVersion_SkipsParsingAndPreservesRaw(t *testing.T) {
	body := []byte(`{"version": 99, "libraries": {"pkg:npm/lib@1.0": {"name": "lib", "version": "1.0", "vulnerabilities": [{"advisoryId": "GHSA-xxxx"}]}}, "vulnerabilities": {}}`)
	result, err := parseResponse(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings for unsupported version, got %d", len(result.Findings))
	}
	if result.UnsupportedVersion != 99 {
		t.Errorf("expected UnsupportedVersion 99, got %d", result.UnsupportedVersion)
	}
	if result.RawResponse != string(body) {
		t.Error("expected RawResponse to be preserved for unsupported version")
	}
}

func TestParseResponse_LibraryWithNoVulns(t *testing.T) {
	body := []byte(`{
		"version": 1,
		"libraries": {
			"pkg:npm/safe-lib@1.0": {
				"name": "safe-lib",
				"version": "1.0",
				"ecosystem": "npm",
				"relation": "direct",
				"vulnerabilities": []
			}
		},
		"vulnerabilities": {}
	}`)

	result, err := parseResponse(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings for library with no vulns, got %d", len(result.Findings))
	}
}
