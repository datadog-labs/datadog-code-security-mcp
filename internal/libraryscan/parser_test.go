package libraryscan

import (
	"testing"
)

func TestParseResponse_Empty(t *testing.T) {
	result, err := parseResponse([]byte(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Libraries) != 0 {
		t.Errorf("expected 0 libraries, got %d", len(result.Libraries))
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
				"cve": "CVE-2021-41269",
				"summary": "Critical vulnerability found in cron-utils",
				"severity": "Critical",
				"cvssScore": 9.8,
				"cwes": ["CWE-94"]
			},
			"GHSA-pfj3-56hm-jwq5": {
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
	if len(result.Libraries) != 2 {
		t.Fatalf("expected 2 libraries, got %d", len(result.Libraries))
	}

	// Index libraries by name for deterministic assertions
	byName := map[string]LibraryInfo{}
	for _, lib := range result.Libraries {
		byName[lib.Name] = lib
	}

	lib1, ok := byName["com.cronutils:cron-utils"]
	if !ok {
		t.Fatal("expected library com.cronutils:cron-utils")
	}
	if lib1.Version != "9.1.2" {
		t.Errorf("expected Version 9.1.2, got %s", lib1.Version)
	}
	if lib1.Ecosystem != "Maven" {
		t.Errorf("expected Ecosystem Maven, got %s", lib1.Ecosystem)
	}
	if lib1.Relation != "direct" {
		t.Errorf("expected Relation direct, got %s", lib1.Relation)
	}
	if len(lib1.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vulnerability for cron-utils, got %d", len(lib1.Vulnerabilities))
	}
	v1 := lib1.Vulnerabilities[0]
	if v1.GHSAID != "GHSA-p9m8-27x8-rg87" {
		t.Errorf("expected GHSA-p9m8-27x8-rg87, got %s", v1.GHSAID)
	}
	if v1.CVE != "CVE-2021-41269" {
		t.Errorf("expected CVE-2021-41269, got %s", v1.CVE)
	}
	if v1.Severity != "Critical" {
		t.Errorf("expected Severity Critical, got %s", v1.Severity)
	}
	if v1.CVSSScore != 9.8 {
		t.Errorf("expected CVSSScore 9.8, got %f", v1.CVSSScore)
	}
	if v1.ClosestFixVersion != "9.1.6" {
		t.Errorf("expected ClosestFixVersion 9.1.6, got %s", v1.ClosestFixVersion)
	}
	if v1.LatestFixVersion != "9.2.0" {
		t.Errorf("expected LatestFixVersion 9.2.0, got %s", v1.LatestFixVersion)
	}
	if v1.ExploitAvailable == nil || !*v1.ExploitAvailable {
		t.Error("expected ExploitAvailable to be true")
	}

	lib2, ok := byName["com.cronutils:cron-utils-deps"]
	if !ok {
		t.Fatal("expected library com.cronutils:cron-utils-deps")
	}
	if lib2.Relation != "transitive" {
		t.Errorf("expected Relation transitive, got %s", lib2.Relation)
	}
	if len(lib2.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vulnerability for cron-utils-deps, got %d", len(lib2.Vulnerabilities))
	}
	v2 := lib2.Vulnerabilities[0]
	if v2.CVE != "CVE-2020-26238" {
		t.Errorf("expected CVE-2020-26238, got %s", v2.CVE)
	}
	if v2.ExploitAvailable != nil {
		t.Errorf("expected ExploitAvailable to be nil, got %v", *v2.ExploitAvailable)
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
	if len(result.Libraries) != 1 {
		t.Fatalf("expected 1 library, got %d", len(result.Libraries))
	}
	lib := result.Libraries[0]
	if len(lib.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(lib.Vulnerabilities))
	}

	v := lib.Vulnerabilities[0]
	if v.GHSAID != "GHSA-xxxx" {
		t.Errorf("expected GHSA-xxxx, got %s", v.GHSAID)
	}
	if v.CVE != "CVE-2024-9999" {
		t.Errorf("expected CVE-2024-9999, got %s", v.CVE)
	}
	if v.Summary != "Test vulnerability" {
		t.Errorf("unexpected summary: %s", v.Summary)
	}
	if v.Severity != "Critical" {
		t.Errorf("expected Critical, got %s", v.Severity)
	}
	if v.CVSSScore != 9.5 {
		t.Errorf("expected CVSSScore 9.5, got %f", v.CVSSScore)
	}
	if len(v.CWEs) != 2 || v.CWEs[0] != "CWE-502" {
		t.Errorf("unexpected CWEs: %v", v.CWEs)
	}
	if v.DatadogScore != 9.5 {
		t.Errorf("expected DatadogScore 9.5, got %f", v.DatadogScore)
	}
	if v.Reachability != "REACHABLE" {
		t.Errorf("expected Reachability REACHABLE, got %s", v.Reachability)
	}
	if v.ExploitAvailable == nil || !*v.ExploitAvailable {
		t.Error("expected ExploitAvailable to be true")
	}
	if v.ExploitPoC == nil || !*v.ExploitPoC {
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
	if len(result.Libraries) != 1 {
		t.Fatalf("expected 1 library, got %d", len(result.Libraries))
	}
	if len(result.Libraries[0].Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(result.Libraries[0].Vulnerabilities))
	}
	v := result.Libraries[0].Vulnerabilities[0]
	if v.ClosestFixVersion != "1.0.5" {
		t.Errorf("expected ClosestFixVersion 1.0.5, got %s", v.ClosestFixVersion)
	}
	if v.LatestFixVersion != "2.0.0" {
		t.Errorf("expected LatestFixVersion 2.0.0, got %s", v.LatestFixVersion)
	}
	if v.HasRemediation != true {
		t.Error("expected HasRemediation to be true")
	}
	if v.ExploitAvailable == nil || *v.ExploitAvailable {
		t.Error("expected ExploitAvailable to be false (non-nil pointer to false)")
	}
	if v.ExploitPoC != nil {
		t.Error("expected ExploitPoC to be nil")
	}
}

func TestParseResponse_UnsupportedVersion_SkipsParsingAndPreservesRaw(t *testing.T) {
	body := []byte(`{"version": 99, "libraries": {"pkg:npm/lib@1.0": {"name": "lib", "version": "1.0", "vulnerabilities": [{"advisoryId": "GHSA-xxxx"}]}}, "vulnerabilities": {}}`)
	result, err := parseResponse(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Libraries) != 0 {
		t.Errorf("expected 0 libraries for unsupported version, got %d", len(result.Libraries))
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
				"licenseId": "MIT",
				"latestVersion": "2.0.0",
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
	if len(result.Libraries) != 1 {
		t.Fatalf("expected 1 library entry, got %d", len(result.Libraries))
	}
	lib := result.Libraries[0]
	if lib.Name != "safe-lib" {
		t.Errorf("expected library name safe-lib, got %s", lib.Name)
	}
	if lib.Version != "1.0" {
		t.Errorf("expected version 1.0, got %s", lib.Version)
	}
	if lib.Ecosystem != "npm" {
		t.Errorf("expected ecosystem npm, got %s", lib.Ecosystem)
	}
	if lib.LicenseID != "MIT" {
		t.Errorf("expected license MIT, got %s", lib.LicenseID)
	}
	if lib.LatestVersion != "2.0.0" {
		t.Errorf("expected latestVersion 2.0.0, got %s", lib.LatestVersion)
	}
	if lib.Relation != "direct" {
		t.Errorf("expected relation direct, got %s", lib.Relation)
	}
	if len(lib.Vulnerabilities) != 0 {
		t.Errorf("expected 0 vulnerabilities, got %d", len(lib.Vulnerabilities))
	}
}

func TestParseResponse_LibrariesPopulatedForAllEntries(t *testing.T) {
	body := []byte(`{
		"version": 1,
		"libraries": {
			"pkg:npm/vuln-lib@1.0": {
				"name": "vuln-lib",
				"version": "1.0",
				"ecosystem": "npm",
				"relation": "direct",
				"vulnerabilities": [{"advisoryId": "GHSA-xxxx", "fixVersion": "", "hasRemediation": false, "fixType": "", "remediations": [], "reachability": ""}]
			},
			"pkg:npm/safe-lib@2.0": {
				"name": "safe-lib",
				"version": "2.0",
				"ecosystem": "npm",
				"relation": "transitive",
				"vulnerabilities": []
			}
		},
		"vulnerabilities": {}
	}`)

	result, err := parseResponse(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Libraries) != 2 {
		t.Fatalf("expected 2 library entries, got %d", len(result.Libraries))
	}

	// Libraries are sorted: most vulns first, then alphabetically.
	if result.Libraries[0].Name != "vuln-lib" {
		t.Errorf("expected vuln-lib first (most vulns), got %s", result.Libraries[0].Name)
	}
	if len(result.Libraries[0].Vulnerabilities) != 1 {
		t.Errorf("expected 1 vulnerability for vuln-lib, got %d", len(result.Libraries[0].Vulnerabilities))
	}
	if result.Libraries[1].Name != "safe-lib" {
		t.Errorf("expected safe-lib second, got %s", result.Libraries[1].Name)
	}
	if len(result.Libraries[1].Vulnerabilities) != 0 {
		t.Errorf("expected 0 vulnerabilities for safe-lib, got %d", len(result.Libraries[1].Vulnerabilities))
	}
}
