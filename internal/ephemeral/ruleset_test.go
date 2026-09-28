package ephemeral

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildRulesJSON(t *testing.T) {
	raw, err := BuildRulesJSON(Input{
		RuleCode:        "function visit() {}",
		TreeSitterQuery: "(identifier) @id",
		Language:        "typescript",
		RuleName:        "missing-guard",
		Description:     "from the uncommitted diff",
	})
	if err != nil {
		t.Fatal(err)
	}

	var doc []struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Rules       []struct {
			Name            string `json:"name"`
			Category        string `json:"category"`
			Severity        string `json:"severity"`
			Language        string `json:"language"`
			RuleType        string `json:"rule_type"`
			Code            string `json:"code"`
			TreeSitterQuery string `json:"tree_sitter_query"`
			Checksum        string `json:"checksum"`
			Tests           []any  `json:"tests"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc) != 1 || len(doc[0].Rules) != 1 {
		t.Fatalf("unexpected document shape: %s", raw)
	}
	rule := doc[0].Rules[0]
	if doc[0].Name != "variant-hunter" || rule.Name != "missing-guard" {
		t.Fatalf("names: ruleset %s rule %s", doc[0].Name, rule.Name)
	}
	if rule.Language != "TYPESCRIPT" || rule.RuleType != "TREE_SITTER_QUERY" {
		t.Fatalf("language/type: %s %s", rule.Language, rule.RuleType)
	}
	if rule.Category != "SECURITY" || rule.Severity != "ERROR" {
		t.Fatalf("category/severity: %s %s", rule.Category, rule.Severity)
	}
	code, err := base64.StdEncoding.DecodeString(rule.Code)
	if err != nil || string(code) != "function visit() {}" {
		t.Fatalf("code payload: %q %v", code, err)
	}
	query, err := base64.StdEncoding.DecodeString(rule.TreeSitterQuery)
	if err != nil || string(query) != "(identifier) @id" {
		t.Fatalf("query payload: %q %v", query, err)
	}
	if len(rule.Checksum) != 64 || strings.Contains(rule.Checksum, "BYPASS") {
		t.Fatalf("checksum: %s", rule.Checksum)
	}
	if rule.Tests == nil {
		t.Fatal("tests must be present")
	}
}

func TestBuildRulesJSONRejectsEmptySource(t *testing.T) {
	_, err := BuildRulesJSON(Input{Language: "GO", TreeSitterQuery: "(identifier) @id"})
	if err == nil {
		t.Fatal("expected empty rule code to fail")
	}
	_, err = BuildRulesJSON(Input{Language: "GO", RuleCode: "function visit() {}"})
	if err == nil {
		t.Fatal("expected empty query to fail")
	}
	_, err = BuildRulesJSON(Input{
		Language:        "COBOL",
		RuleCode:        "function visit() {}",
		TreeSitterQuery: "(identifier) @id",
	})
	if err == nil {
		t.Fatal("expected unknown language to fail")
	}
}
