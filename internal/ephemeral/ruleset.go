// Package ephemeral builds a one-off datadog-static-analyzer ruleset and runs it
// locally. The rule source comes from the caller (an agent). This package only
// packs the JSON envelope and invokes the scanner. It does not infer invariants.
package ephemeral

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// Input is the rule source an agent hands to the local scanner.
type Input struct {
	// RuleCode is the DDSA JavaScript source (visit/buildError/addError), not base64.
	RuleCode string
	// TreeSitterQuery is the tree-sitter query source, not base64.
	TreeSitterQuery string
	// Language is the scanner enum value, for example TYPESCRIPT.
	Language string
	// RuleName is the rule id inside the ruleset. Defaults to "ephemeral".
	RuleName string
	// RulesetName is the Vec<RuleSet> name. Defaults to "security-variants".
	RulesetName string
	// Description is plain text on the ruleset, not base64.
	Description string
}

type rule struct {
	Name            string `json:"name"`
	Category        string `json:"category"`
	Severity        string `json:"severity"`
	Language        string `json:"language"`
	RuleType        string `json:"rule_type"`
	Code            string `json:"code"`
	TreeSitterQuery string `json:"tree_sitter_query"`
	Checksum        string `json:"checksum"`
	Tests           []any  `json:"tests"`
}

type ruleSet struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Rules       []rule `json:"rules"`
}

// BuildRulesJSON returns the Vec<RuleSet> document datadog-static-analyzer -r expects.
// code and tree_sitter_query are standard base64. checksum is the hex SHA-256 of
// the base64 code string, which is what Rule::verify_checksum computes. Scans
// still pass -b because the rule was never published.
func BuildRulesJSON(in Input) ([]byte, error) {
	if strings.TrimSpace(in.RuleCode) == "" {
		return nil, fmt.Errorf("rule code is empty")
	}
	if strings.TrimSpace(in.TreeSitterQuery) == "" {
		return nil, fmt.Errorf("tree-sitter query is empty")
	}
	language := strings.ToUpper(strings.TrimSpace(in.Language))
	if language == "" {
		return nil, fmt.Errorf("language is empty")
	}
	if !knownLanguage(language) {
		return nil, fmt.Errorf("unsupported language %q", language)
	}

	rulesetName, ruleName := ruleNames(in)
	code := base64.StdEncoding.EncodeToString([]byte(in.RuleCode))
	query := base64.StdEncoding.EncodeToString([]byte(in.TreeSitterQuery))
	sum := sha256.Sum256([]byte(code))

	doc := []ruleSet{{
		Name:        rulesetName,
		Description: in.Description,
		Rules: []rule{{
			Name:            ruleName,
			Category:        "SECURITY",
			Severity:        "ERROR",
			Language:        language,
			RuleType:        "TREE_SITTER_QUERY",
			Code:            code,
			TreeSitterQuery: query,
			Checksum:        hex.EncodeToString(sum[:]),
			Tests:           []any{},
		}},
	}}
	return json.MarshalIndent(doc, "", "  ")
}

func ruleNames(in Input) (rulesetName, ruleName string) {
	rulesetName = strings.TrimSpace(in.RulesetName)
	if rulesetName == "" {
		rulesetName = "security-variants"
	}
	ruleName = strings.TrimSpace(in.RuleName)
	if ruleName == "" {
		ruleName = "ephemeral"
	}
	return rulesetName, ruleName
}

// ruleID is the name the analyzer reports for the rule: ruleset/rule.
func ruleID(in Input) string {
	rulesetName, ruleName := ruleNames(in)
	return rulesetName + "/" + ruleName
}

func knownLanguage(language string) bool {
	switch language {
	case "CSHARP", "DART", "DOCKERFILE", "ELIXIR", "GO", "JAVA", "JAVASCRIPT",
		"JSON", "KOTLIN", "PYTHON", "RUBY", "RUST", "SWIFT", "TERRAFORM",
		"TYPESCRIPT", "YAML", "STARLARK", "BASH", "PHP", "MARKDOWN", "APEX",
		"R", "SQL":
		return true
	default:
		return false
	}
}
