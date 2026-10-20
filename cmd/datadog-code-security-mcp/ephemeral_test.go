package main

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestCountViolations(t *testing.T) {
	tests := []struct {
		name   string
		raw    string
		want   int
		wantOK bool
	}{
		{name: "empty", raw: `[]`, want: 0, wantOK: true},
		{name: "per-file results", raw: `[{"filename":"a.go","violations":[{},{}]},{"filename":"b.go","violations":[]},{"filename":"c.go","violations":[{}]}]`, want: 3, wantOK: true},
		{name: "not an array", raw: `{}`, wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := countViolations(json.RawMessage(tt.raw))
			if ok != tt.wantOK || got != tt.want {
				t.Fatalf("countViolations = %d, %v; want %d, %v", got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestParseEphemeralArgs(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{
			"rule_code":         "function visit() {}",
			"tree_sitter_query": "(identifier) @id",
			"language":          "GO",
		}
	}

	t.Run("required and optional fields", func(t *testing.T) {
		args := base()
		args["directory"] = "/repo"
		args["rule_name"] = "missing-guard"
		args["paths"] = []any{"src", 3, "lib"}

		req, err := parseEphemeralArgs(args)
		if err != nil {
			t.Fatalf("parseEphemeralArgs: %v", err)
		}
		if req.RuleCode != "function visit() {}" || req.TreeSitterQuery != "(identifier) @id" || req.Language != "GO" {
			t.Errorf("rule input = %+v", req.Input)
		}
		if req.Directory != "/repo" || req.RuleName != "missing-guard" {
			t.Errorf("directory = %q, rule name = %q", req.Directory, req.RuleName)
		}
		if !slices.Equal(req.Paths, []string{"src", "lib"}) {
			t.Errorf("paths = %v, want non-string entries dropped", req.Paths)
		}
	})

	for _, key := range []string{"rule_code", "tree_sitter_query", "language"} {
		t.Run("missing "+key, func(t *testing.T) {
			args := base()
			delete(args, key)
			if _, err := parseEphemeralArgs(args); err == nil || !strings.Contains(err.Error(), key) {
				t.Fatalf("error = %v, want %s is required", err, key)
			}
		})
		t.Run("empty "+key, func(t *testing.T) {
			args := base()
			args[key] = ""
			if _, err := parseEphemeralArgs(args); err == nil || !strings.Contains(err.Error(), key) {
				t.Fatalf("error = %v, want %s is required", err, key)
			}
		})
	}
}
