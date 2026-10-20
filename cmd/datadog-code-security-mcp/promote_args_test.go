package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/promote"
)

func promoteArgs() map[string]any {
	return map[string]any{
		"user_confirmed":    true,
		"rule_code":         "function visit() {}",
		"tree_sitter_query": "(identifier) @id",
		"language":          "GO",
		"rule_name":         "missing-guard",
	}
}

func TestParsePromoteArgs(t *testing.T) {
	t.Run("all fields", func(t *testing.T) {
		args := promoteArgs()
		args["overwrite"] = true
		args["ruleset_name"] = "my-rules"
		args["short_description"] = "short"
		args["description"] = "long"
		args["tests"] = []any{
			map[string]any{"filename": "ok.go", "code": "ok", "annotation_count": float64(0)},
			map[string]any{"filename": "bad.go", "code": "bad", "annotation_count": float64(1)},
		}

		got, err := parsePromoteArgs(args)
		if err != nil {
			t.Fatalf("parsePromoteArgs: %v", err)
		}
		want := promote.Request{
			UserConfirmed:    true,
			Overwrite:        true,
			RuleCode:         "function visit() {}",
			TreeSitterQuery:  "(identifier) @id",
			Language:         "GO",
			RuleName:         "missing-guard",
			RulesetName:      "my-rules",
			ShortDescription: "short",
			Description:      "long",
			Tests: []promote.Test{
				{Filename: "ok.go", Code: "ok", AnnotationCount: 0},
				{Filename: "bad.go", Code: "bad", AnnotationCount: 1},
			},
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("request = %+v\nwant %+v", got, want)
		}
	})

	t.Run("confirmation and overwrite default to false", func(t *testing.T) {
		args := promoteArgs()
		args["user_confirmed"] = "true"
		got, err := parsePromoteArgs(args)
		if err != nil {
			t.Fatalf("parsePromoteArgs: %v", err)
		}
		if got.UserConfirmed || got.Overwrite {
			t.Fatalf("non-boolean confirmation must not confirm: %+v", got)
		}
	})

	for _, key := range []string{"rule_code", "tree_sitter_query", "language", "rule_name"} {
		t.Run("missing "+key, func(t *testing.T) {
			args := promoteArgs()
			delete(args, key)
			if _, err := parsePromoteArgs(args); err == nil || !strings.Contains(err.Error(), key) {
				t.Fatalf("error = %v, want %s is required", err, key)
			}
		})
	}

	t.Run("bad tests", func(t *testing.T) {
		args := promoteArgs()
		args["tests"] = "not an array"
		if _, err := parsePromoteArgs(args); err == nil {
			t.Fatal("expected an error")
		}
	})
}

func TestParseTestArgs(t *testing.T) {
	tests := []struct {
		name    string
		raw     any
		want    []promote.Test
		wantErr string
	}{
		{name: "empty", raw: []any{}, want: []promote.Test{}},
		{name: "not an array", raw: map[string]any{}, wantErr: "array"},
		{name: "item not an object", raw: []any{"x"}, wantErr: "objects"},
		{name: "missing count", raw: []any{map[string]any{"filename": "a.go", "code": "x"}}, wantErr: "annotation_count"},
		{
			name: "valid",
			raw:  []any{map[string]any{"filename": "a.go", "code": "x", "annotation_count": float64(2)}},
			want: []promote.Test{{Filename: "a.go", Code: "x", AnnotationCount: 2}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseTestArgs(tt.raw)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseTestArgs: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("tests = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestAnnotationCount(t *testing.T) {
	tests := []struct {
		name    string
		raw     any
		want    int
		wantErr bool
	}{
		{name: "zero float", raw: float64(0), want: 0},
		{name: "positive float", raw: float64(3), want: 3},
		{name: "int", raw: 1, want: 1},
		{name: "fractional", raw: 1.5, wantErr: true},
		{name: "negative float", raw: float64(-1), wantErr: true},
		{name: "negative int", raw: -1, wantErr: true},
		{name: "string", raw: "1", wantErr: true},
		{name: "nil", raw: nil, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := annotationCount(tt.raw)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("count = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestReadTestsFile(t *testing.T) {
	if got, err := readTestsFile(""); err != nil || got != nil {
		t.Fatalf("empty path = %v, %v", got, err)
	}

	path := filepath.Join(t.TempDir(), "tests.json")
	if err := os.WriteFile(path, []byte(`[{"filename":"a.go","code":"x","annotation_count":1}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readTestsFile(path)
	if err != nil {
		t.Fatalf("readTestsFile: %v", err)
	}
	if !reflect.DeepEqual(got, []promote.Test{{Filename: "a.go", Code: "x", AnnotationCount: 1}}) {
		t.Fatalf("tests = %+v", got)
	}

	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readTestsFile(path); err == nil {
		t.Fatal("expected an error for a non-array file")
	}
}
