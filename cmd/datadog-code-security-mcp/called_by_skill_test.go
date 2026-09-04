package main

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestCalledBySkillFlagIsHidden(t *testing.T) {
	calledBySkill = false
	t.Cleanup(func() { calledBySkill = false })

	var noTelemetry bool
	root := &cobra.Command{Use: "datadog-code-security-mcp"}
	registerRootFlags(root, &noTelemetry)

	flag := root.PersistentFlags().Lookup("called-by-skill")
	if flag == nil {
		t.Fatal("called-by-skill flag is not registered")
	}
	if !flag.Hidden {
		t.Fatal("called-by-skill must be hidden from help output")
	}
}

func TestCalledBySkillFlagAfterScanArgs(t *testing.T) {
	calledBySkill = false
	t.Cleanup(func() { calledBySkill = false })

	var noTelemetry bool
	root := &cobra.Command{Use: "datadog-code-security-mcp"}
	registerRootFlags(root, &noTelemetry)
	scanCmd := newScanCmd()
	scanCmd.RunE = func(cmd *cobra.Command, args []string) error { return nil }
	root.AddCommand(scanCmd)
	root.SetArgs([]string{"scan", "sast", "./src", "--json", "--called-by-skill"})

	if err := root.Execute(); err != nil {
		t.Fatalf("scan command failed: %v", err)
	}
	if !calledBySkill {
		t.Fatal("--called-by-skill after scan args was not parsed")
	}
}
