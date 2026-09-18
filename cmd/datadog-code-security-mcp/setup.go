package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	setupcmd "github.com/datadog-labs/datadog-code-security-mcp/internal/setup"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/telemetry"
	"github.com/datadog-labs/datadog-code-security-mcp/skills"
)

func newSetupCmd() *cobra.Command {
	var (
		clientIDs              []string
		dryRun                 bool
		removeSkills           bool
		outputJSON             bool
		skipSkillListingBudget bool
	)

	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Install Datadog Code Security skills for AI coding clients",
		Long: `Install Datadog Code Security skills into the shared Agent Skills
directory and the native directories of detected AI coding clients.

Destinations: Agent Skills (~/.agents/skills), Claude Code, and Codex. Setup
manages only skill directories carrying its .datadog-managed.json marker; it
never changes MCP configuration or removes user-managed skills. For Claude
Code, setup also raises the user skill-listing budget to 0.02 unless
--skip-skill-listing-budget is set.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) (runErr error) {
			event := telemetry.OperationEvent{
				Interface: telemetry.InterfaceCLI,
				Caller:    cliCaller(),
				Operation: "setup",
				StartedAt: time.Now(),
			}
			defer func() {
				event.Failure = runErr
				trackOperation(cmd.Context(), event)
			}()

			homeDir, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("resolve user home directory: %w", err)
			}

			var desired []string
			if !removeSkills {
				desired, err = setupcmd.EmbeddedSkillIDs(skills.FS)
				if err != nil {
					return err
				}
			}

			options := setupcmd.Options{
				Source:                 skills.FS,
				Version:                version,
				ClientIDs:              clientIDs,
				HomeDir:                homeDir,
				ClaudeConfigDir:        os.Getenv("CLAUDE_CONFIG_DIR"),
				SkipSkillListingBudget: skipSkillListingBudget,
				Now:                    time.Now(),
				Desired:                desired,
			}

			var result setupcmd.Result
			if dryRun {
				result, err = setupcmd.Preview(options)
			} else {
				result, err = setupcmd.Run(options)
			}
			if err != nil {
				return err
			}
			runErr = result.FailureError()

			renderErr := renderSetupResult(cmd.OutOrStdout(), result, dryRun, outputJSON)
			if runErr == nil {
				runErr = renderErr
			}
			return runErr
		},
	}

	cmd.Flags().StringArrayVar(&clientIDs, "client", nil,
		"Restrict setup to a destination ID (repeatable: agents, claude-code, codex)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Report actions without changing files")
	cmd.Flags().BoolVar(&removeSkills, "remove-skills", false,
		"Remove all Datadog-managed skills instead of installing them")
	cmd.Flags().BoolVarP(&outputJSON, "json", "j", false, "Output a machine-readable JSON report")
	cmd.Flags().BoolVar(&skipSkillListingBudget, "skip-skill-listing-budget", false,
		"Do not raise Claude Code's user skill-listing budget to 0.02")

	return cmd
}

type setupJSONReport struct {
	DryRun  bool                    `json:"dry_run"`
	Clients []setupcmd.ClientResult `json:"clients"`
}

func renderSetupResult(writer io.Writer, result setupcmd.Result, dryRun, outputJSON bool) error {
	if outputJSON {
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(setupJSONReport{DryRun: dryRun, Clients: result.Clients})
	}

	detected := false
	wroteSkills := false
	updatedSettings := false
	for _, client := range result.Clients {
		if client.Status != setupcmd.ClientStatusSkipped {
			detected = true
		}
		if err := renderClient(writer, client, dryRun); err != nil {
			return err
		}
		if err := renderWarnings(writer, client.Warnings); err != nil {
			return err
		}
		wroteSkills = wroteSkills || hasSkillWrites(client.Changes)
		updatedSettings = updatedSettings || settingsUpdated(client.Settings)
	}

	if !detected {
		_, err := fmt.Fprintln(writer, "No selected AI clients were detected. Install or select Claude Code or Codex and run setup again.")
		return err
	}
	if dryRun {
		_, err := fmt.Fprintln(writer, "Dry run complete.")
		return err
	}
	if wroteSkills || updatedSettings {
		_, err := fmt.Fprintln(writer, "Restart updated clients so they discover the installed skills.")
		return err
	}
	return nil
}

func renderClient(writer io.Writer, client setupcmd.ClientResult, dryRun bool) error {
	switch client.Status {
	case setupcmd.ClientStatusSkipped:
		_, err := fmt.Fprintf(writer, "○ %s: skipped (%s)\n", client.DisplayName, client.Reason)
		return err
	case setupcmd.ClientStatusFailed:
		if _, err := fmt.Fprintf(writer, "✗ %s: failed (%s)\n", client.DisplayName, client.Reason); err != nil {
			return err
		}
		if len(client.Changes) == 0 && !settingsUpdated(client.Settings) {
			return nil
		}
		if _, err := fmt.Fprintln(writer, "  Partial changes applied before failure:"); err != nil {
			return err
		}
		if err := renderSkillChanges(writer, client.Changes, false); err != nil {
			return err
		}
		return renderSettingsChange(writer, client.Settings, false)
	case setupcmd.ClientStatusApplied:
		if len(client.Changes) == 0 && client.Settings == nil {
			_, err := fmt.Fprintf(writer, "✓ %s: no changes\n", client.DisplayName)
			return err
		}
		if _, err := fmt.Fprintf(writer, "✓ %s (%s)\n", client.DisplayName, client.SkillsDir); err != nil {
			return err
		}
		if err := renderSkillChanges(writer, client.Changes, dryRun); err != nil {
			return err
		}
		return renderSettingsChange(writer, client.Settings, dryRun)
	}
	return nil
}

func renderSettingsChange(writer io.Writer, change *setupcmd.SettingsChange, dryRun bool) error {
	if change == nil {
		return nil
	}
	action := string(change.Action)
	if dryRun && change.Action == setupcmd.SettingsActionUpdated {
		action = "would be updated"
	}
	_, err := fmt.Fprintf(writer, "  - Claude settings %s: %s (%s)\n",
		change.Path, action, change.Reason)
	return err
}

func renderSkillChanges(writer io.Writer, changes []setupcmd.SkillChange, dryRun bool) error {
	for _, change := range changes {
		action := string(change.Action)
		if dryRun {
			action = "would be " + action
		}
		if _, err := fmt.Fprintf(writer, "  - %s: %s\n", change.SkillID, action); err != nil {
			return err
		}
	}
	return nil
}

func renderWarnings(writer io.Writer, warnings []string) error {
	for _, warning := range warnings {
		if _, err := fmt.Fprintf(writer, "  ⚠ %s\n", warning); err != nil {
			return err
		}
	}
	return nil
}

func settingsUpdated(change *setupcmd.SettingsChange) bool {
	return change != nil && change.Action == setupcmd.SettingsActionUpdated
}

func hasSkillWrites(changes []setupcmd.SkillChange) bool {
	for _, change := range changes {
		if change.Action == setupcmd.SkillActionInstalled || change.Action == setupcmd.SkillActionUpdated {
			return true
		}
	}
	return false
}
