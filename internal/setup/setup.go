package setup

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Options configures a setup reconcile against a desired skill set.
type Options struct {
	Source    fs.FS
	Version   string
	ClientIDs []string
	HomeDir   string
	// ClaudeConfigDir overrides Claude Code's default ~/.claude directory.
	ClaudeConfigDir        string
	SkipSkillListingBudget bool
	Now                    time.Time
	// Desired is the set of embedded skill IDs to keep. An empty set removes
	// every managed skill. Callers must pass this explicitly; it is never
	// inferred from Source.
	Desired []string
}

// Result is the stable report rendered by both human and JSON output modes.
type Result struct {
	Clients []ClientResult `json:"clients"`
}

// ClientResult records the outcome for one supported client.
type ClientResult struct {
	ClientID    string          `json:"client_id"`
	DisplayName string          `json:"display_name"`
	Status      ClientStatus    `json:"status"`
	Reason      string          `json:"reason,omitempty"`
	SkillsDir   string          `json:"skills_dir"`
	Changes     []SkillChange   `json:"changes,omitempty"`
	Settings    *SettingsChange `json:"settings,omitempty"`
	Warnings    []string        `json:"warnings,omitempty"`
}

// ClientStatus describes the outcome of applying setup to one client.
type ClientStatus string

const (
	ClientStatusSkipped ClientStatus = "skipped"
	ClientStatusFailed  ClientStatus = "failed"
	ClientStatusApplied ClientStatus = "applied"
)

// Preview detects clients and reports the skill plan without writing files.
func Preview(options Options) (Result, error) {
	return reconcile(options, false)
}

// Run detects clients and reconciles their managed skills to the desired set.
func Run(options Options) (Result, error) {
	return reconcile(options, true)
}

func reconcile(options Options, execute bool) (Result, error) {
	if options.HomeDir == "" {
		return Result{}, fmt.Errorf("home directory is required")
	}
	if len(options.Desired) > 0 && options.Source == nil {
		return Result{}, fmt.Errorf("embedded skills source is required")
	}
	if options.Now.IsZero() {
		options.Now = time.Now()
	}

	clients, err := selectedClients(options.ClientIDs)
	if err != nil {
		return Result{}, err
	}

	result := Result{Clients: make([]ClientResult, 0, len(clients))}
	for _, client := range clients {
		result.Clients = append(result.Clients, reconcileClient(client, options, execute))
	}
	return result, nil
}

func reconcileClient(client Client, options Options, execute bool) ClientResult {
	skillsDir := client.SkillsDir(options.HomeDir)
	if client.ID == "claude-code" && options.ClaudeConfigDir != "" {
		skillsDir = filepath.Join(options.ClaudeConfigDir, "skills")
	}
	clientResult := ClientResult{
		ClientID:    client.ID,
		DisplayName: client.DisplayName,
		SkillsDir:   skillsDir,
	}

	detection, err := IsInstalled(client, options.HomeDir)
	if err != nil {
		clientResult.Status = ClientStatusFailed
		clientResult.Reason = err.Error()
		return clientResult
	}
	if !detection.Installed && client.ID == "claude-code" && options.ClaudeConfigDir != "" {
		if _, err := os.Stat(options.ClaudeConfigDir); err == nil {
			detection = Detection{
				Installed: true,
				Reason:    fmt.Sprintf("%s exists", options.ClaudeConfigDir),
			}
		} else if !os.IsNotExist(err) {
			clientResult.Status = ClientStatusFailed
			clientResult.Reason = fmt.Sprintf("inspect Claude Code config directory %s: %v", options.ClaudeConfigDir, err)
			return clientResult
		}
	}
	if !detection.Installed {
		clientResult.Status = ClientStatusSkipped
		clientResult.Reason = detection.Reason
		return clientResult
	}

	ops, err := planSkills(options.Source, clientResult.SkillsDir, options.Version, options.Desired, options.Now)
	if err != nil {
		clientResult.Status = ClientStatusFailed
		clientResult.Reason = err.Error()
		return clientResult
	}

	var settingsPlan claudeSettingsPlan
	if client.ID == "claude-code" && len(options.Desired) > 0 {
		configDir := options.ClaudeConfigDir
		if configDir == "" {
			configDir = filepath.Join(options.HomeDir, ".claude")
		}
		var settingsErr error
		settingsPlan, settingsErr = planClaudeSettings(
			filepath.Join(configDir, "settings.json"),
			options.SkipSkillListingBudget,
		)
		if settingsErr != nil {
			clientResult.Warnings = append(clientResult.Warnings, claudeSettingsWarning(settingsErr))
		} else {
			clientResult.Settings = &settingsPlan.change
		}
	}

	clientResult.Status = ClientStatusApplied
	clientResult.Reason = detection.Reason
	if !execute {
		clientResult.Changes = changesFromOps(ops)
		return clientResult
	}

	applied, warnings, err := applySkills(clientResult.SkillsDir, ops)
	clientResult.Changes = applied
	clientResult.Warnings = append(clientResult.Warnings, warnings...)
	if err != nil {
		clientResult.Status = ClientStatusFailed
		clientResult.Reason = err.Error()
	}

	if clientResult.Settings != nil {
		if applyErr := applyClaudeSettings(settingsPlan); applyErr != nil {
			clientResult.Settings = nil
			clientResult.Warnings = append(clientResult.Warnings, claudeSettingsWarning(applyErr))
		}
	}
	return clientResult
}

// HasFailures reports whether any detected client failed to update.
func (r Result) HasFailures() bool {
	for _, client := range r.Clients {
		if client.Status == ClientStatusFailed {
			return true
		}
	}
	return false
}

// FailureError returns a concise aggregate error suitable for a CLI exit.
func (r Result) FailureError() error {
	var failed []string
	for _, client := range r.Clients {
		if client.Status == ClientStatusFailed {
			failed = append(failed, client.DisplayName)
		}
	}
	if len(failed) == 0 {
		return nil
	}
	return fmt.Errorf("setup failed for: %s", strings.Join(failed, ", "))
}

func selectedClients(clientIDs []string) ([]Client, error) {
	if len(clientIDs) == 0 {
		return Clients(), nil
	}

	seen := make(map[string]bool, len(clientIDs))
	clients := make([]Client, 0, len(clientIDs))
	for _, clientID := range clientIDs {
		if seen[clientID] {
			continue
		}
		client, err := ClientByID(clientID)
		if err != nil {
			return nil, err
		}
		seen[clientID] = true
		clients = append(clients, client)
	}
	return clients, nil
}
