package telemetry

import (
	"context"
	"fmt"
	"os"
)

const noticeText = `
Datadog Code Security MCP collects anonymous usage telemetry to improve the tool.

What is collected: tool and scanner versions, OS/arch, run duration,
  success/failure, aggregate counts, coarse auth/workspace metadata, categorized
  error kinds with a short curated (path-free) description, a fixed team
  ownership tag, and a random anonymous install ID.
What is NOT collected: source code, absolute paths or directory structure,
  scan finding contents, secrets, usernames, repo names, or raw error messages.

To opt out, set DD_CODE_SECURITY_TELEMETRY_DISABLED=1 or use --no-telemetry.
More information: https://github.com/datadog-labs/datadog-code-security-mcp/blob/main/docs/TELEMETRY.md
`

// MaybeShowFirstRunNotice prints a one-time telemetry disclosure to stderr
// the first time telemetry is active. It then persists the "notice shown" flag
// so subsequent runs are silent.
//
// In CLI mode this is visible in the terminal. In MCP server mode stderr is
// captured into the client's log files (not directly user-visible); the primary
// disclosure for MCP users is the documentation.
func (c *Client) MaybeShowFirstRunNotice() {
	if !c.Enabled() || !c.firstRun {
		return
	}
	c.noticeOnce.Do(func() {
		fmt.Fprint(os.Stderr, noticeText)
		result := updateConfig(func(cfg *persistedConfig) {
			cfg.FirstRunNoticeShown = true
		})
		c.emitConfigResult(context.Background(), "telemetry_config_update_failed", result.errors, result.renameAttempts, nil)
	})
}
