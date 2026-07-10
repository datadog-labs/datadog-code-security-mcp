package telemetry

import (
	"fmt"
	"os"
)

const noticeText = `
Datadog Code Security MCP collects anonymous usage telemetry to improve the tool.

What is collected: tool name, version, OS/arch, run duration, success/failure,
  finding counts (numbers only), and a random anonymous install ID.
What is NOT collected: source code, file paths, scan findings, secrets,
  usernames, repo names, or any identifying information.

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
	if !c.enabled {
		return
	}

	result := loadOrCreateConfig()
	if result.config.FirstRunNoticeShown {
		return
	}

	fmt.Fprint(os.Stderr, noticeText)

	cfg := result.config
	cfg.FirstRunNoticeShown = true
	persistConfig(cfg)
}
