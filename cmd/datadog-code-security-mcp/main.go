package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/telemetry"
)

var (
	version   = "dev"
	commit    = "none"
	buildTime = "unknown"

	// telemetryClientToken is a publicly-embeddable RUM-style client token injected at
	// build time via -X main.telemetryClientToken=<token>. When empty (local/dev builds)
	// telemetry is silently disabled. Falls back to DD_CODE_SECURITY_TELEMETRY_TOKEN env var.
	telemetryClientToken = ""

	// telemetryEnv is the deployment environment injected at build time.
	// Defaults to "development"; release builds set "production".
	telemetryEnv = "development"
)

// telemetryClient is the package-level client shared by all CLI commands.
// Initialised once in main() before any subcommand runs.
var telemetryClient *telemetry.Client

// flushTelemetry drains any in-flight telemetry POST before the process exits.
// Call this immediately before os.Exit so the goroutine has a chance to finish.
func flushTelemetry() {
	if telemetryClient != nil {
		telemetryClient.Flush()
	}
}

func main() {
	var noTelemetry bool

	rootCmd := &cobra.Command{
		Use:   "datadog-code-security-mcp",
		Short: "Datadog Code Security MCP Server",
		Long: `A local MCP server that provides all Datadog Code security scanning capabilities (SAST, Secrets, SCA) and SBOM generation
for AI coding assistants like Claude Desktop, Cursor, and Zed.

Usage Examples:
  # Start MCP server for AI assistants (STDIO transport)
  datadog-code-security-mcp start

  # Run direct scan without MCP server
  datadog-code-security-mcp scan sast ./src
  datadog-code-security-mcp scan secrets ./config
  datadog-code-security-mcp scan all ./
  datadog-code-security-mcp scan library --purl pkg:golang/github.com/foo/bar@v1.0.0
  datadog-code-security-mcp generate-sbom .

For more information, visit: https://github.com/datadog-labs/datadog-code-security-mcp`,
		Version:       fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, buildTime),
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			telemetryClient = telemetry.New(telemetry.Options{
				CompiledToken: telemetryClientToken,
				Env:           telemetryEnv,
				Version:       version,
				NoTelemetry:   noTelemetry,
			})
			telemetryClient.MaybeShowFirstRunNotice()
		},
		// Flush waits up to 500 ms for any in-flight telemetry POST before the
		// process exits. This keeps Track non-blocking (output is shown first)
		// while still delivering the event in the common case.
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			if telemetryClient != nil {
				telemetryClient.Flush()
			}
		},
	}

	// --no-telemetry is a persistent flag visible on all subcommands.
	rootCmd.PersistentFlags().BoolVar(&noTelemetry, "no-telemetry", false,
		"Disable anonymous usage telemetry")

	// Add commands
	rootCmd.AddCommand(
		newStartCmd(),        // MCP server mode
		newScanCmd(),         // Direct scan mode
		newGenerateSBOMCmd(), // SBOM generation
		newVersionCmd(),      // Version info
	)

	// Execute root command
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
