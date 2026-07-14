package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/binary"
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
// Flush is nil-safe, so this works even if the client was never constructed.
func flushTelemetry() {
	scannerVersionCache.Close()
	telemetryClient.Flush()
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
			opts := telemetry.Options{
				CompiledToken: telemetryClientToken,
				Env:           telemetryEnv,
				Version:       version,
				NoTelemetry:   noTelemetry,
			}
			if cmd.Name() == "start" {
				opts.SessionID = uuid.New().String()
			}
			telemetryClient = telemetry.New(opts)
			if telemetryClient.Enabled() {
				scannerVersionCache = binary.NewBinaryVersionCache()
				scannerVersionCache.Refresh()
			}
			telemetryClient.MaybeShowFirstRunNotice()
		},
		// Flush waits up to 500 ms for any in-flight telemetry POST before the
		// process exits. This keeps Track non-blocking (output is shown first)
		// while still delivering the event in the common case.
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			flushTelemetry()
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

	// Execute root command. When RunE returns an error Cobra skips
	// PersistentPostRun, so we flush telemetry here before exiting.
	// Print the error first so the user sees it immediately; Flush() then
	// waits up to flushTimeout for the in-flight POST before we exit.
	//
	// errViolationsFound is not a failure: the scan succeeded but reported
	// findings, so we exit non-zero without printing an error (the findings
	// were already rendered). Telemetry is still flushed either way.
	if err := rootCmd.Execute(); err != nil {
		if !errors.Is(err, errViolationsFound) {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
		flushTelemetry()
		os.Exit(1)
	}
}
