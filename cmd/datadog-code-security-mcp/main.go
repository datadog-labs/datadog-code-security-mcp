package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	version   = "dev"
	commit    = "none"
	buildTime = "unknown"
)

func main() {
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
  datadog-code-security-mcp generate-sbom .

For more information, visit: https://github.com/datadog-labs/datadog-code-security-mcp`,
		Version:       fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, buildTime),
		SilenceUsage:  true,
		SilenceErrors: true,
	}

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
