package main

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/binary"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/telemetry"
)

func newVersionCmd() *cobra.Command {
	var detailed bool

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Long: `Print version information for datadog-code-security-mcp and related components.

This command displays:
- datadog-code-security-mcp version, commit, and build time
- Go runtime version
- Operating system and architecture
- datadog-static-analyzer version (if installed)

Examples:
  # Basic version info
  datadog-code-security-mcp version

  # Detailed version info with scanner status
  datadog-code-security-mcp version --detailed`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			start := time.Now()
			err := printVersion(ctx, detailed)
			trackCLIOperation(ctx, telemetry.OperationEvent{
				Operation: "version",
				StartedAt: start,
				Detailed:  &detailed,
				Failure:   err,
			})
			return err
		},
	}

	cmd.Flags().BoolVarP(&detailed, "detailed", "d", false, "Show detailed version information including scanner status")

	return cmd
}

func printVersion(ctx context.Context, detailed bool) error {
	// Basic version info
	fmt.Printf("datadog-code-security-mcp version: %s\n", version)
	fmt.Printf("commit: %s\n", commit)
	fmt.Printf("built: %s\n", buildTime)

	if !detailed {
		return nil
	}

	// Runtime information
	fmt.Println()
	fmt.Println("Runtime Information:")
	fmt.Printf("  Go version: %s\n", runtime.Version())
	fmt.Printf("  OS/Arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("  Num CPU: %d\n", runtime.NumCPU())

	// Scanner status
	fmt.Println()
	fmt.Println("Scanner Status:")

	// Check if datadog-static-analyzer is installed
	bm := binary.NewBinaryManager()
	binaryPath, err := bm.GetBinaryPath(ctx)

	if err != nil {
		fmt.Println("  datadog-static-analyzer: ❌ NOT INSTALLED")
		fmt.Println()
		fmt.Println("Installation required:")
		fmt.Println(err.Error())
	} else {
		fmt.Printf("  datadog-static-analyzer: ✅ INSTALLED\n")
		fmt.Printf("  Location: %s\n", binaryPath)

		// Try to get scanner version
		// Note: We don't implement version detection in v1.0, just show it's installed
		fmt.Println("  Capabilities: SAST, Secrets Detection")
	}

	return nil
}
