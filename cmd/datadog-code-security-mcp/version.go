package main

import (
	"context"
	"fmt"
	"io"
	"runtime"
	"strings"
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
- Status, location, and version of every required scanner binary

Examples:
  # Basic version info
  datadog-code-security-mcp version

  # Detailed version info with scanner status
  datadog-code-security-mcp version --detailed`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			start := time.Now()
			err := printVersion(ctx, cmd.OutOrStdout(), detailed)
			trackOperation(ctx, telemetry.OperationEvent{
				Interface: telemetry.InterfaceCLI,
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

func printVersion(ctx context.Context, writer io.Writer, detailed bool) error {
	var output strings.Builder
	write := func(format string, args ...any) {
		_, _ = fmt.Fprintf(&output, format, args...)
	}

	// Basic version info
	write("datadog-code-security-mcp version: %s\n", version)
	write("commit: %s\n", commit)
	write("built: %s\n", buildTime)

	if !detailed {
		_, err := io.WriteString(writer, output.String())
		return err
	}

	// Runtime information
	write("\nRuntime Information:\n")
	write("  Go version: %s\n", runtime.Version())
	write("  OS/Arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	write("  Num CPU: %d\n", runtime.NumCPU())

	// Scanner status
	write("\nScanner Status:\n")

	for index, binaryType := range binary.OrderedBinaryTypes() {
		if index > 0 {
			write("\n")
		}

		config := binary.BinaryConfigs[binaryType]
		manager := binary.NewManager(binaryType)
		binaryPath, err := manager.GetBinaryPath(ctx)
		if err != nil {
			write("  %s: ❌ NOT INSTALLED\n", config.BinaryName)
			write("\nInstallation required:\n")
			write("%s\n", err.Error())
			continue
		}

		write("  %s: ✅ INSTALLED\n", config.BinaryName)
		write("  Location: %s\n", binaryPath)
		probeCtx, cancel := context.WithTimeout(ctx, binary.VersionProbeTimeout)
		binaryVersion := manager.GetVersion(probeCtx)
		cancel()
		write("  Version: %s\n", binaryVersion)
	}

	_, err := io.WriteString(writer, output.String())
	return err
}
