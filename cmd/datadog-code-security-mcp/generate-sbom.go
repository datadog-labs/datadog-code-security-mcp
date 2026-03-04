package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/sbom"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/types"
)

func newGenerateSBOMCmd() *cobra.Command {
	var (
		workingDir string
		outputJSON bool
	)

	cmd := &cobra.Command{
		Use:   "generate-sbom [path]",
		Short: "Generate Software Bill of Materials (SBOM)",
		Long: `Generate a comprehensive Software Bill of Materials (SBOM) listing all
software components, dependencies, versions, and licenses in a repository.

This command analyzes your project's dependency files (package.json, go.mod,
requirements.txt, pom.xml, etc.) and generates a detailed inventory of all
components using the datadog-sbom-generator binary.

The SBOM can be output in human-readable format (default) or JSON format.

Examples:
  # Generate SBOM for current directory
  datadog-code-security-mcp generate-sbom .

  # Generate SBOM for a specific path
  datadog-code-security-mcp generate-sbom ./my-project

  # Generate SBOM from a different working directory
  datadog-code-security-mcp generate-sbom . --working-dir /path/to/project

  # Output in JSON format
  datadog-code-security-mcp generate-sbom . --json`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "."
			if len(args) > 0 {
				path = args[0]
			}
			return runGenerateSBOM(path, workingDir, outputJSON)
		},
	}

	cmd.Flags().StringVarP(&workingDir, "working-dir", "w", "", "Working directory for resolving relative paths (defaults to current directory)")
	cmd.Flags().BoolVarP(&outputJSON, "json", "j", false, "Output results in JSON format")

	return cmd
}

func runGenerateSBOM(path string, workingDir string, outputJSON bool) error {
	ctx := context.Background()

	// Build SBOM args
	sbomArgs := types.SBOMArgs{
		Path:       path,
		WorkingDir: workingDir,
	}

	// Generate SBOM
	generator := sbom.NewGenerator()
	result, err := generator.Generate(ctx, sbomArgs)
	if err != nil {
		return err
	}

	// Output results
	if outputJSON {
		return outputSBOMResultsJSON(result)
	}
	return outputSBOMResultsHuman(result)
}

func outputSBOMResultsJSON(result *types.SBOMResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func outputSBOMResultsHuman(result *types.SBOMResult) error {
	fmt.Println("╔════════════════════════════════════════════════════════════════╗")
	fmt.Println("║       Software Bill of Materials (SBOM)                       ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Check for errors
	if result.Error != nil {
		fmt.Printf("⚠️  Error: %s\n", result.Error.Error)
		if result.Error.Hint != "" {
			fmt.Printf("Hint: %s\n", result.Error.Hint)
		}
		fmt.Println()

		// If no components, exit early
		if len(result.Components) == 0 {
			return nil
		}
	}

	// Summary
	fmt.Printf("Total Components: %d\n", result.Summary.TotalComponents)
	fmt.Println()

	// Breakdown by package manager
	if len(result.Summary.ByLanguage) > 0 {
		fmt.Println("By Package Manager:")
		for lang, count := range result.Summary.ByLanguage {
			fmt.Printf("  • %s: %d\n", lang, count)
		}
		fmt.Println()
	}

	// Breakdown by type
	if len(result.Summary.ByType) > 0 {
		fmt.Println("By Component Type:")
		for typ, count := range result.Summary.ByType {
			fmt.Printf("  • %s: %d\n", typ, count)
		}
		fmt.Println()
	}

	// No components found
	if result.Summary.TotalComponents == 0 {
		fmt.Println("✅ No components detected.")
		return nil
	}

	// Detailed components
	fmt.Println("─────────────────────────────────────────────────────────────────")
	fmt.Println("Components:")
	fmt.Println("─────────────────────────────────────────────────────────────────")
	fmt.Println()

	// Show components (limit to 100 for console output)
	displayLimit := 100
	componentsToShow := result.Components
	if len(result.Components) > displayLimit {
		componentsToShow = result.Components[:displayLimit]
	}

	for i, comp := range componentsToShow {
		fmt.Printf("%d. %s @ %s\n", i+1, comp.Name, comp.Version)
		if comp.Language != "" {
			fmt.Printf("   Language: %s\n", comp.Language)
		}
		if comp.PackageURL != "" {
			fmt.Printf("   PURL: %s\n", comp.PackageURL)
		}
		fmt.Println()
	}

	if len(result.Components) > displayLimit {
		remaining := len(result.Components) - displayLimit
		fmt.Printf("... and %d more components (total: %d)\n", remaining, len(result.Components))
		fmt.Println("Tip: Use --json flag to see all components")
		fmt.Println()
	}

	return nil
}
