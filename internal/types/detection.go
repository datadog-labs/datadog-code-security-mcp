package types

// DetectionType represents the type of security detection
type DetectionType string

const (
	DetectionTypeSAST    DetectionType = "sast"
	DetectionTypeSecrets DetectionType = "secrets"
	DetectionTypeSBOM    DetectionType = "sbom"
	DetectionTypeSCA     DetectionType = "sca"
	DetectionTypeIaC     DetectionType = "iac"
)

// AllowedDetectionTypes returns all valid detection types
func AllowedDetectionTypes() []string {
	return []string{
		string(DetectionTypeSAST),
		string(DetectionTypeSecrets),
		string(DetectionTypeSBOM),
		string(DetectionTypeSCA),
		string(DetectionTypeIaC),
	}
}

// SecurityScanTypes returns the canonical set and order used by "scan all".
// SBOM generation is intentionally excluded because it is not a vulnerability
// scan and has its own command/tool.
func SecurityScanTypes() []string {
	return []string{
		string(DetectionTypeSAST),
		string(DetectionTypeSecrets),
		string(DetectionTypeSCA),
		string(DetectionTypeIaC),
	}
}

// Supported package managers by datadog-sbom-generator
// These are documented for Claude to know when to use the tool vs manual analysis
const (
	SupportedPackageManagers = `.NET: NuGet
C++: Conan
Go: Go modules
Java: Gradle, Maven
JavaScript: NPM, PNPM, Yarn
PHP: Composer
Python: pdm, pipenv, poetry, requirements.txt, uv
Ruby: Bundler
Rust: Cargo`

	ManualSBOMSuggestion = "The package manager may not be supported. Supported: .NET (NuGet), C++ (Conan), Go (modules), Java (Gradle/Maven), JavaScript (NPM/PNPM/Yarn), PHP (Composer), Python (pdm/pipenv/poetry/requirements/uv), Ruby (Bundler), Rust (Cargo). " +
		"Claude should perform manual SBOM generation by reading lock files (package.json, requirements.txt, go.mod, pom.xml, Gemfile.lock, Cargo.lock, composer.lock, etc.) and extracting dependencies."

	// NoComponentsDetectedMessage is the curated, non-fatal notice message used
	// whenever datadog-sbom-generator produces zero components — whether from a
	// standalone SBOM generation or as SCA's internal first step. It is a fixed,
	// privacy-safe string so it can also be logged verbatim in telemetry.
	NoComponentsDetectedMessage = "No components detected by datadog-sbom-generator"
)
