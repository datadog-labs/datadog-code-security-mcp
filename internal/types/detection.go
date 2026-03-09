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
)
