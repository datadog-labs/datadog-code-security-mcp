package binary

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// Binary supported OS/architecture combination
type Platform struct {
	OS   string // "linux", "darwin", "windows"
	Arch string // "x86_64", "aarch64"
}

// NamingConvention represents different binary naming conventions
type NamingConvention string

const (
	NamingConventionRustTriple NamingConvention = "rust-triple" // aarch64-apple-darwin
	NamingConventionSimple     NamingConvention = "simple"      // darwin_arm64
)

// BinaryConfig contains the configuration for a specific binary type
type BinaryConfig struct {
	BinaryName         string
	GitHubRepo         string
	SupportedPlatforms []Platform
	NamingConvention   NamingConvention
}

// BinaryType represents different types of binaries
type BinaryType string

const (
	BinaryTypeStaticAnalyzer BinaryType = "static-analyzer"
	BinaryTypeSBOMGenerator  BinaryType = "sbom-generator"
	BinaryTypeSecurity       BinaryType = "security-cli"
)

// BinaryConfigs contains the configuration for all supported binaries
var BinaryConfigs = map[BinaryType]BinaryConfig{
	BinaryTypeStaticAnalyzer: {
		BinaryName:       "datadog-static-analyzer",
		GitHubRepo:       "DataDog/datadog-static-analyzer",
		NamingConvention: NamingConventionRustTriple,
		SupportedPlatforms: []Platform{
			{OS: "linux", Arch: "x86_64"},
			{OS: "linux", Arch: "aarch64"},
			{OS: "darwin", Arch: "x86_64"},
			{OS: "darwin", Arch: "aarch64"},
			{OS: "windows", Arch: "x86_64"},
		},
	},
	BinaryTypeSBOMGenerator: {
		BinaryName:       "datadog-sbom-generator",
		GitHubRepo:       "DataDog/datadog-sbom-generator",
		NamingConvention: NamingConventionSimple,
		SupportedPlatforms: []Platform{
			{OS: "linux", Arch: "amd64"},
			{OS: "linux", Arch: "arm64"},
			{OS: "darwin", Arch: "amd64"},
			{OS: "darwin", Arch: "arm64"},
		},
	},
	BinaryTypeSecurity: {
		BinaryName:       "datadog-security-cli",
		GitHubRepo:       "",                     // Not distributed via GitHub releases
		NamingConvention: NamingConventionSimple, // Not used for package-based install
		SupportedPlatforms: []Platform{
			{OS: "linux", Arch: "amd64"},
			{OS: "linux", Arch: "arm64"},
			{OS: "darwin", Arch: "amd64"},
			{OS: "darwin", Arch: "arm64"},
		},
	},
}

// BinaryManager manages scanner binaries
type BinaryManager struct {
	config BinaryConfig
}

// NewManager creates a manager for the specified binary type
func NewManager(binaryType BinaryType) *BinaryManager {
	return &BinaryManager{
		config: BinaryConfigs[binaryType],
	}
}

// NewBinaryManager creates a manager for datadog-static-analyzer
func NewBinaryManager() *BinaryManager {
	return NewManager(BinaryTypeStaticAnalyzer)
}

// NewSBOMGeneratorManager creates a manager for datadog-sbom-generator
func NewSBOMGeneratorManager() *BinaryManager {
	return NewManager(BinaryTypeSBOMGenerator)
}

// GetBinaryPath finds the binary in PATH.
// Returns an error with installation instructions if the binary is not found.
func (bm *BinaryManager) GetBinaryPath(ctx context.Context) (string, error) {
	// Check if binary exists in PATH
	path, err := exec.LookPath(bm.config.BinaryName)
	if err == nil {
		return path, nil
	}

	// Binary not found - return structured error with installation instructions
	return "", bm.formatMissingBinaryError()
}

// formatMissingBinaryError creates a structured error message with installation guidance
func (bm *BinaryManager) formatMissingBinaryError() error {
	installInstructions := bm.generateInstallInstructions()

	// Determine the purpose of this binary for context
	var purpose string
	switch bm.config.BinaryName {
	case "datadog-static-analyzer":
		purpose = "required for SAST and Secrets scanning"
	case "datadog-sbom-generator":
		purpose = "required for SBOM generation"
	case "datadog-security-cli":
		purpose = "required for SCA vulnerability scanning"
	default:
		purpose = "required for security scanning"
	}

	separator := strings.Repeat("━", 70)

	return fmt.Errorf(
		"⚠️  PREREQUISITE REQUIRED: Missing Security Scanner\n\n"+
			"Binary '%s' is not installed (%s).\n\n"+
			"%s\n"+
			"ACTION REQUIRED: Install the missing binary first\n"+
			"%s\n\n"+
			"Installation commands:\n\n"+
			"%s\n\n"+
			"%s\n"+
			"NEXT STEPS\n"+
			"%s\n\n"+
			"1. Run the installation command above\n"+
			"2. Retry the comprehensive security scan\n"+
			"3. If installation fails, you may run partial scans as fallback\n\n"+
			"This is a RECOVERABLE error. Install the binary and retry.",
		bm.config.BinaryName,
		purpose,
		separator,
		separator,
		installInstructions,
		separator,
		separator,
	)
}

// Execute runs the binary with the given arguments
func (bm *BinaryManager) Execute(ctx context.Context, binaryPath string, args []string, workingDir string) error {
	// no-dd-sa:go-security/command-injection - binaryPath is validated via exec.LookPath in GetBinaryPath(), not user-controlled
	cmd := exec.CommandContext(ctx, binaryPath, args...)
	cmd.Dir = workingDir

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to execute %s: %w\nOutput: %s", bm.config.BinaryName, err, string(output))
	}

	return nil
}

func (bm *BinaryManager) generateInstallInstructions() string {
	// Special handling for datadog-security-cli (package-based installation)
	if bm.config.BinaryName == "datadog-security-cli" {
		return bm.generateSecurityCLIInstructions()
	}

	os := runtime.GOOS
	arch := runtime.GOARCH

	archName := bm.mapArchitecture(arch)
	if archName == "" {
		return fmt.Sprintf("# Binary not available for %s/%s\n# Please visit: https://github.com/%s/releases",
			os, arch, bm.config.GitHubRepo)
	}

	// Check if this platform is supported
	if !bm.isPlatformSupported(os, archName) {
		return bm.generateUnsupportedPlatformMessage(os, archName)
	}

	// Generate platform-specific binary name
	var binaryFileName string

	if bm.config.NamingConvention == NamingConventionSimple {
		// Simple convention: {name}_{os}_{arch}.zip
		binaryFileName = fmt.Sprintf("%s_%s_%s.zip", bm.config.BinaryName, os, archName)
	} else {
		// Rust triple convention: {name}-{arch}-{platform-suffix}.zip
		switch os {
		case "linux":
			binaryFileName = fmt.Sprintf("%s-%s-unknown-linux-gnu.zip", bm.config.BinaryName, archName)
		case "darwin":
			binaryFileName = fmt.Sprintf("%s-%s-apple-darwin.zip", bm.config.BinaryName, archName)
		case "windows":
			binaryFileName = fmt.Sprintf("%s-%s-pc-windows-msvc.zip", bm.config.BinaryName, archName)
		default:
			return fmt.Sprintf("# Binary not available for %s\n# Please visit: https://github.com/%s/releases",
				os, bm.config.GitHubRepo)
		}
	}

	downloadURL := fmt.Sprintf("https://github.com/%s/releases/latest/download/%s",
		bm.config.GitHubRepo, binaryFileName)

	// Generate OS-specific instructions
	switch os {
	case "linux", "darwin":
		shellRC := "~/.bashrc"
		if os == "darwin" {
			shellRC = "~/.zshrc"
		}
		return fmt.Sprintf(`# Install %s to ~/.local/bin (no sudo required):
curl -L %s -o /tmp/%s.zip && unzip -o /tmp/%s.zip -d /tmp/ && mkdir -p ~/.local/bin && mv /tmp/%s ~/.local/bin/ && chmod +x ~/.local/bin/%s

# Add to PATH (if not already added):
echo 'export PATH="$HOME/.local/bin:$PATH"' >> %s && source %s

# Verify installation:
%s --version

# For more details visit: https://github.com/%s/releases`,
			bm.config.BinaryName,
			downloadURL,
			bm.config.BinaryName,
			bm.config.BinaryName,
			bm.config.BinaryName,
			bm.config.BinaryName,
			shellRC,
			shellRC,
			bm.config.BinaryName,
			bm.config.GitHubRepo)

	case "windows":
		return fmt.Sprintf(`# Download the latest %s:
# https://github.com/%s/releases
# Download URL: %s

# After download, please extract the ZIP file and move the binary to a directory in your PATH

# Finally, run the requested scan.
`,
			bm.config.BinaryName,
			bm.config.GitHubRepo,
			downloadURL)

	default:
		return fmt.Sprintf("# Please visit: https://github.com/%s/releases", bm.config.GitHubRepo)
	}
}

func (bm *BinaryManager) mapArchitecture(goArch string) string {
	// For simple naming convention, use Go architecture names directly
	if bm.config.NamingConvention == NamingConventionSimple {
		switch goArch {
		case "amd64", "arm64":
			return goArch
		default:
			return "" // Unsupported
		}
	}

	// For rust-triple naming convention, map to Rust target names
	switch goArch {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	default:
		return "" // Unsupported architecture
	}
}

func (bm *BinaryManager) isPlatformSupported(os, arch string) bool {
	for _, platform := range bm.config.SupportedPlatforms {
		if platform.OS == os && platform.Arch == arch {
			return true
		}
	}
	return false
}

func (bm *BinaryManager) generateUnsupportedPlatformMessage(os, arch string) string {
	var supportedList strings.Builder
	supportedList.WriteString(fmt.Sprintf("# Binary not available for %s/%s\n\n", os, arch))
	supportedList.WriteString("# Supported platforms:\n")

	for _, platform := range bm.config.SupportedPlatforms {
		supportedList.WriteString(fmt.Sprintf("#   - %s/%s\n", platform.OS, platform.Arch))
	}

	supportedList.WriteString(fmt.Sprintf("\n# For more information, visit: https://github.com/%s/releases", bm.config.GitHubRepo))
	return supportedList.String()
}

func (bm *BinaryManager) generateSecurityCLIInstructions() string {
	os := runtime.GOOS

	switch os {
	case "linux":
		// Detect if it's Debian/Ubuntu or Red Hat based
		return `# Install datadog-security-cli on Linux:

## Debian/Ubuntu
# Import Datadog APT signing key
DD_APT_KEY_URL="https://keys.datadoghq.com/DATADOG_APT_KEY_CURRENT.public"
curl -fsSL "$DD_APT_KEY_URL" | sudo gpg --dearmor -o /usr/share/keyrings/datadog-archive-keyring.gpg

# Add Datadog repository
echo "deb [signed-by=/usr/share/keyrings/datadog-archive-keyring.gpg] https://apt.datadoghq.com/ stable datadog-security-cli" | sudo tee /etc/apt/sources.list.d/datadog-security-cli.list

# Update package list and install
sudo apt update
sudo apt install datadog-security-cli

## Red Hat/CentOS/Fedora
# Import Datadog RPM signing key
sudo rpm --import https://keys.datadoghq.com/DATADOG_RPM_KEY_CURRENT.public

# Add Datadog repository
sudo tee /etc/yum.repos.d/datadog-security-cli.repo > /dev/null <<'EOF'
[datadog-security-cli]
name=Datadog Security CLI
baseurl=https://yum.datadoghq.com/stable/datadog-security-cli/$basearch/
enabled=1
gpgcheck=1
gpgkey=https://keys.datadoghq.com/DATADOG_RPM_KEY_CURRENT.public
repo_gpgcheck=1
EOF

# Install the CLI
sudo yum install datadog-security-cli

# Verify installation
datadog-security-cli --version`

	case "darwin":
		return `# Install datadog-security-cli on macOS:

# Install via Homebrew
brew install --cask datadog/tap/datadog-security-cli

# Verify installation
datadog-security-cli --version`

	default:
		return `# datadog-security-cli installation:

# This tool is currently only available for Linux and macOS.
# Please visit the Datadog documentation for installation instructions:
# https://docs.datadoghq.com/security/cloud_security_management/setup/ci_cd`
	}
}
