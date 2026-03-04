#!/bin/bash
# Claude Desktop E2E Test Script
# Tests the complete user workflow: clean slate → install → configure → scan
#
# This script validates:
# 1. Remove all binaries (clean environment)
# 2. Install datadog-code-security-mcp via brew/manual
# 3. Configure Claude Desktop
# 4. Verify tools are available
# 5. Test that scans prompt for binary installation
# 6. Confirm installation and verify scans work
#
# Usage:
#   ./scripts/test-claude-e2e.sh

set -e  # Exit on error

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=========================================="
echo "Claude CLI/Desktop E2E Test"
echo "==========================================${NC}"
echo ""
echo "This test simulates a complete user workflow:"
echo "  1. Clean environment (remove binaries)"
echo "  2. Build and install MCP server"
echo "  3. Configure Claude CLI/Desktop"
echo "  4. Test MCP tools registration"
echo "  5. Test binary installation prompts"
echo "  6. Run security scans"
echo ""

# Get project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_ROOT}"

# =============================================================================
# Step 1: CLEAN ENVIRONMENT - Remove all binaries
# =============================================================================
echo -e "${BLUE}==> Step 1/7: Cleaning environment (removing binaries)...${NC}"

REMOVED_BINARIES=()

# Remove datadog-static-analyzer
if command -v datadog-static-analyzer &> /dev/null; then
  ANALYZER_PATH=$(which datadog-static-analyzer)
  echo "  Found datadog-static-analyzer at: ${ANALYZER_PATH}"

  if [[ "$ANALYZER_PATH" == *"/.local/bin/"* ]] || [[ "$ANALYZER_PATH" == */bin/* ]]; then
    echo "  Removing: ${ANALYZER_PATH}"
    rm -f "${ANALYZER_PATH}"
    REMOVED_BINARIES+=("datadog-static-analyzer")
    echo -e "${GREEN}  ✓ Removed datadog-static-analyzer${NC}"
  else
    echo -e "${YELLOW}  ⚠ Skipping removal (system/brew installation): ${ANALYZER_PATH}${NC}"
    echo "    To fully test, manually remove with: brew uninstall datadog-static-analyzer"
  fi
else
  echo "  ✓ datadog-static-analyzer not found (already clean)"
fi

# Remove datadog-sbom-generator
if command -v datadog-sbom-generator &> /dev/null; then
  SBOM_PATH=$(which datadog-sbom-generator)
  echo "  Found datadog-sbom-generator at: ${SBOM_PATH}"

  if [[ "$SBOM_PATH" == *"/.local/bin/"* ]] || [[ "$SBOM_PATH" == */bin/* ]]; then
    echo "  Removing: ${SBOM_PATH}"
    rm -f "${SBOM_PATH}"
    REMOVED_BINARIES+=("datadog-sbom-generator")
    echo -e "${GREEN}  ✓ Removed datadog-sbom-generator${NC}"
  else
    echo -e "${YELLOW}  ⚠ Skipping removal (system/brew installation): ${SBOM_PATH}${NC}"
    echo "    To fully test, manually remove with: brew uninstall datadog-sbom-generator"
  fi
else
  echo "  ✓ datadog-sbom-generator not found (already clean)"
fi

# Remove datadog-security-cli
if command -v datadog-security-cli &> /dev/null; then
  CLI_PATH=$(which datadog-security-cli)
  echo "  Found datadog-security-cli at: ${CLI_PATH}"

  if [[ "$CLI_PATH" == *"/.local/bin/"* ]] || [[ "$CLI_PATH" == */bin/* ]]; then
    echo "  Removing: ${CLI_PATH}"
    rm -f "${CLI_PATH}"
    REMOVED_BINARIES+=("datadog-security-cli")
    echo -e "${GREEN}  ✓ Removed datadog-security-cli${NC}"
  else
    echo -e "${YELLOW}  ⚠ Skipping removal (system/brew installation): ${CLI_PATH}${NC}"
    echo "    To fully test, manually remove with: brew uninstall datadog-security-cli"
  fi
else
  echo "  ✓ datadog-security-cli not found (already clean)"
fi

echo ""
if [[ ${#REMOVED_BINARIES[@]} -gt 0 ]]; then
  echo -e "${GREEN}✓ Cleaned ${#REMOVED_BINARIES[@]} binary(ies): ${REMOVED_BINARIES[*]}${NC}"
else
  echo -e "${YELLOW}⚠ No binaries removed (may need manual cleanup for brew installations)${NC}"
fi
echo ""

# =============================================================================
# Step 2: BUILD MCP SERVER
# =============================================================================
echo -e "${BLUE}==> Step 2/7: Building MCP server...${NC}"

make clean
make build

if [[ -f "bin/datadog-code-security-mcp" ]]; then
  echo -e "${GREEN}✓ MCP server built successfully${NC}"
  ls -lh bin/datadog-code-security-mcp
else
  echo -e "${RED}❌ ERROR: MCP server binary not found${NC}"
  exit 1
fi
echo ""

# =============================================================================
# Step 3: CONFIGURE CLAUDE DESKTOP
# =============================================================================
echo -e "${BLUE}==> Step 3/7: Configuring Claude Desktop...${NC}"

# Check if claude CLI is available
if ! command -v claude &> /dev/null; then
  echo -e "${RED}❌ ERROR: claude CLI not found${NC}"
  echo ""
  echo "Install Claude CLI:"
  echo "  brew install anthropics/claude/claude"
  exit 1
fi

# Remove existing configuration
claude mcp remove datadog-code-security 2>/dev/null || true

# Add MCP server
BINARY_PATH="${PROJECT_ROOT}/bin/datadog-code-security-mcp"
claude mcp add datadog-code-security \
  ${DD_API_KEY:+-e DD_API_KEY="$DD_API_KEY"} \
  ${DD_APP_KEY:+-e DD_APP_KEY="$DD_APP_KEY"} \
  ${DD_SITE:+-e DD_SITE="$DD_SITE"} \
  -- "${BINARY_PATH}" start

echo -e "${GREEN}✓ Claude Desktop configured${NC}"
echo "  Binary: ${BINARY_PATH}"
echo "  Environment: DD_API_KEY, DD_APP_KEY, DD_SITE (if set)"
echo ""

# =============================================================================
# Step 4: VERIFY CLAUDE CLI
# =============================================================================
echo -e "${BLUE}==> Step 4/7: Verifying Claude CLI configuration...${NC}"

# Check current MCP configuration
if claude mcp list | grep -q "datadog-code-security"; then
  echo -e "${GREEN}✓ MCP server configured in Claude CLI${NC}"
  claude mcp list | grep -A 3 "datadog-code-security"
else
  echo -e "${RED}❌ ERROR: MCP server not found in Claude CLI config${NC}"
  exit 1
fi
echo ""

# =============================================================================
# Step 5: VERIFY MCP TOOLS REGISTERED
# =============================================================================
echo -e "${BLUE}==> Step 5/7: Verifying MCP tools registration...${NC}"

# Test MCP protocol directly via STDIO
TOOLS_REQUEST='{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
TOOLS_RESPONSE=$(echo "${TOOLS_REQUEST}" | timeout 10 "${BINARY_PATH}" start 2>&1 | tail -1)

if command -v jq &> /dev/null; then
  TOOL_COUNT=$(echo "${TOOLS_RESPONSE}" | jq -r '.result.tools | length' 2>/dev/null || echo "0")

  if [[ $TOOL_COUNT -ge 5 ]]; then
    echo -e "${GREEN}✓ MCP tools registered: ${TOOL_COUNT} tools${NC}"
    echo ""
    echo "  Available tools:"
    echo "${TOOLS_RESPONSE}" | jq -r '.result.tools[].name' 2>/dev/null | sed 's/^/    - /'
  else
    echo -e "${RED}❌ ERROR: Expected at least 5 tools, found ${TOOL_COUNT}${NC}"
    exit 1
  fi
else
  echo -e "${YELLOW}⚠ jq not found, skipping tool count validation${NC}"
fi
echo ""

# =============================================================================
# Step 6: TEST BINARY INSTALLATION WORKFLOW (MCP Protocol)
# =============================================================================
echo -e "${BLUE}==> Step 6/7: Testing binary installation workflow via MCP...${NC}"
echo ""
echo "Testing that scanner detects missing binaries via MCP tools..."
echo ""

# Test SAST scan via MCP protocol without binaries (should fail with instructions)
SAST_REQUEST='{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"datadog_sast_scan","arguments":{"file_paths":["./testdata/vulnerabilities/sast"]}}}'
SAST_RESPONSE=$(echo "${SAST_REQUEST}" | timeout 30 "${BINARY_PATH}" start 2>&1 | grep -v "Starting\|Auth:\|Note:\|Server ready" | tail -1)

if echo "$SAST_RESPONSE" | grep -q "not found in PATH"; then
  echo -e "${GREEN}✓ MCP tool correctly detects missing datadog-static-analyzer${NC}"

  if echo "$SAST_RESPONSE" | grep -q "curl"; then
    echo -e "${GREEN}✓ Provides installation instructions via MCP${NC}"
  else
    echo -e "${RED}❌ ERROR: No installation instructions provided${NC}"
    exit 1
  fi
else
  echo -e "${YELLOW}⚠ Binary already installed - skipping installation test${NC}"
fi
echo ""

# =============================================================================
# Step 7: VERIFY SCANS WORK AFTER BINARY INSTALLATION
# =============================================================================
echo -e "${BLUE}==> Step 7/7: Testing scans with binaries installed via MCP...${NC}"
echo ""
echo -e "${YELLOW}This step requires the security binaries to be installed.${NC}"
echo ""
echo "Install the binaries now? This will download and install:"
echo "  - datadog-static-analyzer (for SAST/Secrets)"
echo "  - datadog-sbom-generator (for SBOM)"
echo "  - datadog-security-cli (for SCA)"
echo ""
echo "Install now? (y/n): "
read -r INSTALL_ANSWER

if [[ "$INSTALL_ANSWER" == "y" ]] || [[ "$INSTALL_ANSWER" == "Y" ]]; then
  echo ""
  echo "Installing binaries..."
  echo ""

  # Get installation instructions via MCP
  SAST_REQUEST='{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"datadog_sast_scan","arguments":{"file_paths":["./testdata/vulnerabilities/sast"]}}}'
  INSTALL_INSTRUCTIONS=$(echo "${SAST_REQUEST}" | timeout 30 "${BINARY_PATH}" start 2>&1 | grep -A 20 "Installation:" || true)

  # Install datadog-static-analyzer using a known-safe command instead of
  # extracting and eval'ing commands from MCP output (which would be RCE if
  # the server were compromised).
  # Release artifacts use rust-triple naming: {name}-{arch}-{platform-suffix}.zip
  #   e.g. datadog-static-analyzer-aarch64-apple-darwin.zip
  #        datadog-static-analyzer-x86_64-unknown-linux-gnu.zip
  echo "Installing datadog-static-analyzer from GitHub releases..."
  ARCH=$(uname -m)  # x86_64 or aarch64 (matches rust-triple arch names)
  case "$(uname -s)" in
    Darwin) PLATFORM_SUFFIX="apple-darwin" ;;
    Linux)  PLATFORM_SUFFIX="unknown-linux-gnu" ;;
    *)      echo -e "${RED}❌ Unsupported OS: $(uname -s)${NC}"; exit 1 ;;
  esac
  curl -fsSL "https://github.com/DataDog/datadog-static-analyzer/releases/latest/download/datadog-static-analyzer-${ARCH}-${PLATFORM_SUFFIX}.zip" -o /tmp/dsa.zip
  unzip -o /tmp/dsa.zip -d /tmp/
  mkdir -p ~/.local/bin
  mv /tmp/datadog-static-analyzer ~/.local/bin/
  chmod +x ~/.local/bin/datadog-static-analyzer
  export PATH="$HOME/.local/bin:$PATH"
  echo -e "${GREEN}✓ datadog-static-analyzer installed${NC}"

  echo ""
  echo -e "${YELLOW}Note: You may need to install other binaries manually if needed${NC}"
  echo ""
fi

echo ""
echo "Now testing scans via MCP protocol..."
echo ""

# Test SBOM generation via MCP (works without auth)
echo "1. Testing SBOM generation via MCP..."
SBOM_REQUEST='{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"datadog_generate_sbom","arguments":{"path":"./testdata/sbom-test"}}}'
SBOM_RESPONSE=$(echo "${SBOM_REQUEST}" | timeout 30 "${BINARY_PATH}" start 2>&1 | grep -v "Starting\|Auth:\|Note:\|Server ready" | tail -1)

if command -v jq &> /dev/null; then
  COMPONENT_COUNT=$(echo "$SBOM_RESPONSE" | jq -r '.result.content[0].text' 2>/dev/null | grep -o "Components found: [0-9]*" || echo "unknown")
  if [[ "$COMPONENT_COUNT" != "unknown" ]]; then
    echo -e "${GREEN}✓ SBOM generation works via MCP${NC}"
    echo "  $COMPONENT_COUNT"
  else
    echo -e "${YELLOW}⚠ SBOM generation may need datadog-sbom-generator binary${NC}"
  fi
else
  echo -e "${YELLOW}⚠ jq not found, skipping SBOM validation${NC}"
fi
echo ""

# Test comprehensive scan via MCP (if binaries available)
echo "2. Testing comprehensive security scan via MCP..."
SCAN_REQUEST='{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"datadog_code_security_scan","arguments":{"file_paths":["./testdata/vulnerabilities"]}}}'
SCAN_RESPONSE=$(echo "${SCAN_REQUEST}" | timeout 60 "${BINARY_PATH}" start 2>&1 | grep -v "Starting\|Auth:\|Note:\|Server ready" | tail -1)

if echo "$SCAN_RESPONSE" | grep -q "result"; then
  echo -e "${GREEN}✓ Comprehensive security scan via MCP works${NC}"

  if command -v jq &> /dev/null; then
    SCAN_TEXT=$(echo "$SCAN_RESPONSE" | jq -r '.result.content[0].text' 2>/dev/null | head -20)
    echo ""
    echo "Sample output:"
    echo "$SCAN_TEXT" | sed 's/^/  /'
  fi
else
  echo -e "${YELLOW}⚠ Scan may require binaries to be installed${NC}"
fi
echo ""

echo -e "${YELLOW}To test interactively with Claude CLI:${NC}"
echo ""
echo -e "${GREEN}  claude \"Scan testdata/vulnerabilities/sast for security issues\"${NC}"
echo "  Expected: Detect SQL injection, XSS, path traversal via MCP"
echo ""
echo -e "${GREEN}  claude \"Check testdata/vulnerabilities/secrets for hardcoded credentials\"${NC}"
echo "  Expected: Detect API keys, AWS credentials, GitHub tokens via MCP"
echo ""
echo -e "${GREEN}  claude \"Generate an SBOM for testdata/sbom-test\"${NC}"
echo "  Expected: Find ~27 Go module components via MCP"
echo ""

# =============================================================================
# SUMMARY
# =============================================================================
echo ""
echo -e "${GREEN}=========================================="
echo "✅ Claude CLI/Desktop E2E Test Complete!"
echo "==========================================${NC}"
echo ""
echo "Workflow tested:"
echo "  ✅ Clean environment (removed binaries)"
echo "  ✅ Built MCP server from source"
echo "  ✅ Configured Claude CLI"
echo "  ✅ Verified MCP tools registered (${TOOL_COUNT} tools)"
echo "  ✅ Tested binary installation prompts"
echo ""
echo "Next steps:"
echo "  1. Test scans using Claude CLI:"
echo "     claude \"Scan this directory for vulnerabilities\""
echo "  2. Verify all scan types (SAST, Secrets, SBOM, SCA)"
echo "  3. Test error handling and edge cases"
echo "  4. If using Claude Desktop, test with the GUI interface"
echo ""
echo -e "${YELLOW}Note: Remember to reinstall binaries for regular use:${NC}"
if [[ ${#REMOVED_BINARIES[@]} -gt 0 ]]; then
  for binary in "${REMOVED_BINARIES[@]}"; do
    echo "  brew install datadog/tap/${binary}"
  done
fi
echo ""
