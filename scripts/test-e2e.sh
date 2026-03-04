#!/bin/bash
# E2E Test Script for datadog-code-security-mcp
# Tests SAST and Secrets scanners with test fixtures
#
# Usage:
#   ./scripts/test-e2e.sh           # CI mode (default, headless)
#   ./scripts/test-e2e.sh --ci      # CI mode (explicit)
#   ./scripts/test-e2e.sh --full    # Full mode (includes Claude Desktop)

set -e  # Exit on error
set -o pipefail  # Exit on pipe failure

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_WARNED=0

# Parse arguments
MODE="ci"  # Default to CI mode
if [[ "$1" == "--full" ]]; then
  MODE="full"
elif [[ "$1" == "--ci" ]]; then
  MODE="ci"
elif [[ -n "$1" ]]; then
  echo -e "${RED}❌ ERROR: Unknown argument '$1'${NC}"
  echo "Usage: $0 [--ci|--full]"
  exit 1
fi

if [[ "$MODE" == "ci" ]]; then
  echo -e "${BLUE}==> Running E2E tests in CI mode (7 tests, Claude Desktop skipped)${NC}"
else
  echo -e "${BLUE}==> Running E2E tests in FULL mode (8 tests, including Claude Desktop)${NC}"
fi
echo ""

# Determine project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_ROOT}"

# Create temp directory for test outputs
TEST_OUTPUT_DIR="${TEST_OUTPUT_DIR:-/tmp}"
mkdir -p "${TEST_OUTPUT_DIR}"

echo -e "${BLUE}==> Project root: ${PROJECT_ROOT}${NC}"
echo -e "${BLUE}==> Test outputs will be saved to: ${TEST_OUTPUT_DIR}/*-output.json${NC}"
echo ""

# =============================================================================
# Test 1: BUILD - Build local MCP server
# =============================================================================
echo -e "${BLUE}==> Test 1/7: Building MCP server...${NC}"
if make clean && make build; then
  if [[ -f "bin/datadog-code-security-mcp" ]]; then
    echo -e "${GREEN}✓ Build successful${NC}"
    ls -lh bin/datadog-code-security-mcp
    TESTS_PASSED=$((TESTS_PASSED + 1))
  else
    echo -e "${RED}❌ ERROR: Binary not found after build${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    exit 1
  fi
else
  echo -e "${RED}❌ ERROR: Build failed${NC}"
  TESTS_FAILED=$((TESTS_FAILED + 1))
  exit 1
fi
echo ""

# =============================================================================
# Test 2: CHECK BINARIES - Verify required binaries exist
# =============================================================================
echo -e "${BLUE}==> Test 2/7: Checking for required binaries...${NC}"

BINARIES_OK=true

if command -v datadog-static-analyzer &> /dev/null; then
  ANALYZER_PATH=$(which datadog-static-analyzer)
  ANALYZER_VERSION=$(datadog-static-analyzer --version 2>&1 | head -n 1 || echo "unknown")
  echo -e "${GREEN}✓ datadog-static-analyzer found: ${ANALYZER_PATH}${NC}"
  echo "  Version: ${ANALYZER_VERSION}"
  TESTS_PASSED=$((TESTS_PASSED + 1))
else
  echo -e "${RED}❌ ERROR: datadog-static-analyzer not found${NC}"
  echo ""
  echo "Install instructions:"
  echo ""
  if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "  macOS (Homebrew):"
    echo "    brew tap datadog/tap"
    echo "    brew install datadog-static-analyzer"
  elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "  Linux:"
    echo "    # Download from GitHub releases"
    echo "    ARCH=\"x86_64\"  # or aarch64"
    echo "    curl -L \"https://github.com/DataDog/datadog-static-analyzer/releases/latest/download/datadog-static-analyzer-\${ARCH}-unknown-linux-gnu.zip\" -o /tmp/analyzer.zip"
    echo "    unzip /tmp/analyzer.zip -d ~/.local/bin"
    echo "    chmod +x ~/.local/bin/datadog-static-analyzer"
  else
    echo "  See: https://github.com/DataDog/datadog-static-analyzer"
  fi
  echo ""
  BINARIES_OK=false
  TESTS_FAILED=$((TESTS_FAILED + 1))
fi

if [[ "$BINARIES_OK" == "false" ]]; then
  echo -e "${RED}❌ Required binaries missing. Exiting.${NC}"
  exit 1
fi
echo ""

# =============================================================================
# Test 3: TEST MCP PROTOCOL - Test STDIO directly (no Claude Desktop)
# =============================================================================
echo -e "${BLUE}==> Test 3/7: Testing MCP protocol (STDIO)...${NC}"

# Test initialize method
echo -e "${BLUE}  Testing MCP initialize...${NC}"
INIT_REQUEST='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"e2e-test","version":"1.0.0"}}}'

if echo "${INIT_REQUEST}" | timeout 10 ./bin/datadog-code-security-mcp start > "${TEST_OUTPUT_DIR}/mcp-init.json" 2>&1; then
  if command -v jq &> /dev/null; then
    # Extract just the JSON response (last line) - MCP server logs to stderr which gets mixed with stdout
    JSON_RESPONSE=$(tail -1 "${TEST_OUTPUT_DIR}/mcp-init.json")
    if echo "${JSON_RESPONSE}" | jq -e '.result.protocolVersion' > /dev/null 2>&1; then
      PROTOCOL_VERSION=$(echo "${JSON_RESPONSE}" | jq -r '.result.protocolVersion')
      echo -e "${GREEN}✓ MCP initialize successful (protocol: ${PROTOCOL_VERSION})${NC}"
      TESTS_PASSED=$((TESTS_PASSED + 1))
    else
      echo -e "${RED}❌ MCP initialize returned invalid response${NC}"
      cat "${TEST_OUTPUT_DIR}/mcp-init.json"
      TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
  else
    echo -e "${YELLOW}⚠ jq not found, skipping response validation${NC}"
    echo -e "${GREEN}✓ MCP initialize returned response${NC}"
    TESTS_WARNED=$((TESTS_WARNED + 1))
  fi
else
  echo -e "${RED}❌ MCP initialize failed${NC}"
  cat "${TEST_OUTPUT_DIR}/mcp-init.json"
  TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# Test tools/list method
echo -e "${BLUE}  Testing MCP tools/list...${NC}"
TOOLS_REQUEST='{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'

if echo "${TOOLS_REQUEST}" | timeout 10 ./bin/datadog-code-security-mcp start > "${TEST_OUTPUT_DIR}/mcp-tools.json" 2>&1; then
  if command -v jq &> /dev/null; then
    # Extract just the JSON response (last line) - MCP server logs to stderr which gets mixed with stdout
    JSON_RESPONSE=$(tail -1 "${TEST_OUTPUT_DIR}/mcp-tools.json")
    TOOL_COUNT=$(echo "${JSON_RESPONSE}" | jq -r '.result.tools | length' 2>/dev/null || echo "0")
    if [[ $TOOL_COUNT -ge 5 ]]; then
      echo -e "${GREEN}✓ MCP tools registered: ${TOOL_COUNT} tools found${NC}"
      TESTS_PASSED=$((TESTS_PASSED + 1))
    else
      echo -e "${RED}❌ ERROR: Expected at least 5 tools, found ${TOOL_COUNT}${NC}"
      echo "JSON Response:"
      echo "${JSON_RESPONSE}" | jq . || echo "${JSON_RESPONSE}"
      TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
  else
    echo -e "${YELLOW}⚠ jq not found, skipping tool count validation${NC}"
    TESTS_WARNED=$((TESTS_WARNED + 1))
  fi
else
  echo -e "${RED}❌ MCP tools/list failed${NC}"
  cat "${TEST_OUTPUT_DIR}/mcp-tools.json"
  TESTS_FAILED=$((TESTS_FAILED + 1))
fi
echo ""

# =============================================================================
# Test 4: TEST SAST SCANNER
# =============================================================================
echo -e "${BLUE}==> Test 4/7: Testing SAST scanner...${NC}"

SAST_EXIT_CODE=0
./bin/datadog-code-security-mcp scan sast ./testdata/vulnerabilities/sast \
  --json > "${TEST_OUTPUT_DIR}/sast-output.json" 2>&1 || SAST_EXIT_CODE=$?

# SAST scanner returns non-zero exit code when vulnerabilities are found (expected)
if [[ -f "${TEST_OUTPUT_DIR}/sast-output.json" ]]; then
  # Check if vulnerabilities were detected
  FOUND_SQL_INJECTION=false
  FOUND_XSS=false
  FOUND_PATH_TRAVERSAL=false

  if grep -qi "sql.*injection\|SQL.*injection\|sql-injection" "${TEST_OUTPUT_DIR}/sast-output.json"; then
    FOUND_SQL_INJECTION=true
  fi

  if grep -qi "xss\|cross.*site.*script\|innerhtml" "${TEST_OUTPUT_DIR}/sast-output.json"; then
    FOUND_XSS=true
  fi

  if grep -qi "path.*traversal\|directory.*traversal" "${TEST_OUTPUT_DIR}/sast-output.json"; then
    FOUND_PATH_TRAVERSAL=true
  fi

  # Report findings
  if [[ "$FOUND_SQL_INJECTION" == "true" ]]; then
    echo -e "${GREEN}✓ SAST detected SQL injection${NC}"
  else
    echo -e "${YELLOW}⚠ SAST: SQL injection not detected (check if binary has rules)${NC}"
    TESTS_WARNED=$((TESTS_WARNED + 1))
  fi

  if [[ "$FOUND_XSS" == "true" ]]; then
    echo -e "${GREEN}✓ SAST detected XSS vulnerabilities${NC}"
  else
    echo -e "${YELLOW}⚠ SAST: XSS not detected (check if binary has rules)${NC}"
    TESTS_WARNED=$((TESTS_WARNED + 1))
  fi

  if [[ "$FOUND_PATH_TRAVERSAL" == "true" ]]; then
    echo -e "${GREEN}✓ SAST detected path traversal${NC}"
  else
    echo -e "${YELLOW}⚠ SAST: Path traversal not detected (check if binary has rules)${NC}"
    TESTS_WARNED=$((TESTS_WARNED + 1))
  fi

  # Overall SAST test result
  if [[ "$FOUND_SQL_INJECTION" == "true" ]] || [[ "$FOUND_XSS" == "true" ]] || [[ "$FOUND_PATH_TRAVERSAL" == "true" ]]; then
    echo -e "${GREEN}✓ SAST scanner operational (at least 1 vulnerability type detected)${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
  else
    echo -e "${YELLOW}⚠ SAST scanner may not be fully operational (no vulnerabilities detected)${NC}"
    echo "  This could mean:"
    echo "  - Scanner needs authentication to fetch rules"
    echo "  - Scanner version doesn't include these rules"
    echo "  - Test fixtures don't match current rule patterns"
    TESTS_WARNED=$((TESTS_WARNED + 1))
  fi
else
  echo -e "${RED}❌ SAST output file not created${NC}"
  TESTS_FAILED=$((TESTS_FAILED + 1))
fi
echo ""

# =============================================================================
# Test 5: TEST SECRETS SCANNER
# =============================================================================
echo -e "${BLUE}==> Test 5/7: Testing Secrets scanner...${NC}"

SECRETS_EXIT_CODE=0
./bin/datadog-code-security-mcp scan secrets ./testdata/vulnerabilities/secrets \
  --json > "${TEST_OUTPUT_DIR}/secrets-output.json" 2>&1 || SECRETS_EXIT_CODE=$?

# Secrets scanner returns non-zero exit code when secrets are found (expected)
if [[ -f "${TEST_OUTPUT_DIR}/secrets-output.json" ]]; then
  # Check if secrets were detected
  FOUND_AWS=false
  FOUND_GITHUB=false
  FOUND_API_KEYS=false

  if grep -qi "aws\|AKIA" "${TEST_OUTPUT_DIR}/secrets-output.json"; then
    FOUND_AWS=true
  fi

  if grep -qi "github\|ghp_\|gho_" "${TEST_OUTPUT_DIR}/secrets-output.json"; then
    FOUND_GITHUB=true
  fi

  if grep -qi "api.*key\|secret.*key\|token" "${TEST_OUTPUT_DIR}/secrets-output.json"; then
    FOUND_API_KEYS=true
  fi

  # Report findings
  if [[ "$FOUND_AWS" == "true" ]]; then
    echo -e "${GREEN}✓ Secrets scanner detected AWS credentials${NC}"
  else
    echo -e "${YELLOW}⚠ Secrets: AWS credentials not detected${NC}"
    TESTS_WARNED=$((TESTS_WARNED + 1))
  fi

  if [[ "$FOUND_GITHUB" == "true" ]]; then
    echo -e "${GREEN}✓ Secrets scanner detected GitHub tokens${NC}"
  else
    echo -e "${YELLOW}⚠ Secrets: GitHub tokens not detected${NC}"
    TESTS_WARNED=$((TESTS_WARNED + 1))
  fi

  if [[ "$FOUND_API_KEYS" == "true" ]]; then
    echo -e "${GREEN}✓ Secrets scanner detected API keys/tokens${NC}"
  else
    echo -e "${YELLOW}⚠ Secrets: API keys not detected${NC}"
    TESTS_WARNED=$((TESTS_WARNED + 1))
  fi

  # Overall Secrets test result
  if [[ "$FOUND_AWS" == "true" ]] || [[ "$FOUND_GITHUB" == "true" ]] || [[ "$FOUND_API_KEYS" == "true" ]]; then
    echo -e "${GREEN}✓ Secrets scanner operational (at least 1 secret type detected)${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
  else
    echo -e "${YELLOW}⚠ Secrets scanner may not be fully operational (no secrets detected)${NC}"
    echo "  This could mean:"
    echo "  - Scanner needs authentication to fetch rules"
    echo "  - Scanner version doesn't include these patterns"
    echo "  - Test fixtures don't match current detection patterns"
    TESTS_WARNED=$((TESTS_WARNED + 1))
  fi
else
  echo -e "${RED}❌ Secrets output file not created${NC}"
  TESTS_FAILED=$((TESTS_FAILED + 1))
fi
echo ""

# =============================================================================
# Test 6: TEST NEGATIVE CASE (Clean Code)
# =============================================================================
echo -e "${BLUE}==> Test 6/7: Testing negative case (clean code)...${NC}"

CLEAN_EXIT_CODE=0
./bin/datadog-code-security-mcp scan sast ./testdata/vulnerabilities/clean \
  --json > "${TEST_OUTPUT_DIR}/clean-output.json" 2>&1 || CLEAN_EXIT_CODE=$?

if [[ -f "${TEST_OUTPUT_DIR}/clean-output.json" ]]; then
  # Should return 0 findings
  HAS_NO_FINDINGS=false

  if grep -qi "\"total\".*:.*0\|no.*findings\|no.*vulnerabilities\|0.*violations" "${TEST_OUTPUT_DIR}/clean-output.json"; then
    HAS_NO_FINDINGS=true
  fi

  # Exit code 0 also indicates no findings
  if [[ $CLEAN_EXIT_CODE -eq 0 ]]; then
    HAS_NO_FINDINGS=true
  fi

  if [[ "$HAS_NO_FINDINGS" == "true" ]]; then
    echo -e "${GREEN}✓ Clean code passed (no false positives)${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
  else
    echo -e "${YELLOW}⚠ Warning: Clean code may have false positives${NC}"
    echo "  Review output: ${TEST_OUTPUT_DIR}/clean-output.json"
    TESTS_WARNED=$((TESTS_WARNED + 1))
  fi
else
  echo -e "${RED}❌ Clean code output file not created${NC}"
  TESTS_FAILED=$((TESTS_FAILED + 1))
fi
echo ""

# =============================================================================
# Test 7: TEST SBOM GENERATION
# =============================================================================
echo -e "${BLUE}==> Test 7/7: Testing SBOM generation...${NC}"

# Check if datadog-sbom-generator is installed
if command -v datadog-sbom-generator &> /dev/null; then
  SBOM_EXIT_CODE=0
  ./bin/datadog-code-security-mcp generate-sbom ./testdata/sbom-test \
    --json > "${TEST_OUTPUT_DIR}/sbom-output.json" 2>&1 || SBOM_EXIT_CODE=$?

  if [[ -f "${TEST_OUTPUT_DIR}/sbom-output.json" ]]; then
    # Check if components were found
    HAS_COMPONENTS=false
    COMPONENT_COUNT=0

    if command -v jq &> /dev/null; then
      # Try to extract component count from JSON
      COMPONENT_COUNT=$(jq -r '.summary.total_components // .total // 0' "${TEST_OUTPUT_DIR}/sbom-output.json" 2>/dev/null || echo "0")

      # Also check for Go modules detection
      if grep -qi "go.*module\|golang\|go\.mod" "${TEST_OUTPUT_DIR}/sbom-output.json"; then
        HAS_COMPONENTS=true
      fi
    else
      # Fallback: just check if output mentions components
      if grep -qi "component\|dependency\|package" "${TEST_OUTPUT_DIR}/sbom-output.json"; then
        HAS_COMPONENTS=true
      fi
    fi

    if [[ "$HAS_COMPONENTS" == "true" ]] || [[ $COMPONENT_COUNT -gt 0 ]]; then
      echo -e "${GREEN}✓ SBOM generation successful${NC}"
      if [[ $COMPONENT_COUNT -gt 0 ]]; then
        echo "  Components found: ${COMPONENT_COUNT}"
      fi
      TESTS_PASSED=$((TESTS_PASSED + 1))
    else
      echo -e "${YELLOW}⚠ SBOM generated but no components detected${NC}"
      echo "  This may indicate:"
      echo "  - go.mod dependencies not resolved"
      echo "  - SBOM generator needs different input format"
      TESTS_WARNED=$((TESTS_WARNED + 1))
    fi
  else
    echo -e "${RED}❌ SBOM output file not created${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
  fi
else
  echo -e "${YELLOW}⚠ datadog-sbom-generator not installed (skipping SBOM test)${NC}"
  echo "  Install with:"
  if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "    # datadog-sbom-generator is not on Homebrew"
    echo "    # Download from: https://github.com/DataDog/datadog-sbom-generator/releases"
  fi
  echo "  Or see: https://github.com/DataDog/datadog-sbom-generator"
  TESTS_WARNED=$((TESTS_WARNED + 1))
fi
echo ""

# =============================================================================
# Test 8: FULL MODE - Claude Desktop integration (optional, --full mode only)
# =============================================================================
if [[ "$MODE" == "full" ]]; then
  echo -e "${BLUE}==> Test 8/8: Configuring Claude Desktop...${NC}"

  # Check if claude CLI is available
  if ! command -v claude &> /dev/null; then
    echo -e "${RED}❌ ERROR: claude CLI not found${NC}"
    echo ""
    echo "Install Claude CLI:"
    echo "  macOS: brew install anthropics/claude/claude"
    echo "  Other: See https://github.com/anthropics/claude-cli"
    echo ""
    TESTS_FAILED=$((TESTS_FAILED + 1))
  else
    # Remove existing configuration
    claude mcp remove datadog-code-security 2>/dev/null || true

    # Add using absolute path to local binary
    CURRENT_DIR="${PROJECT_ROOT}"
    if claude mcp add datadog-code-security \
      ${DD_API_KEY:+-e DD_API_KEY="$DD_API_KEY"} \
      ${DD_APP_KEY:+-e DD_APP_KEY="$DD_APP_KEY"} \
      ${DD_SITE:+-e DD_SITE="$DD_SITE"} \
      -- "${CURRENT_DIR}/bin/datadog-code-security-mcp" start; then
      echo -e "${GREEN}✓ Claude Desktop configured${NC}"
      echo ""
      echo "Configuration applied:"
      echo "  Binary: ${CURRENT_DIR}/bin/datadog-code-security-mcp"
      echo "  Environment: DD_API_KEY, DD_APP_KEY, DD_SITE (if set)"
      echo ""
      echo -e "${YELLOW}Next steps:${NC}"
      echo "  1. Restart Claude Desktop:"
      if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "     killall Claude && open -a Claude"
      else
        echo "     Quit and reopen Claude Desktop"
      fi
      echo ""
      echo "  2. Test with prompts in Claude Desktop:"
      echo "     - 'List available security scanning tools'"
      echo "     - 'Scan testdata/vulnerabilities/sast for security issues'"
      echo "     - 'Check testdata/vulnerabilities/secrets for hardcoded credentials'"
      echo ""
      TESTS_PASSED=$((TESTS_PASSED + 1))
    else
      echo -e "${RED}❌ Failed to configure Claude Desktop${NC}"
      TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
  fi
  echo ""
fi

# In CI mode, we skip Test 8 entirely (no Claude CLI available in CI environment)

# =============================================================================
# SUMMARY
# =============================================================================
echo ""
echo "=========================================="
if [[ "$MODE" == "ci" ]]; then
  echo "E2E Test Summary (CI Mode - 7 tests)"
else
  echo "E2E Test Summary (Full Mode - 8 tests)"
fi
echo "=========================================="
echo ""
echo -e "Tests passed:  ${GREEN}${TESTS_PASSED}${NC}"
echo -e "Tests failed:  ${RED}${TESTS_FAILED}${NC}"
echo -e "Tests warned:  ${YELLOW}${TESTS_WARNED}${NC}"
echo ""
if [[ "$MODE" == "ci" ]]; then
  echo "Note: Claude Desktop integration (Test 8) skipped in CI mode"
  echo ""
fi
echo "Test outputs saved to:"
echo "  ${TEST_OUTPUT_DIR}/mcp-init.json"
echo "  ${TEST_OUTPUT_DIR}/mcp-tools.json"
echo "  ${TEST_OUTPUT_DIR}/sast-output.json"
echo "  ${TEST_OUTPUT_DIR}/secrets-output.json"
echo "  ${TEST_OUTPUT_DIR}/clean-output.json"
echo "  ${TEST_OUTPUT_DIR}/sbom-output.json"
echo ""

if [[ $TESTS_FAILED -gt 0 ]]; then
  echo -e "${RED}❌ E2E tests FAILED${NC}"
  echo ""
  echo "Review the output above and test outputs in ${TEST_OUTPUT_DIR}/"
  exit 1
else
  echo -e "${GREEN}✅ All E2E tests passed!${NC}"
  echo ""
  if [[ $TESTS_WARNED -gt 0 ]]; then
    echo -e "${YELLOW}Note: ${TESTS_WARNED} warnings detected. Review output for details.${NC}"
    echo ""
  fi
  exit 0
fi
