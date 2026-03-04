#!/bin/bash
set -e

VERSION="${1:-0.1.0}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELEASE_DIR="${REPO_ROOT}/release"

echo "🚀 Building release v${VERSION}"

# Clean and create release directory
rm -rf "${RELEASE_DIR}"
mkdir -p "${RELEASE_DIR}"

# Build for all platforms
echo ""
echo "📦 Building binaries for all platforms..."

PLATFORMS=(
  "darwin/amd64"
  "darwin/arm64"
  "linux/amd64"
  "linux/arm64"
)

for platform in "${PLATFORMS[@]}"; do
  IFS='/' read -r GOOS GOARCH <<< "$platform"
  echo "  Building ${GOOS}-${GOARCH}..."
  
  output="datadog-code-security-mcp"
  if [ "$GOOS" = "windows" ]; then
    output="${output}.exe"
  fi
  
  GOOS=$GOOS GOARCH=$GOARCH go build \
    -ldflags "-s -w -X main.version=${VERSION} -X main.commit=$(git rev-parse --short HEAD) -X main.buildTime=$(date -u +%Y-%m-%d_%H:%M:%S)" \
    -o "${RELEASE_DIR}/${output}" \
    ./cmd/datadog-code-security-mcp
  
  # Create tarball
  cd "${RELEASE_DIR}"
  tar_name="datadog-code-security-mcp-${GOOS}-${GOARCH}.tar.gz"
  tar czf "${tar_name}" "${output}"
  rm "${output}"
  
  # Calculate SHA256
  if command -v shasum &> /dev/null; then
    shasum -a 256 "${tar_name}" | tee "${tar_name}.sha256"
  else
    sha256sum "${tar_name}" | tee "${tar_name}.sha256"
  fi
  
  cd "${REPO_ROOT}"
done

echo ""
echo "✅ Build complete! Artifacts in ${RELEASE_DIR}/"
echo ""
echo "📋 Release artifacts:"
ls -lh "${RELEASE_DIR}"/*.tar.gz

echo ""
echo "🔑 SHA256 checksums:"
cat "${RELEASE_DIR}"/*.sha256

echo ""
echo "📝 Next steps:"
echo "1. Create GitHub release: gh release create v${VERSION} --generate-notes release/*.tar.gz"
echo "2. Update homebrew formula with SHA256s"
echo "3. Test formula: brew install --build-from-source homebrew/datadog-code-security-mcp.rb"
