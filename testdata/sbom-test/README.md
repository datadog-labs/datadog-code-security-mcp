# SBOM Test Fixture

This is a minimal Go application used for testing SBOM (Software Bill of Materials) generation.

## Purpose

Tests the ability to:
1. Detect Go modules (`go.mod` present)
2. Parse dependency information
3. Generate SBOM in CycloneDX format
4. Extract component details (name, version, licenses)

## Expected SBOM Components

This fixture includes the following direct dependencies:
- `github.com/gin-gonic/gin` v1.9.1 - Web framework
- `github.com/sirupsen/logrus` v1.9.3 - Logging library

Plus ~20 transitive dependencies.

## Testing

```bash
# Generate SBOM
./bin/datadog-code-security-mcp generate-sbom ./testdata/sbom-test

# Expected output:
# - Total components: ~22 (2 direct + ~20 transitive)
# - Package manager: Go modules
# - License information for each component
```

## Validation Criteria

✅ **Minimum 20 components detected** (direct + transitive dependencies)
✅ **Go modules detected** as package manager
✅ **Component details include**: name, version, purl (package URL)
✅ **License information** populated for major dependencies

## Notes

- This is a minimal test fixture - real projects have more dependencies
- Uses well-known, stable packages (gin, logrus)
- go.mod is the source of truth for dependency versions
- No go.sum included - SBOM generator should work with go.mod alone
