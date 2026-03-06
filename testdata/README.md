# Test Fixtures

This directory contains test fixtures for E2E testing of the datadog-code-security-mcp scanner.

## Purpose

These fixtures enable automated and reproducible testing of security scanning capabilities without requiring external vulnerable repositories. Each fixture demonstrates a specific vulnerability pattern that the scanners should detect.

## Directory Structure

```
testdata/
├── README.md                       # This file
├── vulnerabilities/                # Sample vulnerable code
│   ├── sast/                      # Static Application Security Testing samples
│   │   ├── sql-injection.go       # SQL injection in Go
│   │   ├── xss.js                 # Cross-Site Scripting in JavaScript
│   │   └── path-traversal.py      # Path traversal in Python
│   ├── secrets/                   # Hardcoded secrets samples
│   │   ├── aws-keys.py            # AWS credentials
│   │   ├── github-token.js        # GitHub Personal Access Tokens
│   │   └── api-key.env            # Generic API keys and credentials
│   ├── iac/                       # Infrastructure-as-Code samples
│   │   ├── insecure-s3.tf         # Insecure S3 bucket (public access, no encryption)
│   │   ├── insecure-security-group.tf # Open security groups (SSH/RDP/all to 0.0.0.0/0)
│   │   ├── insecure-iam.tf        # Overly permissive IAM policies (wildcard actions)
│   │   ├── insecure-k8s.yaml      # Kubernetes misconfigurations (privileged, root, hostNetwork)
│   │   └── Dockerfile             # Insecure Dockerfile (root, latest tag, secrets in ENV)
│   └── clean/                     # Safe code (negative tests)
│       └── safe-code.go           # Secure coding patterns (no vulnerabilities)
├── sbom-test/                     # SBOM generation test fixtures
│   ├── go.mod                     # Go module with dependencies
│   ├── main.go                    # Simple Go application
│   └── README.md                  # SBOM test documentation
```

## Test Fixtures by Type

### SAST (Static Application Security Testing)

| File | Language | Vulnerability Type | Severity | Description |
|------|----------|-------------------|----------|-------------|
| `sast/sql-injection.go` | Go | SQL Injection | High | Demonstrates string concatenation in SQL queries |
| `sast/xss.js` | JavaScript | Cross-Site Scripting | High | Shows innerHTML and eval vulnerabilities |
| `sast/path-traversal.py` | Python | Path Traversal | High | Unsafe file path handling with user input |

**Expected Detections:**
- SQL injection via concatenation and string formatting
- XSS through innerHTML, eval, and document.write
- Path traversal through unsanitized file paths

### Secrets Detection

| File | Type | Secrets Included | Confidence | Description |
|------|------|-----------------|------------|-------------|
| `secrets/aws-keys.py` | AWS | Access Key ID, Secret Key, Session Token | High | Hardcoded AWS credentials in various formats |
| `secrets/github-token.js` | GitHub | PAT, OAuth, App tokens | High | Multiple GitHub token formats |
| `secrets/api-key.env` | Generic | API keys, DB passwords, OAuth secrets | Medium-High | Environment file with multiple secret types |

**Expected Detections:**
- AWS access keys (AKIA* pattern)
- GitHub tokens (ghp_*, gho_*, ghs_* patterns)
- Database credentials in connection strings
- API keys and OAuth secrets
- JWT and encryption keys

### IaC (Infrastructure-as-Code)

| File | Format | Misconfiguration Type | Severity | Description |
|------|--------|-----------------------|----------|-------------|
| `iac/insecure-s3.tf` | Terraform | S3 public access, no encryption | High | Public S3 bucket with no server-side encryption |
| `iac/insecure-security-group.tf` | Terraform | Open network ports | High | Security groups with SSH/RDP/all ports open to 0.0.0.0/0 |
| `iac/insecure-iam.tf` | Terraform | IAM privilege escalation | High | Wildcard actions/resources, overly permissive assume role |
| `iac/insecure-k8s.yaml` | Kubernetes | Container security | Medium-High | Privileged containers, hostNetwork, root user, cluster-admin |
| `iac/Dockerfile` | Docker | Container hardening | Medium | Running as root, latest tag, secrets in ENV, ADD from URL |

**Expected Detections:**
- S3 bucket public access and missing encryption
- Security groups open to 0.0.0.0/0 (SSH, RDP, database ports)
- IAM policies with wildcard permissions
- Kubernetes privileged containers and host namespace access
- Dockerfile running as root, hardcoded secrets in ENV

### Clean Code (Negative Tests)

| File | Language | Purpose | Expected Result |
|------|----------|---------|-----------------|
| `clean/safe-code.go` | Go | Demonstrates secure patterns | 0 vulnerabilities |

**Secure Patterns Demonstrated:**
- Parameterized SQL queries
- HTML template auto-escaping
- File path validation and sanitization
- Environment variable usage for secrets
- Proper error handling

### SBOM Generation

| Directory | Package Manager | Purpose | Expected Components |
|-----------|----------------|---------|---------------------|
| `sbom-test/` | Go modules | Test SBOM generation | ~22 (2 direct + ~20 transitive) |

**Test Details:**
- **Direct dependencies**: gin-gonic/gin, sirupsen/logrus
- **Transitive dependencies**: ~20 indirect dependencies
- **go.mod**: Contains all dependency information
- **Expected output**: CycloneDX format SBOM with component names, versions, licenses

## Usage

### Testing Individual Scan Types

```bash
# Test SAST scanner
./bin/datadog-code-security-mcp scan sast ./testdata/vulnerabilities/sast

# Expected output: SQL injection, XSS, and path traversal findings

# Test Secrets scanner
./bin/datadog-code-security-mcp scan secrets ./testdata/vulnerabilities/secrets

# Expected output: AWS keys, GitHub tokens, API keys

# Test IaC scanner
./bin/datadog-code-security-mcp scan iac ./testdata/vulnerabilities/iac

# Expected output: S3 misconfigurations, open security groups, IAM issues, K8s misconfigs

# Test with JSON output
./bin/datadog-code-security-mcp scan sast ./testdata/vulnerabilities/sast --json

# Test negative case (should find no vulnerabilities)
./bin/datadog-code-security-mcp scan sast ./testdata/vulnerabilities/clean
```

## Expected Results

Use these validation criteria to verify scanners are working correctly:

### SAST Expected Detections

| Test File | Expected Findings | Severity | Count |
|-----------|------------------|----------|-------|
| `sql-injection.go` | SQL injection | High | 2-3 |
| `xss.js` | Cross-Site Scripting | High | 5-7 |
| `path-traversal.py` | Path traversal | High | 5-6 |

**Validation:** Run SAST scanner on each file and verify at least 1 finding per file.

### Secrets Expected Detections

| Test File | Expected Secrets | Confidence | Count |
|-----------|-----------------|------------|-------|
| `aws-keys.py` | AWS credentials | High | 7-10 |
| `github-token.js` | GitHub tokens | High | 10-15 |
| `api-key.env` | Various secrets | High/Med | 20-30 |

**Validation:** Run Secrets scanner and verify API keys, AWS keys, or GitHub tokens detected.

### SBOM Expected Components

| Test Directory | Package Manager | Expected Components |
|---------------|----------------|---------------------|
| `sbom-test/` | Go modules | ~22 components |

**Validation:** Run SBOM generation and verify at least 20 Go module components found.

### IaC Expected Detections

| Test File | Expected Findings | Severity | Count |
|-----------|------------------|----------|-------|
| `insecure-s3.tf` | S3 public access, missing encryption | High | 3-5 |
| `insecure-security-group.tf` | Open SSH/RDP/all ports | High | 4-8 |
| `insecure-iam.tf` | Wildcard permissions, escalation | High | 3-5 |
| `insecure-k8s.yaml` | Privileged containers, root, hostNetwork | Medium-High | 5-10 |
| `Dockerfile` | Root user, latest tag, secrets in ENV | Medium | 3-6 |

**Validation:** Run IaC scanner and verify at least 1 misconfiguration type detected.

### Clean Code (Negative Test)

| Test File | Expected Result |
|-----------|----------------|
| `clean/safe-code.go` | 0 findings |

**Validation:** Run SAST scanner and verify no vulnerabilities detected (no false positives).

## Troubleshooting Expected Results

**No findings detected:**
- Verify scanner binary version: `datadog-static-analyzer --version`
- Check authentication is configured
- Scanner rules may require internet connection

**Different findings than expected:**
- Scanner versions may have different rulesets (this is normal)
- Document your scanner version for reproducibility
- Update this README if rules have improved

**False positives in clean code:**
- Review the finding carefully
- May indicate new detection rule or false positive
- Report to Datadog if genuine false positive

### Running Full E2E Test Suite

```bash
# CI mode (headless, no Claude Desktop required)
./scripts/test-e2e.sh --ci

# Full mode (includes Claude Desktop integration)
./scripts/test-e2e.sh --full
```

### Testing with Claude Desktop

After configuring Claude Desktop to use your local build:

```
Prompts to try:
- "Scan testdata/vulnerabilities/sast for security vulnerabilities"
- "Check testdata/vulnerabilities/secrets for hardcoded credentials"
- "What security issues are in testdata/vulnerabilities/sast/sql-injection.go?"
```

## Validation Criteria

### SAST Tests Should Detect:
- ✅ At least 2 SQL injection vulnerabilities in `sql-injection.go`
- ✅ At least 3 XSS vulnerabilities in `xss.js`
- ✅ At least 3 path traversal vulnerabilities in `path-traversal.py`
- ✅ 0 vulnerabilities in `clean/safe-code.go` (no false positives)

### Secrets Tests Should Detect:
- ✅ At least 5 AWS-related secrets in `aws-keys.py`
- ✅ At least 6 GitHub token patterns in `github-token.js`
- ✅ At least 15 different secret types in `api-key.env`

### IaC Tests Should Detect:
- ✅ S3 bucket public access or missing encryption in `insecure-s3.tf`
- ✅ Open security group rules (SSH/RDP to 0.0.0.0/0) in `insecure-security-group.tf`
- ✅ Overly permissive IAM policies in `insecure-iam.tf`
- ✅ Kubernetes privileged containers or host access in `insecure-k8s.yaml`
- ✅ Dockerfile running as root or hardcoded secrets in `Dockerfile`

## Important Notes

### ⚠️ Security Warning

**All secrets in these files are FAKE examples for testing purposes only.** They follow real patterns but are not valid credentials. Do NOT:
- Use these patterns in production code
- Commit real secrets to version control
- Assume these examples cover all secret patterns

### Test Fixture Maintenance

When updating fixtures:
1. **Keep patterns realistic**: Use actual vulnerability patterns found in the wild
2. **Document expected behavior**: Update this README with expected detections
3. **Test after changes**: Run E2E tests to verify scanners still detect issues
4. **Add variety**: Include different variations of the same vulnerability type
5. **Update expected results**: Modify the "Expected Results" section if findings change

### Adding New Test Cases

To add a new vulnerability test:

1. **Create the file** in the appropriate directory:
   ```bash
   # For SAST
   touch testdata/vulnerabilities/sast/new-vulnerability.{ext}

   # For Secrets
   touch testdata/vulnerabilities/secrets/new-secret-type.{ext}
   ```

2. **Add realistic vulnerable code** that demonstrates the issue

3. **Update this README** with:
   - File name and description in the tables above
   - Expected detections in validation criteria
   - Usage examples if needed

4. **Test detection**:
   ```bash
   ./bin/datadog-code-security-mcp scan {type} ./testdata/vulnerabilities/{type}/
   ```

5. **Update expected results**: Add detection details to the "Expected Results" section in this README

6. **Run E2E tests** to ensure integration:
   ```bash
   ./scripts/test-e2e.sh --ci
   ```

## CI/CD Integration

These fixtures are used in automated testing:

- **GitHub Actions**: `.github/workflows/e2e.yml` runs tests on every PR
- **Pre-commit checks**: Developers can run `./scripts/test-e2e.sh --ci` locally
- **Release validation**: E2E tests run before creating releases

## Troubleshooting

### No vulnerabilities detected

```bash
# Check if scanner binary is installed
which datadog-static-analyzer

# Verify binary version
datadog-static-analyzer --version

# Check if rules are up to date
# (Some detections require internet connection to fetch latest rules)
```

### Different findings than expected

```bash
# Scanner versions may have different rules
# Document your scanner version in test output:
datadog-static-analyzer --version > test-scanner-version.txt

# Rules may be updated over time - this is expected
# Update the "Expected Results" section in this README if rules improve
```

### False positives in clean code

```bash
# Review the finding - it may indicate a new detection rule
# If it's a genuine false positive, report to Datadog
# Consider updating clean/safe-code.go to demonstrate the safe pattern more clearly
```

## Contributing

When contributing new test fixtures:

1. Follow the existing file structure and naming conventions
2. Include comments explaining why the code is vulnerable
3. Add corresponding safe examples to `clean/` directory when applicable
4. Update this README with complete documentation
5. Test with actual scanners before submitting PR
6. Document expected findings in the "Expected Results" section

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE - Common Weakness Enumeration](https://cwe.mitre.org/)
- [Datadog Static Analysis](https://docs.datadoghq.com/security/application_security/static_analysis/)
- [Datadog Secrets Detection](https://docs.datadoghq.com/security/secrets/)
