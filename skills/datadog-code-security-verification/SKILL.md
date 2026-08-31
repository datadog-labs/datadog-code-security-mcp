---
name: datadog-code-security-verification
description: Verify and enrich a local Datadog Code Security finding with Datadog platform context. Use when the user asks whether a local finding exists in Datadog, wants its triage or exposure status, or provides a Datadog finding link for local verification.
---

# Datadog Code Security finding verification

Combine current local evidence with Datadog platform context without confusing
the two sources.

## Ordering

1. Run the relevant local Code Security scan first. Prefer the local Datadog
   Code Security MCP tool; fall back to `datadog-code-security-mcp scan
   <type> <path> --json`.
2. Treat the local result as authoritative for the code currently on disk.
3. If a Datadog MCP server is available, query it for the matching repository,
   file, rule, vulnerability or package.
4. Present platform data only as enrichment: triage state, first/last seen,
   service/repository exposure, owner, and remediation status.

Platform data must never override or suppress a current local finding. A
backend finding can be stale because the local code has changed since the last
upload; a local clean result does not prove that every deployed branch is clean.

## Authentication boundary

The local scan may use `DD_API_KEY` / `DD_APP_KEY`, while the Datadog MCP may
use OAuth for a different organisation. If available, read
`datadog://mcp/whoami` and compare organisation identity only when both sides
expose comparable identifiers. Do not infer identity from `DD_SITE` alone.

If a mismatch is detected:

- warn clearly that local and platform results may belong to different orgs;
- keep the local result authoritative;
- do not present the other org's data as a match;
- continue rather than blocking the local workflow.

If no Datadog MCP is available, say that platform verification could not be
performed and return the local evidence. Never fabricate status, attempt to
enable a toolset without user involvement, or treat absence of a platform
result as proof that the local issue is safe.
