---
name: datadog-code-security-verification
description: Verify and enrich a local Datadog Code Security finding with Datadog platform context. Use when the user asks whether a local finding exists in Datadog, wants its triage or exposure status, or provides a Datadog finding link for local verification.
---

# Datadog Code Security finding verification

Combine current local evidence with Datadog platform context without confusing
the two sources.

## Ordering

Choose the order from the information supplied:

- **Datadog finding URL or ID without a known local file:** query the Datadog
  MCP first to identify the repository, file, line, rule, and detection type.
  Use this initial response only to locate the relevant code and choose the
  local scan; it is not evidence that the current checkout is vulnerable.
  Match the reported repository and file to the current checkout without
  guessing. If they cannot be matched safely, ask the user for the checkout or
  file instead of scanning the entire repository.
- **Known local file or finding:** run the relevant local Code Security scan
  first.

Once the local target is known:

1. Select the narrowest scan target:
   - SAST or Secrets: the resolved file, not its parent directory.
   - Standalone IaC manifest, template, or Dockerfile: the resolved file.
   - Terraform: start with the resolved `.tf` file. The IaC scanner reads
     sibling `.tf`, `*.auto.tfvars`, and `terraform.tfvars` for variables,
     locals, and data sources while scanning only the requested file.
   - Helm or Kustomize: the smallest chart or overlay root needed to render
     the resolved file.
   - SCA: the smallest project directory needed to resolve the dependency
     graph.
2. State the selected local scan target, then run the matching local scanner
   against exactly that target. Generic directory-scan examples in project
   documentation do not override this requirement. Prefer the local Datadog
   Code Security MCP tool; fall back to `datadog-code-security-mcp scan <type>
   <path> --json`.
3. If a Terraform file scan does not reproduce the finding and the flagged
   expression depends on sibling resources or module context, explain why and
   retry with the smallest containing Terraform module directory before
   concluding that the finding is absent. Never broaden directly to the
   repository root unless it is itself that module.
4. Treat the local result as authoritative for the code currently on disk.
5. Use the initial Datadog response, and query the Datadog MCP again only when
   needed, to enrich the result with triage state, first/last seen,
   service/repository exposure, owner, and remediation status.

Reading or manually inspecting the flagged code does not count as local
verification and must never replace the scanner. If the local scan cannot run
or fails, report the finding as not locally verified; do not claim that it is
still present or fixed. A request to verify a finding authorises the read-only
local scan, so do not ask for separate confirmation before running it.

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
