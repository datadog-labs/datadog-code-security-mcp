---
name: dd-codesec-find-security-variants
description: >-
  After a local uncommitted security fix, infer the security invariant from
  the git diff, generate an ephemeral Datadog SAST rule, scan with the local
  Code Security MCP, and report other places that break the same invariant.
  Use when the user just fixed a security bug, asks whether the same mistake
  exists elsewhere, asks whether the same check is missing in other files, or
  refers to an uncommitted security fix, or asks to save, promote, or upload
  the temporary rule as a custom SAST rule, including after changing which
  findings to include. Also use when the user runs
  /dd-codesec-find-security-variants.
---

# Find security variants

The developer just fixed a security issue and has not committed it. Find other places that break the same invariant. Do not ask them to paste the diff, name the invariant, or point at a line.

The report names where the same mistake is. It does not say which path found each hit.

## Scratch files

Write `invariant.yaml`, `rule.js`, and `query.scm` in one directory under the system temporary directory, outside this repository. Create it once and reuse it for the rest of the run:

```bash
scratch="${TMPDIR:-/tmp}/dd-codesec-find-security-variants$(pwd | tr '/' '-')"
mkdir -p "$scratch"
```

Do not write these files in the repository. Do not mention this directory in the report.

## Skill attribution

Every `datadog-code-security-mcp` CLI invocation this skill runs must include
`--called-by-skill`. Never omit it, and never pass it to scanner binaries,
package managers, GitHub commands, or other non-wrapper commands.

Every local Code Security MCP tool call made while following this skill must
include `called_by_skill: true`. Never omit it from those calls. Do not pass
`called_by_skill` on other MCP servers' tools. If you later call a Code
Security MCP tool outside this skill's workflow, omit the flag even if you
have seen it here.

## 1. Read the diff

Run `git diff` and `git diff --cached`. If both are empty, stop and say there is no uncommitted change.

## 2. Infer the invariant

From that diff only, write a structured invariant. Generalize the fix. You may read the functions and helpers the diff touches so the invariant names the real guard and the real operation. Do not go hunting for other violations in this step.

```yaml
vulnerability:
  type: <class>
security_invariant:
  description: >
    <one paragraph>
authorization_guard:
  function: <name or null>
privileged_operations:
  - <operations the fix protects, plus obvious siblings on the same object>
```

Save it at `$scratch/invariant.yaml`.

## 3. Generate the rule

Write `$scratch/rule.js` and `$scratch/query.scm` from the invariant you just inferred. Favor recall. The scanner contract is in [rule-contract.md](rule-contract.md). That file is part of this skill. Do not look for an example rule in the repository.

## 4. Scan with the local MCP

Prefer the MCP tool `datadog_ephemeral_sast_scan` with `rule_code`, `tree_sitter_query`, `language`, and `directory`. Pass `called_by_skill: true`.

If that tool is not registered, run the local binary (no API key):

```bash
datadog-code-security-mcp ephemeral-scan --called-by-skill \
  --language <LANGUAGE> \
  --directory . \
  --code-file "$scratch/rule.js" \
  --query-file "$scratch/query.scm"
```

`<LANGUAGE>` is the scanner enum for the code under the diff (`TYPESCRIPT`, `JAVASCRIPT`, …). Omit `--path` to scan the whole directory. Pass `--path` only for a subdirectory the diff actually touches.

## 5. Explore, separately

Before you treat the scan as the answer, search the repository with the usual read and search tools for code that breaks the invariant. Do not open the scan output until this list is written down.

## 6. Merge

Union the two lists by file and function. Drop the function the diff itself changed. Keep a hit that only one path found.

## 7. Triage

Read each candidate's function and the helpers it calls. Classify:

- **likely variant** — same missing guard, same class of operation the invariant names.
- **needs review** — same shape (authenticate, then a similar call, no guard) but the operation is not clearly the privileged class.
- **unrelated** — the guard is already present, or the operation is a different class (for example reading the caller's own data).

Base the class on the operation, not on a comment that labels the file as a test case. Leave unrelated hits out of the report.

Do not rank hits by how damaging they look. HIGH means the operation is the same class the fix protects. MEDIUM means the shape matches, but the operation is not that class. A sensitive read is not HIGH only because the data is sensitive. An operation of the same class as the fix does not drop to MEDIUM because it looks less severe.

## 8. Report

```text
Analyzing current security fix...

Inferred security invariant:
<one or two lines from the invariant>

Searching repository...
Running temporary Code Security detector...

<N> likely variants found.

HIGH
<path>:<line>

<what the function does, and why it breaks the same invariant as the fix>

MEDIUM
<path>:<line>

<why it is the same shape but not clearly the same class>
```

`N` counts only likely variants. HIGH is likely variant: the same class of operation the fix protects. MEDIUM is needs review: the same shape, not that class. Do not rank by impact. One short paragraph each. If a section has no hits, omit it.

## 9. Ask before saving

After the report, ask once whether to save a permanent custom rule. Do not call `datadog_promote_sast_rule` in this step.

Propose the HIGH list only. Name each MEDIUM file that would stay out. Say that every saved hit appears in the IDE as an error, because the rule severity is ERROR.

The user can save that HIGH list, add a MEDIUM, drop a HIGH, or save nothing. If they do not agree, stop.

If they change the set, edit `$scratch/rule.js` so it reports only the operations they accepted. Keep the query. Scan again with `datadog_ephemeral_sast_scan` and `called_by_skill: true`, and show the new list. Ask once more whether to save that list.

Only after they agree to the list just shown, call `datadog_promote_sast_rule` with `user_confirmed: true`, the exact `rule_code` and `tree_sitter_query` from `$scratch`, `language`, a slug `rule_name`, and `ruleset_name` `variant-hunter` unless they choose another. Pass `called_by_skill: true`. The tool uploads that source. It does not choose which hits belong. It refuses when `user_confirmed` is not true.

If the tool is not registered, run:

```bash
datadog-code-security-mcp promote-sast-rule --called-by-skill --user-confirmed \
  --language <LANGUAGE> \
  --code-file "$scratch/rule.js" \
  --query-file "$scratch/query.scm" \
  --rule-name <slug> \
  --ruleset-name variant-hunter
```

That command uses the same Datadog credentials as the MCP server: `DD_API_KEY` and `DD_APP_KEY`, or `DD_AUTH_DOMAIN` so `dd-auth` can supply a short-lived token.

After the rule is saved, if this session is Cursor or VS Code, tell the user to run **Datadog: Refresh Static Analysis Rules** from the command palette. The Datadog extension keeps rules in memory and fetches them again after that command, after two hours, or when the static analysis engine restarts. The refresh only requests a ruleset the project already names in its static analysis config. Do not mention this command in any other client.

A later message that asks to save the rule, or to include or drop a hit and then save it, starts at this step. Read the files in `$scratch`. Do not repeat the diff analysis unless those files are missing.

Do not upload a rule that still matches a MEDIUM the user did not accept.
