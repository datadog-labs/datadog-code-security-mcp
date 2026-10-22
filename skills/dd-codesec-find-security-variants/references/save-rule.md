# Save the rule

Read this file only after the user agreed to save. `SKILL.md` step 10 decides what to save. This file is how.

## Examples

The rule page shows two examples. You already have both: the function after the fix, and that same function before the fix.

Write them outside the repository:

- `$scratch/examples/compliant/compliant.<ext>` is the whole function after the fix. Its `annotation_count` is 0.
- `$scratch/examples/noncompliant/noncompliant.<ext>` is that same function as it was before the fix, from the committed file. Its `annotation_count` is 1.

`<ext>` is the extension for the language (`ts` for TYPESCRIPT, `js` for JAVASCRIPT, otherwise the normal extension). Use the whole function. Always pass both. Do not scan them to decide whether to keep them, and do not save the rule without them.

## Description

Write `$scratch/description.md` from the confirmed invariant and from the rule source you are about to save. The rule page shows this text. The ruleset is shared, so its description stays generic and this upload does not change it. Make the rule text as specific as the rule:

- the guard function, and that the rule flags its absence
- the precondition, such as `authenticate(req)` already having run
- where the guard has to run, relative to that precondition and the privileged call
- every operation the rule flags, by the name used in the rule
- the wider same-shape case, when the rule still flags other calls on that object, and that those need a human check
- every same-shape operation left out, by name, and why it is not this rule

Write several sentences. Do not shorten it to one generic line, and do not write "Custom SAST rule saved from a local variant search."

Also write one line of at most 60 characters that names the guard and the operation class. Count the characters. Pass that line as `short_description` and the file text as `description`.

## Upload

Call `datadog_promote_sast_rule` with `user_confirmed: true`, the exact `rule_code` and `tree_sitter_query` from `$scratch`, `language`, `rule_name` set to the slug the report showed or the rule name they gave, `ruleset_name` set to the ruleset they named or `security-variants`, `short_description`, and `description`. Pass `called_by_skill: true`. Also pass `tests`: the fixed function with `annotation_count` 0, and the same function before the fix with `annotation_count` 1. Each item is `filename`, `code` (the file text, not base64), and `annotation_count`. The tool uploads that source and those two examples. It refuses when `user_confirmed` is not true.

Before it saves, the tool runs the rule on both examples. When a count differs, or the rule raises an exception, it saves nothing and says so:

- `noncompliant.<ext>: expected 1, got N` with N of 2 or more means the function before the fix has N flagged operations. Call the tool again with that example's `annotation_count` set to N.
- Any other mismatch, `got 0` on the function before the fix, a finding in the fixed function, or a rule exception means the rule is wrong. A rule with a syntax error, or one that times out, also gets 0. Do not change the counts to make it pass. Fix the rule, scan the repository again, and show the user the new rule before you save it.

After the upload, name the rule, the ruleset, and the `revision_id` from the tool reply. It is the revision number the rule page shows. When it is empty, the reply has a `warning`. Show that warning instead of the number.

If the tool replies that the rule already exists, nothing was saved. The existing rule may be someone else's. Pause at the end of the turn with this message:

````markdown
**`<rule slug>` already exists** in the ruleset `<ruleset>`. Saving now would publish a new revision over it, and the IDE would report this rule's hits under that name.

Replace it? Reply replace, or give another rule name.
````

If they reply replace, call the tool again with the same arguments and `overwrite: true`. If they give another name, call it again with that `rule_name`. Never pass `overwrite: true` without that reply.

If the tool is not registered, write both examples to `$scratch/tests.json` as a JSON array of `{filename, code, annotation_count}` and run:

```bash
datadog-code-security-mcp promote-sast-rule --called-by-skill --user-confirmed \
  --language <LANGUAGE> \
  --code-file "$scratch/rule.js" \
  --query-file "$scratch/query.scm" \
  --rule-name <slug> \
  --ruleset-name <ruleset> \
  --short-description "<line of at most 60 characters>" \
  --description-file "$scratch/description.md" \
  --tests-file "$scratch/tests.json"
```

Always pass `--tests-file`, `--description-file`, and `--short-description`. Add `--overwrite` only after they replied replace.

`<ruleset>` is the name they chose, or `security-variants`. That command uses the same Datadog credentials as the MCP server: `DD_API_KEY` and `DD_APP_KEY`, or `DD_AUTH_DOMAIN` so `dd-auth` can supply a short-lived token.

## Project config

Write the config only after they replied yes in `SKILL.md` step 11.

- If `code-security.datadog.yaml` or `code-security.datadog.yml` exists, add the slug under `sast.use-rulesets`. Keep every other setting. Do not set `use-default-rulesets` to false.
- If only a legacy `static-analysis.datadog.yml` or `.yaml` exists, add the slug to its `rulesets` list. Do not create a second config file. The extension prefers `code-security.datadog.yaml` when both exist, and a new file would hide the legacy rulesets.
- If no config file exists, create `code-security.datadog.yaml` at the repository root:

```yaml
schema-version: v1.0
sast:
  use-rulesets:
    - <ruleset>
```

Do not set `use-default-rulesets: false`. Default language rulesets stay on. Do not write this file under `$scratch`.

## Refresh in the IDE

**Datadog: Refresh Static Analysis Rules** is a fallback, not a required step. The command stays hidden until the config file is the effective config and static analysis is enabled. Saving the config file clears the in-memory rule cache. The extension fetches the rules again after that command, after two hours, or when the static analysis engine restarts. The refresh only requests rulesets the config names.
