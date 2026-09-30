# Ephemeral rule contract

`datadog-static-analyzer` only executes `rule_type: TREE_SITTER_QUERY`. The MCP tool packs this. The agent writes the two sources.

## Query (`.scm`)

One pattern per match. Name captures with `@`. The visitor receives those names.

```scm
(function_declaration
  name: (identifier) @fn_name
  body: (statement_block) @fn_body) @fn
```

## JavaScript

`visit(captures)` is called once per match. `captures.get("fn")` is a tree-sitter node with `.text`, `.start.line`, `.start.col`, `.end.line`, `.end.col`.

```javascript
function visit(captures) {
  const fn = captures.get("fn");
  if (!fn) return;
  addError(buildError(fn.start.line, fn.start.col, fn.end.line, fn.end.col, "message"));
}
```

`buildError`, `addError`, `buildEditAdd`, `buildEditUpdate`, `buildEditRemove`, and `buildFix` are runtime globals. Do not `import` them. Do not assign `module.exports`. Top-level `const` bindings are visible inside `visit`.

Attach the fix on the violation before reporting it:

```javascript
const error = buildError(fn.start.line, fn.start.col, fn.end.line, fn.end.col, "message");
const edit = buildEditAdd(line, col, "inserted text");
addError(error.addFix(buildFix("what the edit does", [edit])));
```

`buildEditAdd(line, col, content)` inserts. `buildEditUpdate(startLine, startCol, endLine, endCol, content)` replaces. `buildEditRemove(startLine, startCol, endLine, endCol)` deletes. Line and column come from the matched node.

Severity is the rule's severity (`ERROR`), not an argument of `buildError`. Put confidence in the message text.

## Language

Pass the scanner enum (`TYPESCRIPT`, `JAVASCRIPT`, …), not a lowercase name.
