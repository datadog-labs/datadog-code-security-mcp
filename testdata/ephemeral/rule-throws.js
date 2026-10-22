// Matches the same calls as rule.js, then throws. The ephemeral scan must report
// the exception as an error instead of returning no findings.
function visit(captures) {
  captures.get("call").missing.boom();
}
