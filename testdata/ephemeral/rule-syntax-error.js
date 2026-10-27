// Does not compile: visit is never closed. The ephemeral scan must report the
// syntax error instead of returning no findings.
function visit(captures) {
  const call = captures.get("call");
