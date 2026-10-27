// Throws while the rule loads, before visit runs. The ephemeral scan must report
// the exception instead of returning no findings.
const limits = undefined.limits;

function visit(captures) {
  const call = captures.get("call");
  addError(buildError(call.start.line, call.start.col, call.end.line, call.end.col, "limit " + limits));
}
