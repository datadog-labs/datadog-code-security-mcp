// Stores state on `this`. The analyzer calls these functions without a receiver
// in strict mode, so `this` is undefined and beforeAll throws. The ephemeral scan
// must report that instead of passing a rule that fails once published.
function beforeAll() {
  this.calls = 0;
}

function visit(captures) {
  const call = captures.get("call");
  this.calls++;
  addError(buildError(call.start.line, call.start.col, call.end.line, call.end.col, "call " + this.calls));
}
