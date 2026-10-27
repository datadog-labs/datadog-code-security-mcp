function visit(captures) {
  const call = captures.get("call");
  if (!call) return;
  addError(buildError(call.start.line, call.start.col, call.end.line, call.end.col, "runUnchecked is called without validateCommand"));
}
