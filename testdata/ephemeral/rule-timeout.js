// Never returns, so the analyzer stops it at its per-file timeout. The ephemeral
// scan must report the timeout instead of returning no findings.
function visit(captures) {
  for (;;) {}
}
