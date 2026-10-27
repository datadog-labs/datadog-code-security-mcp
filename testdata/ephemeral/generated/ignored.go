// Ephemeral scan fixture. static-analysis.datadog.yml ignores generated/**,
// so this runUnchecked call must not be reported.
package generated

func runUnchecked(command string) error { return nil }

func handler(command string) {
	_ = runUnchecked(command)
}
