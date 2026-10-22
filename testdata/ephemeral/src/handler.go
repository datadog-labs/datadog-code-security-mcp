// Ephemeral scan fixture. The rule in ../rule.js reports every runUnchecked
// call. The go-security ruleset named in ../static-analysis.datadog.yml would
// also report the shell command below, so a finding from it means the scan ran
// the configured rulesets instead of only the ephemeral rule.
package main

import (
	"net/http"
	"os/exec"
)

func validateCommand(command string) error { return nil }

func runUnchecked(command string) error {
	return exec.Command("sh", "-c", command).Run()
}

// VULNERABLE: runs the request parameter without validateCommand.
func handler(w http.ResponseWriter, r *http.Request) {
	_ = runUnchecked(r.URL.Query().Get("cmd"))
}

// SAFE: validates before running.
func safeHandler(w http.ResponseWriter, r *http.Request) {
	command := r.URL.Query().Get("cmd")
	if err := validateCommand(command); err != nil {
		return
	}
	_ = exec.Command("sh", "-c", command).Run()
}
