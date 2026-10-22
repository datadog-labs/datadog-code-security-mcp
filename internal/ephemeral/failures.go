package ephemeral

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

// debugFlag makes the analyzer print one line per rule failure. It drops a
// result that has an execution error or a timeout and no violations, so a
// failing rule otherwise looks like a clean scan. In JSON output the flag only
// adds logs.
var debugFlag = []string{"--debug", "yes"}

// The analyzer's --debug lines for a failed rule, from analyze.rs:
//
//	rule:file <ruleset>/<rule>:<file> execution error, message: <reason>
//	rule:file <ruleset>/<rule>:<file> TIMED OUT (<n> ms)
const (
	failurePrefix   = "rule:file "
	executionMarker = " execution error, message: "
	timeoutMarker   = " TIMED OUT ("
)

const (
	// maxReportedFailures bounds how many failed files the scan error lists.
	maxReportedFailures = 3
	// maxLogLine bounds one buffered output line. A longer line is cut.
	maxLogLine = 64 * 1024
	// maxLogTail bounds the output kept for error messages.
	maxLogTail = 2000
)

// RuleFailureError means the rule threw, did not compile, or timed out on at
// least one file, so the findings are incomplete.
type RuleFailureError struct {
	// Files counts the files where the rule failed.
	Files int
	// Examples lists up to maxReportedFailures "file: reason" entries.
	Examples []string
}

func (e *RuleFailureError) Error() string {
	return fmt.Sprintf("the rule failed in %d file(s), so the results are incomplete. Fix the rule and scan again:\n%s",
		e.Files, strings.Join(e.Examples, "\n"))
}

// analyzerLog receives the analyzer's stdout and stderr. --debug prints a line
// per scanned file, so it keeps only the failures of one rule and the end of
// the output instead of the whole log.
type analyzerLog struct {
	prefix    string
	line      []byte
	tail      []byte
	truncated bool
	reasons   map[string]string
}

func newAnalyzerLog(ruleID string) *analyzerLog {
	return &analyzerLog{prefix: failurePrefix + ruleID + ":", reasons: map[string]string{}}
}

func (l *analyzerLog) Write(p []byte) (int, error) {
	l.tail = append(l.tail, p...)
	if over := len(l.tail) - maxLogTail; over > 0 {
		l.tail = l.tail[over:]
		for len(l.tail) > 0 && !utf8.RuneStart(l.tail[0]) {
			l.tail = l.tail[1:]
		}
		l.truncated = true
	}
	n := len(p)
	for len(p) > 0 {
		end := bytes.IndexByte(p, '\n')
		if end < 0 {
			l.appendLine(p)
			break
		}
		l.appendLine(p[:end])
		l.flush()
		p = p[end+1:]
	}
	return n, nil
}

func (l *analyzerLog) appendLine(p []byte) {
	if room := maxLogLine - len(l.line); room > 0 {
		l.line = append(l.line, p[:min(len(p), room)]...)
	}
}

// flush parses the buffered line. Call it once more after the process exits.
func (l *analyzerLog) flush() {
	line := strings.TrimRight(string(l.line), "\r")
	l.line = l.line[:0]
	rest, ok := strings.CutPrefix(line, l.prefix)
	if !ok {
		return
	}
	if file, reason, ok := strings.Cut(rest, executionMarker); ok {
		l.reasons[file] = strings.TrimPrefix(reason, "Uncaught ")
	} else if file, duration, ok := strings.Cut(rest, timeoutMarker); ok {
		l.reasons[file] = "timed out (" + duration
	}
}

// String returns the end of the output.
func (l *analyzerLog) String() string {
	if l.truncated {
		return "…" + string(l.tail)
	}
	return string(l.tail)
}

// failure returns a RuleFailureError when the rule failed on any file.
func (l *analyzerLog) failure() error {
	if len(l.reasons) == 0 {
		return nil
	}
	files := make([]string, 0, len(l.reasons))
	for file := range l.reasons {
		files = append(files, file)
	}
	sort.Strings(files)
	report := &RuleFailureError{Files: len(files)}
	for _, file := range files[:min(len(files), maxReportedFailures)] {
		report.Examples = append(report.Examples, file+": "+l.reasons[file])
	}
	return report
}
