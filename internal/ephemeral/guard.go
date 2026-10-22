package ephemeral

import (
	"encoding/json"
	"fmt"
	"strings"
)

// exceptionMarker prefixes the message of the violation guardRuleCode reports
// when the rule throws. The analyzer drops results that only carry an
// execution error, so a throwing rule would otherwise look like a clean scan.
const exceptionMarker = "__DD_EPHEMERAL_RULE_EXCEPTION__ "

// maxReportedExceptions bounds how many rule exceptions the scan error lists.
const maxReportedExceptions = 3

// guardRuleCode wraps the rule so an exception in visit, beforeAll, or afterAll
// becomes a marked violation instead of a dropped result. The analyzer runs the
// rule inside its own strict-mode function and calls those three names, so the
// wrapper keeps them, and keeps the arity the analyzer checks on beforeAll.
// The wrappers are var so that, while the rule's own scope is evaluated, a name
// the rule does not declare reads as undefined rather than the wrapper or a
// const in its temporal dead zone.
// The rule's functions are held in plain variables and called without a
// receiver, as the analyzer calls them, so this is undefined inside the rule.
// When the rule's top-level code throws, visit reports that exception once
// instead, and the rule's own callbacks are never installed.
// It cannot catch a syntax error: that stops the whole script before it runs.
func guardRuleCode(code string) string {
	return `const [__ddsaVisit, __ddsaBeforeAll, __ddsaAfterAll] = (() => {
try {
` + code + `
;return [
  typeof visit === "function" ? visit : undefined,
  typeof beforeAll === "function" ? beforeAll : undefined,
  typeof afterAll === "function" ? afterAll : undefined,
];
} catch (e) {
  let reported = false;
  return [function () { if (!reported) { reported = true; __ddsaReport(e); } }, undefined, undefined];
}
})();
function __ddsaReport(e) {
  addError(buildError(1, 1, 1, 2, "` + exceptionMarker + `" + String(e)));
}
var visit = __ddsaVisit === undefined ? undefined
  : function (queryMatch, filename, fileContents) {
    try {
      return __ddsaVisit(queryMatch, filename, fileContents);
    } catch (e) {
      __ddsaReport(e);
    }
  };
var beforeAll = __ddsaBeforeAll === undefined ? undefined
  : __ddsaBeforeAll.length === 0
    ? function () { try { __ddsaBeforeAll(); } catch (e) { __ddsaReport(e); } }
    : function (matches) { try { __ddsaBeforeAll(matches); } catch (e) { __ddsaReport(e); } };
var afterAll = __ddsaAfterAll === undefined ? undefined
  : function () { try { __ddsaAfterAll(); } catch (e) { __ddsaReport(e); } };
`
}

// RuleExceptionError means the rule threw while the analyzer ran it, so the
// findings are incomplete.
type RuleExceptionError struct {
	// Files counts the files where the rule threw.
	Files int
	// Examples lists up to maxReportedExceptions "file: message" entries.
	Examples []string
}

func (e *RuleExceptionError) Error() string {
	return fmt.Sprintf("the rule raised an exception in %d file(s), so the results are incomplete. Fix the rule and scan again:\n%s",
		e.Files, strings.Join(e.Examples, "\n"))
}

// ruleExceptions returns a RuleExceptionError when the findings contain marked
// violations, and nil otherwise.
func ruleExceptions(findings []byte) error {
	var results []struct {
		Filename   string `json:"filename"`
		Violations []struct {
			Message string `json:"message"`
		} `json:"violations"`
	}
	if err := json.Unmarshal(findings, &results); err != nil {
		return nil
	}
	report := &RuleExceptionError{}
	for _, result := range results {
		for _, violation := range result.Violations {
			message, ok := strings.CutPrefix(violation.Message, exceptionMarker)
			if !ok {
				continue
			}
			report.Files++
			if len(report.Examples) < maxReportedExceptions {
				report.Examples = append(report.Examples, result.Filename+": "+message)
			}
			break
		}
	}
	if report.Files == 0 {
		return nil
	}
	return report
}
