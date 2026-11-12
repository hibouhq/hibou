package remediation

import (
	"fmt"
	"regexp"
)

type toolFailure struct {
	cause       error
	diagnostics []byte
}

var npmErrorCode = regexp.MustCompile(`(?m)npm (?:error|ERR!) code ([A-Z0-9_]+)`)

func (e *toolFailure) Error() string {
	code := ""
	if match := npmErrorCode.FindSubmatch(e.diagnostics); len(match) == 2 {
		switch string(match[1]) {
		case "EUSAGE", "ELOCKVERIFY", "EBADENGINE", "ETARGET", "EINTEGRITY", "E401", "E403", "E404", "ERESOLVE", "ENOTFOUND", "ECONNREFUSED", "ETIMEDOUT":
			code = " (" + string(match[1]) + ")"
		}
	}
	return fmt.Sprintf("process execution%s: %v", code, e.cause)
}

func (e *toolFailure) Unwrap() error { return e.cause }
