package callgraph

import (
	"bytes"
	"testing"
)

// A miniature govulncheck -json stream: one advisory called (symbol-level
// trace), one merely present (module-level trace, no function).
const govulncheckStream = `{"osv":{"id":"GO-2021-0061","aliases":["CVE-2021-4235","GHSA-r88r-gmrh-7j83"]}}
{"osv":{"id":"GO-2020-0017","aliases":["CVE-2020-26160"]}}
{"finding":{"osv":"GO-2021-0061","trace":[{"module":"gopkg.in/yaml.v2"}]}}
{"finding":{"osv":"GO-2021-0061","trace":[{"module":"gopkg.in/yaml.v2","package":"gopkg.in/yaml.v2","function":"Unmarshal"},{"module":"example.com/app","package":"example.com/app","function":"ParseConfig"}]}}
{"finding":{"osv":"GO-2020-0017","trace":[{"module":"github.com/dgrijalva/jwt-go"}]}}
`

func TestParseGovulncheckStream(t *testing.T) {
	report, err := parseGovulncheckStream(bytes.NewBufferString(govulncheckStream))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(report.Findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(report.Findings))
	}

	called := report.Findings[0]
	if called.OSV != "GO-2021-0061" || !called.Called {
		t.Fatalf("symbol-level finding not marked called: %+v", called)
	}
	// The most specific trace wins — it carries the graph edges downstream
	// consumers (cycle detection, module graphing) need.
	if len(called.Trace) != 2 || called.Trace[0].Function != "Unmarshal" {
		t.Fatalf("expected the longest trace kept, got %+v", called.Trace)
	}

	present := report.Findings[1]
	if present.OSV != "GO-2020-0017" || present.Called {
		t.Fatalf("module-level finding must not be called: %+v", present)
	}

	reachable, unreachable := report.ReachabilityVerdicts()
	if len(reachable) != 3 || reachable[0] != "GO-2021-0061" {
		t.Fatalf("reachable = %v, want the called advisory + aliases", reachable)
	}
	if len(unreachable) != 2 || unreachable[1] != "CVE-2020-26160" {
		t.Fatalf("unreachable = %v, want the present-only advisory + alias", unreachable)
	}
}
