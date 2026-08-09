// Package callgraph runs language call-graph analyses in a source checkout
// and exposes their results as data, decoupled from any single use.
//
// Producers, each at its honest precision:
//   - Go:   govulncheck (SYMBOL-level call graph — the vulnerable function is
//     provably on/off the call path)
//   - Java: bytecode constant-pool scan (CLASS-level — which packages the
//     compiled app references)
//   - Rust: cargo metadata + source scan (CRATE-level — which crates the
//     workspace source names)
//
// One consumer today (vulnerability reachability: `hibou analyze
// reachability`), but the types deliberately keep the underlying data —
// trace frames, referenced packages/crates — rather than collapsing to a
// verdict, because the same graphs feed future analyses: module-dependency
// graphing, cycle (inter-dependency loop) detection, and architecture
// metrics. Consumers derive their own views; producers never pre-aggregate.
package callgraph

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// Frame is one node on a call path, most specific first (the vulnerable
// symbol) up to the caller in the analyzed module.
type Frame struct {
	Module   string `json:"module"`
	Package  string `json:"package"`
	Function string `json:"function"`
}

// GoVulnFinding is one govulncheck finding: an advisory plus the call trace
// that reaches it. Called is true when the trace is symbol-level — the
// vulnerable function is on the analyzed code's call graph — and false for
// module-level findings (the dependency is present, the symbol never called).
type GoVulnFinding struct {
	OSV     string   `json:"osv"`
	Aliases []string `json:"aliases"`
	Called  bool     `json:"called"`
	Trace   []Frame  `json:"trace"`
}

// GoVulnReport is a parsed govulncheck run.
type GoVulnReport struct {
	Findings []GoVulnFinding `json:"findings"`
}

// RunGovulncheck executes `govulncheck -json ./...` in dir (working directory
// when empty) and parses its streamed output. govulncheck's non-zero exit on
// called vulnerabilities is data, not an error; the run only fails when no
// parseable output was produced.
func RunGovulncheck(ctx context.Context, dir string) (*GoVulnReport, error) {
	if _, err := exec.LookPath("govulncheck"); err != nil {
		return nil, errors.New("govulncheck not found on PATH — install with: go install golang.org/x/vuln/cmd/govulncheck@latest")
	}

	cmd := exec.CommandContext(ctx, "govulncheck", "-json", "./...")
	if dir != "" {
		cmd.Dir = dir
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	report, parseErr := parseGovulncheckStream(&stdout)
	if parseErr != nil || len(report.Findings) == 0 {
		if runErr != nil {
			return nil, fmt.Errorf("govulncheck: %w: %s", runErr, strings.TrimSpace(stderr.String()))
		}
	}
	if parseErr != nil {
		return nil, parseErr
	}
	return report, nil
}

// parseGovulncheckStream consumes govulncheck's -json format: a stream of
// concatenated JSON objects ({"osv": …} advisory descriptions interleaved
// with {"finding": …} trace records; one advisory can carry several finding
// records at different precision levels).
func parseGovulncheckStream(stream *bytes.Buffer) (*GoVulnReport, error) {
	aliasesByOSV := map[string][]string{}
	tracesByOSV := map[string][][]Frame{}
	calledByOSV := map[string]bool{}
	order := []string{}

	decoder := json.NewDecoder(stream)
	for {
		var message struct {
			OSV *struct {
				ID      string   `json:"id"`
				Aliases []string `json:"aliases"`
			} `json:"osv"`
			Finding *struct {
				OSV   string `json:"osv"`
				Trace []struct {
					Module   string `json:"module"`
					Package  string `json:"package"`
					Function string `json:"function"`
				} `json:"trace"`
			} `json:"finding"`
		}
		if err := decoder.Decode(&message); err != nil {
			break
		}
		if message.OSV != nil {
			aliasesByOSV[message.OSV.ID] = message.OSV.Aliases
		}
		if message.Finding != nil {
			osv := message.Finding.OSV
			if _, seen := tracesByOSV[osv]; !seen {
				order = append(order, osv)
			}
			frames := make([]Frame, 0, len(message.Finding.Trace))
			for _, frame := range message.Finding.Trace {
				frames = append(frames, Frame{Module: frame.Module, Package: frame.Package, Function: frame.Function})
			}
			tracesByOSV[osv] = append(tracesByOSV[osv], frames)
			// A finding whose trace reaches a function is symbol-level: the
			// vulnerable code is on the call graph.
			if len(frames) > 0 && frames[0].Function != "" {
				calledByOSV[osv] = true
			}
		}
	}

	report := &GoVulnReport{}
	for _, osv := range order {
		// Keep the most specific (longest) trace — the one carrying the most
		// graph information for downstream consumers.
		var best []Frame
		for _, trace := range tracesByOSV[osv] {
			if len(trace) > len(best) {
				best = trace
			}
		}
		report.Findings = append(report.Findings, GoVulnFinding{
			OSV:     osv,
			Aliases: aliasesByOSV[osv],
			Called:  calledByOSV[osv],
			Trace:   best,
		})
	}
	return report, nil
}

// ReachabilityVerdicts derives the vulnerability-reachability view: every
// identifier (OSV id + aliases) of called findings, and of present-but-never-
// called ones. This is one projection of the report, not the report.
func (r *GoVulnReport) ReachabilityVerdicts() (reachable, unreachable []string) {
	for _, finding := range r.Findings {
		identifiers := append([]string{finding.OSV}, finding.Aliases...)
		if finding.Called {
			reachable = append(reachable, identifiers...)
		} else {
			unreachable = append(unreachable, identifiers...)
		}
	}
	return reachable, unreachable
}
