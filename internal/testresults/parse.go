// Package testresults parses CI test reports (JUnit XML and equivalents) into a
// normalized model the server stores and the UI renders.
package testresults

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
)

// Case statuses.
const (
	StatusPassed  = "passed"
	StatusFailed  = "failed"
	StatusSkipped = "skipped"
	StatusError   = "error"
)

// Case is a single test case result.
type Case struct {
	Suite           string
	Name            string
	Classname       string
	Status          string
	DurationSeconds float64
	Message         string
	FilePath        string
}

// Report is the aggregated result of a test run.
type Report struct {
	Format          string
	Total           int
	Passed          int
	Failed          int
	Skipped         int
	Errors          int
	DurationSeconds float64
	Cases           []Case
}

// Parse decodes a test report of the given format. An empty format defaults to
// JUnit XML, the de-facto interchange format emitted by most language toolchains.
func Parse(content []byte, format string) (*Report, error) {
	if len(bytes.TrimSpace(content)) == 0 {
		return nil, errors.New("empty test report")
	}

	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "junit", "junit-xml", "xunit":
		return parseJUnit(content)
	default:
		return nil, fmt.Errorf("unsupported test report format: %s", format)
	}
}

// tally recomputes the report counters from its cases.
func (r *Report) tally() {
	r.Total = len(r.Cases)
	r.Passed, r.Failed, r.Skipped, r.Errors = 0, 0, 0, 0
	for _, c := range r.Cases {
		switch c.Status {
		case StatusFailed:
			r.Failed++
		case StatusSkipped:
			r.Skipped++
		case StatusError:
			r.Errors++
		default:
			r.Passed++
		}
	}
}
