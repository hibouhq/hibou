// Package scancoverage states, per repository and scanner, whether the
// coverage the policy asks for actually happened (ADR-035 §5–6): configured
// and observed are kept apart, so an enabled scanner that never ran is a gap,
// not a green cell. It is pure; the server feeds it policy decisions, the
// latest plan and recorded producer runs, and persists the result.
package scancoverage

import (
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/scanplan"
	"github.com/hibouhq/hibou/internal/scanpolicy"
	"github.com/hibouhq/hibou/internal/store"
)

// Cell states (ADR-035 §6), plus "missing" (enabled, plannable, never ran)
// and "unverified" (ran, but not bound to a plan job, while a blocking
// requirement needs authenticated evidence).
const (
	StateCovered             = "covered"
	StatePending             = "pending"
	StateMissing             = "missing"
	StateMissingSetup        = "missing_setup"
	StateDisabled            = "disabled"
	StatePrerequisiteBlocked = "prerequisite_blocked"
	StateFailed              = "failed"
	StatePartial             = "partial"
	StateStale               = "stale"
	StateUnsupported         = "unsupported"
	StateExempt              = "exempt"
	StateNotApplicable       = "not_applicable"
	StateUnknown             = "unknown"
	StateUnverified          = "unverified"
)

// pendingWindow: a ready job planned this recently is still expected.
const pendingWindow = 2 * time.Hour

// Run is one recorded producer run attributed to a catalog scanner.
type Run struct {
	ScannerID string
	Outcome   string
	Scope     string
	// Bound: uploaded with its plan job (authenticated evidence).
	Bound  bool
	At     time.Time
	Commit string
}

// Requirement is what the coverage of a required scanner is held to.
type Requirement struct {
	ID            uuid.UUID
	Enforcement   string
	FreshnessDays int
}

// Input is everything a coverage computation reads.
type Input struct {
	Decisions           []scanpolicy.Decision
	Requirements        map[uuid.UUID]Requirement
	ApplicabilityStatus string
	Plan                *scanplan.Plan
	PlanCreatedAt       time.Time
	Runs                []Run
	// BundleCreatedAt: in offline mode, when the scanner bundle (binaries,
	// later rules and databases) was exported. Runs use its content, so a
	// bundle older than a requirement's freshness makes them stale too.
	BundleCreatedAt *time.Time
	Now             time.Time
}

// Cell is one repository × scanner state.
type Cell struct {
	ScannerID   string     `json:"scanner_id"`
	State       string     `json:"state"`
	Reason      string     `json:"reason"`
	Required    bool       `json:"required"`
	Enforcement string     `json:"enforcement,omitempty"`
	Configured  string     `json:"configured"`
	LastRunAt   *time.Time `json:"last_run_at,omitempty"`
	LastCommit  string     `json:"last_commit,omitempty"`
}

// Gap reports whether the cell is a coverage gap that a requirement can
// fail on. Pending is not yet a gap.
func (c Cell) Gap() bool {
	switch c.State {
	case StateMissing, StateMissingSetup, StatePrerequisiteBlocked, StateFailed, StatePartial,
		StateStale, StateUnsupported, StateUnknown, StateUnverified:
		return true
	}
	return false
}

// Compute returns one cell per decision.
func Compute(input Input) []Cell {
	latest := map[string]Run{}
	for _, run := range input.Runs {
		if current, ok := latest[run.ScannerID]; !ok || run.At.After(current.At) {
			latest[run.ScannerID] = run
		}
	}
	jobs := map[string]scanplan.Job{}
	if input.Plan != nil {
		for _, job := range input.Plan.Jobs {
			jobs[job.ScannerID] = job
		}
	}
	listingIncomplete := input.ApplicabilityStatus == "truncated" || input.ApplicabilityStatus == "unknown"

	cells := make([]Cell, 0, len(input.Decisions))
	for _, decision := range input.Decisions {
		cell := Cell{ScannerID: decision.ScannerID, Configured: decision.State, Required: decision.State == scanpolicy.StateRequired}
		requirement := strictest(decision.Requirements, input.Requirements)
		if cell.Required {
			cell.Enforcement = requirement.Enforcement
		}
		switch {
		case decision.State == scanpolicy.StateNotApplied:
			cell.State, cell.Reason = StateNotApplicable, decision.Reason
		case len(decision.Exempted) > 0 && !cell.Required:
			cell.State, cell.Reason = StateExempt, "requirement waived by an approved exception"
		case !decision.Runs():
			cell.State, cell.Reason = StateDisabled, decision.Reason
		default:
			cell.State, cell.Reason = observed(cell, requirement, latest, jobs, input)
			if run, ok := latest[decision.ScannerID]; ok {
				at := run.At
				cell.LastRunAt, cell.LastCommit = &at, run.Commit
			}
			if listingIncomplete && (cell.State == StateMissing || cell.State == StateMissingSetup) {
				cell.State, cell.Reason = StateUnknown, "the forge listing was incomplete: what applies is not known"
			}
		}
		cells = append(cells, cell)
	}
	return cells
}

func observed(cell Cell, requirement Requirement, latest map[string]Run, jobs map[string]scanplan.Job, input Input) (string, string) {
	run, ran := latest[cell.ScannerID]
	if ran {
		switch {
		case run.Outcome == store.ProducerOutcomeFailed:
			return StateFailed, "the latest run failed"
		case run.Outcome == store.ProducerOutcomePartial || run.Scope == store.ProducerScopePartial:
			return StatePartial, "the latest run covered only part of the scope"
		case cell.Required && requirement.Enforcement == "blocking" && !run.Bound:
			return StateUnverified, "ran, but the report is not bound to a plan job: a blocking requirement needs planned evidence"
		case requirement.FreshnessDays > 0 && input.Now.Sub(run.At) > time.Duration(requirement.FreshnessDays)*24*time.Hour:
			return StateStale, "the latest run is older than the required freshness"
		case requirement.FreshnessDays > 0 && input.BundleCreatedAt != nil && input.Now.Sub(*input.BundleCreatedAt) > time.Duration(requirement.FreshnessDays)*24*time.Hour:
			return StateStale, "the offline scanner bundle is older than the required freshness: export and import a new one"
		}
		return StateCovered, "ran on " + shortCommit(run.Commit)
	}
	job, planned := jobs[cell.ScannerID]
	switch {
	case planned && job.Status == scanplan.JobBlocked && strings.HasPrefix(job.BlockedReason, "no verified"):
		return StateUnsupported, job.BlockedReason
	case planned && job.Status == scanplan.JobBlocked:
		return StateMissingSetup, job.BlockedReason
	case planned && input.Now.Sub(input.PlanCreatedAt) < pendingWindow:
		return StatePending, "planned, waiting for its report"
	case planned:
		return StateMissing, "planned but never reported"
	}
	return StateMissing, "enabled but never ran: wire hibou scan into CI"
}

// strictest picks the blocking requirement with the tightest freshness.
func strictest(ids []uuid.UUID, requirements map[uuid.UUID]Requirement) Requirement {
	out := Requirement{Enforcement: "advisory"}
	for _, id := range ids {
		requirement, ok := requirements[id]
		if !ok {
			continue
		}
		if requirement.Enforcement == "blocking" {
			out.Enforcement = "blocking"
		}
		if requirement.FreshnessDays > 0 && (out.FreshnessDays == 0 || requirement.FreshnessDays < out.FreshnessDays) {
			out.FreshnessDays = requirement.FreshnessDays
		}
	}
	return out
}

func shortCommit(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}
