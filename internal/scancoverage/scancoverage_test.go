package scancoverage

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/scanplan"
	"github.com/hibouhq/hibou/internal/scanpolicy"
)

func TestComputeStates(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	blocking := uuid.New()
	requirements := map[uuid.UUID]Requirement{blocking: {ID: blocking, Enforcement: "blocking", FreshnessDays: 7}}
	decisions := []scanpolicy.Decision{
		{ScannerID: "covered", State: scanpolicy.StateRecommended},
		{ScannerID: "never-ran", State: scanpolicy.StateEnabled},
		{ScannerID: "failed", State: scanpolicy.StateRecommended},
		{ScannerID: "partial", State: scanpolicy.StateRecommended},
		{ScannerID: "stale", State: scanpolicy.StateRequired, Requirements: []uuid.UUID{blocking}},
		{ScannerID: "unbound", State: scanpolicy.StateRequired, Requirements: []uuid.UUID{blocking}},
		{ScannerID: "blocked", State: scanpolicy.StateRecommended},
		{ScannerID: "pending", State: scanpolicy.StateRecommended},
		{ScannerID: "off", State: scanpolicy.StateDisabled},
		{ScannerID: "exempt", State: scanpolicy.StateDisabled, Exempted: []uuid.UUID{blocking}},
		{ScannerID: "na", State: scanpolicy.StateNotApplied},
	}
	runs := []Run{
		{ScannerID: "covered", Outcome: "completed", Scope: "full", At: now.Add(-time.Hour), Commit: "abcdef123"},
		{ScannerID: "failed", Outcome: "failed", At: now},
		{ScannerID: "partial", Outcome: "completed", Scope: "partial", At: now},
		{ScannerID: "stale", Outcome: "completed", Scope: "full", Bound: true, At: now.Add(-10 * 24 * time.Hour)},
		{ScannerID: "unbound", Outcome: "completed", Scope: "full", Bound: false, At: now},
	}
	plan := &scanplan.Plan{Jobs: []scanplan.Job{
		{ScannerID: "blocked", Status: scanplan.JobBlocked, BlockedReason: "no approved ruleset: x"},
		{ScannerID: "pending", Status: scanplan.JobReady},
	}}
	cells := Compute(Input{Decisions: decisions, Requirements: requirements, ApplicabilityStatus: "complete", Plan: plan, PlanCreatedAt: now.Add(-time.Minute), Runs: runs, Now: now})
	want := map[string]string{
		"covered": StateCovered, "never-ran": StateMissing, "failed": StateFailed, "partial": StatePartial,
		"stale": StateStale, "unbound": StateUnverified, "blocked": StateMissingSetup, "pending": StatePending,
		"off": StateDisabled, "exempt": StateExempt, "na": StateNotApplicable,
	}
	for _, cell := range cells {
		if cell.State != want[cell.ScannerID] {
			t.Errorf("%s: %s (%s), want %s", cell.ScannerID, cell.State, cell.Reason, want[cell.ScannerID])
		}
	}
	for _, cell := range cells {
		if cell.ScannerID == "stale" && (!cell.Required || cell.Enforcement != "blocking" || !cell.Gap()) {
			t.Fatalf("stale required cell = %+v", cell)
		}
		if cell.ScannerID == "pending" && cell.Gap() {
			t.Fatal("pending is not yet a gap")
		}
	}

	// An incomplete listing turns "never ran" into "unknown".
	unknown := Compute(Input{Decisions: decisions[1:2], ApplicabilityStatus: "truncated", Now: now})
	if unknown[0].State != StateUnknown {
		t.Fatalf("truncated listing = %+v", unknown[0])
	}
}

// In offline mode a fresh run on an old bundle is stale: the scanner
// started fine, but with content older than the org allows.
func TestComputeStaleOfflineBundle(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	requirement := uuid.New()
	input := Input{
		Decisions:           []scanpolicy.Decision{{ScannerID: "opengrep", State: scanpolicy.StateRequired, Requirements: []uuid.UUID{requirement}}},
		Requirements:        map[uuid.UUID]Requirement{requirement: {ID: requirement, Enforcement: "blocking", FreshnessDays: 30}},
		ApplicabilityStatus: "complete",
		Runs:                []Run{{ScannerID: "opengrep", Outcome: "completed", Scope: "full", Bound: true, At: now.Add(-time.Hour)}},
		Now:                 now,
	}
	fresh := now.Add(-10 * 24 * time.Hour)
	input.BundleCreatedAt = &fresh
	if cells := Compute(input); cells[0].State != StateCovered {
		t.Fatalf("fresh bundle = %+v", cells[0])
	}
	old := now.Add(-45 * 24 * time.Hour)
	input.BundleCreatedAt = &old
	if cells := Compute(input); cells[0].State != StateStale {
		t.Fatalf("45-day-old bundle under a 30-day policy = %+v", cells[0])
	}
	input.Requirements[requirement] = Requirement{ID: requirement, Enforcement: "blocking"}
	if cells := Compute(input); cells[0].State != StateCovered {
		t.Fatalf("no freshness policy = %+v", cells[0])
	}
}
