package store

import (
	"testing"
	"time"
)

func TestAuditPartitionNameRoundTrip(t *testing.T) {
	t.Parallel()

	monthStart := time.Date(2026, time.August, 1, 0, 0, 0, 0, time.UTC)
	name := auditPartitionName(monthStart)
	if name != "audit_logs_p202608" {
		t.Fatalf("name = %q", name)
	}

	parsed, ok := auditPartitionMonth(name)
	if !ok || !parsed.Equal(monthStart) {
		t.Fatalf("parsed = %v ok=%v, want %v", parsed, ok, monthStart)
	}
}

func TestAuditPartitionMonthRejectsUnmanagedRelations(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"audit_logs_default", "audit_logs", "audit_logs_p2026", "audit_logs_p20260801", "other_p202608"} {
		if _, ok := auditPartitionMonth(name); ok {
			t.Fatalf("%q parsed as a managed monthly partition", name)
		}
	}
}

func TestAuditRetentionCutoffAndDropDecision(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 15, 10, 0, 0, 0, time.UTC)
	cutoff := auditRetentionCutoff(now, 6)
	if want := time.Date(2026, time.February, 1, 0, 0, 0, 0, time.UTC); !cutoff.Equal(want) {
		t.Fatalf("cutoff = %v, want %v", cutoff, want)
	}

	droppable := func(name string) bool {
		monthStart, ok := auditPartitionMonth(name)
		return ok && !monthStart.AddDate(0, 1, 0).After(cutoff)
	}

	if !droppable("audit_logs_p202512") {
		t.Fatal("December 2025 should be droppable with a 6-month window")
	}
	if !droppable("audit_logs_p202601") {
		t.Fatal("January 2026 ends exactly at the cutoff and is entirely older, so it is droppable")
	}
	if droppable("audit_logs_p202602") {
		t.Fatal("February 2026 is the oldest kept month and must not be dropped")
	}
	if droppable("audit_logs_p202608") {
		t.Fatal("the current month must never be dropped")
	}
}
