package server

import (
	"testing"

	"github.com/hibouhq/hibou/internal/store"
)

// ADR-023 semantics table: a false positive never was a vulnerability; an
// accepted risk is still risk, flagged; resolved/suppressed are not risk.
func TestRiskSeverityCounts(t *testing.T) {
	t.Parallel()

	vulnerabilities := []store.Vulnerability{
		{Fingerprint: "open", Severity: store.SeverityLevelCritical, Status: "detected"},
		{Fingerprint: "accepted", Severity: store.SeverityLevelHigh, Status: "detected"},
		{Fingerprint: "fp", Severity: store.SeverityLevelHigh, Status: "detected"},
		{Fingerprint: "fixed", Severity: store.SeverityLevelLow, Status: "resolved"},
		{Fingerprint: "nosec", Severity: store.SeverityLevelLow, Status: "suppressed"},
	}
	acceptances := []store.FindingAcceptance{
		{Fingerprint: "accepted", ReasonKind: "risk_accepted"},
		{Fingerprint: "fp", ReasonKind: "false_positive"},
	}

	counts := riskSeverityCounts(vulnerabilities, acceptances)
	if counts.Critical != 1 || counts.High != 1 || counts.Low != 0 {
		t.Fatalf("counts = %+v, want critical=1 high=1 low=0", counts)
	}
	if counts.AcceptedRisk != 1 {
		t.Fatalf("accepted_risk = %d, want 1 (accepted risk counts, flagged)", counts.AcceptedRisk)
	}
}

func TestCountTrendSnapshotSeveritiesExcludesFalsePositives(t *testing.T) {
	t.Parallel()

	vulnerabilities := []store.Vulnerability{
		{Fingerprint: "sast-open", Type: "sast", Severity: store.SeverityLevelHigh, Status: "detected"},
		{Fingerprint: "sast-fp", Type: "sast", Severity: store.SeverityLevelHigh, Status: "detected"},
		{Fingerprint: "dep-fp", Type: "dependency", Severity: store.SeverityLevelCritical, Status: "detected"},
	}
	kinds := map[string]string{"sast-fp": "false_positive", "dep-fp": "false_positive"}

	findings, vulns := countTrendSnapshotSeverities(vulnerabilities, kinds)
	if findings.High != 1 {
		t.Fatalf("findings.High = %d, want 1 (FP excluded)", findings.High)
	}
	if vulns.Critical != 0 {
		t.Fatalf("vulns.Critical = %d, want 0 (FP excluded)", vulns.Critical)
	}
}
