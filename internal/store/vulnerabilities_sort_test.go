package store

import (
	"strings"
	"testing"
)

func TestVulnerabilityOrderByClausePinsMalwareThenKEV(t *testing.T) {
	clause := vulnerabilityOrderByClause(4)

	// risk_desc puts KEV first by definition (ADR-038 §5).
	if !strings.Contains(clause, "$4::text IN ('', 'detected_desc', 'severity_desc', 'risk_desc')") {
		t.Fatalf("KEV ranking must apply only to default sorts and risk: %s", clause)
	}
	if !strings.Contains(clause, "FROM kev_entries") {
		t.Fatalf("KEV ranking must query known-exploited entries: %s", clause)
	}
	// Open malware outranks everything, KEV included, for every sort.
	if strings.Index(clause, "type = 'malware'") > strings.Index(clause, "FROM kev_entries") {
		t.Fatalf("malware ranking must precede KEV ranking: %s", clause)
	}
	if !strings.Contains(clause, "fd.fingerprint IS NOT NULL") || !strings.Contains(clause, "'false_positive'") {
		t.Fatalf("malware pin must use the open-malware definition: %s", clause)
	}
}
