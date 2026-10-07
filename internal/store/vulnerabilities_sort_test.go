package store

import (
	"strings"
	"testing"
)

func TestVulnerabilityOrderByClausePrioritizesKEVForDefaultSorts(t *testing.T) {
	clause := vulnerabilityOrderByClause(4)

	if !strings.Contains(clause, "$4::text IN ('', 'detected_desc', 'severity_desc')") {
		t.Fatalf("KEV ranking must apply only to default sorts: %s", clause)
	}
	if !strings.Contains(clause, "FROM kev_entries") {
		t.Fatalf("KEV ranking must query known-exploited entries: %s", clause)
	}
	if strings.Index(clause, "FROM kev_entries") > strings.Index(clause, "type = 'malware'") {
		t.Fatalf("KEV ranking must precede malware ranking: %s", clause)
	}
}
