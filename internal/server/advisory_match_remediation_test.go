package server

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hibouhq/hibou/internal/advisorydb"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

func TestRemediationMatchCarriesCompleteIntervalsAndPrivacy(t *testing.T) {
	private := false
	interval := exportedAffectedRange(dbgen.AffectedRange{Ecosystem: "npm", PackageName: "fixture", Introduced: "1.0.0", Fixed: "1.2.3"})
	response := purlMatchResponse{
		Purl: "pkg:npm/fixture@1.0.0", Supported: true, PrivateNamespace: &private,
		Advisories: []matchedAdvisoryResponse{{CanonicalID: "TEST-1", AffectedRanges: []advisorydb.Range{interval}}},
	}
	data, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{`"private_namespace":false`, `"affected_ranges":[`, `"introduced":"1.0.0"`, `"fixed":"1.2.3"`} {
		if !strings.Contains(string(data), required) {
			t.Fatalf("missing remediation evidence %s: %s", required, data)
		}
	}
	legacy, err := json.Marshal(purlMatchResponse{Purl: "pkg:npm/fixture@1.0.0", Supported: true})
	if err != nil || strings.Contains(string(legacy), "private_namespace") {
		t.Fatalf("legacy response gained unknown privacy verdict: %s %v", legacy, err)
	}
}

func TestExportedAffectedRangePreservesAllBoundaries(t *testing.T) {
	row := dbgen.AffectedRange{Ecosystem: "npm", PackageName: "fixture", Introduced: "1.0.0", LastAffected: "1.2.2", Release: "scope"}
	got := exportedAffectedRange(row)
	if got.Ecosystem != row.Ecosystem || got.Package != row.PackageName || got.Introduced != row.Introduced ||
		got.LastAffected != row.LastAffected || got.Release != row.Release || got.Fixed != "" {
		t.Fatalf("affected interval lost evidence: %+v", got)
	}
}
