package cvetriage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/advisory"
	"github.com/hibouhq/hibou/internal/cvefeed"
)

func loadRecord(t *testing.T, name string) cvefeed.Projection {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "cvefeed", "testdata", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	record, err := cvefeed.Decode(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return record
}

type fakeIngester struct {
	provider string
	results  []advisory.IngestResult
}

func (f *fakeIngester) Ingest(_ context.Context, provider string, results []advisory.IngestResult) (map[string]uuid.UUID, error) {
	f.provider = provider
	f.results = results
	ids := map[string]uuid.UUID{}
	for _, result := range results {
		ids[result.ProviderID] = uuid.New()
	}
	return ids, nil
}

// The whole point: a person names packages, and the ranges come from the record.
func TestBuildIngestResultAuthorsRangesFromTheRecord(t *testing.T) {
	record := loadRecord(t, "CVE-2026-59084.json")
	decision := Decision{
		CVEID:   record.ID,
		ActorID: uuid.New(),
		Packages: []Package{
			{Ecosystem: "Maven", Name: "org.apache.tomcat:tomcat-catalina"},
			{Ecosystem: "Maven", Name: "org.apache.tomcat.embed:tomcat-embed-core"},
		},
	}

	result, err := BuildIngestResult(decision, record)
	if err != nil {
		t.Fatalf("BuildIngestResult: %v", err)
	}

	// Five branch ranges x two packages.
	if len(result.AffectedRanges) != 10 {
		t.Fatalf("authored %d ranges, want 10", len(result.AffectedRanges))
	}
	for _, r := range result.AffectedRanges {
		if r.Ecosystem != "maven" {
			t.Errorf("ecosystem = %q, want normalized maven", r.Ecosystem)
		}
		// Apache publishes inclusive bounds only. A Fixed here would name a
		// release nobody verified exists.
		if r.Fixed != "" {
			t.Errorf("range %+v invented a fixed version", r)
		}
		if r.LastAffected == "" {
			t.Errorf("range %+v lost its upper bound", r)
		}
		if r.Source != SourceTriage {
			t.Errorf("source = %q", r.Source)
		}
	}

	// Severity rides along from the record — CISA-ADP's 9.1, not the CNA's "low".
	if result.Severity == nil || *result.Severity != advisory.SeverityCritical {
		t.Errorf("severity = %v, want critical", result.Severity)
	}
	if result.CVSSScore == nil || *result.CVSSScore != 9.1 {
		t.Errorf("score = %v, want 9.1", result.CVSSScore)
	}
}

// The dedup guarantee. Authoring must not mint a parallel identity: carrying the
// CVE in Aliases is what makes the ingester converge this onto the same advisory
// row as OSV's and NVD's records, so upstream catching up does not double-count.
func TestAuthoredResultCarriesCVEAlias(t *testing.T) {
	record := loadRecord(t, "CVE-2026-59084.json")
	result, err := BuildIngestResult(Decision{
		CVEID:    record.ID,
		ActorID:  uuid.New(),
		Packages: []Package{{Ecosystem: "Maven", Name: "org.apache.tomcat:tomcat-catalina"}},
	}, record)
	if err != nil {
		t.Fatalf("BuildIngestResult: %v", err)
	}

	if len(result.Aliases) != 1 || result.Aliases[0] != record.ID {
		t.Fatalf("aliases = %v, want [%s]", result.Aliases, record.ID)
	}
	// preferredCanonicalID picks a CVE alias over the provider id, which is what
	// makes convergence work; assert the alias is in the shape it recognizes.
	if !cvefeed.ValidCVEID(result.Aliases[0]) {
		t.Errorf("alias %q is not a CVE id", result.Aliases[0])
	}
}

// One source, because triage is instance-wide: an authored range is
// attributable to the act of triage, not to a tenant.
func TestSourceIsAlwaysTriage(t *testing.T) {
	if got := (Decision{}).Source(); got != SourceTriage {
		t.Errorf("Source() = %q, want %q", got, SourceTriage)
	}
}

// A withdrawn record must carry that through, so derived findings retire rather
// than standing until somebody notices.
func TestWithdrawnRecordPropagates(t *testing.T) {
	record := loadRecord(t, "CVE-2026-59084.json")
	record.State = cvefeed.StateRejected

	result, err := BuildIngestResult(Decision{
		CVEID:    record.ID,
		ActorID:  uuid.New(),
		Packages: []Package{{Ecosystem: "Maven", Name: "org.apache.tomcat:tomcat-catalina"}},
	}, record)
	if err != nil {
		t.Fatalf("BuildIngestResult: %v", err)
	}
	if result.WithdrawnAt == nil {
		t.Fatal("a REJECTED record authored no withdrawal")
	}
}

func TestDecisionValidation(t *testing.T) {
	valid := Decision{CVEID: "CVE-2026-59084", ActorID: uuid.New(),
		Packages: []Package{{Ecosystem: "Maven", Name: "g:a"}}}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid decision rejected: %v", err)
	}

	cases := map[string]Decision{
		"malformed id": {CVEID: "nope", ActorID: uuid.New(), Packages: valid.Packages},
		"no packages":  {CVEID: valid.CVEID, ActorID: uuid.New()},
		"no actor":     {CVEID: valid.CVEID, Packages: valid.Packages},
		"empty coordinate": {CVEID: valid.CVEID, ActorID: uuid.New(),
			Packages: []Package{{Ecosystem: "Maven", Name: "  "}}},
	}
	for name, decision := range cases {
		if err := decision.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestApplyIngestsUnderTheTriageSource(t *testing.T) {
	record := loadRecord(t, "CVE-2026-59084.json")
	ingester := &fakeIngester{}

	id, err := Apply(context.Background(), ingester, Decision{
		CVEID:    record.ID,
		ActorID:  uuid.New(),
		Packages: []Package{{Ecosystem: "Maven", Name: "org.apache.tomcat:tomcat-catalina"}},
	}, record)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if id == uuid.Nil {
		t.Error("Apply returned no advisory id")
	}
	if ingester.provider != SourceTriage {
		t.Errorf("ingested under %q, want %q", ingester.provider, SourceTriage)
	}
}

// A record with no usable ranges must not author an empty advisory — that would
// be a finding with nothing behind it.
func TestBuildRefusesRecordWithoutRanges(t *testing.T) {
	record := loadRecord(t, "CVE-2026-59084.json")
	record.Affected = nil

	if _, err := BuildIngestResult(Decision{
		CVEID:    record.ID,
		ActorID:  uuid.New(),
		Packages: []Package{{Ecosystem: "Maven", Name: "g:a"}},
	}, record); err == nil {
		t.Fatal("authored an advisory with no ranges")
	}
}

func TestDiffRangesDetectsWidening(t *testing.T) {
	before := loadRecord(t, "CVE-2026-59084.json")
	after := loadRecord(t, "CVE-2026-59084.json")

	// The 9.0 branch is widened backwards, the shape that can newly implicate a
	// version somebody runs without any code changing.
	for i := range after.Affected[0].Ranges {
		if after.Affected[0].Ranges[i].Introduced == "9.0.13" {
			after.Affected[0].Ranges[i].LastAffected = "9.0.130"
		}
	}

	deltas := DiffRanges(before, after)
	if len(deltas) != 1 {
		t.Fatalf("deltas = %+v, want exactly the changed branch", deltas)
	}
	if !deltas[0].Widened {
		t.Errorf("a later upper bound was not flagged as widening: %+v", deltas[0])
	}
	if deltas[0].Before == "" || deltas[0].After == "" {
		t.Errorf("delta %+v does not show what moved", deltas[0])
	}

	// An unchanged record produces no noise.
	if unchanged := DiffRanges(before, before); len(unchanged) != 0 {
		t.Errorf("identical records produced %+v", unchanged)
	}
}

func TestNeedsReview(t *testing.T) {
	triaged := loadRecord(t, "CVE-2026-59084.json")
	revised := loadRecord(t, "CVE-2026-59084.json")
	revised.Updated = triaged.Updated.Add(time.Hour)

	if !NeedsReview(revised, &triaged) {
		t.Error("a revised record did not re-open review")
	}
	if NeedsReview(triaged, &triaged) {
		t.Error("an unchanged record re-opened review")
	}
	if NeedsReview(revised, nil) {
		t.Error("an untriaged record re-opened review")
	}
}
