package cvetriage

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

func pkgs(pairs ...string) []Package {
	out := make([]Package, 0, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, Package{Ecosystem: pairs[i], Name: pairs[i+1]})
	}
	return out
}

// The asymmetry is the decision this whole comparison exists to encode: upstream
// saying MORE than us is safe to adopt, upstream saying LESS is a question,
// because adopting a narrower set retires findings nobody chose to retire.
func TestCompareCoordinatesIsAsymmetric(t *testing.T) {
	cases := []struct {
		name     string
		ours     []Package
		upstream []Package
		want     DivergenceVerdict
	}{
		{
			name:     "upstream adds a package we missed",
			ours:     pkgs("maven", "org.apache.tomcat:tomcat-catalina"),
			upstream: pkgs("maven", "org.apache.tomcat:tomcat-catalina", "maven", "org.apache.tomcat:tomcat"),
			want:     VerdictSuperseded,
		},
		{
			name:     "upstream drops a package we named",
			ours:     pkgs("maven", "org.apache.tomcat:tomcat-catalina", "maven", "org.apache.tomcat:tomcat"),
			upstream: pkgs("maven", "org.apache.tomcat:tomcat"),
			want:     VerdictDiverged,
		},
		{
			name:     "upstream both adds and drops",
			ours:     pkgs("maven", "a:a"),
			upstream: pkgs("maven", "b:b"),
			want:     VerdictDiverged,
		},
		{
			name:     "identical sets",
			ours:     pkgs("npm", "left-pad"),
			upstream: pkgs("npm", "left-pad"),
			want:     VerdictAgrees,
		},
		{
			name:     "upstream still names nothing",
			ours:     pkgs("maven", "a:a"),
			upstream: nil,
			want:     VerdictNoUpstream,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := CompareCoordinates(testCase.ours, testCase.upstream)
			if got.Verdict != testCase.want {
				t.Errorf("verdict = %q, want %q (%s)", got.Verdict, testCase.want, got.Summary())
			}
		})
	}
}

// A set that is broader in one place and narrower in another is still a
// question: the packages it drops are findings that would disappear, and being
// generous elsewhere does not make that safe.
func TestCompareCoordinatesTreatsAnyContractionAsDivergence(t *testing.T) {
	got := CompareCoordinates(
		pkgs("maven", "keep:me", "maven", "drop:me"),
		pkgs("maven", "keep:me", "maven", "add:me"),
	)
	if got.Verdict != VerdictDiverged {
		t.Fatalf("verdict = %q, want diverged", got.Verdict)
	}
	if len(got.Extra) != 1 || got.Extra[0] != "maven:drop:me" {
		t.Errorf("Extra = %v, want the dropped package", got.Extra)
	}
	if len(got.Missing) != 1 || got.Missing[0] != "maven:add:me" {
		t.Errorf("Missing = %v, want the added package", got.Missing)
	}
}

// Coordinates are compared by identity, not by spelling: OSV writes "Maven"
// where a mapping may say "maven", and a comparison that diverged on case would
// raise a question about every mapping on every pass.
func TestCompareCoordinatesIgnoresCaseAndSurroundingSpace(t *testing.T) {
	got := CompareCoordinates(
		pkgs("Maven", " org.apache.tomcat:tomcat "),
		pkgs("maven", "org.apache.tomcat:tomcat"),
	)
	if got.Verdict != VerdictAgrees {
		t.Fatalf("verdict = %q, want agrees (%s)", got.Verdict, got.Summary())
	}
}

type fakeDivergenceStore struct {
	rows   []dbgen.ListMappedCVEsForDivergenceCheckRow
	events []store.AdvisoryEvent
}

func (f *fakeDivergenceStore) ListMappedCVEsForDivergenceCheck(context.Context, int32) ([]dbgen.ListMappedCVEsForDivergenceCheckRow, error) {
	return f.rows, nil
}

func (f *fakeDivergenceStore) RecordAdvisoryEvent(_ context.Context, event store.AdvisoryEvent) error {
	f.events = append(f.events, event)
	return nil
}

type fakeUpstream struct {
	byCVE map[string][]Package
	fail  map[string]bool
}

func (f *fakeUpstream) PackagesFor(_ context.Context, cveID string) ([]Package, error) {
	if f.fail[cveID] {
		return nil, errors.New("upstream unreachable")
	}
	return f.byCVE[cveID], nil
}

func mappedRow(t *testing.T, cveID string, packages []Package) dbgen.ListMappedCVEsForDivergenceCheckRow {
	t.Helper()
	encoded, err := json.Marshal(packages)
	if err != nil {
		t.Fatal(err)
	}
	return dbgen.ListMappedCVEsForDivergenceCheckRow{
		CveID: cveID, MappingID: uuid.New(), Packages: encoded,
	}
}

func TestCheckDivergenceRecordsOnlyTheVerdictsWorthReading(t *testing.T) {
	divergenceStore := &fakeDivergenceStore{rows: []dbgen.ListMappedCVEsForDivergenceCheckRow{
		mappedRow(t, "CVE-1", pkgs("maven", "a:a")),                 // superseded
		mappedRow(t, "CVE-2", pkgs("maven", "b:b", "maven", "c:c")), // diverged
		mappedRow(t, "CVE-3", pkgs("maven", "d:d")),                 // agrees
		mappedRow(t, "CVE-4", pkgs("maven", "e:e")),                 // no upstream
	}}
	upstream := &fakeUpstream{byCVE: map[string][]Package{
		"CVE-1": pkgs("maven", "a:a", "maven", "a2:a2"),
		"CVE-2": pkgs("maven", "b:b"),
		"CVE-3": pkgs("maven", "d:d"),
	}}

	result, err := CheckDivergence(context.Background(), divergenceStore, upstream)
	if err != nil {
		t.Fatalf("CheckDivergence: %v", err)
	}
	if result.Superseded != 1 || result.Diverged != 1 || result.NoUpstream != 1 {
		t.Fatalf("got %+v, want 1 superseded, 1 diverged, 1 no-upstream", result)
	}
	// Agreement is deliberately silent: an event per unchanged mapping per pass
	// would bury the two that need reading.
	if len(divergenceStore.events) != 2 {
		t.Fatalf("recorded %d events, want only superseded and diverged", len(divergenceStore.events))
	}
	kinds := map[store.AdvisoryEventKind]bool{}
	for _, event := range divergenceStore.events {
		kinds[event.Kind] = true
		if len(event.Detail) == 0 {
			t.Errorf("%s event carries no detail, so a reviewer cannot see what moved", event.Kind)
		}
	}
	if !kinds[store.EventSuperseded] || !kinds[store.EventDiverged] {
		t.Errorf("kinds = %v, want both", kinds)
	}
}

// An unreachable upstream must not read as "upstream names nothing". Counting a
// failed lookup as a comparison would diverge every mapping whenever the network
// blipped — and a diverged event asks a person to adjudicate.
func TestCheckDivergenceDoesNotTreatALookupFailureAsAVerdict(t *testing.T) {
	divergenceStore := &fakeDivergenceStore{rows: []dbgen.ListMappedCVEsForDivergenceCheckRow{
		mappedRow(t, "CVE-1", pkgs("maven", "a:a")),
	}}
	upstream := &fakeUpstream{fail: map[string]bool{"CVE-1": true}}

	result, err := CheckDivergence(context.Background(), divergenceStore, upstream)
	if err != nil {
		t.Fatalf("CheckDivergence: %v", err)
	}
	if result.Failed != 1 || result.Checked != 0 || result.Diverged != 0 {
		t.Fatalf("got %+v, want the lookup counted as failed only", result)
	}
	if len(divergenceStore.events) != 0 {
		t.Fatalf("recorded %d events from a failed lookup", len(divergenceStore.events))
	}
}

// No upstream configured is not a failure; there is simply nothing to compare.
func TestCheckDivergenceWithoutAnUpstreamIsANoop(t *testing.T) {
	result, err := CheckDivergence(context.Background(), &fakeDivergenceStore{}, nil)
	if err != nil {
		t.Fatalf("CheckDivergence: %v", err)
	}
	if result != (DivergenceResult{}) {
		t.Fatalf("got %+v, want a zero result", result)
	}
}
