package delta

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/presence"
	storepkg "github.com/hibouhq/hibou/internal/store"
)

type coverageMockStore struct {
	*mockStore
	runs  map[uuid.UUID][]storepkg.ProducerRun
	known map[uuid.UUID]bool
}

func (m *coverageMockStore) SnapshotProducerRuns(_ context.Context, snapshotID uuid.UUID) ([]storepkg.ProducerRun, error) {
	return m.runs[snapshotID], nil
}

func (m *coverageMockStore) SnapshotCoverageKnown(_ context.Context, snapshotID uuid.UUID) (bool, error) {
	known, ok := m.known[snapshotID]
	return known || !ok, nil
}

func located(scanner, fingerprint, file string) storepkg.Vulnerability {
	return storepkg.Vulnerability{Type: "sast", ScannerName: scanner, Fingerprint: fingerprint, FilePath: &file, Status: "detected", Origin: "scanner", Presence: storepkg.PresenceReported}
}

// A PR build that did not run gosec, or ran a partial scan, must not claim
// to fix the base's findings (ADR-034 §6).
func TestComputeDeltaNotRechecked(t *testing.T) {
	base := newMockStore()
	store := &coverageMockStore{mockStore: base, runs: map[uuid.UUID][]storepkg.ProducerRun{}, known: map[uuid.UUID]bool{}}
	pr, target := uuid.New(), uuid.New()
	carried := located("trivy", "carried", "Dockerfile")
	carried.Presence = storepkg.PresenceNotRechecked
	base.vulnsBySnapshot[target] = []storepkg.Vulnerability{
		located("gosec", "gosec-missing", "a.go"),
		located("opengrep oss", "outside-scope", "lib/x.go"),
		located("opengrep oss", "fixed", "src/y.go"),
		located("trivy", "carried", "Dockerfile"),
		{Type: "manual", Fingerprint: "assertion", Status: "detected", Origin: "agent", Presence: storepkg.PresenceReported},
	}
	base.vulnsBySnapshot[pr] = []storepkg.Vulnerability{carried}
	store.runs[pr] = []storepkg.ProducerRun{
		{Producer: "opengrep oss", Outcome: storepkg.ProducerOutcomePartial, Scope: storepkg.ProducerScopePartial, ScopePaths: []string{"src/"}},
	}

	result, err := NewService(store, zerolog.Nop()).ComputeDelta(context.Background(), pr, target)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Resolved) != 1 || result.Resolved[0].Fingerprint != "fixed" {
		t.Fatalf("resolved = %+v", result.Resolved)
	}
	reasons := map[string]string{}
	for _, vuln := range result.NotRechecked {
		reason := ""
		if vuln.PresenceReason != nil {
			reason = *vuln.PresenceReason
		}
		reasons[vuln.Fingerprint] = reason
	}
	want := map[string]string{"gosec-missing": "producer_missing", "outside-scope": "outside_scope", "carried": "", "assertion": "assertion"}
	if len(reasons) != len(want) {
		t.Fatalf("not rechecked = %v", reasons)
	}
	for fingerprint, reason := range want {
		if got, ok := reasons[fingerprint]; !ok || got != reason {
			t.Errorf("%s: reason %q (present %v), want %q", fingerprint, got, ok, reason)
		}
	}
	if result.Unchanged != 1 {
		t.Fatalf("carried row is still present: unchanged = %d", result.Unchanged)
	}
}

// A snapshot processed before runs were recorded keeps the old reading.
func TestComputeDeltaLegacyCoverage(t *testing.T) {
	base := newMockStore()
	store := &coverageMockStore{mockStore: base, runs: map[uuid.UUID][]storepkg.ProducerRun{}, known: map[uuid.UUID]bool{}}
	pr, target := uuid.New(), uuid.New()
	base.vulnsBySnapshot[target] = []storepkg.Vulnerability{located("gosec", "gone", "a.go")}
	store.known[pr] = false
	result, err := NewService(store, zerolog.Nop()).ComputeDelta(context.Background(), pr, target)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Resolved) != 1 || len(result.NotRechecked) != 0 {
		t.Fatalf("legacy snapshot: resolved=%d notRechecked=%d", len(result.Resolved), len(result.NotRechecked))
	}
}

// The PR's scanner covered the file but the PR did not touch it: the finding
// is unconfirmed and stays on the base side; a scanner upgrade is no fix.
func TestComputeDeltaUnconfirmedAndProducerChange(t *testing.T) {
	base := newMockStore()
	store := &coverageMockStore{mockStore: base, runs: map[uuid.UUID][]storepkg.ProducerRun{}, known: map[uuid.UUID]bool{}}
	pr, target := uuid.New(), uuid.New()
	base.snapshots[target] = &storepkg.Snapshot{ID: target, CommitSHA: "base-sha"}
	base.vulnsBySnapshot[target] = []storepkg.Vulnerability{
		located("gosec", "untouched", "same.go"),
		located("gosec", "edited", "edited.go"),
		located("trivy", "upgraded", "Dockerfile"),
	}
	v1, v2 := "0.59.0", "0.60.0"
	store.runs[target] = []storepkg.ProducerRun{{Producer: "trivy", Outcome: "completed", Scope: "full", Version: &v1}}
	store.runs[pr] = []storepkg.ProducerRun{
		{Producer: "gosec", Outcome: "completed", Scope: "full"},
		{Producer: "trivy", Outcome: "completed", Scope: "full", Version: &v2},
	}
	service := NewService(store, zerolog.Nop())
	service.SetPresenceOptions(func(context.Context, uuid.UUID) (presence.Options, error) {
		return presence.Options{Changed: func(base, path string) presence.Change {
			if base != "base-sha" {
				t.Errorf("change base = %q", base)
			}
			return presence.Change{Known: true, Changed: path == "edited.go"}
		}}, nil
	})
	result, err := service.ComputeDelta(context.Background(), pr, target)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.NotRechecked) != 1 || result.NotRechecked[0].Fingerprint != "untouched" || result.NotRechecked[0].Presence != storepkg.PresenceUnconfirmed {
		t.Fatalf("not rechecked = %+v", result.NotRechecked)
	}
	reasons := map[string]string{}
	for _, vuln := range result.Resolved {
		reasons[vuln.Fingerprint] = *vuln.ResolutionReason
	}
	if reasons["edited"] != presence.ResolvedFixed || reasons["upgraded"] != presence.ResolvedProducerChanged || len(reasons) != 2 {
		t.Fatalf("resolved = %v", reasons)
	}
}
