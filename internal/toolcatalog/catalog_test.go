package toolcatalog

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

type fakeStore struct {
	findings []FindingToolStat
	runs     []ProducerRunStat
}

func (f fakeStore) ListAdvisoryProviderStats(context.Context, uuid.UUID) ([]AdvisoryProviderStat, error) {
	return nil, nil
}
func (f fakeStore) ListFindingToolStats(context.Context, uuid.UUID) ([]FindingToolStat, error) {
	return f.findings, nil
}
func (f fakeStore) ListProducerRunToolStats(context.Context, uuid.UUID) ([]ProducerRunStat, error) {
	return f.runs, nil
}
func (f fakeStore) ListVEXSourceStats(context.Context, uuid.UUID) ([]VEXSourceStat, error) {
	return nil, nil
}
func (f fakeStore) ListComponentEcosystemStats(context.Context, uuid.UUID) ([]ComponentEcosystemStat, error) {
	return nil, nil
}
func (f fakeStore) ListCoverageSnapshotStats(context.Context, uuid.UUID) ([]CoverageSnapshotStat, error) {
	return nil, nil
}

func TestCatalogProducerHealth(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	recent := now.Add(-time.Hour)
	service := NewService(fakeStore{
		runs: []ProducerRunStat{
			{Producer: "gosec", LastRunAt: recent, LastOutcome: "completed", RunCount: 4, RepoCount: 2},
			{Producer: "opengrep oss", LastRunAt: recent, LastOutcome: "partial"},
			{Producer: "codeql", LastRunAt: recent, LastOutcome: "failed", LastError: "out of memory"},
			{Producer: "secret-scanning", LastRunAt: recent, LastOutcome: "completed"},
		},
		findings: []FindingToolStat{
			{Tool: "gosec", LastSeenAt: recent, FindingCount: 9},                // has runs: not duplicated
			{Tool: "Bandit", LastSeenAt: recent, FindingCount: 3, RepoCount: 1}, // legacy upload
		},
	})
	service.now = func() time.Time { return now }
	catalog, err := service.Catalog(context.Background(), uuid.New(), "org")
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]ToolEntry{}
	for _, tool := range catalog.Tools {
		if _, dup := byName[tool.Name]; dup {
			t.Fatalf("duplicate entry %s", tool.Name)
		}
		byName[tool.Name] = tool
	}
	if got := byName["gosec"]; got.Status != StatusHealthy || got.DataPoints != 4 || got.Warning != "" {
		t.Fatalf("gosec = %+v", got)
	}
	if got := byName["opengrep oss"]; got.Status != StatusDegraded || got.Warning == "" {
		t.Fatalf("opengrep = %+v", got)
	}
	if got := byName["codeql"]; got.Status != StatusUnhealthy || got.LastError != "out of memory" {
		t.Fatalf("codeql = %+v", got)
	}
	if got := byName["secret-scanning"]; got.Category != CategorySecretScanning {
		t.Fatalf("secret scanning = %+v", got)
	}
	// The pre-fix bug: finding-only tools showed inactive for lack of a last-seen time.
	if got := byName["bandit"]; got.Status != StatusHealthy || got.RepoCount != 1 {
		t.Fatalf("bandit = %+v", got)
	}
}
