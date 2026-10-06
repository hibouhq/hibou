package delta

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	storepkg "github.com/hibouhq/hibou/internal/store"
)

// kevTestStore wraps the mock with a canned KEV catalog, the way the real
// store answers from the local kev_entries mirror.
type kevTestStore struct {
	*mockStore
	listedAdvisories map[uuid.UUID]struct{}
	listedIDs        map[string]struct{}
	err              error
}

func (m *kevTestStore) FilterKEVAdvisoryIDs(_ context.Context, advisoryIDs []uuid.UUID) ([]uuid.UUID, error) {
	if m.err != nil {
		return nil, m.err
	}
	hits := []uuid.UUID{}
	for _, id := range advisoryIDs {
		if _, ok := m.listedAdvisories[id]; ok {
			hits = append(hits, id)
		}
	}
	return hits, nil
}

func (m *kevTestStore) FilterKEVIdentifiers(_ context.Context, identifiers []string) ([]string, error) {
	if m.err != nil {
		return nil, m.err
	}
	hits := []string{}
	for _, id := range identifiers {
		if _, ok := m.listedIDs[id]; ok {
			hits = append(hits, id)
		}
	}
	return hits, nil
}

func TestEvaluateGatesKEVBlocksUnconditionally(t *testing.T) {
	advisoryID := uuid.New()
	mock := &kevTestStore{
		mockStore:        newMockStore(),
		listedAdvisories: map[uuid.UUID]struct{}{advisoryID: {}},
	}
	service := NewService(mock, zerolog.Nop())
	component := "log4j-core"
	version := "2.14.1"
	deltaResult := &DeltaResult{New: []storepkg.Vulnerability{
		{
			Type: "dependency", Severity: storepkg.SeverityLevelMedium,
			AdvisoryID: &advisoryID, PrimaryIdentifierValue: "GHSA-jfh8-c2jp-5v3q",
			ComponentName: &component, ComponentVersion: &version,
		},
		// Not listed: must not appear in the reason.
		{Type: "dependency", Severity: storepkg.SeverityLevelCritical, PrimaryIdentifierValue: "CVE-2026-0001"},
	}}

	// No gate sections configured at all — KEV still blocks, like malware.
	gate, err := service.EvaluateGatesWithConfig(context.Background(), uuid.New(), uuid.New(), deltaResult, nil)
	if err != nil {
		t.Fatal(err)
	}
	if gate.Passed {
		t.Fatalf("gate = %+v, want failed on the KEV-listed finding", gate)
	}
	if len(gate.Reasons) != 1 || !strings.Contains(gate.Reasons[0], "KEV catalog") || !strings.Contains(gate.Reasons[0], "log4j-core@2.14.1") {
		t.Fatalf("reasons = %v, want one KEV reason naming log4j-core@2.14.1", gate.Reasons)
	}
	if strings.Contains(gate.Reasons[0], "CVE-2026-0001") {
		t.Fatalf("reason %q names an unlisted finding", gate.Reasons[0])
	}
}

func TestEvaluateGatesKEVMatchesByIdentifierWithoutAdvisory(t *testing.T) {
	mock := &kevTestStore{
		mockStore: newMockStore(),
		listedIDs: map[string]struct{}{"CVE-2021-44228": {}},
	}
	service := NewService(mock, zerolog.Nop())
	deltaResult := &DeltaResult{New: []storepkg.Vulnerability{
		// Lowercase on purpose: the lookup normalizes before matching.
		{Type: "dependency", Severity: storepkg.SeverityLevelHigh, PrimaryIdentifierValue: "cve-2021-44228"},
	}}

	gate, err := service.EvaluateGatesWithConfig(context.Background(), uuid.New(), uuid.New(), deltaResult, nil)
	if err != nil {
		t.Fatal(err)
	}
	if gate.Passed || len(gate.Reasons) != 1 {
		t.Fatalf("gate = %+v, want one KEV failure", gate)
	}
}

func TestEvaluateGatesKEVBlocksContainerFindings(t *testing.T) {
	// A KEV-listed CVE in a base image is exactly as exploited as the same CVE
	// in a manifest — and the finding drawer renders both with the same "the
	// gate blocks this" wording, so the gate must deliver.
	mock := &kevTestStore{
		mockStore: newMockStore(),
		listedIDs: map[string]struct{}{"CVE-2024-21626": {}},
	}
	service := NewService(mock, zerolog.Nop())
	deltaResult := &DeltaResult{New: []storepkg.Vulnerability{
		{Type: "container", Severity: storepkg.SeverityLevelHigh, PrimaryIdentifierValue: "CVE-2024-21626"},
	}}

	gate, err := service.EvaluateGatesWithConfig(context.Background(), uuid.New(), uuid.New(), deltaResult, nil)
	if err != nil {
		t.Fatal(err)
	}
	if gate.Passed || len(gate.Reasons) != 1 {
		t.Fatalf("gate = %+v, want one KEV failure for the container finding", gate)
	}
}

func TestEvaluateGatesKEVIgnoresNonDependencyFindings(t *testing.T) {
	mock := &kevTestStore{
		mockStore: newMockStore(),
		listedIDs: map[string]struct{}{"CVE-2021-44228": {}},
	}
	service := NewService(mock, zerolog.Nop())
	deltaResult := &DeltaResult{New: []storepkg.Vulnerability{
		// A SAST finding can share an identifier string; no advisory stands
		// behind it, so KEV must not block on it.
		{Type: "sast", Severity: storepkg.SeverityLevelHigh, PrimaryIdentifierValue: "CVE-2021-44228"},
	}}

	gate, err := service.EvaluateGatesWithConfig(context.Background(), uuid.New(), uuid.New(), deltaResult, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !gate.Passed {
		t.Fatalf("gate = %+v, want passed", gate)
	}
}

func TestEvaluateGatesKEVLookupErrorFailsClosed(t *testing.T) {
	mock := &kevTestStore{
		mockStore: newMockStore(),
		err:       errors.New("kev table unreachable"),
	}
	service := NewService(mock, zerolog.Nop())
	deltaResult := &DeltaResult{New: []storepkg.Vulnerability{
		{Type: "dependency", Severity: storepkg.SeverityLevelLow, PrimaryIdentifierValue: "CVE-2026-1234"},
	}}

	if _, err := service.EvaluateGatesWithConfig(context.Background(), uuid.New(), uuid.New(), deltaResult, nil); err == nil {
		t.Fatal("a KEV lookup error must fail the evaluation, not pass the gate")
	}
}

func TestEvaluateGatesWithoutKEVStoreStillEvaluates(t *testing.T) {
	// The plain mock does not implement kevLister: the block is skipped, other
	// gating is untouched.
	service := NewService(newMockStore(), zerolog.Nop())
	deltaResult := &DeltaResult{New: []storepkg.Vulnerability{
		{Type: "dependency", Severity: storepkg.SeverityLevelHigh, PrimaryIdentifierValue: "CVE-2021-44228"},
	}}

	gate, err := service.EvaluateGatesWithConfig(context.Background(), uuid.New(), uuid.New(), deltaResult, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !gate.Passed {
		t.Fatalf("gate = %+v, want passed when the store cannot answer KEV", gate)
	}
}
