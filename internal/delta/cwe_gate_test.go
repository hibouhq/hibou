package delta

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/cwe"
	storepkg "github.com/hibouhq/hibou/internal/store"
)

// cweMockStore answers ListFindingCWEs from a fixed map (or fails).
type cweMockStore struct {
	*mockStore
	cwes map[uuid.UUID][]int
	err  error
}

func (m *cweMockStore) ListFindingCWEs(_ context.Context, ids []uuid.UUID) (map[uuid.UUID][]storepkg.FindingCWE, error) {
	if m.err != nil {
		return nil, m.err
	}
	out := map[uuid.UUID][]storepkg.FindingCWE{}
	for _, id := range ids {
		for _, cweID := range m.cwes[id] {
			out[id] = append(out[id], storepkg.FindingCWE{ID: cweID})
		}
	}
	return out, nil
}

func mustRule(t *testing.T, path, kind, value string) CWERule {
	t.Helper()
	selector, err := cwe.ParseSelector(kind, []string{value})
	if err != nil {
		t.Fatal(err)
	}
	return CWERule{Path: path, Selector: selector}
}

func strPtr(value string) *string { return &value }
func i32Ptr(value int32) *int32   { return &value }

func TestCWEGateDeniesAcrossFindingTypes(t *testing.T) {
	sast := storepkg.Vulnerability{ID: uuid.New(), Type: "sast", Severity: storepkg.SeverityLevelHigh, PrimaryIdentifierValue: "G201", FilePath: strPtr("db/query.go"), StartLine: i32Ptr(42)}
	dependency := storepkg.Vulnerability{ID: uuid.New(), Type: "dependency", Severity: storepkg.SeverityLevelMedium, PrimaryIdentifierValue: "CVE-2020-11022"}
	lowSAST := storepkg.Vulnerability{ID: uuid.New(), Type: "sast", Severity: storepkg.SeverityLevelLow, PrimaryIdentifierValue: "G202"}
	clean := storepkg.Vulnerability{ID: uuid.New(), Type: "sast", Severity: storepkg.SeverityLevelHigh, PrimaryIdentifierValue: "G101"}
	store := &cweMockStore{mockStore: newMockStore(), cwes: map[uuid.UUID][]int{
		sast.ID: {89}, dependency.ID: {79}, lowSAST.ID: {89}, clean.ID: {798},
	}}
	service := NewService(store, zerolog.Nop())

	gate := &CWEGate{
		Rules:       []CWERule{mustRule(t, "cwe.deny_tree CWE-74", cwe.KindTree, "74")},
		MinSeverity: "medium",
	}
	result, err := service.EvaluateGatesWithConfig(context.Background(), uuid.New(), uuid.New(), &DeltaResult{
		New: []storepkg.Vulnerability{sast, dependency, lowSAST, clean},
	}, &GateConfig{CWE: gate})
	if err != nil {
		t.Fatalf("EvaluateGatesWithConfig: %v", err)
	}
	if result.Passed || len(result.Reasons) != 2 {
		t.Fatalf("want the SAST injection and the dependency XSS denied (low severity skipped, CWE-798 allowed), got %#v", result.Reasons)
	}
	if !strings.Contains(result.Reasons[0], "G201 in db/query.go:42 carries CWE-89 (Improper Neutralization of Special Elements used in an SQL Command") ||
		!strings.Contains(result.Reasons[0], "denied by cwe.deny_tree CWE-74") {
		t.Fatalf("reason must name the CWE by title and the rule: %q", result.Reasons[0])
	}

	// types narrows the scope.
	gate.Types = []string{"dependency"}
	result, err = service.EvaluateGatesWithConfig(context.Background(), uuid.New(), uuid.New(), &DeltaResult{
		New: []storepkg.Vulnerability{sast, dependency},
	}, &GateConfig{CWE: gate})
	if err != nil || len(result.Reasons) != 1 || !strings.Contains(result.Reasons[0], "CVE-2020-11022") {
		t.Fatalf("types: dependency only, got %#v, %v", result, err)
	}
}

// A CWE gate must never fail open: a lookup error, a store that cannot
// resolve CWEs, and an uncompilable policy all fail the evaluation.
func TestCWEGateFailsClosed(t *testing.T) {
	finding := storepkg.Vulnerability{ID: uuid.New(), Type: "sast", Severity: storepkg.SeverityLevelHigh}
	gate := &CWEGate{Rules: []CWERule{mustRule(t, "cwe.deny CWE-89", cwe.KindExact, "89")}}
	run := func(store DeltaStore, gate *CWEGate) error {
		_, err := NewService(store, zerolog.Nop()).EvaluateGatesWithConfig(context.Background(), uuid.New(), uuid.New(),
			&DeltaResult{New: []storepkg.Vulnerability{finding}}, &GateConfig{CWE: gate})
		return err
	}
	if err := run(&cweMockStore{mockStore: newMockStore(), err: errors.New("db down")}, gate); err == nil {
		t.Error("lookup error passed the gate")
	}
	if err := run(newMockStore(), gate); err == nil {
		t.Error("store without CWE lookup passed the gate")
	}
	if err := run(&cweMockStore{mockStore: newMockStore()}, &CWEGate{Invalid: errors.New("bad selector")}); err == nil {
		t.Error("invalid policy passed the gate")
	}
}

// ADR-037 §8: the code section counts code findings only. A new critical
// dependency CVE or leaked secret belongs to its own section and must not
// trip the code thresholds as well.
func TestCodeGateCountsOnlyCodeFindings(t *testing.T) {
	service := NewService(newMockStore(), zerolog.Nop())
	gate := &GateConfig{Code: &CodeGate{MaxCritical: intPtr(0)}}
	result, err := service.EvaluateGatesWithConfig(context.Background(), uuid.New(), uuid.New(), &DeltaResult{
		New: []storepkg.Vulnerability{
			{Type: "dependency", Severity: storepkg.SeverityLevelCritical},
			{Type: "secret", Severity: storepkg.SeverityLevelCritical},
		},
	}, gate)
	if err != nil || !result.Passed {
		t.Fatalf("dependency/secret findings must not count against code thresholds: %#v, %v", result, err)
	}
	result, err = service.EvaluateGatesWithConfig(context.Background(), uuid.New(), uuid.New(), &DeltaResult{
		New: []storepkg.Vulnerability{{Type: "manual", Severity: storepkg.SeverityLevelCritical}},
	}, gate)
	if err != nil || result.Passed || !strings.Contains(result.Reasons[0], "max critical code findings") {
		t.Fatalf("a manual finding is code: %#v, %v", result, err)
	}
}
