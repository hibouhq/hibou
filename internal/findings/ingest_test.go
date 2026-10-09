package findings

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type mockIngestStore struct {
	vulnerabilities []*store.Vulnerability
	err             error
	seen            map[string]bool
	rules           map[string]uuid.UUID
	ruleCWECalls    map[uuid.UUID]int
	syncCalls       int
	upserts         int
	ruleCWEs        map[uuid.UUID][]int
	resultCWEs      map[string][]int
	resultPrints    []string
}

func (m *mockIngestStore) SyncScanRuleCWEs(_ context.Context, byRule map[uuid.UUID][]int) error {
	if m.ruleCWEs == nil {
		m.ruleCWEs = map[uuid.UUID][]int{}
		m.ruleCWECalls = map[uuid.UUID]int{}
	}
	m.syncCalls++
	for ruleID, ids := range byRule {
		m.ruleCWEs[ruleID] = ids
		m.ruleCWECalls[ruleID]++
	}
	return nil
}

func (m *mockIngestStore) ReplaceSnapshotSARIFResultCWEs(_ context.Context, _ uuid.UUID, fingerprints []string, cwes map[string][]int) error {
	m.resultPrints = fingerprints
	m.resultCWEs = cwes
	return nil
}

func (m *mockIngestStore) UpsertScanRule(_ context.Context, params dbgen.UpsertScanRuleParams) (uuid.UUID, error) {
	m.upserts++
	if m.rules == nil {
		m.rules = map[string]uuid.UUID{}
	}
	key := params.Tool + "\x00" + params.RuleID
	if id, ok := m.rules[key]; ok {
		return id, nil
	}
	id := uuid.New()
	m.rules[key] = id
	return id, nil
}

func (m *mockIngestStore) CreateVulnerability(_ context.Context, params dbgen.CreateVulnerabilityParams) (*store.Vulnerability, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.seen == nil {
		m.seen = map[string]bool{}
	}
	if m.seen[params.Fingerprint] {
		for _, vulnerability := range m.vulnerabilities {
			if vulnerability.Fingerprint == params.Fingerprint {
				return vulnerability, nil
			}
		}
	}
	m.seen[params.Fingerprint] = true
	vulnerability := &store.Vulnerability{
		ID:          uuid.New(),
		SnapshotID:  params.SnapshotID,
		Type:        params.Type,
		Title:       params.Title,
		Severity:    params.Severity,
		Status:      params.Status,
		Fingerprint: params.Fingerprint,
		ScannerName: params.ScannerName,
		Metadata:    params.Metadata,
	}
	if params.FilePath.Valid {
		vulnerability.FilePath = &params.FilePath.String
	}
	if params.LocationHash.Valid {
		vulnerability.LocationHash = &params.LocationHash.String
	}
	m.vulnerabilities = append(m.vulnerabilities, vulnerability)
	return vulnerability, nil
}

func TestIngestCreatesFindingsAndComputesFingerprint(t *testing.T) {
	snapshotID := uuid.New()
	store := &mockIngestStore{}
	ingester := NewIngester(store, zerolog.Nop())

	count, err := ingester.Ingest(context.Background(), snapshotID, []GenericFinding{{
		Tool:      "semgrep",
		RuleID:    "rule-1",
		Severity:  "high",
		FilePath:  "main.go",
		StartLine: 10,
		EndLine:   11,
		Message:   "Issue",
		Rule:      &ScanRuleInput{Name: "Test rule", HelpURI: "https://example.com/rule-1", CWEs: []int{798}},
	}})
	if err != nil {
		t.Fatalf("Ingest returned error: %v", err)
	}
	if count != 1 || len(store.vulnerabilities) != 1 {
		t.Fatalf("expected 1 created vulnerability, got count=%d len=%d", count, len(store.vulnerabilities))
	}
	if len(store.rules) != 1 {
		t.Fatalf("expected rule to be upserted once into the catalog, got %d", len(store.rules))
	}
	for _, ruleID := range store.rules {
		if got := store.ruleCWEs[ruleID]; len(got) != 1 || got[0] != 798 {
			t.Fatalf("rule CWEs = %v, want [798]", got)
		}
	}
	if store.vulnerabilities[0].LocationHash == nil || store.vulnerabilities[0].Fingerprint != *store.vulnerabilities[0].LocationHash {
		t.Fatalf("expected fingerprint to default to location hash, got fingerprint=%q location_hash=%#v", store.vulnerabilities[0].Fingerprint, store.vulnerabilities[0].LocationHash)
	}
}

func TestIngestPreservesProducerFingerprint(t *testing.T) {
	snapshotID := uuid.New()
	store := &mockIngestStore{}
	ingester := NewIngester(store, zerolog.Nop())

	count, err := ingester.Ingest(context.Background(), snapshotID, []GenericFinding{{
		Tool:        "semgrep",
		RuleID:      "rule-1",
		Severity:    "high",
		FilePath:    "main.go",
		StartLine:   10,
		EndLine:     11,
		Message:     "Issue",
		Fingerprint: "producer-stable",
	}})
	if err != nil {
		t.Fatalf("Ingest returned error: %v", err)
	}
	if count != 1 || len(store.vulnerabilities) != 1 {
		t.Fatalf("expected 1 created vulnerability, got count=%d len=%d", count, len(store.vulnerabilities))
	}
	vulnerability := store.vulnerabilities[0]
	if vulnerability.Fingerprint != "producer-stable" {
		t.Fatalf("expected producer fingerprint, got %q", vulnerability.Fingerprint)
	}
	if vulnerability.LocationHash == nil || *vulnerability.LocationHash == "" {
		t.Fatal("expected location hash to remain populated")
	}
	if vulnerability.LocationHash != nil && *vulnerability.LocationHash == vulnerability.Fingerprint {
		t.Fatalf("expected location hash to stay separate from fingerprint, got %q", *vulnerability.LocationHash)
	}
}

func TestIngestSkipsDuplicates(t *testing.T) {
	snapshotID := uuid.New()
	store := &mockIngestStore{}
	ingester := NewIngester(store, zerolog.Nop())
	findings := []GenericFinding{{Tool: "semgrep", RuleID: "rule-1", Severity: "low", FilePath: "main.go", StartLine: 1, EndLine: 1, Message: "Issue"}, {Tool: "semgrep", RuleID: "rule-1", Severity: "low", FilePath: "main.go", StartLine: 1, EndLine: 1, Message: "Issue"}}

	count, err := ingester.Ingest(context.Background(), snapshotID, findings)
	if err != nil {
		t.Fatalf("Ingest returned error: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected both upsert attempts to succeed, got %d", count)
	}
	if len(store.vulnerabilities) != 1 {
		t.Fatalf("expected one stored vulnerability, got %d", len(store.vulnerabilities))
	}
}

// ADR-023: a scanner-suppressed result (SARIF suppressions[]) must never open
// a finding — it lands with status 'suppressed', kind + justification kept.
func TestIngestSuppressedFinding(t *testing.T) {
	mock := &mockIngestStore{}
	ingester := NewIngester(mock, zerolog.Nop())

	created, err := ingester.Ingest(context.Background(), uuid.New(), []GenericFinding{
		{Tool: "eslint", RuleID: "no-eval", Severity: "high", Message: "suppressed", Fingerprint: "fp-sup",
			Suppressed: true, SuppressionKind: "inSource", SuppressionJustification: "test fixture"},
		{Tool: "eslint", RuleID: "no-eval", Severity: "high", Message: "active", Fingerprint: "fp-act"},
	})
	if err != nil || created != 2 {
		t.Fatalf("Ingest = %d, %v; want 2, nil", created, err)
	}

	byFingerprint := map[string]*store.Vulnerability{}
	for _, vulnerability := range mock.vulnerabilities {
		byFingerprint[vulnerability.Fingerprint] = vulnerability
	}
	suppressed := byFingerprint["fp-sup"]
	if suppressed.Status != "suppressed" {
		t.Fatalf("suppressed finding status = %q, want suppressed", suppressed.Status)
	}
	if !strings.Contains(string(suppressed.Metadata), `"kind":"inSource"`) || !strings.Contains(string(suppressed.Metadata), `"justification":"test fixture"`) {
		t.Fatalf("suppression metadata not preserved: %s", suppressed.Metadata)
	}
	if active := byFingerprint["fp-act"]; active.Status != "detected" {
		t.Fatalf("active finding status = %q, want detected", active.Status)
	}
}

// ADR-037: a rule is upserted once per ingest and all rule CWEs go out in one
// batch (a SARIF log repeats the rule for every result), and result.taxa CWEs
// are recorded per fingerprint in one batch covering every reported fingerprint.
func TestIngestStoresRuleAndResultCWEs(t *testing.T) {
	store := &mockIngestStore{}
	ingester := NewIngester(store, zerolog.Nop())
	rule := &ScanRuleInput{Name: "SQL injection", CWEs: []int{89}}
	_, err := ingester.Ingest(context.Background(), uuid.New(), []GenericFinding{
		{Tool: "gosec", RuleID: "G201", Severity: "high", FilePath: "a.go", StartLine: 1, Message: "a", Fingerprint: "fp-a", Rule: rule, ResultCWEs: []int{564}},
		{Tool: "gosec", RuleID: "G201", Severity: "high", FilePath: "b.go", StartLine: 2, Message: "b", Fingerprint: "fp-b", Rule: rule},
	})
	if err != nil {
		t.Fatalf("Ingest returned error: %v", err)
	}
	if len(store.ruleCWECalls) != 1 {
		t.Fatalf("expected one rule, got %d", len(store.ruleCWECalls))
	}
	if store.upserts != 1 || store.syncCalls != 1 {
		t.Fatalf("rule upserts = %d, CWE syncs = %d; want 1 each", store.upserts, store.syncCalls)
	}
	if len(store.resultPrints) != 2 || store.resultPrints[0] != "fp-a" || store.resultPrints[1] != "fp-b" {
		t.Fatalf("result CWE batch must cover every fingerprint, got %v", store.resultPrints)
	}
	if got := store.resultCWEs["fp-a"]; len(got) != 1 || got[0] != 564 {
		t.Fatalf("fp-a result CWEs = %v", got)
	}
	if _, ok := store.resultCWEs["fp-b"]; ok {
		t.Fatal("fp-b has no result taxa")
	}
}
