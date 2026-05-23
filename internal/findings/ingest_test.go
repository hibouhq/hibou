package findings

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/rs/zerolog"

	"github.com/hibouhq/lehibou/internal/store"
)

type mockIngestStore struct {
	findings []*store.Finding
	err      error
	seen     map[string]bool
}

func (m *mockIngestStore) CreateFinding(_ context.Context, snapshotID uuid.UUID, tool, ruleID string, severity store.SeverityLevel, status, filePath string, startLine, endLine *int32, locationHash, message string, fingerprint *string, metadata json.RawMessage) (*store.Finding, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.seen == nil {
		m.seen = map[string]bool{}
	}
	key := snapshotID.String() + "/" + tool + "/" + ruleID + "/" + locationHash
	if m.seen[key] {
		return nil, &pq.Error{Code: "23505"}
	}
	m.seen[key] = true
	finding := &store.Finding{SnapshotID: snapshotID, Tool: tool, RuleID: ruleID, Severity: severity, Status: status, FilePath: filePath, StartLine: startLine, EndLine: endLine, LocationHash: locationHash, Message: message, Fingerprint: fingerprint, Metadata: metadata}
	m.findings = append(m.findings, finding)
	return finding, nil
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
		Metadata:  map[string]any{"source": "test"},
	}})
	if err != nil {
		t.Fatalf("Ingest returned error: %v", err)
	}
	if count != 1 || len(store.findings) != 1 {
		t.Fatalf("expected 1 created finding, got count=%d len=%d", count, len(store.findings))
	}
	if store.findings[0].Fingerprint == nil || *store.findings[0].Fingerprint != store.findings[0].LocationHash {
		t.Fatalf("expected fingerprint to default to location hash, got %#v", store.findings[0].Fingerprint)
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
	if count != 1 {
		t.Fatalf("expected duplicate to be skipped, got %d", count)
	}
}
