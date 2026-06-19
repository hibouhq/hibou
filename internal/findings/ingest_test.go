package findings

import (
	"context"
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
		Status:      "detected",
		Fingerprint: params.Fingerprint,
		ScannerName: params.ScannerName,
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
		Metadata:  map[string]any{"source": "test"},
	}})
	if err != nil {
		t.Fatalf("Ingest returned error: %v", err)
	}
	if count != 1 || len(store.vulnerabilities) != 1 {
		t.Fatalf("expected 1 created vulnerability, got count=%d len=%d", count, len(store.vulnerabilities))
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
