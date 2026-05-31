package secretscan

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/lehibou/internal/store"
)

type ingestStoreStub struct {
	rows    map[string]*store.SecretFinding
	sources map[uuid.UUID]map[string]*store.SecretFindingSource
	created int
}

func (s *ingestStoreStub) CreateSecretFinding(_ context.Context, snapshotID uuid.UUID, tool, ruleID string, severity store.SeverityLevel, status store.SecretStatus, discoveryContext, filePath string, startLine, endLine *int32, secretType, secretHash, commitSHA, authorEmail string, verified bool, metadata json.RawMessage, fingerprint string) (*store.SecretFinding, error) {
	if s.rows == nil {
		s.rows = make(map[string]*store.SecretFinding)
	}
	row := &store.SecretFinding{
		ID:               uuid.New(),
		SnapshotID:       snapshotID,
		Tool:             tool,
		RuleID:           ruleID,
		Severity:         severity,
		Status:           status,
		DiscoveryContext: discoveryContext,
		FilePath:         filePath,
		StartLine:        startLine,
		EndLine:          endLine,
		SecretType:       secretType,
		SecretHash:       secretHash,
		CommitSHA:        commitSHA,
		AuthorEmail:      authorEmail,
		Verified:         verified,
		Fingerprint:      fingerprint,
		Metadata:         metadata,
	}
	if s.rows == nil {
		s.rows = make(map[string]*store.SecretFinding)
	}
	s.rows[fingerprint] = row
	s.created++
	return row, nil
}

func (s *ingestStoreStub) GetSecretFindingByFingerprint(_ context.Context, _ uuid.UUID, fingerprint string) (*store.SecretFinding, error) {
	if s.rows == nil {
		return nil, nil
	}
	return s.rows[fingerprint], nil
}

func (s *ingestStoreStub) UpsertSecretFindingSource(_ context.Context, findingID uuid.UUID, tool, ruleID string, metadata json.RawMessage) error {
	if s.sources == nil {
		s.sources = make(map[uuid.UUID]map[string]*store.SecretFindingSource)
	}
	if s.sources[findingID] == nil {
		s.sources[findingID] = make(map[string]*store.SecretFindingSource)
	}
	if source, ok := s.sources[findingID][tool]; ok {
		source.ScanCount++
		source.RuleID = ruleID
		source.Metadata = metadata
		return nil
	}
	s.sources[findingID][tool] = &store.SecretFindingSource{
		ID:        uuid.New(),
		FindingID: findingID,
		Tool:      tool,
		RuleID:    ruleID,
		ScanCount: 1,
		Metadata:  metadata,
	}
	return nil
}

func TestIngesterCreatesFindings(t *testing.T) {
	stub := &ingestStoreStub{}
	ingester := NewIngester(stub, zerolog.Nop())
	snapshotID := uuid.New()

	created, err := ingester.Ingest(context.Background(), snapshotID, []SecretFinding{{
		Tool:        "gitleaks",
		RuleID:      "aws-access-key",
		Severity:    "critical",
		FilePath:    "app.env",
		StartLine:   4,
		EndLine:     4,
		SecretType:  "aws-access-key",
		SecretHash:  HashSecret("AKIA123"),
		Fingerprint: ComputeFingerprint("app.env", 4, HashSecret("AKIA123")),
		Metadata:    map[string]any{"source": "test"},
	}}, "full_scan")
	if err != nil {
		t.Fatalf("Ingest returned error: %v", err)
	}
	if created != 1 {
		t.Fatalf("created = %d, want 1", created)
	}
	if stub.created != 1 {
		t.Fatalf("store created = %d, want 1", stub.created)
	}
	if len(stub.sources) != 1 {
		t.Fatalf("len(sources) = %d, want 1", len(stub.sources))
	}
	for _, row := range stub.rows {
		if row.DiscoveryContext != "full_scan" {
			t.Fatalf("discovery_context = %q, want %q", row.DiscoveryContext, "full_scan")
		}
	}
}

func TestIngesterDeduplicatesByFingerprint(t *testing.T) {
	stub := &ingestStoreStub{}
	ingester := NewIngester(stub, zerolog.Nop())
	snapshotID := uuid.New()
	fingerprint := ComputeFingerprint("app.env", 4, HashSecret("AKIA123"))

	findings := []SecretFinding{
		{Tool: "gitleaks", RuleID: "aws-access-key", Severity: "critical", FilePath: "app.env", StartLine: 4, SecretType: "aws-access-key", SecretHash: HashSecret("AKIA123"), Fingerprint: fingerprint},
		{Tool: "gitleaks", RuleID: "aws-access-key", Severity: "critical", FilePath: "app.env", StartLine: 4, SecretType: "aws-access-key", SecretHash: HashSecret("AKIA123"), Fingerprint: fingerprint},
	}

	created, err := ingester.Ingest(context.Background(), snapshotID, findings, "full_scan")
	if err != nil {
		t.Fatalf("Ingest returned error: %v", err)
	}
	if created != 1 {
		t.Fatalf("created = %d, want 1", created)
	}
	if len(stub.sources) != 1 {
		t.Fatalf("len(sources) = %d, want 1", len(stub.sources))
	}
	for _, sourceMap := range stub.sources {
		source := sourceMap["gitleaks"]
		if source == nil {
			t.Fatal("expected gitleaks source attribution")
		}
		if source.ScanCount != 2 {
			t.Fatalf("scan_count = %d, want 2", source.ScanCount)
		}
	}
}

func TestIngesterCrossProviderDedup(t *testing.T) {
	stub := &ingestStoreStub{}
	ingester := NewIngester(stub, zerolog.Nop())
	snapshotID := uuid.New()
	secretHash := HashSecret("AKIA123")
	fingerprint := ComputeFingerprint("app.env", 4, secretHash)

	findings := []SecretFinding{
		{Tool: "gitleaks", RuleID: "aws-access-key", Severity: "critical", FilePath: "app.env", StartLine: 4, SecretType: "aws-access-key", SecretHash: secretHash, Fingerprint: fingerprint},
		{Tool: "github", RuleID: "aws-access-key", Severity: "critical", FilePath: "app.env", StartLine: 4, SecretType: "aws-access-key", SecretHash: secretHash, Fingerprint: fingerprint},
	}

	created, err := ingester.Ingest(context.Background(), snapshotID, findings, "full_scan")
	if err != nil {
		t.Fatalf("Ingest returned error: %v", err)
	}
	if created != 1 {
		t.Fatalf("created = %d, want 1", created)
	}
	if len(stub.rows) != 1 {
		t.Fatalf("len(rows) = %d, want 1", len(stub.rows))
	}
	if len(stub.sources) != 1 {
		t.Fatalf("len(sources) = %d, want 1", len(stub.sources))
	}
	for _, sourceMap := range stub.sources {
		if len(sourceMap) != 2 {
			t.Fatalf("len(sourceMap) = %d, want 2", len(sourceMap))
		}
		if sourceMap["gitleaks"] == nil || sourceMap["github"] == nil {
			t.Fatal("expected source attributions for both tools")
		}
	}
}

func TestIngesterLineZeroUsesSecretHashFingerprintFallback(t *testing.T) {
	stub := &ingestStoreStub{}
	ingester := NewIngester(stub, zerolog.Nop())
	snapshotID := uuid.New()
	firstHash := HashSecret("AKIA123")
	secondHash := HashSecret("ghp_456")

	created, err := ingester.Ingest(context.Background(), snapshotID, []SecretFinding{
		{Tool: "gitleaks", RuleID: "aws-access-key", Severity: "critical", FilePath: "app.env", SecretType: "aws-access-key", SecretHash: firstHash, Fingerprint: ComputeFingerprint("app.env", 0, firstHash)},
		{Tool: "gitleaks", RuleID: "github-pat", Severity: "critical", FilePath: "app.env", SecretType: "github-pat", SecretHash: secondHash, Fingerprint: ComputeFingerprint("app.env", 0, secondHash)},
	}, "full_scan")
	if err != nil {
		t.Fatalf("Ingest returned error: %v", err)
	}
	if created != 2 {
		t.Fatalf("created = %d, want 2", created)
	}
	if len(stub.rows) != 2 {
		t.Fatalf("len(rows) = %d, want 2", len(stub.rows))
	}
}

func TestIngesterUpsertSourceRefreshesMetadata(t *testing.T) {
	stub := &ingestStoreStub{}
	ingester := NewIngester(stub, zerolog.Nop())
	snapshotID := uuid.New()
	secretHash := HashSecret("AKIA123")
	fingerprint := ComputeFingerprint("app.env", 4, secretHash)

	_, err := ingester.Ingest(context.Background(), snapshotID, []SecretFinding{{
		Tool:        "gitleaks",
		RuleID:      "aws-access-key",
		Severity:    "critical",
		Description: "first",
		FilePath:    "app.env",
		StartLine:   4,
		EndLine:     4,
		SecretType:  "aws-access-key",
		SecretHash:  secretHash,
		Fingerprint: fingerprint,
	}}, "full_scan")
	if err != nil {
		t.Fatalf("first Ingest returned error: %v", err)
	}

	_, err = ingester.Ingest(context.Background(), snapshotID, []SecretFinding{{
		Tool:        "gitleaks",
		RuleID:      "aws-secret-key",
		Severity:    "critical",
		Description: "second",
		FilePath:    "app.env",
		StartLine:   4,
		EndLine:     4,
		SecretType:  "aws-secret-key",
		SecretHash:  secretHash,
		Fingerprint: fingerprint,
	}}, "full_scan")
	if err != nil {
		t.Fatalf("second Ingest returned error: %v", err)
	}

	if len(stub.sources) != 1 {
		t.Fatalf("len(sources) = %d, want 1", len(stub.sources))
	}
	for _, sourceMap := range stub.sources {
		source := sourceMap["gitleaks"]
		if source == nil {
			t.Fatal("expected gitleaks source attribution")
		}
		if source.RuleID != "aws-secret-key" {
			t.Fatalf("rule_id = %q, want %q", source.RuleID, "aws-secret-key")
		}
		var metadata map[string]any
		if err := json.Unmarshal(source.Metadata, &metadata); err != nil {
			t.Fatalf("unmarshal metadata: %v", err)
		}
		if metadata["description"] != "second" {
			t.Fatalf("metadata description = %v, want %q", metadata["description"], "second")
		}
		if metadata["secret_type"] != "aws-secret-key" {
			t.Fatalf("metadata secret_type = %v, want %q", metadata["secret_type"], "aws-secret-key")
		}
		if source.ScanCount != 2 {
			t.Fatalf("scan_count = %d, want 2", source.ScanCount)
		}
	}
}

func TestSeverityFromString(t *testing.T) {
	severity, err := severityFromString("moderate")
	if err != nil {
		t.Fatalf("severityFromString returned error: %v", err)
	}
	if severity != store.SeverityLevelMedium {
		t.Fatalf("severity = %q, want %q", severity, store.SeverityLevelMedium)
	}
}
