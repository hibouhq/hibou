package secretscan

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/lehibou/internal/store"
	"github.com/hibouhq/lehibou/internal/store/dbgen"
)

type ingestStoreStub struct {
	rows    map[string]*store.Vulnerability
	created int
	err     error
}

func (s *ingestStoreStub) CreateVulnerability(_ context.Context, params dbgen.CreateVulnerabilityParams) (*store.Vulnerability, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.rows == nil {
		s.rows = make(map[string]*store.Vulnerability)
	}
	if existing, ok := s.rows[params.Fingerprint]; ok {
		return existing, nil
	}
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
	if params.SecretType.Valid {
		vulnerability.SecretType = &params.SecretType.String
	}
	if params.SecretHash.Valid {
		vulnerability.SecretHash = &params.SecretHash.String
	}
	s.rows[params.Fingerprint] = vulnerability
	s.created++
	return vulnerability, nil
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
	if len(stub.rows) != 1 {
		t.Fatalf("len(rows) = %d, want 1", len(stub.rows))
	}
}

func TestIngesterDeduplicatesByFingerprint(t *testing.T) {
	stub := &ingestStoreStub{}
	ingester := NewIngester(stub, zerolog.Nop())
	snapshotID := uuid.New()
	fingerprint := ComputeFingerprint("app.env", 4, HashSecret("AKIA123"))

	findings := []SecretFinding{
		{Tool: "gitleaks", RuleID: "aws-access-key", Severity: "critical", FilePath: "app.env", StartLine: 4, SecretType: "aws-access-key", SecretHash: HashSecret("AKIA123"), Fingerprint: fingerprint, Metadata: map[string]any{}},
		{Tool: "gitleaks", RuleID: "aws-access-key", Severity: "critical", FilePath: "app.env", StartLine: 4, SecretType: "aws-access-key", SecretHash: HashSecret("AKIA123"), Fingerprint: fingerprint, Metadata: map[string]any{}},
	}

	_, err := ingester.Ingest(context.Background(), snapshotID, findings, "full_scan")
	if err != nil {
		t.Fatalf("Ingest returned error: %v", err)
	}
	if stub.created != 1 {
		t.Fatalf("store created = %d, want 1", stub.created)
	}
	if len(stub.rows) != 1 {
		t.Fatalf("len(rows) = %d, want 1", len(stub.rows))
	}
}

func TestIngesterCrossProviderDedup(t *testing.T) {
	stub := &ingestStoreStub{}
	ingester := NewIngester(stub, zerolog.Nop())
	snapshotID := uuid.New()
	secretHash := HashSecret("AKIA123")
	fingerprint := ComputeFingerprint("app.env", 4, secretHash)

	findings := []SecretFinding{
		{Tool: "gitleaks", RuleID: "aws-access-key", Severity: "critical", FilePath: "app.env", StartLine: 4, SecretType: "aws-access-key", SecretHash: secretHash, Fingerprint: fingerprint, Metadata: map[string]any{}},
		{Tool: "github", RuleID: "aws-access-key", Severity: "critical", FilePath: "app.env", StartLine: 4, SecretType: "aws-access-key", SecretHash: secretHash, Fingerprint: fingerprint, Metadata: map[string]any{}},
	}

	_, err := ingester.Ingest(context.Background(), snapshotID, findings, "full_scan")
	if err != nil {
		t.Fatalf("Ingest returned error: %v", err)
	}
	if len(stub.rows) != 1 {
		t.Fatalf("len(rows) = %d, want 1", len(stub.rows))
	}
	if stub.created != 1 {
		t.Fatalf("store created = %d, want 1", stub.created)
	}
}

func TestIngesterLineZeroUsesSecretHashFingerprintFallback(t *testing.T) {
	stub := &ingestStoreStub{}
	ingester := NewIngester(stub, zerolog.Nop())
	snapshotID := uuid.New()
	firstHash := HashSecret("AKIA123")
	secondHash := HashSecret("ghp_456")

	created, err := ingester.Ingest(context.Background(), snapshotID, []SecretFinding{
		{Tool: "gitleaks", RuleID: "aws-access-key", Severity: "critical", FilePath: "app.env", SecretType: "aws-access-key", SecretHash: firstHash, Fingerprint: ComputeFingerprint("app.env", 0, firstHash), Metadata: map[string]any{}},
		{Tool: "gitleaks", RuleID: "github-pat", Severity: "critical", FilePath: "app.env", SecretType: "github-pat", SecretHash: secondHash, Fingerprint: ComputeFingerprint("app.env", 0, secondHash), Metadata: map[string]any{}},
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
		Metadata:    map[string]any{},
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
		Metadata:    map[string]any{},
	}}, "full_scan")
	if err != nil {
		t.Fatalf("second Ingest returned error: %v", err)
	}

	if stub.created != 1 {
		t.Fatalf("store created = %d, want 1", stub.created)
	}
	if len(stub.rows) != 1 {
		t.Fatalf("len(rows) = %d, want 1", len(stub.rows))
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
