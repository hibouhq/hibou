package server

import (
	"context"
	"testing"

	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/secretscan"
	"github.com/hibouhq/hibou/internal/store"
)

func TestSecretIngesterIsIdempotentForCommitFindings(t *testing.T) {
	t.Parallel()

	srv, org, _, _ := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)
	ref, err := srv.queries.CreateRef(context.Background(), repo.ID, "main", store.RefTypeBranch, nil, nil, stringPtrForTest(uniqueName(t, "sha")))
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	snapshot, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, uniqueName(t, "secret-commit"), store.SnapshotStatusComplete)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}

	secretHash := secretscan.HashSecret("ghp_123")
	fingerprint := secretscan.ComputeFingerprint(".env", 8, secretHash)
	findings := []secretscan.SecretFinding{{
		Tool:        "gitleaks",
		RuleID:      "github-pat",
		Severity:    "critical",
		Description: "hardcoded GitHub PAT",
		FilePath:    ".env",
		StartLine:   8,
		EndLine:     8,
		SecretType:  "github-pat",
		SecretHash:  secretHash,
		CommitSHA:   "deadbeef",
		AuthorEmail: "dev@example.com",
		Fingerprint: fingerprint,
		Metadata:    map[string]any{"source": "incremental"},
	}}

	ingester := secretscan.NewIngester(srv.queries, zerolog.Nop())
	if _, err := ingester.Ingest(context.Background(), snapshot.ID, findings, "incremental_scan"); err != nil {
		t.Fatalf("first Ingest: %v", err)
	}
	if _, err := ingester.Ingest(context.Background(), snapshot.ID, findings, "incremental_scan"); err != nil {
		t.Fatalf("second Ingest: %v", err)
	}

	vulnerabilities, _, err := srv.queries.ListVulnerabilitiesBySnapshot(context.Background(), snapshot.ID, store.VulnerabilityListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("ListVulnerabilitiesBySnapshot: %v", err)
	}
	if len(vulnerabilities) != 1 {
		t.Fatalf("vulnerability count = %d, want 1", len(vulnerabilities))
	}
	if vulnerabilities[0].Type != "secret" {
		t.Fatalf("type = %q, want secret", vulnerabilities[0].Type)
	}
	if vulnerabilities[0].Fingerprint != fingerprint {
		t.Fatalf("fingerprint = %q, want %q", vulnerabilities[0].Fingerprint, fingerprint)
	}
	if vulnerabilities[0].CommitSHA == nil || *vulnerabilities[0].CommitSHA != "deadbeef" {
		t.Fatalf("commit_sha = %v, want deadbeef", vulnerabilities[0].CommitSHA)
	}
	if vulnerabilities[0].AuthorEmail == nil || *vulnerabilities[0].AuthorEmail != "dev@example.com" {
		t.Fatalf("author_email = %v, want dev@example.com", vulnerabilities[0].AuthorEmail)
	}
	var vulnCount int
	if err := srv.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM vulnerabilities WHERE snapshot_id = $1 AND type = 'secret'`, snapshot.ID).Scan(&vulnCount); err != nil {
		t.Fatalf("count secret vulnerabilities: %v", err)
	}
	if vulnCount != 1 {
		t.Fatalf("secret vulnerability rows = %d, want 1", vulnCount)
	}
	row, err := srv.queries.GetVulnerabilityByID(context.Background(), vulnerabilities[0].ID)
	if err != nil {
		t.Fatalf("GetVulnerabilityByID: %v", err)
	}
	if row == nil {
		t.Fatal("expected stored secret vulnerability")
	}
	if row.SecretType == nil || *row.SecretType != "github-pat" {
		t.Fatalf("secret_type = %v, want github-pat", row.SecretType)
	}
	if row.SecretHash == nil || *row.SecretHash != secretHash {
		t.Fatalf("secret_hash = %v, want stable hash", row.SecretHash)
	}
	if row.Metadata == nil {
		t.Fatal("metadata = nil, want value")
	}
}
