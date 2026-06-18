package store

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSnapshotArtifactsCreateListAndCascadeDelete(t *testing.T) {
	databaseURL := os.Getenv("HIBOU_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = testDatabaseURL
	}

	var (
		db  *sql.DB
		err error
	)
	for range 10 {
		db, err = New(databaseURL)
		if err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		t.Skipf("database not available for snapshot artifact test: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})

	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate() returned error: %v", err)
	}

	queries := NewQueries(db)
	ctx := context.Background()
	snapshotID := createSnapshotForArtifactTest(t, ctx, queries)
	format := "cyclonedx-json"
	tool := "trivy"
	sha := "abc123"
	contentType := "application/json"

	created, err := queries.CreateSnapshotArtifact(ctx, CreateSnapshotArtifactParams{
		SnapshotID:  snapshotID,
		Kind:        "sbom",
		Format:      &format,
		ToolName:    &tool,
		ObjectKey:   "snapshots/" + snapshotID.String() + "/abc123",
		SHA256:      &sha,
		SizeBytes:   128,
		ContentType: &contentType,
	})
	if err != nil {
		t.Fatalf("CreateSnapshotArtifact() error = %v", err)
	}
	if created == nil || created.SnapshotID != snapshotID {
		t.Fatalf("CreateSnapshotArtifact() = %#v, want snapshot %s", created, snapshotID)
	}

	artifacts, err := queries.ListSnapshotArtifactsBySnapshot(ctx, snapshotID)
	if err != nil {
		t.Fatalf("ListSnapshotArtifactsBySnapshot() error = %v", err)
	}
	if len(artifacts) != 1 {
		t.Fatalf("artifact count = %d, want 1", len(artifacts))
	}
	if artifacts[0].ObjectKey != "snapshots/"+snapshotID.String()+"/abc123" {
		t.Fatalf("artifact object key = %q, want expected key", artifacts[0].ObjectKey)
	}

	keys, err := queries.ListSnapshotArtifactObjectKeys(ctx, snapshotID)
	if err != nil {
		t.Fatalf("ListSnapshotArtifactObjectKeys() error = %v", err)
	}
	if len(keys) != 1 || keys[0] != artifacts[0].ObjectKey {
		t.Fatalf("artifact keys = %#v, want %q", keys, artifacts[0].ObjectKey)
	}

	if _, err := db.ExecContext(ctx, `DELETE FROM snapshots WHERE id = $1`, snapshotID); err != nil {
		t.Fatalf("DELETE snapshot error = %v", err)
	}

	var remaining int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM snapshot_artifacts WHERE snapshot_id = $1`, snapshotID).Scan(&remaining); err != nil {
		t.Fatalf("count snapshot_artifacts error = %v", err)
	}
	if remaining != 0 {
		t.Fatalf("remaining snapshot_artifacts = %d, want 0", remaining)
	}
}

func createSnapshotForArtifactTest(t *testing.T, ctx context.Context, queries *Queries) uuid.UUID {
	t.Helper()

	org, err := queries.CreateOrganization(ctx, uniqueStoreTestName(t, "org"), uniqueStoreTestName(t, "org"), "Snapshot Artifact Org", "github")
	if err != nil {
		t.Fatalf("CreateOrganization() error = %v", err)
	}
	repo, err := queries.CreateRepository(ctx, org.ID, nil, uniqueStoreTestName(t, "repo"), uniqueStoreTestName(t, "repo"), "github", uniqueStoreTestName(t, "provider"), "main", "enrolled")
	if err != nil {
		t.Fatalf("CreateRepository() error = %v", err)
	}
	commitSHA := uniqueStoreTestName(t, "commit")
	ref, err := queries.CreateRef(ctx, repo.ID, "main", RefTypeBranch, nil, nil, &commitSHA)
	if err != nil {
		t.Fatalf("CreateRef() error = %v", err)
	}
	snapshot, err := queries.CreateSnapshot(ctx, ref.ID, commitSHA, SnapshotStatusComplete)
	if err != nil {
		t.Fatalf("CreateSnapshot() error = %v", err)
	}
	return snapshot.ID
}

func uniqueStoreTestName(t *testing.T, prefix string) string {
	t.Helper()
	return normalizeStoreTestName(t.Name()) + "-" + prefix + "-" + uuid.NewString()[:8]
}
