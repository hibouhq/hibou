package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMarkSnapshotFailedIfPending(t *testing.T) {
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
		t.Skipf("database not available for snapshot status test: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})

	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate() returned error: %v", err)
	}

	queries := NewQueries(db)
	ctx := context.Background()
	pendingID := createSnapshotForStatusTest(t, ctx, queries, SnapshotStatusPending)
	completeID := createSnapshotForStatusTest(t, ctx, queries, SnapshotStatusComplete)

	affected, err := queries.MarkSnapshotFailedIfPending(ctx, pendingID)
	if err != nil {
		t.Fatalf("MarkSnapshotFailedIfPending(pending) error = %v", err)
	}
	if affected != 1 {
		t.Fatalf("MarkSnapshotFailedIfPending(pending) affected = %d, want 1", affected)
	}
	pendingSnapshot, err := queries.GetSnapshotByID(ctx, pendingID)
	if err != nil {
		t.Fatalf("GetSnapshotByID(pending) error = %v", err)
	}
	if pendingSnapshot == nil || pendingSnapshot.Status != SnapshotStatusFailed {
		t.Fatalf("pending snapshot status = %#v, want failed", pendingSnapshot)
	}

	affected, err = queries.MarkSnapshotFailedIfPending(ctx, completeID)
	if err != nil {
		t.Fatalf("MarkSnapshotFailedIfPending(complete) error = %v", err)
	}
	if affected != 0 {
		t.Fatalf("MarkSnapshotFailedIfPending(complete) affected = %d, want 0", affected)
	}
	completeSnapshot, err := queries.GetSnapshotByID(ctx, completeID)
	if err != nil {
		t.Fatalf("GetSnapshotByID(complete) error = %v", err)
	}
	if completeSnapshot == nil || completeSnapshot.Status != SnapshotStatusComplete {
		t.Fatalf("complete snapshot status = %#v, want complete", completeSnapshot)
	}
}

func TestCompleteSnapshotRejectsFailedSnapshot(t *testing.T) {
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
		t.Skipf("database not available for snapshot completion test: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})

	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate() returned error: %v", err)
	}

	queries := NewQueries(db)
	ctx := context.Background()
	failedID := createSnapshotForStatusTest(t, ctx, queries, SnapshotStatusFailed)
	pendingID := createSnapshotForStatusTest(t, ctx, queries, SnapshotStatusPending)

	failedSnapshot, err := queries.CompleteSnapshot(ctx, failedID)
	if !errors.Is(err, ErrSnapshotNotCompletable) {
		t.Fatalf("CompleteSnapshot(failed) error = %v, want %v", err, ErrSnapshotNotCompletable)
	}
	if failedSnapshot != nil {
		t.Fatalf("CompleteSnapshot(failed) snapshot = %#v, want nil", failedSnapshot)
	}
	storedFailed, err := queries.GetSnapshotByID(ctx, failedID)
	if err != nil {
		t.Fatalf("GetSnapshotByID(failed) error = %v", err)
	}
	if storedFailed == nil || storedFailed.Status != SnapshotStatusFailed {
		t.Fatalf("failed snapshot status = %#v, want failed", storedFailed)
	}

	completedSnapshot, err := queries.CompleteSnapshot(ctx, pendingID)
	if err != nil {
		t.Fatalf("CompleteSnapshot(pending) error = %v", err)
	}
	if completedSnapshot == nil || completedSnapshot.Status != SnapshotStatusComplete {
		t.Fatalf("CompleteSnapshot(pending) = %#v, want complete snapshot", completedSnapshot)
	}
}

func TestCompleteSnapshotEntersProcessingWhileArtifactsQueued(t *testing.T) {
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
		t.Skipf("database not available for snapshot completion test: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})

	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate() returned error: %v", err)
	}

	queries := NewQueries(db)
	ctx := context.Background()

	// A finalized upload with queued SBOM/SARIF work must NOT read as complete:
	// data views resolve the latest complete snapshot, and an unprocessed one
	// would shadow real data with zeros.
	withArtifactsID := createSnapshotForStatusTest(t, ctx, queries, SnapshotStatusPending)
	format := "cyclonedx-json"
	if _, err := queries.CreateSnapshotArtifact(ctx, CreateSnapshotArtifactParams{
		SnapshotID: withArtifactsID,
		Kind:       "sbom",
		Format:     &format,
		ObjectKey:  "snapshots/" + withArtifactsID.String() + "/sbom.json",
		SizeBytes:  64,
	}); err != nil {
		t.Fatalf("CreateSnapshotArtifact(sbom) error = %v", err)
	}
	finalized, err := queries.CompleteSnapshot(ctx, withArtifactsID)
	if err != nil {
		t.Fatalf("CompleteSnapshot(with artifacts) error = %v", err)
	}
	if finalized == nil || finalized.Status != SnapshotStatusProcessing {
		t.Fatalf("CompleteSnapshot(with artifacts) status = %#v, want processing", finalized)
	}
	latest, err := queries.GetLatestCompleteSnapshotByRef(ctx, finalized.RefID)
	if err != nil {
		t.Fatalf("GetLatestCompleteSnapshotByRef() error = %v", err)
	}
	if latest != nil {
		t.Fatalf("GetLatestCompleteSnapshotByRef() = %#v, want nil while processing", latest)
	}

	// Coverage/tests ingest at upload time: a snapshot without async artifacts
	// completes immediately.
	withoutArtifactsID := createSnapshotForStatusTest(t, ctx, queries, SnapshotStatusPending)
	completed, err := queries.CompleteSnapshot(ctx, withoutArtifactsID)
	if err != nil {
		t.Fatalf("CompleteSnapshot(without artifacts) error = %v", err)
	}
	if completed == nil || completed.Status != SnapshotStatusComplete {
		t.Fatalf("CompleteSnapshot(without artifacts) status = %#v, want complete", completed)
	}

	// The processing snapshot must be claimable by the artifact worker, or it
	// would be stuck in processing forever.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()
	if _, err := tx.ExecContext(ctx, `LOCK TABLE snapshots, snapshot_artifacts IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatalf("lock snapshot tables: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE snapshots
		SET artifact_processing_finished_at = NOW(),
			artifact_processing_claimed_by = NULL,
			artifact_processing_claim_expires_at = NULL
		WHERE id <> $1
	`, withArtifactsID); err != nil {
		t.Fatalf("quarantine unrelated snapshots: %v", err)
	}
	txQueries := queries.WithTx(tx)
	claimed, err := txQueries.ClaimNextArtifactProcessingSnapshot(ctx, "worker-processing-test", time.Now().Add(5*time.Minute), 3)
	if err != nil {
		t.Fatalf("ClaimNextArtifactProcessingSnapshot(processing) error = %v", err)
	}
	if claimed == nil || claimed.ID != withArtifactsID {
		t.Fatalf("claimed = %#v, want processing snapshot %s", claimed, withArtifactsID)
	}
	done, err := txQueries.CompleteArtifactProcessingSnapshot(ctx, withArtifactsID, "worker-processing-test")
	if err != nil {
		t.Fatalf("CompleteArtifactProcessingSnapshot() error = %v", err)
	}
	if done == nil || done.Status != SnapshotStatusComplete {
		t.Fatalf("post-processing status = %#v, want complete", done)
	}
}

func createSnapshotForStatusTest(t *testing.T, ctx context.Context, queries *Queries, status SnapshotStatus) uuid.UUID {
	t.Helper()

	org, err := queries.CreateOrganization(ctx, uniqueStoreTestName(t, "org"), uniqueStoreTestName(t, "org"), "Snapshot Status Org", "github")
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
	snapshot, err := queries.CreateSnapshot(ctx, ref.ID, commitSHA, status)
	if err != nil {
		t.Fatalf("CreateSnapshot() error = %v", err)
	}
	return snapshot.ID
}
