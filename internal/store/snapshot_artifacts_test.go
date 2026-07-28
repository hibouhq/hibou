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

func TestClaimNextArtifactProcessingSnapshotSkipsClaimedRowsAndStopsAfterFinishedFailure(t *testing.T) {
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
	txQueries := queries.WithTx(tx)
	snapshotID := createSnapshotForArtifactTest(t, ctx, txQueries)
	format := "cyclonedx-json"
	if _, err := txQueries.CreateSnapshotArtifact(ctx, CreateSnapshotArtifactParams{
		SnapshotID: snapshotID,
		Kind:       "sbom",
		Format:     &format,
		ObjectKey:  "snapshots/" + snapshotID.String() + "/sbom.json",
		SizeBytes:  64,
	}); err != nil {
		t.Fatalf("CreateSnapshotArtifact(sbom) error = %v", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE snapshots
		SET artifact_processing_finished_at = NOW(),
			artifact_processing_claimed_by = NULL,
			artifact_processing_claim_expires_at = NULL
		WHERE id <> $1
	`, snapshotID); err != nil {
		t.Fatalf("quarantine unrelated snapshots: %v", err)
	}

	claimed, err := txQueries.ClaimNextArtifactProcessingSnapshot(ctx, "worker-a", time.Now().Add(5*time.Minute), 3)
	if err != nil {
		t.Fatalf("ClaimNextArtifactProcessingSnapshot(worker-a) error = %v", err)
	}
	if claimed == nil || claimed.ID != snapshotID {
		t.Fatalf("claimed snapshot = %#v, want %s", claimed, snapshotID)
	}
	if claimed.ArtifactProcessingAttempts != 1 {
		t.Fatalf("artifact_processing_attempts = %d, want 1", claimed.ArtifactProcessingAttempts)
	}

	secondClaim, err := txQueries.ClaimNextArtifactProcessingSnapshot(ctx, "worker-b", time.Now().Add(5*time.Minute), 3)
	if err != nil {
		t.Fatalf("ClaimNextArtifactProcessingSnapshot(worker-b) error = %v", err)
	}
	if secondClaim != nil {
		t.Fatalf("second claim = %#v, want nil while lease is active", secondClaim)
	}

	failed, err := txQueries.FailArtifactProcessingSnapshot(ctx, snapshotID, "worker-a", false, "temporary failure")
	if err != nil {
		t.Fatalf("FailArtifactProcessingSnapshot(retryable) error = %v", err)
	}
	if failed == nil || failed.Status != SnapshotStatusFailed {
		t.Fatalf("failed snapshot = %#v, want failed status", failed)
	}
	if failed.ArtifactProcessingFinishedAt != nil {
		t.Fatalf("artifact_processing_finished_at = %v, want nil for retryable failure", failed.ArtifactProcessingFinishedAt)
	}

	retryClaim, err := txQueries.ClaimNextArtifactProcessingSnapshot(ctx, "worker-b", time.Now().Add(5*time.Minute), 3)
	if err != nil {
		t.Fatalf("ClaimNextArtifactProcessingSnapshot(retry) error = %v", err)
	}
	if retryClaim == nil || retryClaim.ID != snapshotID {
		t.Fatalf("retry claim = %#v, want snapshot %s", retryClaim, snapshotID)
	}
	if retryClaim.ArtifactProcessingAttempts != 2 {
		t.Fatalf("artifact_processing_attempts after retry = %d, want 2", retryClaim.ArtifactProcessingAttempts)
	}

	if _, err := txQueries.FailArtifactProcessingSnapshot(ctx, snapshotID, "worker-b", true, "permanent failure"); err != nil {
		t.Fatalf("FailArtifactProcessingSnapshot(final) error = %v", err)
	}

	finalClaim, err := txQueries.ClaimNextArtifactProcessingSnapshot(ctx, "worker-c", time.Now().Add(5*time.Minute), 3)
	if err != nil {
		t.Fatalf("ClaimNextArtifactProcessingSnapshot(final) error = %v", err)
	}
	if finalClaim != nil {
		t.Fatalf("final claim = %#v, want nil after finished failure", finalClaim)
	}
}

func TestClaimNextArtifactProcessingSnapshotSkipsUploadLifecycleFailures(t *testing.T) {
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
	if _, err := db.ExecContext(ctx, `UPDATE snapshots SET status = 'pending' WHERE id = $1`, snapshotID); err != nil {
		t.Fatalf("set snapshot pending: %v", err)
	}
	if _, err := queries.CreateSnapshotArtifact(ctx, CreateSnapshotArtifactParams{
		SnapshotID: snapshotID,
		Kind:       "sbom",
		Format:     &format,
		ObjectKey:  "snapshots/" + snapshotID.String() + "/sbom.json",
		SizeBytes:  64,
	}); err != nil {
		t.Fatalf("CreateSnapshotArtifact(sbom) error = %v", err)
	}
	if err := finishOtherSnapshotsForArtifactProcessingTest(ctx, db, snapshotID); err != nil {
		t.Fatalf("quarantine unrelated snapshots: %v", err)
	}

	affected, err := queries.MarkSnapshotFailedIfPending(ctx, snapshotID)
	if err != nil {
		t.Fatalf("MarkSnapshotFailedIfPending: %v", err)
	}
	if affected != 1 {
		t.Fatalf("MarkSnapshotFailedIfPending affected = %d, want 1", affected)
	}

	claimed, err := queries.ClaimNextArtifactProcessingSnapshot(ctx, "worker-a", time.Now().Add(5*time.Minute), 3)
	if err != nil {
		t.Fatalf("ClaimNextArtifactProcessingSnapshot: %v", err)
	}
	if claimed != nil {
		t.Fatalf("claimed snapshot = %#v, want nil for upload lifecycle failure", claimed)
	}
}

func TestClaimNextArtifactProcessingSnapshotSkipsCompleteSnapshotsWithoutClaimableArtifactsUntilArtifactArrives(t *testing.T) {
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
	txQueries := queries.WithTx(tx)
	snapshotID := createSnapshotForArtifactTest(t, ctx, txQueries)
	if _, err := tx.ExecContext(ctx, `UPDATE snapshots SET created_at = TIMESTAMP '2000-01-01 00:00:00+00' WHERE id = $1`, snapshotID); err != nil {
		t.Fatalf("make target oldest snapshot: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE snapshots
		SET artifact_processing_finished_at = NOW(),
			artifact_processing_claimed_by = NULL,
			artifact_processing_claim_expires_at = NULL
		WHERE id <> $1
	`, snapshotID); err != nil {
		t.Fatalf("quarantine unrelated snapshots: %v", err)
	}

	claimed, err := txQueries.ClaimNextArtifactProcessingSnapshot(ctx, "worker-a", time.Now().Add(5*time.Minute), 3)
	if err != nil {
		t.Fatalf("ClaimNextArtifactProcessingSnapshot(without artifacts) error = %v", err)
	}
	if claimed != nil && claimed.ID == snapshotID {
		t.Fatalf("claimed target snapshot = %#v, want target to stay unclaimed before claimable artifact exists", claimed)
	}
	target, err := txQueries.GetSnapshotByID(ctx, snapshotID)
	if err != nil {
		t.Fatalf("GetSnapshotByID(before artifact): %v", err)
	}
	if target.ArtifactProcessingClaimedBy != nil {
		t.Fatalf("target claim owner before artifact = %#v, want nil", target.ArtifactProcessingClaimedBy)
	}
	if target.ArtifactProcessingAttempts != 0 {
		t.Fatalf("target artifact_processing_attempts before artifact = %d, want 0", target.ArtifactProcessingAttempts)
	}
	if claimed != nil {
		if _, err := db.ExecContext(ctx, `
			UPDATE snapshots
			SET artifact_processing_finished_at = NOW(),
				artifact_processing_claimed_by = NULL,
				artifact_processing_claim_expires_at = NULL
			WHERE id = $1
		`, claimed.ID); err != nil {
			t.Fatalf("finish unrelated claimed snapshot: %v", err)
		}
	}

	format := "cyclonedx-json"
	if _, err := txQueries.CreateSnapshotArtifact(ctx, CreateSnapshotArtifactParams{
		SnapshotID: snapshotID,
		Kind:       "sbom",
		Format:     &format,
		ObjectKey:  "snapshots/" + snapshotID.String() + "/sbom.json",
		SizeBytes:  64,
	}); err != nil {
		t.Fatalf("CreateSnapshotArtifact(sbom) error = %v", err)
	}

	for attempt := 0; attempt < 10; attempt++ {
		claimed, err = txQueries.ClaimNextArtifactProcessingSnapshot(ctx, "worker-a", time.Now().Add(5*time.Minute), 3)
		if err != nil {
			t.Fatalf("ClaimNextArtifactProcessingSnapshot(with artifact, attempt %d) error = %v", attempt+1, err)
		}
		if claimed != nil && claimed.ID == snapshotID {
			return
		}
		if claimed == nil {
			continue
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE snapshots
			SET artifact_processing_finished_at = NOW(),
				artifact_processing_claimed_by = NULL,
				artifact_processing_claim_expires_at = NULL
			WHERE id = $1
		`, claimed.ID); err != nil {
			t.Fatalf("finish unrelated claimed snapshot during retry %d: %v", attempt+1, err)
		}
	}
	t.Fatalf("target snapshot %s was never claimed after claimable artifact arrived", snapshotID)
}

func TestReleaseArtifactProcessingClaimsReleasesOnlyMatchingWorkerActiveClaims(t *testing.T) {
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
	releasedID := createSnapshotForArtifactTest(t, ctx, queries)
	otherWorkerID := createSnapshotForArtifactTest(t, ctx, queries)
	finishedID := createSnapshotForArtifactTest(t, ctx, queries)

	// Release is scoped by worker id, not by row, so literal "worker-a" would
	// also release rows seeded by other packages running against this same
	// database — and theirs would release ours. Unique ids per run instead.
	workerA := "worker-a-" + uuid.NewString()[:8]
	workerB := "worker-b-" + uuid.NewString()[:8]

	claimExpiry := time.Now().Add(5 * time.Minute)
	if _, err := db.ExecContext(ctx, `
		UPDATE snapshots
		SET artifact_processing_claimed_by = $3,
			artifact_processing_claim_expires_at = $2,
			artifact_processing_finished_at = NULL,
			status = 'complete'
		WHERE id = $1
	`, releasedID, claimExpiry, workerA); err != nil {
		t.Fatalf("seed released claim: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		UPDATE snapshots
		SET artifact_processing_claimed_by = $3,
			artifact_processing_claim_expires_at = $2,
			artifact_processing_finished_at = NULL,
			status = 'complete'
		WHERE id = $1
	`, otherWorkerID, claimExpiry, workerB); err != nil {
		t.Fatalf("seed other worker claim: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		UPDATE snapshots
		SET artifact_processing_claimed_by = $3,
			artifact_processing_claim_expires_at = $2,
			artifact_processing_finished_at = NOW(),
			status = 'failed'
		WHERE id = $1
	`, finishedID, claimExpiry, workerA); err != nil {
		t.Fatalf("seed finished claim: %v", err)
	}

	released, err := queries.ReleaseArtifactProcessingClaims(ctx, workerA)
	if err != nil {
		t.Fatalf("ReleaseArtifactProcessingClaims() error = %v", err)
	}
	if released != 1 {
		t.Fatalf("ReleaseArtifactProcessingClaims() = %d, want 1", released)
	}

	releasedSnapshot, err := queries.GetSnapshotByID(ctx, releasedID)
	if err != nil {
		t.Fatalf("GetSnapshotByID(released): %v", err)
	}
	if releasedSnapshot.ArtifactProcessingClaimedBy != nil || releasedSnapshot.ArtifactProcessingClaimExpiresAt != nil {
		t.Fatalf("released snapshot claim = %#v / %#v, want nil", releasedSnapshot.ArtifactProcessingClaimedBy, releasedSnapshot.ArtifactProcessingClaimExpiresAt)
	}

	otherSnapshot, err := queries.GetSnapshotByID(ctx, otherWorkerID)
	if err != nil {
		t.Fatalf("GetSnapshotByID(other): %v", err)
	}
	if otherSnapshot.ArtifactProcessingClaimedBy == nil || *otherSnapshot.ArtifactProcessingClaimedBy != workerB {
		t.Fatalf("other worker claim = %#v, want %s", otherSnapshot.ArtifactProcessingClaimedBy, workerB)
	}

	finishedSnapshot, err := queries.GetSnapshotByID(ctx, finishedID)
	if err != nil {
		t.Fatalf("GetSnapshotByID(finished): %v", err)
	}
	if finishedSnapshot.ArtifactProcessingClaimedBy == nil || *finishedSnapshot.ArtifactProcessingClaimedBy != workerA {
		t.Fatalf("finished claim = %#v, want preserved %s", finishedSnapshot.ArtifactProcessingClaimedBy, workerA)
	}
}

func TestRenewArtifactProcessingSnapshotClaimRequiresOwner(t *testing.T) {
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
	if _, err := queries.CreateSnapshotArtifact(ctx, CreateSnapshotArtifactParams{
		SnapshotID: snapshotID,
		Kind:       "sbom",
		Format:     &format,
		ObjectKey:  "snapshots/" + snapshotID.String() + "/sbom.json",
		SizeBytes:  64,
	}); err != nil {
		t.Fatalf("CreateSnapshotArtifact(sbom) error = %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		UPDATE snapshots s
		SET artifact_processing_finished_at = NOW()
		WHERE s.id <> $1
			AND EXISTS (
				SELECT 1
				FROM snapshot_artifacts sa
				WHERE sa.snapshot_id = s.id
					AND sa.kind IN ('sbom', 'sarif')
			)
	`, snapshotID); err != nil {
		t.Fatalf("quarantine unrelated claimable snapshots: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		UPDATE snapshots
		SET artifact_processing_claimed_by = 'worker-a',
			artifact_processing_claim_expires_at = $2,
			artifact_processing_finished_at = NULL,
			status = 'complete'
		WHERE id = $1
	`, snapshotID, time.Now().Add(5*time.Minute)); err != nil {
		t.Fatalf("seed active claim: %v", err)
	}

	renewed, err := queries.RenewArtifactProcessingSnapshotClaim(ctx, snapshotID, "worker-b", time.Now().Add(10*time.Minute))
	if err != nil {
		t.Fatalf("RenewArtifactProcessingSnapshotClaim(non-owner) error = %v", err)
	}
	if renewed != 0 {
		t.Fatalf("RenewArtifactProcessingSnapshotClaim(non-owner) = %d, want 0", renewed)
	}

	snapshot, err := queries.GetSnapshotByID(ctx, snapshotID)
	if err != nil {
		t.Fatalf("GetSnapshotByID: %v", err)
	}
	if snapshot.ArtifactProcessingClaimedBy == nil || *snapshot.ArtifactProcessingClaimedBy != "worker-a" {
		t.Fatalf("claim owner = %#v, want worker-a", snapshot.ArtifactProcessingClaimedBy)
	}
}

func TestExpiredArtifactProcessingClaimCanBeReclaimed(t *testing.T) {
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

	// ClaimNextArtifactProcessingSnapshot claims the globally-oldest eligible
	// snapshot. The hibou_test database is shared across packages, so other
	// tests' committed snapshots would be claimed instead of this one. Isolate
	// inside a rolled-back transaction, lock the tables, and quarantine every
	// other snapshot -- same pattern as
	// TestClaimNextArtifactProcessingSnapshotSkipsClaimedRowsAndStopsAfterFinishedFailure.
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
	txQueries := queries.WithTx(tx)

	snapshotID := createSnapshotForArtifactTest(t, ctx, txQueries)
	format := "cyclonedx-json"
	if _, err := txQueries.CreateSnapshotArtifact(ctx, CreateSnapshotArtifactParams{
		SnapshotID: snapshotID,
		Kind:       "sbom",
		Format:     &format,
		ObjectKey:  "snapshots/" + snapshotID.String() + "/sbom.json",
		SizeBytes:  64,
	}); err != nil {
		t.Fatalf("CreateSnapshotArtifact(sbom) error = %v", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE snapshots
		SET artifact_processing_finished_at = NOW()
		WHERE id <> $1
	`, snapshotID); err != nil {
		t.Fatalf("quarantine unrelated snapshots: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE snapshots
		SET artifact_processing_claimed_by = 'worker-a',
			artifact_processing_claim_expires_at = NOW() - INTERVAL '1 minute',
			artifact_processing_finished_at = NULL,
			status = 'complete'
		WHERE id = $1
	`, snapshotID); err != nil {
		t.Fatalf("seed expired claim: %v", err)
	}

	claimed, err := txQueries.ClaimNextArtifactProcessingSnapshot(ctx, "worker-b", time.Now().Add(5*time.Minute), 3)
	if err != nil {
		t.Fatalf("ClaimNextArtifactProcessingSnapshot(reclaim) error = %v", err)
	}
	if claimed == nil || claimed.ID != snapshotID {
		t.Fatalf("reclaimed snapshot = %#v, want %s", claimed, snapshotID)
	}
	if claimed.ArtifactProcessingClaimedBy == nil || *claimed.ArtifactProcessingClaimedBy != "worker-b" {
		t.Fatalf("reclaimed owner = %#v, want worker-b", claimed.ArtifactProcessingClaimedBy)
	}
	if claimed.ArtifactProcessingAttempts != 1 {
		t.Fatalf("artifact_processing_attempts = %d, want 1 after reclaim", claimed.ArtifactProcessingAttempts)
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

func finishOtherSnapshotsForArtifactProcessingTest(ctx context.Context, db *sql.DB, keepSnapshotID uuid.UUID) error {
	_, err := db.ExecContext(ctx, `
		UPDATE snapshots
		SET artifact_processing_finished_at = NOW(),
			artifact_processing_claimed_by = NULL,
			artifact_processing_claim_expires_at = NULL
		WHERE id <> $1
	`, keepSnapshotID)
	return err
}
