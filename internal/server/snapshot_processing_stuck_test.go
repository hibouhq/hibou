package server

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store"
)

// A snapshot that stops mid-processing on its last attempt is invisible to the
// claim query for ever after: that query only takes rows with
// attempts < max_attempts, so nothing re-claims it and nothing moves it off
// 'processing'. The UI then shows a run that died hours ago as in progress.
//
// Three ways in, none of which write a terminal status:
//   - abandoning on a lost claim or a cancelled context, which skips the
//     failure write entirely
//   - the worker dying mid-attempt
//   - the failure write itself losing the claim, so it matches no rows
func TestFinalizeUnreachableArtifactProcessing(t *testing.T) {
	srv, org, _, _ := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)
	ctx := context.Background()
	ref, err := srv.queries.CreateRef(ctx, repo.ID, "main", store.RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}

	stuck, err := srv.queries.CreateSnapshot(ctx, ref.ID, uuid.NewString(), store.SnapshotStatusProcessing)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	// Out of attempts, never finished, claim gone — exactly what a worker that
	// died on its final attempt leaves behind.
	if _, err := srv.db.ExecContext(ctx, `
		UPDATE snapshots
		SET artifact_processing_attempts = $2,
		    artifact_processing_started_at = NOW() - interval '2 hours',
		    artifact_processing_finished_at = NULL,
		    artifact_processing_claimed_by = NULL,
		    artifact_processing_claim_expires_at = NULL
		WHERE id = $1`, stuck.ID, artifactProcessingMaxAttempts); err != nil {
		t.Fatalf("stage the stuck row: %v", err)
	}

	// A snapshot still within its attempt budget must be left alone: it is
	// genuinely retryable, and finalizing it would discard work that would have
	// succeeded on the next pass.
	retryable, err := srv.queries.CreateSnapshot(ctx, ref.ID, uuid.NewString(), store.SnapshotStatusProcessing)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	if _, err := srv.db.ExecContext(ctx, `
		UPDATE snapshots SET artifact_processing_attempts = 1 WHERE id = $1`, retryable.ID); err != nil {
		t.Fatalf("stage the retryable row: %v", err)
	}

	// So must one a live worker is holding right now.
	held, err := srv.queries.CreateSnapshot(ctx, ref.ID, uuid.NewString(), store.SnapshotStatusProcessing)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	if _, err := srv.db.ExecContext(ctx, `
		UPDATE snapshots
		SET artifact_processing_attempts = $2,
		    artifact_processing_claimed_by = 'worker-a',
		    artifact_processing_claim_expires_at = NOW() + interval '5 minutes'
		WHERE id = $1`, held.ID, artifactProcessingMaxAttempts); err != nil {
		t.Fatalf("stage the held row: %v", err)
	}

	finalized, err := srv.queries.FinalizeUnreachableArtifactProcessing(ctx, artifactProcessingMaxAttempts)
	if err != nil {
		t.Fatalf("FinalizeUnreachableArtifactProcessing: %v", err)
	}
	if finalized != 1 {
		t.Fatalf("finalized %d snapshots, want only the unreachable one", finalized)
	}

	assertStatus(t, srv, stuck.ID, store.SnapshotStatusFailed)
	assertStatus(t, srv, retryable.ID, store.SnapshotStatusProcessing)
	assertStatus(t, srv, held.ID, store.SnapshotStatusProcessing)

	// The reason is recorded, so the finding is explicable rather than a bare
	// status flip nobody can account for.
	var reason string
	var finishedAt *string
	if err := srv.db.QueryRowContext(ctx, `
		SELECT artifact_processing_last_error, artifact_processing_finished_at::text
		FROM snapshots WHERE id = $1`, stuck.ID).Scan(&reason, &finishedAt); err != nil {
		t.Fatalf("read the finalized row: %v", err)
	}
	if reason == "" {
		t.Error("no reason recorded on a snapshot finalized by the reaper")
	}
	if finishedAt == nil {
		t.Error("finished_at still null, so the claim query would keep skipping it")
	}

	// Idempotent: a second pass has nothing left to do.
	again, err := srv.queries.FinalizeUnreachableArtifactProcessing(ctx, artifactProcessingMaxAttempts)
	if err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if again != 0 {
		t.Errorf("second pass finalized %d rows, want 0", again)
	}
}

func assertStatus(t *testing.T, srv *Server, snapshotID uuid.UUID, want store.SnapshotStatus) {
	t.Helper()
	var got string
	if err := srv.db.QueryRowContext(context.Background(),
		`SELECT status FROM snapshots WHERE id = $1`, snapshotID).Scan(&got); err != nil {
		t.Fatalf("read status: %v", err)
	}
	if got != string(want) {
		t.Errorf("snapshot %s status = %q, want %q", snapshotID, got, want)
	}
}
