package server

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/store"
)

// A pipeline that dies before uploading leaves a pending snapshot no upload will
// ever complete. Until the build event existed, hibou heard nothing about it and
// the chip stayed in-progress until the stale-pending window closed.
func TestBuildFailureFailsPendingSnapshotImmediately(t *testing.T) {
	srv, org, _, _ := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)
	ctx := context.Background()
	ref, err := srv.queries.CreateRef(ctx, repo.ID, "main", store.RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	commit := uuid.NewString()
	pending, err := srv.queries.CreateSnapshot(ctx, ref.ID, commit, store.SnapshotStatusPending)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}

	event := forge.BuildEvent{
		Repo:       forge.Repository{ProviderID: repo.ProviderID, FullName: repo.Slug},
		CommitSHA:  commit,
		Succeeded:  false,
		Conclusion: "failure",
	}
	if err := srv.handleBuildWebhookEvent(ctx, repo.Provider, event); err != nil {
		t.Fatalf("handleBuildWebhookEvent: %v", err)
	}
	assertStatus(t, srv, pending.ID, store.SnapshotStatusFailed)
}

// A successful run completes its own snapshot by uploading; touching it here
// would race the upload and fail a build that worked.
func TestBuildSuccessLeavesSnapshotsAlone(t *testing.T) {
	srv, org, _, _ := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)
	ctx := context.Background()
	ref, err := srv.queries.CreateRef(ctx, repo.ID, "main", store.RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	commit := uuid.NewString()
	pending, err := srv.queries.CreateSnapshot(ctx, ref.ID, commit, store.SnapshotStatusPending)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}

	if err := srv.handleBuildWebhookEvent(ctx, repo.Provider, forge.BuildEvent{
		Repo:      forge.Repository{ProviderID: repo.ProviderID},
		CommitSHA: commit,
		Succeeded: true,
	}); err != nil {
		t.Fatalf("handleBuildWebhookEvent: %v", err)
	}
	assertStatus(t, srv, pending.ID, store.SnapshotStatusPending)
}

// Artifacts already uploaded are worth keeping. The build's outcome says nothing
// about scan results that arrived before it died, and failing them would discard
// findings somebody's gate may already have acted on.
func TestBuildFailureLeavesProcessingSnapshotsAlone(t *testing.T) {
	srv, org, _, _ := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)
	ctx := context.Background()
	ref, err := srv.queries.CreateRef(ctx, repo.ID, "main", store.RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	commit := uuid.NewString()
	processing, err := srv.queries.CreateSnapshot(ctx, ref.ID, commit, store.SnapshotStatusProcessing)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}

	if err := srv.handleBuildWebhookEvent(ctx, repo.Provider, forge.BuildEvent{
		Repo:       forge.Repository{ProviderID: repo.ProviderID},
		CommitSHA:  commit,
		Conclusion: "failure",
	}); err != nil {
		t.Fatalf("handleBuildWebhookEvent: %v", err)
	}
	assertStatus(t, srv, processing.ID, store.SnapshotStatusProcessing)
}

// Two runs on one commit: a failing run must not fail the other run's snapshot.
func TestBuildFailureIsScopedToItsRun(t *testing.T) {
	srv, org, _, _ := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)
	ctx := context.Background()
	ref, err := srv.queries.CreateRef(ctx, repo.ID, "main", store.RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	commit := uuid.NewString()
	// Distinct run ids up front: snapshots are unique per build identity.
	mine, err := srv.queries.CreateSnapshot(ctx, ref.ID, commit, store.SnapshotStatusPending)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	if _, err := srv.db.ExecContext(ctx, `UPDATE snapshots SET run_id='111' WHERE id=$1`, mine.ID); err != nil {
		t.Fatal(err)
	}
	theirs, err := srv.queries.CreateSnapshot(ctx, ref.ID, commit, store.SnapshotStatusPending)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	if _, err := srv.db.ExecContext(ctx, `UPDATE snapshots SET run_id='222' WHERE id=$1`, theirs.ID); err != nil {
		t.Fatal(err)
	}

	if err := srv.handleBuildWebhookEvent(ctx, repo.Provider, forge.BuildEvent{
		Repo:       forge.Repository{ProviderID: repo.ProviderID},
		CommitSHA:  commit,
		RunID:      "111",
		Conclusion: "failure",
	}); err != nil {
		t.Fatalf("handleBuildWebhookEvent: %v", err)
	}
	assertStatus(t, srv, mine.ID, store.SnapshotStatusFailed)
	assertStatus(t, srv, theirs.ID, store.SnapshotStatusPending)
}
