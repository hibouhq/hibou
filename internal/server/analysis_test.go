package server

import (
	"context"
	"testing"

	"github.com/hibouhq/hibou/internal/store"
)

func TestResolveSnapshotForRepoPrefersLatestFinishedSnapshot(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	repo := createRepository(t, srv, org, repoSeed{
		name:          uniqueName(t, "analysis-repo"),
		slug:          uniqueName(t, "analysis-repo"),
		provider:      "github",
		providerID:    uniqueName(t, "analysis-provider"),
		defaultBranch: "main",
	})
	ref, err := srv.queries.CreateRef(context.Background(), repo.ID, "main", store.RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	completeSnapshot, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, "complete-sha", store.SnapshotStatusComplete)
	if err != nil {
		t.Fatalf("CreateSnapshot(complete): %v", err)
	}
	if _, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, "pending-sha", store.SnapshotStatusPending); err != nil {
		t.Fatalf("CreateSnapshot(pending): %v", err)
	}

	_, snapshot, err := srv.resolveSnapshotForRepo(newOrgRequest(t, admin, "GET", "/", repo.Provider, org.Slug), repo, "main")
	if err != nil {
		t.Fatalf("resolveSnapshotForRepo: %v", err)
	}
	if snapshot == nil {
		t.Fatal("expected snapshot")
	}
	if snapshot.ID != completeSnapshot.ID {
		t.Fatalf("snapshot id = %s, want %s", snapshot.ID, completeSnapshot.ID)
	}
}

func TestResolveSnapshotForRepoFallsBackToLatestPendingSnapshot(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	repo := createRepository(t, srv, org, repoSeed{
		name:          uniqueName(t, "analysis-repo"),
		slug:          uniqueName(t, "analysis-repo"),
		provider:      "github",
		providerID:    uniqueName(t, "analysis-provider"),
		defaultBranch: "main",
	})
	ref, err := srv.queries.CreateRef(context.Background(), repo.ID, "main", store.RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	pendingSnapshot, err := srv.queries.CreateSnapshot(context.Background(), ref.ID, "pending-sha", store.SnapshotStatusPending)
	if err != nil {
		t.Fatalf("CreateSnapshot(pending): %v", err)
	}

	_, snapshot, err := srv.resolveSnapshotForRepo(newOrgRequest(t, admin, "GET", "/", repo.Provider, org.Slug), repo, "main")
	if err != nil {
		t.Fatalf("resolveSnapshotForRepo: %v", err)
	}
	if snapshot == nil {
		t.Fatal("expected snapshot")
	}
	if snapshot.ID != pendingSnapshot.ID {
		t.Fatalf("snapshot id = %s, want %s", snapshot.ID, pendingSnapshot.ID)
	}
}
