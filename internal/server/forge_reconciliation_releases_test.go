package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/store"
)

func TestForgePollingRetagAndRemovalPreserveShippedHistory(t *testing.T) {
	srv, repo, remote := newReconciliationFixture(t)
	ctx := context.Background()
	oldSHA, newSHA := strings.Repeat("a", 40), strings.Repeat("b", 40)
	ref, err := srv.queries.UpsertRef(ctx, repo.ID, "v1.0.0", store.RefTypeTag, store.UpsertRefOptions{LatestCommitSHA: &oldSHA})
	if err != nil {
		t.Fatal(err)
	}
	old, err := srv.queries.CreateSnapshot(ctx, ref.ID, oldSHA, store.SnapshotStatusComplete)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.reconcileReleaseSnapshot(ctx, old.ID); err != nil {
		t.Fatal(err)
	}
	release, err := srv.queries.GetReleaseByRepoVersion(ctx, repo.ID, ref.Name)
	if err != nil || release == nil {
		t.Fatalf("release=%+v %v", release, err)
	}
	empty := json.RawMessage(`{}`)
	client, err := srv.queries.CreateClient(ctx, repo.OrgID, "Customer", "customer", empty, "external", nil, nil, empty, empty)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.queries.CreateDeployment(ctx, client.ID, release.ID, "production", store.DeploymentStatusActive, time.Now(), nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	newer, err := srv.queries.CreateSnapshot(ctx, ref.ID, newSHA, store.SnapshotStatusComplete)
	if err != nil {
		t.Fatal(err)
	}
	remote.refs = []forge.RefObservation{{Name: ref.Name, SHA: newSHA, Tag: true}}
	if err := reconcileTestScope(t, srv, repo, "refs"); err != nil {
		t.Fatal(err)
	}
	release, err = srv.queries.GetReleaseByRepoVersion(ctx, repo.ID, ref.Name)
	if err != nil || release.SnapshotID == nil || *release.SnapshotID != old.ID || release.PendingSnapshotID == nil || *release.PendingSnapshotID != newer.ID {
		t.Fatalf("retag rewrote shipped identity: %+v %v", release, err)
	}
	remote.refs = nil
	if err := reconcileTestScope(t, srv, repo, "refs"); err != nil {
		t.Fatal(err)
	}
	release, err = srv.queries.GetReleaseByRepoVersion(ctx, repo.ID, ref.Name)
	if err != nil || release == nil || *release.SnapshotID != old.ID {
		t.Fatalf("tag removal destroyed rollout history: %+v %v", release, err)
	}
}
