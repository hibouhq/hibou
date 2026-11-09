package server

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/delta"
	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/store"
)

func TestPollModeUploadThroughPublishedGate(t *testing.T) {
	srv, repo, remote := newReconciliationFixture(t)
	ctx := context.Background()
	org, err := srv.queries.GetOrganizationByID(ctx, repo.OrgID)
	if err != nil {
		t.Fatal(err)
	}
	baseSHA, headSHA := strings.Repeat("a", 40), strings.Repeat("b", 40)
	base, err := srv.queries.UpsertRef(ctx, repo.ID, "main", store.RefTypeBranch, store.UpsertRefOptions{LatestCommitSHA: &baseSHA})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.queries.CreateSnapshot(ctx, base.ID, baseSHA, store.SnapshotStatusComplete); err != nil {
		t.Fatal(err)
	}
	srv.deltaSvc = delta.NewService(delta.NewStoreAdapter(srv.queries), srv.log)
	srv.gatePublisher = forge.NewGatePublisher(srv.forges, srv.deltaSvc, srv.bus, forge.NewGatePublisherStoreAdapter(srv.queries), nil, nil, "https://private.example", srv.log)
	remote.prs = []forge.PullRequestEvent{{Number: 42, Action: "opened", HeadSHA: headSHA, BaseSHA: baseSHA, SourceBranch: "feature", TargetBranch: "main"}}
	if err := reconcileTestScope(t, srv, repo, "pull_requests"); err != nil {
		t.Fatal(err)
	}
	// No webhook is delivered: the private runner uses the existing upload
	// contract, including separate head/checked-out merge provenance.
	response := performUploadAuto(t, srv, remote.admin, uploadPayloadForTest(org.Slug, repo.Slug, minimalSARIFForTest(), map[string]any{
		"provider": repo.Provider, "ref": "refs/pull/42/merge", "commit_sha": headSHA,
		"merge_commit_sha": strings.Repeat("c", 40), "base_commit_sha": baseSHA,
		"pr_number": "42", "pr_target_branch": "main", "complete": true,
	}))
	srv.artifactWorkerID = "poll-e2e"
	snapshotID, err := uuid.Parse(response.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := srv.queries.GetSnapshotByID(ctx, snapshotID)
	if err != nil || snapshot == nil {
		t.Fatalf("uploaded snapshot=%+v %v", snapshot, err)
	}
	processArtifactSnapshotForTest(t, srv, snapshot.ID)
	ref, err := srv.queries.GetRefByRepoAndName(ctx, repo.ID, "refs/pull/42", store.RefTypePullRequest)
	if err != nil || ref == nil {
		t.Fatalf("canonical ref=%+v %v", ref, err)
	}
	srv.gatePublisher.PublishGateForRef(ctx, ref.ID)
	if len(remote.checks) == 0 {
		t.Fatal("no gate published through outbound forge API")
	}
	last := remote.checks[len(remote.checks)-1]
	if last.State != "success" {
		t.Fatalf("final gate=%+v, want success after uploaded clean analysis", last)
	}
	snapshot, err = srv.queries.GetSnapshotByID(ctx, snapshot.ID)
	if err != nil || snapshot.CommitSHA != headSHA || snapshot.MergeCommitSHA != strings.Repeat("c", 40) {
		t.Fatalf("provenance changed: %+v %v", snapshot, err)
	}
}
