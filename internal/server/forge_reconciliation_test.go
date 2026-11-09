package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/config"
	"github.com/hibouhq/hibou/internal/events"
	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/store"
)

type reconciliationTestForge struct {
	discoveryTestForgeProvider
	refs     []forge.RefObservation
	prs      []forge.PullRequestEvent
	releases []forge.ReleaseObservation
	run      forge.WorkflowRun
	readErr  error
	admin    *store.User
	checks   []forge.CommitStatus
}

func (f *reconciliationTestForge) CreateCommitStatus(_ context.Context, _, _, _ string, status forge.CommitStatus) error {
	f.checks = append(f.checks, status)
	return nil
}

func (f *reconciliationTestForge) ReadRefs(context.Context, string, string) ([]forge.RefObservation, error) {
	return f.refs, f.readErr
}
func (f *reconciliationTestForge) ReadOpenPullRequests(context.Context, string, string) ([]forge.PullRequestEvent, error) {
	return f.prs, f.readErr
}
func (f *reconciliationTestForge) ReadPullRequest(_ context.Context, _, _ string, n int) (forge.PullRequestEvent, error) {
	for _, pr := range f.prs {
		if pr.Number == n {
			return pr, f.readErr
		}
	}
	return forge.PullRequestEvent{}, errors.New("PR inaccessible")
}
func (f *reconciliationTestForge) ReadReleases(context.Context, string, string) ([]forge.ReleaseObservation, error) {
	return f.releases, f.readErr
}
func (f *reconciliationTestForge) ReadWorkflowRun(context.Context, string, string, string) (forge.WorkflowRun, error) {
	return f.run, f.readErr
}
func (f *reconciliationTestForge) ListInstallationRepositories(context.Context, int64) ([]forge.Repository, error) {
	return f.repositories, f.readErr
}

func TestPollModeRejectsWebhookEvenInDevelopment(t *testing.T) {
	srv := &Server{cfg: config.Config{Development: true, Forges: []config.ForgeConfig{{ID: "github", EventMode: "poll"}}}, forges: map[string]forge.Provider{"github": forge.NewGitHub("", "", "configured")}}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/github", strings.NewReader(`{}`))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("provider", "github")
	request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, rctx))
	response := httptest.NewRecorder()
	srv.handleWebhook(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func newReconciliationFixture(t *testing.T) (*Server, *store.Repository, *reconciliationTestForge) {
	t.Helper()
	srv, org, admin, _ := newDiscoveryTestServer(t)
	provider := uniqueName(t, "poll-provider")
	if _, err := srv.db.Exec(`UPDATE organizations SET provider=$2 WHERE id=$1`, org.ID, provider); err != nil {
		t.Fatal(err)
	}
	if err := srv.queries.SetOrganizationForgeAccount(context.Background(), org.ID, org.ID.String(), "acme"); err != nil {
		t.Fatal(err)
	}
	repo, err := srv.queries.CreateRepository(context.Background(), org.ID, nil, "app", "app", provider, "acme/app", "main", "active")
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.NewString()
	if _, err := srv.queries.UpsertForgeRepository(context.Background(), store.ForgeRepository{Provider: provider, ProviderRepoID: &id, Owner: "acme", AccountLogin: "acme", Name: "app", FullName: "acme/app", DefaultBranch: "main"}); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.db.Exec(`UPDATE forge_repositories SET account_id=$2 WHERE provider=$1`, provider, org.ID.String()); err != nil {
		t.Fatal(err)
	}
	if err := srv.queries.CaptureForgeRepositoryBinding(context.Background(), repo.ID); err != nil {
		t.Fatal(err)
	}
	fake := &reconciliationTestForge{discoveryTestForgeProvider: discoveryTestForgeProvider{id: "github"}, admin: admin}
	srv.forges = map[string]forge.Provider{provider: fake}
	srv.cfg.Forges = []config.ForgeConfig{{ID: provider, Type: "github", EventMode: "poll", PollInterval: time.Minute, InventoryInterval: 5 * time.Minute}}
	srv.cfg.SecretScan = config.SecretScanConfig{Enabled: true, OnPush: true}
	srv.bus = events.New(srv.log)
	t.Cleanup(func() { _, _ = srv.db.Exec(`DELETE FROM organizations WHERE id=$1`, org.ID) })
	return srv, repo, fake
}

func reconcileTestScope(t *testing.T, srv *Server, repo *store.Repository, kind string) error {
	t.Helper()
	ctx := context.Background()
	id := uuid.NullUUID{UUID: repo.ID, Valid: true}
	if err := srv.queries.EnsureForgeReconciliation(ctx, repo.Provider, repo.ID.String(), kind, id); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.db.Exec(`UPDATE forge_reconciliation SET next_due_at=now()-interval '1 second' WHERE provider=$1 AND kind=$2`, repo.Provider, kind); err != nil {
		t.Fatal(err)
	}
	job, err := srv.queries.ClaimForgeReconciliation(ctx, []string{repo.Provider}, uuid.New(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if job == nil {
		t.Fatal("no claimed scope")
	}
	err = srv.reconcileForgeScope(ctx, job)
	if err != nil {
		if finishErr := srv.queries.FinishForgeReconciliation(ctx, job, job.State, time.Now(), err.Error()); finishErr != nil {
			t.Fatal(finishErr)
		}
	}
	return err
}

func TestForgePollingRefIdempotencyAndAtomicFailure(t *testing.T) {
	srv, repo, fake := newReconciliationFixture(t)
	ctx := context.Background()
	head := strings.Repeat("a", 40)
	fake.refs = []forge.RefObservation{{Name: "main", SHA: head}}
	if err := reconcileTestScope(t, srv, repo, "refs"); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := srv.db.QueryRow(`SELECT count(*) FROM secret_scan_jobs WHERE repo_id=$1`, repo.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("secret jobs=%d", count)
	}
	// Even after a job leaves pending, unchanged polls must not re-enqueue.
	if _, err := srv.db.Exec(`UPDATE secret_scan_jobs SET status='complete',finished_at=now() WHERE repo_id=$1`, repo.ID); err != nil {
		t.Fatal(err)
	}
	if err := reconcileTestScope(t, srv, repo, "refs"); err != nil {
		t.Fatal(err)
	}
	if err := srv.db.QueryRow(`SELECT count(*) FROM secret_scan_jobs WHERE repo_id=$1`, repo.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("duplicate jobs=%d err=%v", count, err)
	}
	// An invalid later observation rolls back an earlier head and enqueue.
	fake.refs = []forge.RefObservation{{Name: "main", SHA: strings.Repeat("b", 40)}, {Name: "invalid", SHA: "bad"}}
	if err := reconcileTestScope(t, srv, repo, "refs"); err == nil {
		t.Fatal("invalid batch succeeded")
	}
	ref, err := srv.queries.GetRefByRepoAndName(ctx, repo.ID, "main", store.RefTypeBranch)
	if err != nil || ref == nil || *ref.LatestCommitSHA != head {
		t.Fatalf("partial head committed: %+v %v", ref, err)
	}
	fake.readErr = errors.New("page 2 unavailable")
	if err := reconcileTestScope(t, srv, repo, "refs"); err == nil {
		t.Fatal("partial listing succeeded")
	}
	ref, err = srv.queries.GetRefByRepoAndName(ctx, repo.ID, "main", store.RefTypeBranch)
	if err != nil || ref.LatestCommitSHA == nil {
		t.Fatal("incomplete listing retired the ref")
	}
}

func TestForgePollingPRLifecycleAndUploadCannotRegressHead(t *testing.T) {
	srv, repo, fake := newReconciliationFixture(t)
	ctx := context.Background()
	pr := forge.PullRequestEvent{Number: 42, Action: "opened", HeadSHA: strings.Repeat("a", 40), BaseSHA: strings.Repeat("b", 40), SourceBranch: "feature", TargetBranch: "main", Title: "Change"}
	fake.prs = []forge.PullRequestEvent{pr}
	if err := reconcileTestScope(t, srv, repo, "pull_requests"); err != nil {
		t.Fatal(err)
	}
	ref, err := srv.queries.GetRefByRepoAndName(ctx, repo.ID, "refs/pull/42", store.RefTypePullRequest)
	if err != nil || ref == nil {
		t.Fatalf("PR ref=%+v err=%v", ref, err)
	}
	// A later upload of an older merge/head build cannot claim lifecycle authority.
	old := strings.Repeat("c", 40)
	if _, err := srv.queries.UpsertRef(ctx, repo.ID, ref.Name, ref.RefType, store.UpsertRefOptions{LatestCommitSHA: &old}); err != nil {
		t.Fatal(err)
	}
	ref, err = srv.queries.GetRefByID(ctx, ref.ID)
	if err != nil || *ref.LatestCommitSHA != pr.HeadSHA {
		t.Fatalf("upload regressed authoritative head: %+v %v", ref, err)
	}
	base := strings.Repeat("d", 40)
	pr.BaseSHA = base
	fake.prs = []forge.PullRequestEvent{pr}
	if err := reconcileTestScope(t, srv, repo, "pull_requests"); err != nil {
		t.Fatal(err)
	}
	target, err := srv.queries.GetRefByID(ctx, *ref.MergeTargetRefID)
	if err != nil || *target.LatestCommitSHA != base {
		t.Fatalf("base did not advance: %+v %v", target, err)
	}
	closed := time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)
	pr.Action = "closed"
	pr.Merged = true
	pr.MergedAt = &closed
	pr.ClosedAt = &closed
	fake.prs = []forge.PullRequestEvent{pr}
	if err := reconcileTestScope(t, srv, repo, "pull_requests"); err != nil {
		t.Fatal(err)
	}
	ref, err = srv.queries.GetRefByID(ctx, ref.ID)
	if err != nil || ref.PrState == nil || *ref.PrState != "merged" || !ref.PrMergedAt.Equal(closed) {
		t.Fatalf("lifecycle=%+v err=%v", ref, err)
	}
	pr.Action = "opened"
	pr.Merged = false
	pr.MergedAt = nil
	pr.ClosedAt = nil
	fake.prs = []forge.PullRequestEvent{pr}
	if err := reconcileTestScope(t, srv, repo, "pull_requests"); err != nil {
		t.Fatal(err)
	}
	ref, err = srv.queries.GetRefByID(ctx, ref.ID)
	if err != nil || *ref.PrState != "open" || ref.PrMergedAt != nil {
		t.Fatalf("reopened=%+v err=%v", ref, err)
	}
}

func TestForgePollingSerializesHybridDeliveryAcrossConnections(t *testing.T) {
	srv, repo, _ := newReconciliationFixture(t)
	ctx := context.Background()
	first, err := srv.lockForgeDelivery(ctx, repo.Provider, true)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := srv.lockForgeDelivery(ctx, repo.Provider, true); err == nil {
		second()
		first()
		t.Fatal("two connections acquired the provider lock")
	}
	first()
	restarted, err := srv.lockForgeDelivery(ctx, repo.Provider, true)
	if err != nil {
		t.Fatal(err)
	}
	restarted()
}

func TestForgeReconciliationLeaseFencesTransaction(t *testing.T) {
	srv, repo, _ := newReconciliationFixture(t)
	ctx := context.Background()
	if err := srv.queries.EnsureForgeReconciliation(ctx, repo.Provider, "test", "refs", uuid.NullUUID{UUID: repo.ID, Valid: true}); err != nil {
		t.Fatal(err)
	}

	first, err := srv.queries.ClaimForgeReconciliation(ctx, []string{repo.Provider}, uuid.New(), time.Now())
	if err != nil || first == nil {
		t.Fatalf("claim=%+v %v", first, err)
	}
	if second, err := srv.queries.ClaimForgeReconciliation(ctx, []string{repo.Provider}, uuid.New(), time.Now()); err != nil || second != nil {
		t.Fatalf("duplicate claim=%+v %v", second, err)
	}
	if _, err := srv.db.Exec(`UPDATE forge_reconciliation SET claim_expires_at=now()-interval '1 second' WHERE id=$1`, first.ID); err != nil {
		t.Fatal(err)
	}
	tx, err := srv.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	q := srv.queries.WithTx(tx)
	if _, err := q.UpsertRef(ctx, repo.ID, "must-rollback", store.RefTypeBranch, store.UpsertRefOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := q.FinishForgeReconciliation(ctx, first, []byte(`{}`), time.Now(), ""); err == nil {
		t.Fatal("expired lease finished")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	ref, err := srv.queries.GetRefByRepoAndName(ctx, repo.ID, "must-rollback", store.RefTypeBranch)
	if err != nil || ref != nil {
		t.Fatalf("unfenced mutation persisted: %+v %v", ref, err)
	}
	reclaimed, err := srv.queries.ClaimForgeReconciliation(ctx, []string{repo.Provider}, uuid.New(), time.Now())
	if err != nil || reclaimed == nil {
		t.Fatalf("reclaim=%+v %v", reclaimed, err)
	}
}

func TestForgePollingInventoryRenameAndSuspension(t *testing.T) {
	srv, repo, fake := newReconciliationFixture(t)
	ctx := context.Background()
	inventory, err := srv.queries.GetForgeRepositoryByProviderKey(ctx, repo.Provider, "acme/app")
	if err != nil {
		t.Fatal(err)
	}
	fake.installations = []forge.Installation{{ID: 7, AccountID: repo.OrgID.String(), AccountName: "renamed"}}
	fake.repositories = []forge.Repository{{ProviderRepoID: *inventory.ProviderRepoID, Owner: "renamed", Name: "renamed-app", FullName: "renamed/renamed-app", DefaultBranch: "trunk"}}
	if err := reconcileTestScope(t, srv, repo, "inventory"); err != nil {
		t.Fatal(err)
	}
	current, err := srv.queries.GetForgeRepositoryByProviderRepoID(ctx, repo.Provider, *inventory.ProviderRepoID)
	if err != nil || current == nil || current.ID != inventory.ID {
		t.Fatalf("inventory identity changed: %+v %v", current, err)
	}
	enrolled, err := srv.queries.GetRepositoryByID(ctx, repo.ID)
	if err != nil || enrolled.ProviderID != "renamed/renamed-app" || enrolled.DefaultBranch != "trunk" {
		t.Fatalf("enrollment did not follow identity: %+v %v", enrolled, err)
	}
	fake.readErr = errors.New("repository page unavailable")
	if err := reconcileTestScope(t, srv, repo, "inventory"); err == nil {
		t.Fatal("incomplete inventory succeeded")
	}
	current, err = srv.queries.GetForgeRepositoryByProviderRepoID(ctx, repo.Provider, *inventory.ProviderRepoID)
	if err != nil || current == nil {
		t.Fatal("partial inventory removed repository")
	}
	fake.readErr = nil
	fake.installations[0].Suspended = true
	if err := reconcileTestScope(t, srv, repo, "inventory"); err != nil {
		t.Fatal(err)
	}
	current, err = srv.queries.GetForgeRepositoryByProviderRepoID(ctx, repo.Provider, *inventory.ProviderRepoID)
	if err != nil || current != nil {
		t.Fatalf("suspended inventory still active: %+v %v", current, err)
	}
	enrolled, err = srv.queries.GetRepositoryByID(ctx, repo.ID)
	if err != nil || enrolled == nil {
		t.Fatal("suspension destroyed enrollment/history")
	}
}

func TestForgePollingBuildMatchesRunAttemptAndCommit(t *testing.T) {
	srv, repo, fake := newReconciliationFixture(t)
	ctx := context.Background()
	ref, err := srv.queries.UpsertRef(ctx, repo.ID, "main", store.RefTypeBranch, store.UpsertRefOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ids := []uuid.UUID{}
	for i, identity := range []struct{ run, attempt string }{{"99", "1"}, {"99", "2"}, {"88", "2"}, {"", ""}} {
		sha := strings.Repeat(string(rune('a'+i)), 40)
		snapshot, err := srv.queries.CreateSnapshot(ctx, ref.ID, sha, store.SnapshotStatusPending)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := srv.db.Exec(`UPDATE snapshots SET run_id=NULLIF($2,''),run_attempt=NULLIF($3,'') WHERE id=$1`, snapshot.ID, identity.run, identity.attempt); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, snapshot.ID)
	}
	fake.run = forge.WorkflowRun{ID: "99", Attempt: "2", SHA: strings.Repeat("b", 40), Status: "completed", Conclusion: "cancelled"}
	if err := reconcileTestScope(t, srv, repo, "builds"); err != nil {
		t.Fatal(err)
	}
	for i, id := range ids {
		snapshot, err := srv.queries.GetSnapshotByID(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		expected := store.SnapshotStatusPending
		if i == 1 {
			expected = store.SnapshotStatusFailed
		}
		if snapshot.Status != expected {
			t.Fatalf("snapshot %d status=%s want=%s", i, snapshot.Status, expected)
		}
	}
}
