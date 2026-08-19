package server

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/hibouhq/hibou/internal/config"
	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/secretscan"
	"github.com/hibouhq/hibou/internal/store"
)

func secretScanTestConfig() config.Config {
	return config.Config{
		Worker: config.WorkerConfig{
			LeaseDuration:     time.Minute,
			HeartbeatInterval: 10 * time.Millisecond,
		},
		SecretScan: config.SecretScanConfig{
			Enabled:        true,
			OnPush:         true,
			MaxConcurrency: 1,
			Timeout:        time.Minute,
			MaxAttempts:    3,
			PollInterval:   time.Second,
		},
	}
}

func newSecretScanTestServer(t *testing.T) (*Server, *store.Organization) {
	t.Helper()
	srv, org, _, _ := newDiscoveryTestServer(t)
	srv.cfg = secretScanTestConfig()
	srv.artifactWorkerID = uniqueName(t, "worker")
	srv.secretScanner = secretscan.NewScanner(nil, srv.queries, nil, srv.log, "")
	srv.secretScanSlots = make(chan struct{}, srv.cfg.SecretScan.MaxConcurrency)
	return srv, org
}

func enqueueTestSecretScanJob(t *testing.T, srv *Server, org *store.Organization) *store.SecretScanJob {
	t.Helper()
	repo := createRepository(t, srv, org, repoSeed{
		name:          uniqueName(t, "secret-scan"),
		slug:          uniqueName(t, "secret-scan"),
		provider:      "github",
		providerID:    uniqueName(t, "secret-scan-provider"),
		defaultBranch: "main",
	})
	job, err := srv.queries.EnqueueSecretScanJob(context.Background(), store.EnqueueSecretScanJobParams{
		RepoID:   repo.ID,
		RefName:  "main",
		Mode:     store.SecretScanModeIncremental,
		ToCommit: "head-sha",
	})
	if err != nil {
		t.Fatalf("EnqueueSecretScanJob: %v", err)
	}
	return job
}

func claimTestSecretScanJob(t *testing.T, srv *Server) *store.SecretScanJob {
	t.Helper()
	job, err := srv.queries.ClaimNextSecretScanJob(context.Background(), srv.artifactWorkerID, time.Now().Add(time.Minute), int32(srv.cfg.SecretScan.MaxAttempts))
	if err != nil {
		t.Fatalf("ClaimNextSecretScanJob: %v", err)
	}
	if job == nil {
		t.Fatal("ClaimNextSecretScanJob returned no job")
	}
	return job
}

func withSecretScanHook(t *testing.T, hook func(ctx context.Context, srv *Server, job *store.SecretScanJob) error) {
	t.Helper()
	previous := secretScanExecuteHook
	secretScanExecuteHook = hook
	t.Cleanup(func() { secretScanExecuteHook = previous })
}

func TestProcessClaimedSecretScanJobCompletesOnSuccess(t *testing.T) {
	srv, org := newSecretScanTestServer(t)
	enqueueTestSecretScanJob(t, srv, org)
	job := claimTestSecretScanJob(t, srv)

	withSecretScanHook(t, func(context.Context, *Server, *store.SecretScanJob) error { return nil })
	srv.processClaimedSecretScanJob(context.Background(), job)

	after, err := srv.queries.GetSecretScanJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("GetSecretScanJob: %v", err)
	}
	if after.Status != store.SecretScanStatusComplete || after.FinishedAt == nil {
		t.Fatalf("job = %s/finished=%v, want complete and finished", after.Status, after.FinishedAt)
	}
}

func TestProcessClaimedSecretScanJobRetryableFailureStaysClaimable(t *testing.T) {
	srv, org := newSecretScanTestServer(t)
	enqueueTestSecretScanJob(t, srv, org)
	job := claimTestSecretScanJob(t, srv)

	withSecretScanHook(t, func(context.Context, *Server, *store.SecretScanJob) error {
		return errors.New("clone blew up")
	})
	srv.processClaimedSecretScanJob(context.Background(), job)

	after, err := srv.queries.GetSecretScanJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("GetSecretScanJob: %v", err)
	}
	if after.Status != store.SecretScanStatusFailed {
		t.Fatalf("status = %s, want failed", after.Status)
	}
	// attempts=1 < max=3: finished_at must stay unset so another worker retries.
	if after.FinishedAt != nil {
		t.Fatal("retryable failure was marked finished; the job would never retry")
	}
	if after.LastError != "clone blew up" {
		t.Fatalf("last_error = %q, want the cause recorded", after.LastError)
	}
}

func TestProcessClaimedSecretScanJobTerminalAtMaxAttempts(t *testing.T) {
	srv, org := newSecretScanTestServer(t)
	enqueueTestSecretScanJob(t, srv, org)
	job := claimTestSecretScanJob(t, srv)
	job.Attempts = int32(srv.cfg.SecretScan.MaxAttempts)

	withSecretScanHook(t, func(context.Context, *Server, *store.SecretScanJob) error {
		return errors.New("still failing")
	})
	srv.processClaimedSecretScanJob(context.Background(), job)

	after, err := srv.queries.GetSecretScanJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("GetSecretScanJob: %v", err)
	}
	if after.Status != store.SecretScanStatusFailed || after.FinishedAt == nil {
		t.Fatalf("job = %s/finished=%v, want terminally failed", after.Status, after.FinishedAt)
	}
}

func TestProcessClaimedSecretScanJobSkipCompletesWithoutRetry(t *testing.T) {
	srv, org := newSecretScanTestServer(t)
	enqueueTestSecretScanJob(t, srv, org)
	job := claimTestSecretScanJob(t, srv)

	withSecretScanHook(t, func(context.Context, *Server, *store.SecretScanJob) error {
		return fmt.Errorf("%w: repo too large", errSecretScanSkipped)
	})
	srv.processClaimedSecretScanJob(context.Background(), job)

	after, err := srv.queries.GetSecretScanJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("GetSecretScanJob: %v", err)
	}
	// Retrying a skip cannot change the outcome, so it must not burn attempts.
	if after.Status != store.SecretScanStatusComplete {
		t.Fatalf("status = %s, want complete", after.Status)
	}
}

func TestProcessClaimedSecretScanJobTimesOutHungScan(t *testing.T) {
	srv, org := newSecretScanTestServer(t)
	srv.cfg.SecretScan.Timeout = 30 * time.Millisecond
	enqueueTestSecretScanJob(t, srv, org)
	job := claimTestSecretScanJob(t, srv)

	withSecretScanHook(t, func(ctx context.Context, _ *Server, _ *store.SecretScanJob) error {
		<-ctx.Done()
		return ctx.Err()
	})
	srv.processClaimedSecretScanJob(context.Background(), job)

	after, err := srv.queries.GetSecretScanJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("GetSecretScanJob: %v", err)
	}
	if after.Status != store.SecretScanStatusFailed {
		t.Fatalf("status = %s, want failed after timeout", after.Status)
	}
}

// A worker whose claim was stolen must abandon: no Complete, no Fail, nothing
// written over the new owner.
func TestProcessClaimedSecretScanJobAbandonsWhenClaimLost(t *testing.T) {
	srv, org := newSecretScanTestServer(t)
	enqueueTestSecretScanJob(t, srv, org)
	job := claimTestSecretScanJob(t, srv)

	withSecretScanHook(t, func(ctx context.Context, hookSrv *Server, hookJob *store.SecretScanJob) error {
		if _, err := hookSrv.db.ExecContext(ctx, `UPDATE secret_scan_jobs SET claimed_by = 'thief' WHERE id = $1`, hookJob.ID); err != nil {
			return err
		}
		// The next heartbeat discovers the theft and cancels this context.
		<-ctx.Done()
		return ctx.Err()
	})
	srv.processClaimedSecretScanJob(context.Background(), job)

	after, err := srv.queries.GetSecretScanJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("GetSecretScanJob: %v", err)
	}
	if after.ClaimedBy == nil || *after.ClaimedBy != "thief" {
		t.Fatalf("claimed_by = %v, want the thief untouched", after.ClaimedBy)
	}
	if after.Status != store.SecretScanStatusProcessing {
		t.Fatalf("status = %s, want processing (owned by the new claimant)", after.Status)
	}
	if after.FinishedAt != nil {
		t.Fatal("abandoning worker finalized a job it no longer owns")
	}
}

func TestStartNextSecretScanJobRespectsConcurrencySlots(t *testing.T) {
	srv, org := newSecretScanTestServer(t)
	enqueueTestSecretScanJob(t, srv, org)

	// Fill the only slot: the loop must decline to claim, leaving the job for
	// another replica rather than stacking clones on this one.
	srv.secretScanSlots <- struct{}{}
	started, err := srv.startNextSecretScanJob(context.Background())
	if err != nil {
		t.Fatalf("startNextSecretScanJob: %v", err)
	}
	if started {
		t.Fatal("started a job with every slot busy")
	}
}

func TestResolveSecretScanSnapshotCreatesPendingPlaceholder(t *testing.T) {
	srv, org, _, _ := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)
	ctx := context.Background()

	commit := "scan-head-1"
	ref, err := srv.queries.UpsertRef(ctx, repo.ID, "main", store.RefTypeBranch, store.UpsertRefOptions{LatestCommitSHA: &commit})
	if err != nil {
		t.Fatalf("UpsertRef: %v", err)
	}

	job := &store.SecretScanJob{RepoID: repo.ID, RefName: "main", ToCommit: commit}
	snapshot, err := srv.resolveSecretScanSnapshot(ctx, job, nil, secretScanTarget{})
	if err != nil {
		t.Fatalf("resolveSecretScanSnapshot: %v", err)
	}
	// A scan-created snapshot must be a pending placeholder: a complete one
	// would shadow the ref's real latest analysis and block the CI upload
	// from adopting the row (duplicate snapshots per commit).
	if snapshot == nil || snapshot.Status != store.SnapshotStatusPending {
		t.Fatalf("scan snapshot = %#v, want pending placeholder", snapshot)
	}
	if snapshot.RefID != ref.ID || snapshot.CommitSHA != commit {
		t.Fatalf("scan snapshot targets %s@%s, want %s@%s", snapshot.RefID, snapshot.CommitSHA, ref.ID, commit)
	}

	// Scan-only repo (no upload history): the scan completes the placeholder
	// so its findings are readable.
	srv.completeScanOnlySnapshot(ctx, repo.ID, snapshot)
	stored, err := srv.queries.GetSnapshotByID(ctx, snapshot.ID)
	if err != nil {
		t.Fatalf("GetSnapshotByID: %v", err)
	}
	if stored == nil || stored.Status != store.SnapshotStatusComplete {
		t.Fatalf("scan-only snapshot status = %#v, want complete", stored)
	}
}

func TestCompleteScanOnlySnapshotLeavesPlaceholderForUploadingRepos(t *testing.T) {
	srv, org, _, _ := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)
	ctx := context.Background()

	commit := "scan-head-2"
	ref, err := srv.queries.UpsertRef(ctx, repo.ID, "main", store.RefTypeBranch, store.UpsertRefOptions{LatestCommitSHA: &commit})
	if err != nil {
		t.Fatalf("UpsertRef: %v", err)
	}

	// Upload history on an earlier commit: this repo's snapshots are finalized
	// by CI, so the scan must leave its placeholder pending for CI to adopt.
	earlier, err := srv.queries.CreateSnapshot(ctx, ref.ID, "earlier-commit", store.SnapshotStatusComplete)
	if err != nil {
		t.Fatalf("CreateSnapshot(earlier): %v", err)
	}
	if _, err := srv.queries.IncrementSnapshotReceivedUploads(ctx, earlier.ID); err != nil {
		t.Fatalf("IncrementSnapshotReceivedUploads: %v", err)
	}

	job := &store.SecretScanJob{RepoID: repo.ID, RefName: "main", ToCommit: commit}
	snapshot, err := srv.resolveSecretScanSnapshot(ctx, job, nil, secretScanTarget{})
	if err != nil {
		t.Fatalf("resolveSecretScanSnapshot: %v", err)
	}
	srv.completeScanOnlySnapshot(ctx, repo.ID, snapshot)

	stored, err := srv.queries.GetSnapshotByID(ctx, snapshot.ID)
	if err != nil {
		t.Fatalf("GetSnapshotByID: %v", err)
	}
	if stored == nil || stored.Status != store.SnapshotStatusPending {
		t.Fatalf("placeholder status = %#v, want pending until the CI upload adopts it", stored)
	}
}

func TestMaybeEnqueueSecretScanPushShapes(t *testing.T) {
	srv, org := newSecretScanTestServer(t)
	repo := createRepository(t, srv, org, repoSeed{
		name:          uniqueName(t, "push-shapes"),
		slug:          uniqueName(t, "push-shapes"),
		provider:      "github",
		providerID:    uniqueName(t, "push-shapes-provider"),
		defaultBranch: "main",
	})
	ctx := context.Background()

	jobsFor := func() []*store.SecretScanJob {
		t.Helper()
		jobs, err := srv.queries.ListSecretScanJobsByRepo(ctx, repo.ID, 10)
		if err != nil {
			t.Fatalf("ListSecretScanJobsByRepo: %v", err)
		}
		return jobs
	}

	// Branch deletion: nothing to scan.
	srv.maybeEnqueueSecretScan(ctx, repo, store.RefTypeBranch, "gone", forge.PushEvent{Before: "aaa", After: gitZeroSHA})
	// Tag push: out of scope.
	srv.maybeEnqueueSecretScan(ctx, repo, store.RefTypeTag, "v1.0.0", forge.PushEvent{Before: gitZeroSHA, After: "bbb"})
	if got := jobsFor(); len(got) != 0 {
		t.Fatalf("jobs after deletion+tag = %d, want 0", len(got))
	}

	// New branch: no base to diff against → full scan.
	srv.maybeEnqueueSecretScan(ctx, repo, store.RefTypeBranch, "feature", forge.PushEvent{Before: gitZeroSHA, After: "ccc"})
	// Ordinary push → incremental over the range.
	srv.maybeEnqueueSecretScan(ctx, repo, store.RefTypeBranch, "main", forge.PushEvent{Before: "ddd", After: "eee"})

	jobs := jobsFor()
	if len(jobs) != 2 {
		t.Fatalf("jobs = %d, want 2", len(jobs))
	}
	byRef := map[string]*store.SecretScanJob{}
	for _, job := range jobs {
		byRef[job.RefName] = job
	}
	if job := byRef["feature"]; job == nil || job.Mode != store.SecretScanModeFull || job.FromCommit != "" {
		t.Fatalf("new-branch job = %+v, want full scan with no base", job)
	}
	if job := byRef["main"]; job == nil || job.Mode != store.SecretScanModeIncremental || job.FromCommit != "ddd" || job.ToCommit != "eee" {
		t.Fatalf("push job = %+v, want incremental ddd..eee", job)
	}

	// Config off: enqueue must be inert.
	srv.cfg.SecretScan.OnPush = false
	srv.maybeEnqueueSecretScan(ctx, repo, store.RefTypeBranch, "other", forge.PushEvent{Before: "fff", After: "ggg"})
	if got := jobsFor(); len(got) != 2 {
		t.Fatalf("jobs after disabled push = %d, want still 2", len(got))
	}
}
