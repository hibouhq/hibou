package store

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

func openSecretScanTestDB(t *testing.T) *sql.DB {
	t.Helper()

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
		t.Skipf("database not available for secret scan job test: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})

	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate() returned error: %v", err)
	}

	return db
}

func createRepoForSecretScanTest(t *testing.T, ctx context.Context, queries *Queries) uuid.UUID {
	t.Helper()

	org, err := queries.CreateOrganization(ctx, uniqueStoreTestName(t, "org"), uniqueStoreTestName(t, "org"), "Secret Scan Org", "github")
	if err != nil {
		t.Fatalf("CreateOrganization() error = %v", err)
	}
	repo, err := queries.CreateRepository(ctx, org.ID, nil, uniqueStoreTestName(t, "repo"), uniqueStoreTestName(t, "repo"), "github", uniqueStoreTestName(t, "provider"), "main", "enrolled")
	if err != nil {
		t.Fatalf("CreateRepository() error = %v", err)
	}

	return repo.ID
}

// A push burst on one branch must cost one clone, not one per push: the pending
// row absorbs the new head while keeping the oldest unscanned commit.
func TestEnqueueSecretScanJobCoalescesPushBurst(t *testing.T) {
	db := openSecretScanTestDB(t)
	ctx := context.Background()
	queries := NewQueries(db)
	repoID := createRepoForSecretScanTest(t, ctx, queries)

	first, err := queries.EnqueueSecretScanJob(ctx, EnqueueSecretScanJobParams{
		RepoID:     repoID,
		RefName:    "refs/heads/main",
		Mode:       SecretScanModeIncremental,
		FromCommit: "aaa",
		ToCommit:   "bbb",
	})
	if err != nil {
		t.Fatalf("EnqueueSecretScanJob(first) error = %v", err)
	}

	second, err := queries.EnqueueSecretScanJob(ctx, EnqueueSecretScanJobParams{
		RepoID:     repoID,
		RefName:    "refs/heads/main",
		Mode:       SecretScanModeIncremental,
		FromCommit: "bbb",
		ToCommit:   "ccc",
	})
	if err != nil {
		t.Fatalf("EnqueueSecretScanJob(second) error = %v", err)
	}

	if second.ID != first.ID {
		t.Fatalf("second enqueue created job %s, want the pending job %s reused", second.ID, first.ID)
	}
	// Range must widen to aaa..ccc — taking bbb..ccc would skip whatever the
	// first push introduced.
	if second.FromCommit != "aaa" {
		t.Fatalf("from_commit = %q, want the earliest unscanned commit %q", second.FromCommit, "aaa")
	}
	if second.ToCommit != "ccc" {
		t.Fatalf("to_commit = %q, want the newest head %q", second.ToCommit, "ccc")
	}

	jobs, err := queries.ListSecretScanJobsByRepo(ctx, repoID, 10)
	if err != nil {
		t.Fatalf("ListSecretScanJobsByRepo() error = %v", err)
	}
	if len(jobs) != 1 {
		t.Fatalf("job count = %d, want 1 coalesced job", len(jobs))
	}
}

func TestEnqueueSecretScanJobKeepsModesAndRefsSeparate(t *testing.T) {
	db := openSecretScanTestDB(t)
	ctx := context.Background()
	queries := NewQueries(db)
	repoID := createRepoForSecretScanTest(t, ctx, queries)

	for _, params := range []EnqueueSecretScanJobParams{
		{RepoID: repoID, RefName: "refs/heads/main", Mode: SecretScanModeIncremental, ToCommit: "aaa"},
		{RepoID: repoID, RefName: "refs/heads/main", Mode: SecretScanModeFull},
		{RepoID: repoID, RefName: "refs/heads/topic", Mode: SecretScanModeIncremental, ToCommit: "bbb"},
	} {
		if _, err := queries.EnqueueSecretScanJob(ctx, params); err != nil {
			t.Fatalf("EnqueueSecretScanJob(%s/%s) error = %v", params.RefName, params.Mode, err)
		}
	}

	jobs, err := queries.ListSecretScanJobsByRepo(ctx, repoID, 10)
	if err != nil {
		t.Fatalf("ListSecretScanJobsByRepo() error = %v", err)
	}
	if len(jobs) != 3 {
		t.Fatalf("job count = %d, want 3 (mode and ref are part of the coalesce key)", len(jobs))
	}
}

// A completed job must not block the next push to the same branch — the unique
// index is partial on status='pending' precisely so it doesn't.
func TestEnqueueSecretScanJobAfterCompletionCreatesNewJob(t *testing.T) {
	db := openSecretScanTestDB(t)
	ctx := context.Background()
	queries := NewQueries(db)
	repoID := createRepoForSecretScanTest(t, ctx, queries)

	first, err := queries.EnqueueSecretScanJob(ctx, EnqueueSecretScanJobParams{
		RepoID:  repoID,
		RefName: "refs/heads/main",
		Mode:    SecretScanModeIncremental,
	})
	if err != nil {
		t.Fatalf("EnqueueSecretScanJob(first) error = %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE secret_scan_jobs SET status = 'complete', claimed_by = NULL, finished_at = NOW() WHERE id = $1`, first.ID); err != nil {
		t.Fatalf("mark complete: %v", err)
	}

	second, err := queries.EnqueueSecretScanJob(ctx, EnqueueSecretScanJobParams{
		RepoID:  repoID,
		RefName: "refs/heads/main",
		Mode:    SecretScanModeIncremental,
	})
	if err != nil {
		t.Fatalf("EnqueueSecretScanJob(second) error = %v", err)
	}
	if second.ID == first.ID {
		t.Fatal("second enqueue reused a completed job; the branch would never be rescanned")
	}
}

func TestClaimNextSecretScanJobIsExclusiveAndBounded(t *testing.T) {
	db := openSecretScanTestDB(t)
	ctx := context.Background()
	queries := NewQueries(db)

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()
	if _, err := tx.ExecContext(ctx, `LOCK TABLE secret_scan_jobs IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatalf("lock secret_scan_jobs: %v", err)
	}
	txQueries := queries.WithTx(tx)
	repoID := createRepoForSecretScanTest(t, ctx, txQueries)

	// Other tests' rows would otherwise win the created_at ordering.
	if _, err := tx.ExecContext(ctx, `UPDATE secret_scan_jobs SET status = 'complete', claimed_by = NULL, claim_expires_at = NULL, finished_at = NOW() WHERE repo_id <> $1`, repoID); err != nil {
		t.Fatalf("quarantine unrelated jobs: %v", err)
	}

	job, err := txQueries.EnqueueSecretScanJob(ctx, EnqueueSecretScanJobParams{
		RepoID:  repoID,
		RefName: "refs/heads/main",
		Mode:    SecretScanModeIncremental,
	})
	if err != nil {
		t.Fatalf("EnqueueSecretScanJob() error = %v", err)
	}

	claimed, err := txQueries.ClaimNextSecretScanJob(ctx, "worker-a", time.Now().Add(5*time.Minute), 3)
	if err != nil {
		t.Fatalf("ClaimNextSecretScanJob(worker-a) error = %v", err)
	}
	if claimed == nil || claimed.ID != job.ID {
		t.Fatalf("claimed = %#v, want job %s", claimed, job.ID)
	}
	if claimed.Status != SecretScanStatusProcessing || claimed.Attempts != 1 {
		t.Fatalf("claimed status/attempts = %s/%d, want processing/1", claimed.Status, claimed.Attempts)
	}

	// Two replicas must never scan the same range concurrently.
	if second, err := txQueries.ClaimNextSecretScanJob(ctx, "worker-b", time.Now().Add(5*time.Minute), 3); err != nil {
		t.Fatalf("ClaimNextSecretScanJob(worker-b) error = %v", err)
	} else if second != nil {
		t.Fatalf("worker-b claimed %s while worker-a holds a live lease", second.ID)
	}

	// A pod that dies mid-scan leaves an expired lease; the work must not be lost.
	if _, err := tx.ExecContext(ctx, `UPDATE secret_scan_jobs SET claim_expires_at = NOW() - interval '1 minute' WHERE id = $1`, job.ID); err != nil {
		t.Fatalf("expire lease: %v", err)
	}
	reclaimed, err := txQueries.ClaimNextSecretScanJob(ctx, "worker-b", time.Now().Add(5*time.Minute), 3)
	if err != nil {
		t.Fatalf("ClaimNextSecretScanJob(reclaim) error = %v", err)
	}
	if reclaimed == nil || reclaimed.ID != job.ID {
		t.Fatalf("reclaimed = %#v, want the abandoned job %s", reclaimed, job.ID)
	}
	if reclaimed.Attempts != 2 {
		t.Fatalf("attempts after reclaim = %d, want 2", reclaimed.Attempts)
	}

	// attempts is now 2; a max of 2 must stop the retry loop rather than spin.
	if _, err := tx.ExecContext(ctx, `UPDATE secret_scan_jobs SET claim_expires_at = NOW() - interval '1 minute' WHERE id = $1`, job.ID); err != nil {
		t.Fatalf("expire lease again: %v", err)
	}
	exhausted, err := txQueries.ClaimNextSecretScanJob(ctx, "worker-c", time.Now().Add(5*time.Minute), 2)
	if err != nil {
		t.Fatalf("ClaimNextSecretScanJob(exhausted) error = %v", err)
	}
	if exhausted != nil {
		t.Fatalf("claimed %s past max_attempts", exhausted.ID)
	}
}

func TestSecretScanJobClaimMutationsAreOwnerGuarded(t *testing.T) {
	db := openSecretScanTestDB(t)
	ctx := context.Background()
	queries := NewQueries(db)
	repoID := createRepoForSecretScanTest(t, ctx, queries)

	job, err := queries.EnqueueSecretScanJob(ctx, EnqueueSecretScanJobParams{
		RepoID:  repoID,
		RefName: "refs/heads/main",
		Mode:    SecretScanModeIncremental,
	})
	if err != nil {
		t.Fatalf("EnqueueSecretScanJob() error = %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE secret_scan_jobs SET status = 'processing', claimed_by = 'worker-a', claim_expires_at = NOW() + interval '5 minutes' WHERE id = $1`, job.ID); err != nil {
		t.Fatalf("simulate claim: %v", err)
	}

	owned, err := queries.RenewSecretScanJobClaim(ctx, job.ID, "worker-a", time.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatalf("RenewSecretScanJobClaim(owner) error = %v", err)
	}
	if !owned {
		t.Fatal("owner could not renew its own claim")
	}

	// The whole point: a worker that lost the row learns it on the next
	// heartbeat instead of writing over the new owner's result.
	stillOwned, err := queries.RenewSecretScanJobClaim(ctx, job.ID, "worker-b", time.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatalf("RenewSecretScanJobClaim(stranger) error = %v", err)
	}
	if stillOwned {
		t.Fatal("a non-owner renewed the claim")
	}

	if got, err := queries.CompleteSecretScanJob(ctx, job.ID, "worker-b"); err != nil {
		t.Fatalf("CompleteSecretScanJob(stranger) error = %v", err)
	} else if got != nil {
		t.Fatal("a non-owner completed the job")
	}

	if got, err := queries.FailSecretScanJob(ctx, job.ID, "worker-b", "boom", true); err != nil {
		t.Fatalf("FailSecretScanJob(stranger) error = %v", err)
	} else if got != nil {
		t.Fatal("a non-owner failed the job")
	}

	completed, err := queries.CompleteSecretScanJob(ctx, job.ID, "worker-a")
	if err != nil {
		t.Fatalf("CompleteSecretScanJob(owner) error = %v", err)
	}
	if completed == nil || completed.Status != SecretScanStatusComplete {
		t.Fatalf("completed = %#v, want status complete", completed)
	}
	if completed.FinishedAt == nil {
		t.Fatal("finished_at not set on completion")
	}
}

// Retryable failure keeps the row claimable; terminal failure does not.
func TestFailSecretScanJobRetryableVersusTerminal(t *testing.T) {
	db := openSecretScanTestDB(t)
	ctx := context.Background()

	// The reclaim assertions below race other tests' rows for the claim's
	// created_at ordering, so run the whole scenario in one locked tx with
	// unrelated jobs quarantined (same pattern as the claim exclusivity test).
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()
	if _, err := tx.ExecContext(ctx, `LOCK TABLE secret_scan_jobs IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatalf("lock secret_scan_jobs: %v", err)
	}
	queries := NewQueries(db).WithTx(tx)
	repoID := createRepoForSecretScanTest(t, ctx, queries)
	if _, err := tx.ExecContext(ctx, `UPDATE secret_scan_jobs SET status = 'complete', claimed_by = NULL, claim_expires_at = NULL, finished_at = NOW() WHERE repo_id <> $1`, repoID); err != nil {
		t.Fatalf("quarantine unrelated jobs: %v", err)
	}

	job, err := queries.EnqueueSecretScanJob(ctx, EnqueueSecretScanJobParams{
		RepoID:  repoID,
		RefName: "refs/heads/main",
		Mode:    SecretScanModeIncremental,
	})
	if err != nil {
		t.Fatalf("EnqueueSecretScanJob() error = %v", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE secret_scan_jobs SET status = 'processing', claimed_by = 'worker-a' WHERE id = $1`, job.ID); err != nil {
		t.Fatalf("simulate claim: %v", err)
	}

	failed, err := queries.FailSecretScanJob(ctx, job.ID, "worker-a", "clone timed out", false)
	if err != nil {
		t.Fatalf("FailSecretScanJob(retryable) error = %v", err)
	}
	if failed == nil || failed.FinishedAt != nil {
		t.Fatalf("retryable failure = %#v, want finished_at unset so it is retried", failed)
	}
	if failed.LastError != "clone timed out" {
		t.Fatalf("last_error = %q, want the cause recorded", failed.LastError)
	}

	// "Retryable" must mean the claim actually picks the row up again — a
	// parked status 'failed'/finished_at NULL row that no claim matches is a
	// zombie, not a retry (the bug this arm of the test pins down).
	reclaimed, err := queries.ClaimNextSecretScanJob(ctx, "worker-b", time.Now().Add(time.Minute), 5)
	if err != nil {
		t.Fatalf("ClaimNextSecretScanJob(after retryable failure) error = %v", err)
	}
	if reclaimed == nil || reclaimed.ID != job.ID {
		t.Fatalf("reclaimed = %#v, want the retryable failed job to be claimed again", reclaimed)
	}

	terminal, err := queries.FailSecretScanJob(ctx, job.ID, "worker-b", "repo too large", true)
	if err != nil {
		t.Fatalf("FailSecretScanJob(terminal) error = %v", err)
	}
	if terminal == nil || terminal.FinishedAt == nil {
		t.Fatalf("terminal failure = %#v, want finished_at set", terminal)
	}
	afterTerminal, err := queries.ClaimNextSecretScanJob(ctx, "worker-c", time.Now().Add(time.Minute), 5)
	if err != nil {
		t.Fatalf("ClaimNextSecretScanJob(after terminal failure) error = %v", err)
	}
	if afterTerminal != nil {
		t.Fatalf("claimed %#v after terminal failure, want nothing claimable", afterTerminal)
	}
}

// A rolling restart must not park work behind a lease nobody is renewing.
func TestReleaseSecretScanJobClaimsReturnsWorkToPending(t *testing.T) {
	db := openSecretScanTestDB(t)
	ctx := context.Background()
	queries := NewQueries(db)
	repoID := createRepoForSecretScanTest(t, ctx, queries)

	job, err := queries.EnqueueSecretScanJob(ctx, EnqueueSecretScanJobParams{
		RepoID:  repoID,
		RefName: "refs/heads/main",
		Mode:    SecretScanModeIncremental,
	})
	if err != nil {
		t.Fatalf("EnqueueSecretScanJob() error = %v", err)
	}
	workerID := "worker-" + uuid.NewString()[:8]
	if _, err := db.ExecContext(ctx, `UPDATE secret_scan_jobs SET status = 'processing', claimed_by = $2, claim_expires_at = NOW() + interval '5 minutes' WHERE id = $1`, job.ID, workerID); err != nil {
		t.Fatalf("simulate claim: %v", err)
	}

	released, err := queries.ReleaseSecretScanJobClaims(ctx, workerID)
	if err != nil {
		t.Fatalf("ReleaseSecretScanJobClaims() error = %v", err)
	}
	if released != 1 {
		t.Fatalf("released = %d, want 1", released)
	}

	after, err := queries.GetSecretScanJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("GetSecretScanJob() error = %v", err)
	}
	if after.Status != SecretScanStatusPending || after.ClaimedBy != nil {
		t.Fatalf("after release = %s/%v, want pending and unclaimed", after.Status, after.ClaimedBy)
	}
}
