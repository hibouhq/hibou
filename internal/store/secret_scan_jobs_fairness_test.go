package store

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// One org enqueueing many repositories must not starve another: after an org
// is served, an older job of the same org waits behind another org's job.
func TestClaimNextSecretScanJobRoundRobinsAcrossOrgs(t *testing.T) {
	db := openSecretScanTestDB(t)
	ctx := context.Background()
	queries := NewQueries(db)

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `LOCK TABLE secret_scan_jobs IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatalf("lock secret_scan_jobs: %v", err)
	}
	txQueries := queries.WithTx(tx)
	if _, err := tx.ExecContext(ctx, `UPDATE secret_scan_jobs SET status = 'complete', claimed_by = NULL, claim_expires_at = NULL, finished_at = NOW() WHERE finished_at IS NULL`); err != nil {
		t.Fatalf("quarantine unrelated jobs: %v", err)
	}

	busyRepoA := createRepoForSecretScanTest(t, ctx, txQueries)
	var busyOrg uuid.UUID
	if err := tx.QueryRowContext(ctx, `SELECT org_id FROM repositories WHERE id = $1`, busyRepoA).Scan(&busyOrg); err != nil {
		t.Fatalf("load org: %v", err)
	}
	busyRepoB, err := txQueries.CreateRepository(ctx, busyOrg, nil, uniqueStoreTestName(t, "repo"), uniqueStoreTestName(t, "repo"), "github", uniqueStoreTestName(t, "provider"), "main", "enrolled")
	if err != nil {
		t.Fatalf("CreateRepository: %v", err)
	}
	quietRepo := createRepoForSecretScanTest(t, ctx, txQueries)

	enqueue := func(repoID uuid.UUID, age time.Duration) uuid.UUID {
		job, err := txQueries.EnqueueSecretScanJob(ctx, EnqueueSecretScanJobParams{RepoID: repoID, RefName: "refs/heads/main", Mode: SecretScanModeIncremental})
		if err != nil {
			t.Fatalf("EnqueueSecretScanJob: %v", err)
		}
		// NOW() is frozen inside the transaction; age the rows explicitly.
		if _, err := tx.ExecContext(ctx, `UPDATE secret_scan_jobs SET created_at = NOW() - $2::interval WHERE id = $1`, job.ID, age.String()); err != nil {
			t.Fatalf("age job: %v", err)
		}
		return job.ID
	}
	first := enqueue(busyRepoA, 3*time.Hour)
	_ = enqueue(busyRepoB.ID, 2*time.Hour)
	quiet := enqueue(quietRepo, time.Hour)

	claim := func(worker string) uuid.UUID {
		job, err := txQueries.ClaimNextSecretScanJob(ctx, worker, time.Now().Add(5*time.Minute), 3)
		if err != nil || job == nil {
			t.Fatalf("ClaimNextSecretScanJob(%s) = %v, %v", worker, job, err)
		}
		return job.ID
	}
	if got := claim("worker-a"); got != first {
		t.Fatalf("first claim = %s, want the oldest job %s", got, first)
	}
	if got := claim("worker-b"); got != quiet {
		t.Fatalf("second claim = %s, want the other org's job %s ahead of the busy org's older one", got, quiet)
	}
}
