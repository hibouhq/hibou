package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestManagedRemediationLeaseRevisionAndCancellation(t *testing.T) {
	db := openSecretScanTestDB(t)
	q := NewQueries(db)
	ctx := context.Background()
	repo := createRepoForSecretScanTest(t, ctx, q)
	t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DELETE FROM repositories WHERE id=$1`, repo) })
	job, err := q.CreateRemediationJob(ctx, RemediationJob{ID: uuid.New(), RepoID: repo, BaseSHA: strings.Repeat("a", 40), SourceRef: "main", TargetBranch: "main", Request: json.RawMessage(`{}`), ExpiresAt: time.Now().Add(time.Hour)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE remediation_jobs SET created_at=now()-interval '100 years' WHERE id=$1`, job.ID); err != nil {
		t.Fatal(err)
	}
	token := uuid.New()
	claim, err := q.ClaimRemediationJob(ctx, token)
	if err != nil || claim == nil {
		t.Fatalf("claim: %v %v", claim, err)
	}

	// Scope this test to its own job in shared test databases.
	if claim.ID != job.ID {
		t.Skip("another test fixture had older queued work")
	}
	if ok, err := q.FinishRemediationJob(ctx, job.ID, uuid.New(), "ready", json.RawMessage(`{}`), "unsafe", ""); err != nil || ok {
		t.Fatalf("stale worker completed: %v %v", ok, err)
	}
	if ok, err := q.FinishRemediationJob(ctx, job.ID, token, "awaiting_selection", json.RawMessage(`{"modules":[]}`), "", ""); err != nil || !ok {
		t.Fatalf("prepare finish: %v %v", ok, err)
	}
	if _, err := q.SelectRemediationUnits(ctx, repo, job.ID, job.Revision+1, json.RawMessage(`{}`)); !errors.Is(err, ErrRemediationConflict) {
		t.Fatalf("stale revision accepted: %v", err)
	}
	selected, err := q.SelectRemediationUnits(ctx, repo, job.ID, job.Revision, json.RawMessage(`{}`))
	if err != nil || selected.Revision != 2 {
		t.Fatalf("selection: %v %v", selected, err)
	}
	if _, err := q.SelectRemediationUnits(ctx, repo, job.ID, job.Revision, json.RawMessage(`{}`)); !errors.Is(err, ErrRemediationConflict) {
		t.Fatalf("duplicate generation accepted: %v", err)
	}
	token = uuid.New()
	claim, err = q.ClaimRemediationJob(ctx, token)
	if err != nil || claim == nil || claim.State != "generating" {
		t.Fatalf("generation claim: %v %v", claim, err)
	}
	if _, err := q.CancelRemediationJob(ctx, repo, job.ID); err != nil {
		t.Fatal(err)
	}
	if alive, err := q.RenewRemediationLease(ctx, job.ID, token); err != nil || alive {
		t.Fatalf("cancelled lease alive: %v %v", alive, err)
	}
	if ok, err := q.FinishRemediationJob(ctx, job.ID, token, "ready", json.RawMessage(`{}`), "unsafe", ""); err != nil || ok {
		t.Fatalf("cancelled job ready: %v %v", ok, err)
	}
}
