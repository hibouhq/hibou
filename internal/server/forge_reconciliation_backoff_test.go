package server

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestForgePollingBackoffIsSharedAndManualSyncCannotBypass(t *testing.T) {
	srv, repo, _ := newReconciliationFixture(t)
	ctx := context.Background()
	if err := srv.queries.EnsureEnrolledForgeReconciliation(ctx, repo.Provider); err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(time.Hour)
	if err := srv.queries.DeferForgeProvider(ctx, repo.Provider, until); err != nil {
		t.Fatal(err)
	}
	if job, err := srv.queries.ClaimForgeReconciliation(ctx, []string{repo.Provider}, uuid.New(), time.Now()); err != nil || job != nil {
		t.Fatalf("shared backoff bypassed: %+v %v", job, err)
	}
	if err := srv.queries.RequestForgeReconciliation(ctx, repo.Provider); err != nil {
		t.Fatal(err)
	}
	if job, err := srv.queries.ClaimForgeReconciliation(ctx, []string{repo.Provider}, uuid.New(), time.Now()); err != nil || job != nil {
		t.Fatalf("manual request bypassed API backoff: %+v %v", job, err)
	}
	jobs, err := srv.queries.ListForgeReconciliation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, job := range jobs {
		if job.Provider == repo.Provider && job.NextDueAt.Before(until.Add(-time.Millisecond)) {
			t.Fatal("visible next attempt omitted shared API deferral")
		}
	}
	if _, err := srv.db.Exec(`DELETE FROM forge_reconciliation_backoff WHERE provider=$1`, repo.Provider); err != nil {
		t.Fatal(err)
	}
	job, err := srv.queries.ClaimForgeReconciliation(ctx, []string{repo.Provider}, uuid.New(), time.Now())
	if err != nil || job == nil {
		t.Fatalf("scope did not resume: %+v %v", job, err)
	}
	if err := srv.queries.FinishForgeReconciliation(ctx, job, job.State, time.Now().Add(time.Minute), ""); err != nil {
		t.Fatal(err)
	}
}
