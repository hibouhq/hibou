package server

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/forge"
)

func TestForgePollingFinishesAndPrunesRunHistory(t *testing.T) {
	srv, repo, remote := newReconciliationFixture(t)
	remote.refs = []forge.RefObservation{}
	if err := reconcileTestScope(t, srv, repo, "refs"); err != nil {
		t.Fatal(err)
	}
	var jobID, runID uuid.UUID
	var finished sql.NullTime
	var message string
	if err := srv.db.QueryRow(`SELECT j.id,r.id,r.finished_at,r.error
		FROM forge_reconciliation j JOIN forge_reconciliation_runs r ON r.job_id=j.id
		WHERE j.provider=$1`, repo.Provider).Scan(&jobID, &runID, &finished, &message); err != nil {
		t.Fatal(err)
	}
	if !finished.Valid || message != "" {
		t.Fatalf("successful run not finalized: finished=%v error=%q", finished, message)
	}
	oldID := uuid.New()
	if _, err := srv.db.Exec(`INSERT INTO forge_reconciliation_runs(id,job_id,queued_at,started_at,finished_at)
		VALUES($1,$2,now()-interval '15 days',now()-interval '15 days',now()-interval '15 days')`, oldID, jobID); err != nil {
		t.Fatal(err)
	}
	if err := reconcileTestScope(t, srv, repo, "refs"); err != nil {
		t.Fatal(err)
	}
	var oldCount, finishedCount int
	if err := srv.db.QueryRow(`SELECT count(*) FROM forge_reconciliation_runs WHERE job_id=$1 AND started_at>now()-interval '1 hour'`, jobID).Scan(&finishedCount); err != nil {
		t.Fatal(err)
	}
	if finishedCount != 1 {
		t.Fatalf("quiet polling stored %d run rows within one hour, want 1", finishedCount)
	}
	remote.refs = []forge.RefObservation{{Name: "main", SHA: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}
	if err := reconcileTestScope(t, srv, repo, "refs"); err != nil {
		t.Fatal(err)
	}
	if err := srv.db.QueryRow(`SELECT count(*) FROM forge_reconciliation_runs WHERE id=$1`, oldID).Scan(&oldCount); err != nil {
		t.Fatal(err)
	}
	if oldCount != 0 {
		t.Fatal("run history older than 14 days was not pruned")
	}
	if err := srv.db.QueryRow(`SELECT count(*) FROM forge_reconciliation_runs
		WHERE job_id=$1 AND finished_at IS NOT NULL AND error=''`, jobID).Scan(&finishedCount); err != nil {
		t.Fatal(err)
	}
	if finishedCount != 2 {
		t.Fatalf("completed run samples=%d, want hourly sample plus material change", finishedCount)
	}
	// Failed observations must finalize their run too, without advancing state.
	remote.readErr = context.DeadlineExceeded
	if err := reconcileTestScope(t, srv, repo, "refs"); err == nil {
		t.Fatal("failed observation succeeded")
	}
	if err := srv.db.QueryRow(`SELECT r.finished_at,r.error
		FROM forge_reconciliation_runs r WHERE r.job_id=$1
		ORDER BY r.started_at DESC LIMIT 1`, jobID).Scan(&finished, &message); err != nil {
		t.Fatal(err)
	}
	if !finished.Valid || message == "" || finished.Time.After(time.Now()) {
		t.Fatalf("failed run not finalized: finished=%v error=%q", finished, message)
	}
}
