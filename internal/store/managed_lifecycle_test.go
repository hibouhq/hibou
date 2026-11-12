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

func TestManagedPublicationSerializesCancellation(t *testing.T) {
	db := openSecretScanTestDB(t)
	q := NewQueries(db)
	ctx := t.Context()
	repo := createRepoForSecretScanTest(t, ctx, q)
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM repositories WHERE id=$1`, repo) })
	job, err := q.CreateRemediationJob(ctx, RemediationJob{ID: uuid.New(), RepoID: repo, BaseSHA: strings.Repeat("a", 40), SourceRef: "main", TargetBranch: "main", Request: json.RawMessage(`{}`), ExpiresAt: time.Now().Add(time.Hour)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE remediation_jobs SET state='ready',artifact_key='private/key' WHERE id=$1`, job.ID); err != nil {
		t.Fatal(err)
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- q.WithRemediationPublication(ctx, repo, job.ID, job.Revision, func(*RemediationJob) error {
			// A separately committed audit intent must not deadlock on the job
			// foreign key while its publication lock is held.
			if err := q.RecordRemediationEvent(ctx, job.ID, "publication_intent", nil); err != nil {
				return err
			}
			close(entered)
			<-release
			return nil
		})
	}()
	select {
	case <-entered:
	case err := <-done:
		t.Fatalf("publication lock: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("audit intent deadlocked")
	}
	blocked, stop := context.WithTimeout(ctx, 100*time.Millisecond)
	_, cancelErr := q.CancelRemediationJob(blocked, repo, job.ID)
	stop()
	close(release)
	if cancelErr == nil {
		t.Error("cancellation overtook an active publication")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := q.CancelRemediationJob(ctx, repo, job.ID); err != nil {
		t.Fatal(err)
	}
	invoked := false
	err = q.WithRemediationPublication(ctx, repo, job.ID, job.Revision, func(*RemediationJob) error { invoked = true; return nil })
	if !errors.Is(err, ErrRemediationConflict) || invoked {
		t.Fatalf("cancelled draft published: %v invoked=%v", err, invoked)
	}
}

func TestManagedRetryExhaustionExpiryAndReadiness(t *testing.T) {
	db := openSecretScanTestDB(t)
	q := NewQueries(db)
	ctx := t.Context()
	repo := createRepoForSecretScanTest(t, ctx, q)
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM repositories WHERE id=$1`, repo) })
	job, err := q.CreateRemediationJob(ctx, RemediationJob{ID: uuid.New(), RepoID: repo, BaseSHA: strings.Repeat("a", 40), SourceRef: "main", Request: json.RawMessage(`{}`), ExpiresAt: time.Now().Add(time.Hour)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	oldToken := uuid.New()
	if _, err := db.ExecContext(ctx, `UPDATE remediation_jobs SET state='generating',attempts=3,lease_token=$2,lease_until=now()-interval '1 second' WHERE id=$1`, job.ID, oldToken); err != nil {
		t.Fatal(err)
	}
	if _, err := q.ExpireRemediationJobs(ctx); err != nil {
		t.Fatal(err)
	}
	current, err := q.GetRemediationJob(ctx, repo, job.ID)
	if err != nil || current.State != "failed" || current.LeaseToken.Valid {
		t.Fatalf("exhausted claim stuck active: %v %v", current, err)
	}
	if ok, err := q.FinishRemediationJob(ctx, job.ID, oldToken, "ready", json.RawMessage(`{}`), "unsafe", ""); err != nil || ok {
		t.Fatalf("exhausted stale worker completed: %v %v", ok, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE remediation_jobs SET state='ready',expires_at=now()-interval '1 second',artifact_key='private/expiring' WHERE id=$1`, job.ID); err != nil {
		t.Fatal(err)
	}
	keys, err := q.ExpireRemediationJobs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, key := range keys {
		if key == "private/expiring" {
			found = true
		}
	}
	if !found {
		t.Fatal("expired artifact not scheduled for cleanup")
	}
	current, err = q.GetRemediationJob(ctx, repo, job.ID)
	if err != nil || current.State != "expired" || string(current.Request) != "{}" {
		t.Fatalf("expired source metadata retained: %v %v", current, err)
	}
	if err := q.ClearExpiredRemediationArtifact(ctx, "private/expiring"); err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	t.Cleanup(func() { _ = q.RemoveRemediationController(context.Background(), id) })
	if err := q.HeartbeatRemediationController(ctx, id, "operator/image@sha256:"+strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if ready, err := q.RemediationControllerAvailable(ctx); err != nil || !ready {
		t.Fatalf("healthy controller not ready: %v %v", ready, err)
	}
	if err := q.RemoveRemediationController(ctx, id); err != nil {
		t.Fatal(err)
	}
}
