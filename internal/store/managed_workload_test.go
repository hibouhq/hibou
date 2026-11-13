package store

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestManagedWorkloadIdentityIsDurableImmutableAndFenced(t *testing.T) {
	db := openSecretScanTestDB(t)
	q := NewQueries(db)
	ctx := t.Context()
	repo := createRepoForSecretScanTest(t, ctx, q)
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM repositories WHERE id=$1`, repo) })
	job, err := q.CreateRemediationJob(ctx, RemediationJob{
		ID: uuid.New(), RepoID: repo, BaseSHA: strings.Repeat("a", 40), SourceRef: "main",
		Request: json.RawMessage(`{}`), ExpiresAt: time.Now().Add(time.Hour),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	lease := uuid.New()
	if _, err := db.ExecContext(ctx, `UPDATE remediation_jobs SET state='generating',lease_token=$2,lease_until=now()+interval '60 seconds' WHERE id=$1`, job.ID, lease); err != nil {
		t.Fatal(err)
	}
	for _, pod := range []string{"", "pod-uid", "pod-uid"} {
		if err := q.BindRemediationWorkload(ctx, job.ID, lease, "attempt", "job-uid", pod); err != nil {
			t.Fatal(err)
		}
	}
	for _, identity := range []struct{ jobUID, podUID string }{
		{"different-job", "pod-uid"}, {"job-uid", "different-pod"},
	} {
		if err := q.BindRemediationWorkload(ctx, job.ID, lease, "attempt", identity.jobUID, identity.podUID); !errors.Is(err, ErrRemediationConflict) {
			t.Fatalf("identity changed within one attempt: %v", err)
		}
	}
	if err := q.BindRemediationWorkload(ctx, job.ID, uuid.New(), "attempt", "job-uid", "pod-uid"); !errors.Is(err, ErrRemediationConflict) {
		t.Fatalf("stale claim accessed broker: %v", err)
	}
	if _, err := q.CancelRemediationJob(ctx, repo, job.ID); err != nil {
		t.Fatal(err)
	}
	if err := q.BindRemediationWorkload(ctx, job.ID, lease, "attempt", "job-uid", "pod-uid"); !errors.Is(err, ErrRemediationConflict) {
		t.Fatalf("cancelled attempt accessed broker: %v", err)
	}
}
