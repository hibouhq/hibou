package server

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestQuietPollingAtHundredsOfRepositories(t *testing.T) {
	srv, repo, _ := newReconciliationFixture(t)
	ctx := context.Background()
	const repositories = 250
	srv.cfg.Forges[0].PollInterval = 5 * time.Minute
	srv.cfg.Forges[0].InventoryInterval = 30 * time.Minute
	if _, err := srv.db.Exec(`INSERT INTO repositories(org_id,name,slug,provider,provider_id,default_branch,sync_state)
	SELECT $1,'scale-'||i,'scale-'||i,$2,'acme/scale-'||i,'main','enrolled' FROM generate_series(1,$3) i`,
		repo.OrgID, repo.Provider, repositories-1); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.db.Exec(`INSERT INTO forge_repositories(provider,provider_repo_id,account_login,owner,name,full_name,provider_key,default_branch,account_id)
	SELECT $1,(100000+i)::text,'acme','acme','scale-'||i,'acme/scale-'||i,'acme/scale-'||i,'main',$2 FROM generate_series(1,$3) i`,
		repo.Provider, repo.OrgID.String(), repositories-1); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.db.Exec(`INSERT INTO forge_repository_bindings(repo_id,provider,account_id,repository_id)
	SELECT r.id,r.provider,$2,f.provider_repo_id FROM repositories r
	JOIN forge_repositories f ON f.provider=r.provider AND f.provider_key=r.provider_id
	WHERE r.provider=$1 ON CONFLICT DO NOTHING`, repo.Provider, repo.OrgID.String()); err != nil {
		t.Fatal(err)
	}
	if err := srv.queries.EnsureEnrolledForgeReconciliation(ctx, repo.Provider); err != nil {
		t.Fatal(err)
	}
	cycle := func() (time.Duration, int) {
		start := time.Now()
		unchanged := 0
		for i := 0; i < repositories*4; i++ {
			job, err := srv.queries.ClaimForgeReconciliation(ctx, []string{repo.Provider}, uuid.New(), time.Now())
			if err != nil || job == nil {
				t.Fatalf("claim %d: %+v %v", i, job, err)
			}
			if err := srv.reconcileForgeScope(ctx, job); err != nil {
				t.Fatal(err)
			}
			if job.StateUnchanged {
				unchanged++
			}
		}
		if extra, err := srv.queries.ClaimForgeReconciliation(ctx, []string{repo.Provider}, uuid.New(), time.Now()); err != nil || extra != nil {
			t.Fatalf("unexpected extra work: %+v %v", extra, err)
		}
		return time.Since(start), unchanged
	}
	cold, _ := cycle()
	if _, err := srv.db.Exec(`UPDATE forge_reconciliation SET next_due_at=now() WHERE provider=$1`, repo.Provider); err != nil {
		t.Fatal(err)
	}
	warm, unchanged := cycle()
	if unchanged != repositories*4 {
		t.Fatalf("unchanged checkpoints rewritten: stable=%d want=%d", unchanged, repositories*4)
	}
	var samples, active int
	if err := srv.db.QueryRow(`SELECT count(*) FROM forge_reconciliation_runs r JOIN forge_reconciliation j ON j.id=r.job_id WHERE j.provider=$1`, repo.Provider).Scan(&samples); err != nil {
		t.Fatal(err)
	}
	if samples != repositories*4 {
		t.Fatalf("quiet polling stored %d samples for %d scopes within one hour", samples, repositories*4)
	}
	if err := srv.db.QueryRow(`SELECT count(*) FROM forge_reconciliation WHERE provider=$1 AND next_due_at<now()+interval '29 minutes'`, repo.Provider).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 0 {
		t.Fatalf("%d idle scopes retained fast cadence", active)
	}
	t.Logf("%d quiet repositories / %d scopes: cold cycle %s; warm cycle %s; %d history samples after two cycles; %d unchanged checkpoint rewrites",
		repositories, repositories*4, cold, warm, samples, repositories*4-unchanged)
}
