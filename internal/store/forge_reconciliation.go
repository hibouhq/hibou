package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type ForgeReconciliation struct {
	ID             uuid.UUID       `json:"id"`
	Provider       string          `json:"provider"`
	Scope          string          `json:"scope"`
	Kind           string          `json:"kind"`
	RepoID         uuid.NullUUID   `json:"-"`
	State          json.RawMessage `json:"-"`
	NextDueAt      time.Time       `json:"next_due_at"`
	LastAttemptAt  *time.Time      `json:"last_attempt_at"`
	LastSuccessAt  *time.Time      `json:"last_success_at"`
	LastError      string          `json:"last_error"`
	Attempts       int             `json:"attempts"`
	Claim          uuid.UUID       `json:"-"`
	RecordRun      bool            `json:"-"`
	StateUnchanged bool            `json:"-"`
}

func (q *Queries) rawDB() dbgen.DBTX {
	if q.tx != nil {
		return q.tx
	}
	return q.sqlDB
}

func scanReconciliation(row interface{ Scan(...any) error }) (*ForgeReconciliation, error) {
	var job ForgeReconciliation
	err := row.Scan(&job.ID, &job.Provider, &job.Scope, &job.Kind, &job.RepoID,
		&job.State, &job.NextDueAt, &job.LastAttemptAt, &job.LastSuccessAt, &job.LastError, &job.Attempts)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &job, err
}

func (q *Queries) EnsureForgeReconciliation(ctx context.Context, provider, scope, kind string, repoID uuid.NullUUID) error {
	_, err := q.execer().ExecContext(ctx, `INSERT INTO forge_reconciliation(provider,scope,kind,repo_id)
	VALUES($1,$2,$3,$4) ON CONFLICT(provider,scope,kind) DO NOTHING`, provider, scope, kind, repoID)
	return err
}

func (q *Queries) ClaimForgeReconciliation(ctx context.Context, providers []string, claim uuid.UUID, now time.Time) (*ForgeReconciliation, error) {
	job, err := scanReconciliation(q.rawDB().QueryRowContext(ctx, `WITH candidate AS (
	SELECT id FROM forge_reconciliation WHERE provider=ANY($1::text[]) AND next_due_at <= $3
	AND (claim_expires_at IS NULL OR claim_expires_at < $3)
	AND NOT EXISTS(SELECT 1 FROM forge_reconciliation_backoff b
		WHERE b.provider=forge_reconciliation.provider AND b.retry_after>$3)
	ORDER BY next_due_at, CASE WHEN kind IN ('pull_requests','builds') THEN 0 ELSE 1 END, id
	FOR UPDATE SKIP LOCKED LIMIT 1)
	, claimed AS (UPDATE forge_reconciliation j SET claimed_by=$2, claim_expires_at=$3+interval '3 minutes',
	last_attempt_at=$3, attempts=attempts+1, requested=false FROM candidate c WHERE j.id=c.id
	RETURNING `+prefixReconciliationColumns()+`),
	abandoned AS (UPDATE forge_reconciliation_runs SET finished_at=$3,error='reconciliation lease expired'
	WHERE job_id IN (SELECT id FROM claimed) AND finished_at IS NULL),
	logged AS (INSERT INTO forge_reconciliation_runs(id,job_id,queued_at,started_at)
	SELECT $2,id,next_due_at,$3 FROM claimed c
	WHERE last_success_at IS NULL OR last_error<>'' OR NOT EXISTS(
		SELECT 1 FROM forge_reconciliation_runs r WHERE r.job_id=c.id AND r.started_at >= $3-interval '1 hour'))
	SELECT * FROM claimed`, pq.Array(providers), claim, now))
	if job != nil {
		job.Claim = claim
	}
	return job, err
}

func prefixReconciliationColumns() string {
	return `j.id,j.provider,j.scope,j.kind,j.repo_id,j.state,j.next_due_at,j.last_attempt_at,j.last_success_at,j.last_error,j.attempts`
}

// Finish is also the fencing check for the transaction applying observations
// and enqueueing work. A lost/expired lease rolls the entire application back.
func (q *Queries) FinishForgeReconciliation(ctx context.Context, job *ForgeReconciliation, state json.RawMessage, due time.Time, message string) error {
	if q.tx == nil {
		tx, err := q.BeginTx(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		if err := q.WithTx(tx).FinishForgeReconciliation(ctx, job, state, due, message); err != nil {
			return err
		}
		return tx.Commit()
	}
	if job.StateUnchanged {
		state = nil
	}
	result, err := q.execer().ExecContext(ctx, `UPDATE forge_reconciliation SET
	state=CASE WHEN $5='' AND $3::jsonb IS NOT NULL THEN $3 ELSE state END,
	next_due_at=CASE WHEN requested AND $5='' THEN now() ELSE $4 END,
	last_success_at=CASE WHEN $5='' THEN now() ELSE last_success_at END,
	last_error=$5, attempts=CASE WHEN $5='' THEN 0 ELSE attempts END,
	claimed_by=NULL, claim_expires_at=NULL
	WHERE id=$1 AND claimed_by=$2 AND claim_expires_at>now()`,
		job.ID, job.Claim, state, due, message)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("forge reconciliation lease lost")
	}
	logged, err := q.execer().ExecContext(ctx, `INSERT INTO forge_reconciliation_runs(id,job_id,queued_at,started_at,finished_at,error)
	SELECT $1,$2,$3,$4,now(),$5 WHERE $6::boolean
	OR EXISTS(SELECT 1 FROM forge_reconciliation_runs WHERE id=$1)
	OR NOT EXISTS(SELECT 1 FROM forge_reconciliation_runs WHERE job_id=$2 AND started_at>=now()-interval '1 hour')
	ON CONFLICT(id) DO UPDATE SET finished_at=EXCLUDED.finished_at,error=EXCLUDED.error`,
		job.Claim, job.ID, job.NextDueAt, job.LastAttemptAt, message,
		message != "" || job.RecordRun || job.Attempts > 1)
	if err != nil {
		return err
	}
	n, err = logged.RowsAffected()
	if err != nil || n == 0 {
		return err
	}
	_, err = q.execer().ExecContext(ctx, `DELETE FROM forge_reconciliation_runs WHERE id IN(
	SELECT id FROM forge_reconciliation_runs WHERE started_at<now()-interval '14 days'
	ORDER BY started_at LIMIT 1000)`)
	return err
}

func (q *Queries) ListForgeReconciliation(ctx context.Context) ([]ForgeReconciliation, error) {
	rows, err := q.rawDB().QueryContext(ctx, `SELECT j.id,j.provider,j.scope,j.kind,j.repo_id,
	jsonb_strip_nulls(jsonb_build_object('note',CASE WHEN b.retry_after>now()
		THEN to_jsonb('GitHub API budget deferred until '||b.retry_after::text) ELSE j.state->'note' END,
		'gate_pending',j.state->'gate_pending')),
	GREATEST(j.next_due_at,COALESCE(b.retry_after,j.next_due_at)),
	j.last_attempt_at,j.last_success_at,j.last_error,j.attempts
	FROM forge_reconciliation j LEFT JOIN forge_reconciliation_backoff b ON b.provider=j.provider
	ORDER BY j.provider,j.scope,j.kind`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	jobs := []ForgeReconciliation{}
	for rows.Next() {
		job, err := scanReconciliation(rows)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, *job)
	}
	return jobs, rows.Err()
}

func (q *Queries) RequestForgeReconciliation(ctx context.Context, provider string) error {
	_, err := q.execer().ExecContext(ctx, `UPDATE forge_reconciliation SET requested=true,
	next_due_at=CASE WHEN last_error='' THEN LEAST(next_due_at,now()) ELSE next_due_at END WHERE provider=$1`, provider)
	return err
}

func (q *Queries) DeferForgeProvider(ctx context.Context, provider string, until time.Time) error {
	_, err := q.execer().ExecContext(ctx, `INSERT INTO forge_reconciliation_backoff(provider,retry_after) VALUES($1,$2)
	ON CONFLICT(provider) DO UPDATE SET retry_after=GREATEST(forge_reconciliation_backoff.retry_after,EXCLUDED.retry_after)`, provider, until)
	return err
}

func (q *Queries) RequestRepositoryReconciliation(ctx context.Context, repoID uuid.UUID) error {
	_, err := q.execer().ExecContext(ctx, `UPDATE forge_reconciliation SET requested=true,
	next_due_at=CASE WHEN last_error='' THEN LEAST(next_due_at,now()) ELSE next_due_at END
	WHERE repo_id=$1 AND kind IN ('pull_requests','builds')`, repoID)
	return err
}

func (q *Queries) EnsureEnrolledForgeReconciliation(ctx context.Context, provider string) error {
	_, err := q.execer().ExecContext(ctx, `INSERT INTO forge_reconciliation(provider,scope,kind,repo_id)
	SELECT r.provider,r.id::text,k.kind,r.id FROM repositories r
	JOIN forge_repository_bindings b ON b.repo_id=r.id AND b.provider=r.provider
	JOIN forge_repositories f ON f.provider=r.provider AND lower(f.provider_key)=lower(r.provider_id)
	JOIN organizations o ON o.id=r.org_id
	CROSS JOIN unnest(ARRAY['refs','pull_requests','releases','builds']) AS k(kind)
	WHERE r.provider=$1 AND f.removed_at IS NULL AND NOT f.archived
	AND b.account_id=o.forge_account_id AND f.account_id=b.account_id AND f.provider_repo_id=b.repository_id
	ON CONFLICT(provider,scope,kind) DO NOTHING`, provider)
	return err
}

func (q *Queries) TouchForgeInventory(ctx context.Context, provider string) error {
	_, err := q.execer().ExecContext(ctx, `UPDATE forge_repositories SET last_seen_at=now() WHERE provider=$1 AND removed_at IS NULL`, provider)
	return err
}

type ReconciliationRepository struct {
	ID          uuid.UUID
	ProviderKey string
}

func (q *Queries) ReconciliationRepositories(ctx context.Context, provider string) ([]ReconciliationRepository, error) {
	rows, err := q.rawDB().QueryContext(ctx, `SELECT r.id, f.full_name FROM repositories r
	JOIN forge_repositories f ON f.provider=r.provider AND lower(f.provider_key)=lower(r.provider_id)
	WHERE r.provider=$1 AND f.removed_at IS NULL AND NOT f.archived ORDER BY r.id`, provider)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []ReconciliationRepository{}
	for rows.Next() {
		var row ReconciliationRepository
		if err := rows.Scan(&row.ID, &row.ProviderKey); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func (q *Queries) FailObservedBuild(ctx context.Context, repoID uuid.UUID, runID, attempt, sha string) (int64, error) {
	result, err := q.execer().ExecContext(ctx, `UPDATE snapshots s SET status='failed' FROM refs r
	WHERE s.ref_id=r.id AND r.repo_id=$1 AND s.status='pending'
	AND s.run_id=$2 AND s.run_attempt=$3 AND s.commit_sha=$4`, repoID, runID, attempt, sha)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

type PendingForgeBuild struct{ RunID, Attempt, SHA string }

func (q *Queries) PendingForgeBuilds(ctx context.Context, repoID uuid.UUID, offset int) ([]PendingForgeBuild, error) {
	rows, err := q.rawDB().QueryContext(ctx, `SELECT COALESCE(s.run_id,''),COALESCE(s.run_attempt,''),s.commit_sha
	FROM snapshots s JOIN refs r ON r.id=s.ref_id WHERE r.repo_id=$1 AND s.status='pending'
	GROUP BY s.run_id,s.run_attempt,s.commit_sha
	ORDER BY min(s.created_at),COALESCE(s.run_id,''),COALESCE(s.run_attempt,''),s.commit_sha LIMIT 101 OFFSET $2`, repoID, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []PendingForgeBuild{}
	for rows.Next() {
		var row PendingForgeBuild
		if err := rows.Scan(&row.RunID, &row.Attempt, &row.SHA); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

// Retire a disappeared ref without deleting its snapshots or evidence.
func (q *Queries) RetireObservedRef(ctx context.Context, id uuid.UUID) error {
	_, err := q.execer().ExecContext(ctx, `UPDATE refs SET latest_commit_sha=NULL,updated_at=now() WHERE id=$1`, id)
	return err
}

func (q *Queries) observeAnalysis(ctx context.Context, repoID uuid.UUID, ref, sha, revision string, enqueue func(*Queries) error) error {
	if q.tx == nil {
		tx, err := q.BeginTx(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		if err := q.WithTx(tx).observeAnalysis(ctx, repoID, ref, sha, revision, enqueue); err != nil {
			return err
		}
		return tx.Commit()
	}
	result, err := q.execer().ExecContext(ctx, `INSERT INTO forge_analysis_observations(repo_id,ref_name,commit_sha,analysis_revision)
	VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, repoID, ref, sha, revision)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil || n == 0 {
		return err
	}
	return enqueue(q)
}

func (q *Queries) EnqueueObservedSecretScan(ctx context.Context, input EnqueueSecretScanJobParams, revision string) error {
	return q.observeAnalysis(ctx, input.RepoID, input.RefName, input.ToCommit, "secret:"+revision, func(q *Queries) error {
		_, err := q.EnqueueSecretScanJob(ctx, input)
		return err
	})
}

func (q *Queries) EnqueueObservedExtraction(ctx context.Context, input EnqueueDepExtractionJobParams, revision string) error {
	return q.observeAnalysis(ctx, input.RepoID, input.RefName, input.CommitSHA, "inventory:"+revision, func(q *Queries) error {
		_, err := q.EnqueueDepExtractionJob(ctx, input)
		return err
	})
}

type ForgeInstallationSnapshot struct {
	ID           int64
	AccountID    string
	Account      string
	Suspended    bool
	Repositories []ForgeRepository
}

func (q *Queries) ApplyForgeInventory(ctx context.Context, provider string, installations []ForgeInstallationSnapshot) error {
	if q.tx == nil {
		return errors.New("forge inventory reconciliation requires a transaction")
	}
	rows, err := q.tx.QueryContext(ctx, `SELECT id,COALESCE(provider_repo_id,''),full_name,archived,removed_at IS NOT NULL
	FROM forge_repositories WHERE provider=$1 FOR UPDATE`, provider)
	if err != nil {
		return err
	}
	type prior struct {
		id                uuid.UUID
		name              string
		archived, removed bool
	}
	before := map[string]prior{}
	for rows.Next() {
		var p prior
		var identity string
		if err := rows.Scan(&p.id, &identity, &p.name, &p.archived, &p.removed); err != nil {
			rows.Close()
			return err
		}
		before[identity] = p
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	seen := map[uuid.UUID]bool{}
	for _, inst := range installations {
		if inst.Suspended {
			continue
		}
		// Follow account renames only through the immutable binding.
		if inst.AccountID != "" {
			if _, err := q.tx.ExecContext(ctx, `UPDATE organizations SET forge_account_login=$3
			WHERE provider=$1 AND forge_account_id=$2`, provider, inst.AccountID, inst.Account); err != nil {
				return err
			}
		}
		for _, repo := range inst.Repositories {
			if repo.ProviderRepoID == nil || *repo.ProviderRepoID == "" {
				return errors.New("forge inventory repository has no immutable id")
			}
			p, existed := before[*repo.ProviderRepoID]
			if existed && !strings.EqualFold(p.name, repo.FullName) {
				if _, err := q.tx.ExecContext(ctx, `UPDATE forge_repositories SET full_name=$2,provider_key=lower($2) WHERE id=$1`, p.id, repo.FullName); err != nil {
					return err
				}
				if _, err := q.tx.ExecContext(ctx, `UPDATE repositories r SET provider_id=$3,default_branch=$4,updated_at=now()
				FROM organizations o,forge_repository_bindings b WHERE r.org_id=o.id AND b.repo_id=r.id
				AND r.provider=$1 AND lower(r.provider_id)=lower($2)
				AND o.forge_account_id=$5 AND b.account_id=$5 AND b.repository_id=$6`, provider, p.name, repo.FullName, repo.DefaultBranch, inst.AccountID, *repo.ProviderRepoID); err != nil {
					return err
				}
			}
			repo.Provider = provider
			repo.InstallationID = &inst.ID
			repo.AccountLogin = inst.Account
			upsert, err := q.UpsertForgeRepository(ctx, repo)
			if err != nil {
				return err
			}
			if _, err := q.tx.ExecContext(ctx, `UPDATE forge_repositories SET account_id=$2 WHERE id=$1`, upsert.Repository.ID, inst.AccountID); err != nil {
				return err
			}
			seen[upsert.Repository.ID] = true
			if _, err := q.SetForgeRepositoryArchived(ctx, provider, repo.FullName, repo.Archived); err != nil {
				return err
			}
			if _, err := q.tx.ExecContext(ctx, `UPDATE repositories r SET default_branch=$3,updated_at=now()
			FROM forge_repository_bindings b WHERE b.repo_id=r.id AND r.provider=$1 AND lower(r.provider_id)=lower($2)
			AND b.account_id=$4 AND b.repository_id=$5 AND r.default_branch<>$3`,
				provider, repo.FullName, repo.DefaultBranch, inst.AccountID, *repo.ProviderRepoID); err != nil {
				return err
			}
			if !existed || p.removed || p.name != repo.FullName || p.archived != repo.Archived {
				if err := q.auditForgeObservation(ctx, provider, repo.FullName, "inventory.updated"); err != nil {
					return err
				}
			}
		}
	}
	for _, p := range before {
		if seen[p.id] || p.removed {
			continue
		}
		if _, err := q.tx.ExecContext(ctx, `UPDATE forge_repositories SET removed_at=now(),updated_at=now() WHERE id=$1`, p.id); err != nil {
			return err
		}
		if err := q.auditForgeObservation(ctx, provider, p.name, "inventory.inaccessible"); err != nil {
			return err
		}
	}
	return nil
}

func (q *Queries) auditForgeObservation(ctx context.Context, provider, resource, action string) error {
	detail, err := json.Marshal(map[string]string{"provider": provider, "provenance": "poll"})
	if err != nil {
		return err
	}

	_, err = q.CreateAuditLog(ctx, dbgen.CreateAuditLogParams{ActorType: audit.ActorSystem, ActorDisplay: "forge reconciliation", Action: action, ResourceType: "forge", ResourceID: resource, Context: detail})
	return err
}

func (q *Queries) RecordForgeReconciliationChange(ctx context.Context, provider, resource, action string) error {
	return q.auditForgeObservation(ctx, provider, resource, action)
}

func (q *Queries) ForgeGatePublicationFresh(ctx context.Context, repoID uuid.UUID, since time.Time) (bool, error) {
	var fresh bool
	err := q.rawDB().QueryRowContext(ctx, `SELECT NOT EXISTS(
	SELECT 1 FROM refs r WHERE r.repo_id=$1 AND r.ref_type='pull_request' AND COALESCE(r.pr_state,'open')='open'
	AND NOT EXISTS(SELECT 1 FROM pr_checks c WHERE c.ref_id=r.id AND c.head_sha=r.latest_commit_sha
	AND c.context='hibou/security' AND c.forge_synced_at >= $2))`, repoID, since).Scan(&fresh)
	return fresh, err
}
