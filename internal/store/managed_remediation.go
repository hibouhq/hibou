package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

var ErrRemediationConflict = errors.New("remediation state or revision changed")

type RemediationJob struct {
	ID           uuid.UUID       `json:"id"`
	RepoID       uuid.UUID       `json:"repo_id"`
	BaseSHA      string          `json:"base_sha"`
	SourceRef    string          `json:"source_ref"`
	TargetBranch string          `json:"target_branch"`
	Revision     int             `json:"revision"`
	State        string          `json:"state"`
	Request      json.RawMessage `json:"-"`
	Result       json.RawMessage `json:"result"`
	Error        string          `json:"error,omitempty"`
	ArtifactKey  string          `json:"-"`
	LeaseToken   uuid.NullUUID   `json:"-"`
	ExpiresAt    time.Time       `json:"expires_at"`
}

const remediationColumns = `id,repo_id,base_sha,source_ref,target_branch,revision,state,request,result,error,artifact_key,lease_token,expires_at`

func scanRemediation(row interface{ Scan(...any) error }) (*RemediationJob, error) {
	var j RemediationJob
	err := row.Scan(&j.ID, &j.RepoID, &j.BaseSHA, &j.SourceRef, &j.TargetBranch, &j.Revision, &j.State, &j.Request, &j.Result, &j.Error, &j.ArtifactKey, &j.LeaseToken, &j.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &j, err
}

func (q *Queries) CreateRemediationJob(ctx context.Context, j RemediationJob, creator *uuid.UUID) (*RemediationJob, error) {
	return scanRemediation(q.sqlDB.QueryRowContext(ctx, `INSERT INTO remediation_jobs
	(id,repo_id,creator_id,base_sha,source_ref,target_branch,state,request,expires_at)
	VALUES ($1,$2,$3,$4,$5,$6,'queued_prepare',$7,$8) RETURNING `+remediationColumns,
		j.ID, j.RepoID, creator, j.BaseSHA, j.SourceRef, j.TargetBranch, j.Request, j.ExpiresAt))
}

func (q *Queries) GetRemediationJob(ctx context.Context, repo, id uuid.UUID) (*RemediationJob, error) {
	return scanRemediation(q.sqlDB.QueryRowContext(ctx, `SELECT `+remediationColumns+` FROM remediation_jobs WHERE id=$1 AND repo_id=$2`, id, repo))
}

func (q *Queries) SelectRemediationUnits(ctx context.Context, repo, id uuid.UUID, revision int, request json.RawMessage) (*RemediationJob, error) {
	j, err := scanRemediation(q.sqlDB.QueryRowContext(ctx, `UPDATE remediation_jobs SET request=$4,state='queued_generate',
	revision=revision+1,attempts=0,updated_at=now() WHERE id=$1 AND repo_id=$2 AND revision=$3
	AND state='awaiting_selection' AND expires_at>now() RETURNING `+remediationColumns, id, repo, revision, request))
	if err == nil && j == nil {
		err = ErrRemediationConflict
	}
	return j, err
}

func (q *Queries) ClaimRemediationJob(ctx context.Context, token uuid.UUID) (*RemediationJob, error) {
	// A crashed claim can be retried twice. Every completion is fenced with a
	// fresh token, including retries of the same draft revision.
	return scanRemediation(q.sqlDB.QueryRowContext(ctx, `UPDATE remediation_jobs SET
	state=CASE WHEN state IN ('queued_prepare','preparing') THEN 'preparing' ELSE 'generating' END,
	lease_token=$1,lease_until=now()+interval '60 seconds',attempts=attempts+1,updated_at=now()
	WHERE id=(SELECT id FROM remediation_jobs
	WHERE expires_at>now() AND attempts<3 AND
	(state IN ('queued_prepare','queued_generate') OR (state IN ('preparing','generating') AND lease_until<now()))
	ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING `+remediationColumns, token))
}

func (q *Queries) RenewRemediationLease(ctx context.Context, id, token uuid.UUID) (bool, error) {
	result, err := q.sqlDB.ExecContext(ctx, `UPDATE remediation_jobs SET lease_until=now()+interval '60 seconds'
	WHERE id=$1 AND lease_token=$2 AND lease_until>now() AND expires_at>now() AND state IN ('preparing','generating')`, id, token)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n == 1, err
}

func (q *Queries) FinishRemediationJob(ctx context.Context, id, token uuid.UUID, state string, result json.RawMessage, key, message string) (bool, error) {
	if state != "awaiting_selection" && state != "ready" && state != "failed" {
		return false, ErrRemediationConflict
	}
	r, err := q.sqlDB.ExecContext(ctx, `UPDATE remediation_jobs SET state=$3,result=$4,artifact_key=$5,error=$6,
	lease_token=NULL,lease_until=NULL,updated_at=now() WHERE id=$1 AND lease_token=$2 AND lease_until>now()
	AND expires_at>now() AND state IN ('preparing','generating')`, id, token, state, result, key, message)
	if err != nil {
		return false, err
	}
	n, err := r.RowsAffected()
	return n == 1, err
}

func (q *Queries) CancelRemediationJob(ctx context.Context, repo, id uuid.UUID) (bool, error) {
	r, err := q.sqlDB.ExecContext(ctx, `UPDATE remediation_jobs SET state='cancelled',lease_token=NULL,lease_until=NULL,updated_at=now()
	WHERE id=$1 AND repo_id=$2 AND state NOT IN ('cancelled','expired')`, id, repo)
	if err != nil {
		return false, err
	}
	n, err := r.RowsAffected()
	return n == 1, err
}

func (q *Queries) ExpireRemediationJobs(ctx context.Context) ([]string, error) {
	if _, err := q.sqlDB.ExecContext(ctx, `UPDATE remediation_jobs SET state='failed',lease_token=NULL,lease_until=NULL,
	error='Isolated execution retry limit exhausted; prepare a new draft.',updated_at=now()
	WHERE attempts>=3 AND state IN ('preparing','generating') AND lease_until<now()`); err != nil {
		return nil, err
	}
	rows, err := q.sqlDB.QueryContext(ctx, `UPDATE remediation_jobs SET state='expired',lease_token=NULL,lease_until=NULL,
	request='{}',result='{}',updated_at=now() WHERE expires_at<=now() AND (state!='expired' OR artifact_key!='') RETURNING artifact_key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, err
		}
		if key != "" {
			keys = append(keys, key)
		}
	}
	return keys, rows.Err()
}

func (q *Queries) ClearExpiredRemediationArtifact(ctx context.Context, key string) error {
	_, err := q.sqlDB.ExecContext(ctx, `UPDATE remediation_jobs SET artifact_key='' WHERE artifact_key=$1 AND state='expired'`, key)
	return err
}

func (q *Queries) RecordRemediationEvent(ctx context.Context, id uuid.UUID, action string, detail any) error {
	data, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	_, err = q.sqlDB.ExecContext(ctx, `INSERT INTO remediation_events(job_id,action,detail) VALUES($1,$2,$3)`, id, action, data)
	return err
}

func (q *Queries) HeartbeatRemediationController(ctx context.Context, id uuid.UUID, profile string) error {
	_, err := q.sqlDB.ExecContext(ctx, `INSERT INTO remediation_controllers(id,profile) VALUES($1,$2)
	ON CONFLICT(id) DO UPDATE SET profile=$2,heartbeat_at=now()`, id, profile)
	return err
}

func (q *Queries) RemediationControllerAvailable(ctx context.Context) (bool, error) {
	var ready bool
	err := q.sqlDB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM remediation_controllers WHERE heartbeat_at>now()-interval '30 seconds')`).Scan(&ready)
	return ready, err
}

func (q *Queries) RemediationControllerReady(ctx context.Context, profile string) (bool, error) {
	if !strings.HasPrefix(profile, "kubernetes-v1:") {
		return false, errors.New("an approved Kubernetes workload profile is required")
	}
	var ready bool
	err := q.sqlDB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM remediation_controllers
		WHERE profile=$1 AND heartbeat_at>now()-interval '30 seconds')`, profile).Scan(&ready)
	return ready, err
}
func (q *Queries) SetManagedRemediationConsent(ctx context.Context, org uuid.UUID, enabled bool) error {
	_, err := q.sqlDB.ExecContext(ctx, `UPDATE organizations SET settings=jsonb_set(COALESCE(settings,'{}'),'{managed_remediation_pr_consent}',to_jsonb($2::boolean)) WHERE id=$1`, org, enabled)
	return err
}

// WithRemediationPublication serializes publication, cancellation and expiry for
// a draft across API replicas. NO KEY UPDATE permits the separately committed
// audit events' foreign-key checks while retaining the cancellation fence.
func (q *Queries) WithRemediationPublication(ctx context.Context, repo, id uuid.UUID, revision int, publish func(*RemediationJob) error) error {
	tx, err := q.sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	job, err := scanRemediation(tx.QueryRowContext(ctx, `SELECT `+remediationColumns+` FROM remediation_jobs
	WHERE id=$1 AND repo_id=$2 FOR NO KEY UPDATE`, id, repo))
	if err != nil {
		return err
	}
	if job == nil || job.State != "ready" || job.Revision != revision || !job.ExpiresAt.After(time.Now()) || job.ArtifactKey == "" {
		return ErrRemediationConflict
	}
	if err := publish(job); err != nil {
		return err
	}
	return tx.Commit()
}

func (q *Queries) RemoveRemediationController(ctx context.Context, id uuid.UUID) error {
	_, err := q.sqlDB.ExecContext(ctx, `DELETE FROM remediation_controllers WHERE id=$1`, id)
	return err
}
