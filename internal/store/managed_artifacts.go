package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

func (q *Queries) RegisterRemediationArtifact(ctx context.Context, key string, job uuid.UUID, expires time.Time) error {
	_, err := q.sqlDB.ExecContext(ctx, `INSERT INTO remediation_artifact_expiry(artifact_key,job_id,expires_at)
	VALUES($1,$2,$3) ON CONFLICT(artifact_key) DO NOTHING`, key, job, expires)
	return err
}

func (q *Queries) ScheduleRemediationArtifactCleanup(ctx context.Context, key string) error {
	_, err := q.sqlDB.ExecContext(ctx, `UPDATE remediation_artifact_expiry SET expires_at=now() WHERE artifact_key=$1`, key)
	return err
}

func (q *Queries) ListExpiredRemediationArtifacts(ctx context.Context) ([]string, error) {
	rows, err := q.sqlDB.QueryContext(ctx, `SELECT artifact_key FROM remediation_artifact_expiry WHERE expires_at<=now() ORDER BY expires_at LIMIT 100`)
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
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func (q *Queries) ClearRemediationArtifactExpiry(ctx context.Context, key string) error {
	_, err := q.sqlDB.ExecContext(ctx, `DELETE FROM remediation_artifact_expiry WHERE artifact_key=$1`, key)
	return err
}
