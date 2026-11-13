package store

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
)

// BindRemediationWorkload persists the Job/Pod identity once per fenced attempt
// and rechecks the current durable claim before every broker operation.
func (q *Queries) BindRemediationWorkload(ctx context.Context, job, lease uuid.UUID, attempt, jobUID, podUID string) error {
	if job == uuid.Nil || lease == uuid.Nil || attempt == "" || jobUID == "" ||
		len(attempt) > 200 || len(jobUID) > 200 || len(podUID) > 200 ||
		strings.ContainsAny(attempt+jobUID+podUID, "\x00\r\n\t ") {
		return errors.New("invalid managed workload identity")
	}
	result, err := q.sqlDB.ExecContext(ctx, `INSERT INTO remediation_workload_attempts(job_id,lease_token,attempt,job_uid,pod_uid)
		SELECT id,$2,$3,$4,$5 FROM remediation_jobs
		WHERE id=$1 AND lease_token=$2 AND state='generating' AND lease_until>now() AND expires_at>now()
		ON CONFLICT(job_id,lease_token,attempt) DO UPDATE SET
		pod_uid=CASE WHEN remediation_workload_attempts.pod_uid='' THEN EXCLUDED.pod_uid ELSE remediation_workload_attempts.pod_uid END
		WHERE remediation_workload_attempts.job_uid=EXCLUDED.job_uid AND
		(remediation_workload_attempts.pod_uid='' OR EXCLUDED.pod_uid='' OR remediation_workload_attempts.pod_uid=EXCLUDED.pod_uid)`,
		job, lease, attempt, jobUID, podUID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrRemediationConflict
	}
	return nil
}
