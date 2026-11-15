package store

import (
	"context"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// GetGateScanReadiness reports a snapshot's advisory-scan state for gate
// eligibility (PLAN §1); see the SQL comment for the semantics.
func (q *Queries) GetGateScanReadiness(ctx context.Context, snapshotID uuid.UUID) (dbgen.GetGateScanReadinessRow, error) {
	return q.db.GetGateScanReadiness(ctx, snapshotID)
}

func (q *Queries) FailUnfinishedScan(ctx context.Context, scanID uuid.UUID, detail string) error {
	return q.finishUnfinishedScan(ctx, scanID, "failed", detail)
}

func (q *Queries) CancelUnfinishedScan(ctx context.Context, scanID uuid.UUID, detail string) error {
	return q.finishUnfinishedScan(ctx, scanID, "cancelled", detail)
}

func (q *Queries) finishUnfinishedScan(ctx context.Context, scanID uuid.UUID, status, detail string) error {
	_, err := q.execer().ExecContext(ctx, `WITH finished AS (
		UPDATE scans SET status=$2::scan_status,error_message=$3,completed_at=now()
		WHERE id=$1 AND status IN ('pending','running') RETURNING id
	)
	UPDATE scan_providers SET status=$2::scan_status,error_message=$3,completed_at=now()
	WHERE scan_id IN (SELECT id FROM finished) AND status IN ('pending','running')`, scanID, status, detail)
	return err
}
