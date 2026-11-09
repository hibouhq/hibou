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
	_, err := q.execer().ExecContext(ctx, `UPDATE scans SET status='failed',error_message=$2,completed_at=now()
		WHERE id=$1 AND status IN ('pending','running')`, scanID, detail)
	return err
}
