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
