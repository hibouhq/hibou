package store

import (
	"context"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// UpsertScanRule inserts or updates the catalog row for a (tool, rule_id) pair
// and returns its stable id. Findings reference this id via rule_ref_id instead
// of copying the rule descriptor into every vulnerability's metadata.
func (q *Queries) UpsertScanRule(ctx context.Context, params dbgen.UpsertScanRuleParams) (uuid.UUID, error) {
	return q.db.UpsertScanRule(ctx, params)
}

// ListScanRulesBySnapshot returns the distinct rule descriptors referenced by a
// snapshot's findings, so the UI can fetch rule metadata once per rule instead
// of per finding.
func (q *Queries) ListScanRulesBySnapshot(ctx context.Context, snapshotID uuid.UUID) ([]dbgen.ScanRule, error) {
	return q.db.ListScanRulesBySnapshot(ctx, snapshotID)
}
