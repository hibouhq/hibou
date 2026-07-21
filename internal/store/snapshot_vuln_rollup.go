package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// SnapshotVulnRollup is the compact per-snapshot severity/type summary retained
// after a snapshot is archived and its detail vulnerability rows are pruned.
type SnapshotVulnRollup = dbgen.SnapshotVulnRollup

// RollupSnapshotVulnerabilities collapses a snapshot's detail vulnerability rows
// into a single snapshot_vuln_rollup row (counts keyed as {type: {severity: n}})
// and deletes the detail. Runs in one transaction so a snapshot is never left
// with neither detail nor rollup. Returns the total number of rolled-up rows.
func (q *Queries) RollupSnapshotVulnerabilities(ctx context.Context, snapshotID uuid.UUID) (int64, error) {
	tx, err := q.BeginTx(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	qtx := q.WithTx(tx).db

	rows, err := qtx.AggregateSnapshotVulnRollup(ctx, snapshotID)
	if err != nil {
		return 0, fmt.Errorf("aggregate snapshot vuln rollup: %w", err)
	}

	counts := make(map[string]map[string]int64, len(rows))
	var total int64
	for _, row := range rows {
		if counts[row.VulnType] == nil {
			counts[row.VulnType] = map[string]int64{}
		}
		counts[row.VulnType][row.Severity] = row.Count
		total += row.Count
	}
	countsJSON, err := json.Marshal(counts)
	if err != nil {
		return 0, fmt.Errorf("marshal rollup counts: %w", err)
	}

	if err := qtx.UpsertSnapshotVulnRollup(ctx, dbgen.UpsertSnapshotVulnRollupParams{
		SnapshotID: snapshotID,
		Counts:     countsJSON,
		Total:      int32(total),
	}); err != nil {
		return 0, fmt.Errorf("upsert snapshot vuln rollup: %w", err)
	}

	if err := qtx.DeleteVulnerabilitiesBySnapshot(ctx, snapshotID); err != nil {
		return 0, fmt.Errorf("prune snapshot vulnerabilities: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return total, nil
}

// GetSnapshotVulnRollup returns the rollup for a snapshot, or (_, false, nil)
// when the snapshot has not been rolled up.
func (q *Queries) GetSnapshotVulnRollup(ctx context.Context, snapshotID uuid.UUID) (SnapshotVulnRollup, bool, error) {
	rollup, err := q.db.GetSnapshotVulnRollup(ctx, snapshotID)
	if errors.Is(err, sql.ErrNoRows) {
		return SnapshotVulnRollup{}, false, nil
	}
	if err != nil {
		return SnapshotVulnRollup{}, false, err
	}
	return rollup, true, nil
}
