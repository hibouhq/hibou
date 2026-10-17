package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// Findings once per repository, presence per snapshot (ADR-049). The
// readers keep the vulnerabilities view; these are the few calls that
// address the two tables directly.

// GetVulnerabilityBySnapshotAndID reads one occurrence: the finding as
// the snapshot carries it.
func (q *Queries) GetVulnerabilityBySnapshotAndID(ctx context.Context, snapshotID, findingID uuid.UUID) (*Vulnerability, error) {
	row, err := q.db.GetVulnerabilityBySnapshotAndID(ctx, dbgen.GetVulnerabilityBySnapshotAndIDParams{SnapshotID: snapshotID, ID: findingID})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return vulnerabilityFromRow(row), nil
}

// FindingExists says whether the finding row itself still exists,
// whatever snapshots carry it.
func (q *Queries) FindingExists(ctx context.Context, findingID uuid.UUID) (bool, error) {
	_, err := q.db.GetFindingByID(ctx, findingID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// CollectOrphanFindings deletes up to limit findings no snapshot carries
// and nothing has seen for a month. Returns how many went.
func (q *Queries) CollectOrphanFindings(ctx context.Context, limit int) (int64, error) {
	return q.db.CollectOrphanFindings(ctx, int32(limit)) // #nosec G115 -- a small page size
}

// FindingStats is the monitoring view of the findings (ADR-039): how many
// distinct findings the instance holds and how many snapshot rows point
// at them.
type FindingStats struct {
	Findings     int64 `json:"findings"`
	SnapshotRows int64 `json:"snapshot_rows"`
}

// FindingStats counts findings and the snapshot rows carrying them.
func (q *Queries) FindingStats(ctx context.Context) (FindingStats, error) {
	row, err := q.db.FindingStats(ctx)
	if err != nil {
		return FindingStats{}, err
	}
	return FindingStats{Findings: row.Findings, SnapshotRows: row.SnapshotRows}, nil
}
