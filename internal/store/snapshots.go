package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/hibouhq/lehibou/internal/store/dbgen"
)

type SnapshotStatus = dbgen.SnapshotStatus

const (
	SnapshotStatusPending    = dbgen.SnapshotStatusPending
	SnapshotStatusProcessing = dbgen.SnapshotStatusProcessing
	SnapshotStatusComplete   = dbgen.SnapshotStatusComplete
	SnapshotStatusFailed     = dbgen.SnapshotStatusFailed
)

type Snapshot struct {
	ID             uuid.UUID      `json:"id"`
	RefID          uuid.UUID      `json:"ref_id"`
	CommitSHA      string         `json:"commit_sha"`
	Label          *string        `json:"label,omitempty"`
	Status         SnapshotStatus `json:"status"`
	RawArtifactURL *string        `json:"raw_artifact_url,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
}

func (q *Queries) CreateSnapshot(ctx context.Context, refID uuid.UUID, commitSHA string, label *string, status SnapshotStatus, rawArtifactURL *string) (*Snapshot, error) {
	row, err := q.db.CreateSnapshot(ctx, dbgen.CreateSnapshotParams{
		RefID:          refID,
		CommitSha:      commitSHA,
		Label:          nullStringFromPtr(label),
		Status:         status,
		RawArtifactUrl: nullStringFromPtr(rawArtifactURL),
	})
	if err != nil {
		return nil, err
	}

	return snapshotFromRow(row), nil
}

func (q *Queries) GetSnapshotByID(ctx context.Context, id uuid.UUID) (*Snapshot, error) {
	row, err := q.db.GetSnapshotByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return snapshotFromRow(row), nil
}

func (q *Queries) ListSnapshotsByRef(ctx context.Context, refID uuid.UUID, limit, offset int) ([]Snapshot, int, error) {
	rows, err := q.db.ListSnapshotsByRef(ctx, dbgen.ListSnapshotsByRefParams{
		RefID:  refID,
		Limit:  int32(limit),
		Offset: int32(offset),
	})
	if err != nil {
		return nil, 0, err
	}

	snapshots := make([]Snapshot, len(rows))
	for i, row := range rows {
		snapshots[i] = *snapshotFromRow(row)
	}

	total, err := q.db.CountSnapshotsByRef(ctx, refID)
	if err != nil {
		return nil, 0, err
	}

	return snapshots, int(total), nil
}

func (q *Queries) UpdateSnapshotStatus(ctx context.Context, id uuid.UUID, status SnapshotStatus) (*Snapshot, error) {
	row, err := q.db.UpdateSnapshotStatus(ctx, dbgen.UpdateSnapshotStatusParams{
		ID:     id,
		Status: status,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return snapshotFromRow(row), nil
}

func (q *Queries) GetLatestSnapshotByRef(ctx context.Context, refID uuid.UUID) (*Snapshot, error) {
	row, err := q.db.GetLatestSnapshotByRef(ctx, refID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return snapshotFromRow(row), nil
}

func snapshotFromRow(row dbgen.Snapshot) *Snapshot {
	return &Snapshot{
		ID:             row.ID,
		RefID:          row.RefID,
		CommitSHA:      row.CommitSha,
		Label:          stringPtrFromNull(row.Label),
		Status:         row.Status,
		RawArtifactURL: stringPtrFromNull(row.RawArtifactUrl),
		CreatedAt:      row.CreatedAt,
	}
}
