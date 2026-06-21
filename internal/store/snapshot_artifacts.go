package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type SnapshotArtifact struct {
	ID          uuid.UUID `json:"id"`
	SnapshotID  uuid.UUID `json:"snapshot_id"`
	Kind        string    `json:"kind"`
	Format      *string   `json:"format,omitempty"`
	ToolName    *string   `json:"tool_name,omitempty"`
	ObjectKey   string    `json:"object_key"`
	SHA256      *string   `json:"sha256,omitempty"`
	SizeBytes   int64     `json:"size_bytes"`
	ContentType *string   `json:"content_type,omitempty"`
	Filename    string    `json:"filename,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

type CreateSnapshotArtifactParams struct {
	SnapshotID  uuid.UUID
	Kind        string
	Format      *string
	ToolName    *string
	ObjectKey   string
	SHA256      *string
	SizeBytes   int64
	ContentType *string
	Filename    string
}

func (q *Queries) CreateSnapshotArtifact(ctx context.Context, params CreateSnapshotArtifactParams) (*SnapshotArtifact, error) {
	row, err := q.db.CreateSnapshotArtifact(ctx, dbgen.CreateSnapshotArtifactParams{
		SnapshotID:  params.SnapshotID,
		Kind:        params.Kind,
		Format:      nullStringFromPtr(params.Format),
		ToolName:    nullStringFromPtr(params.ToolName),
		ObjectKey:   params.ObjectKey,
		Sha256:      nullStringFromPtr(params.SHA256),
		SizeBytes:   params.SizeBytes,
		ContentType: nullStringFromPtr(params.ContentType),
		Filename:    params.Filename,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return snapshotArtifactFromRow(row), nil
}

func (q *Queries) ListSnapshotArtifactsBySnapshot(ctx context.Context, snapshotID uuid.UUID) ([]SnapshotArtifact, error) {
	rows, err := q.db.ListSnapshotArtifactsBySnapshot(ctx, snapshotID)
	if err != nil {
		return nil, err
	}

	artifacts := make([]SnapshotArtifact, len(rows))
	for i, row := range rows {
		artifacts[i] = *snapshotArtifactFromRow(row)
	}

	return artifacts, nil
}

func (q *Queries) ListSnapshotArtifactObjectKeys(ctx context.Context, snapshotID uuid.UUID) ([]string, error) {
	return q.db.ListSnapshotArtifactObjectKeys(ctx, snapshotID)
}

// ListSnapshotArtifactObjectKeysByRepo returns every object-store key for all
// snapshots under a repository, for cleanup before a repository hard delete.
func (q *Queries) ListSnapshotArtifactObjectKeysByRepo(ctx context.Context, repoID uuid.UUID) ([]string, error) {
	return q.db.ListSnapshotArtifactObjectKeysByRepo(ctx, repoID)
}

// ListSnapshotArtifactObjectKeysByOrg returns every object-store key for all
// snapshots under an organization, for cleanup before an org hard delete.
func (q *Queries) ListSnapshotArtifactObjectKeysByOrg(ctx context.Context, orgID uuid.UUID) ([]string, error) {
	return q.db.ListSnapshotArtifactObjectKeysByOrg(ctx, orgID)
}

func snapshotArtifactFromRow(row dbgen.SnapshotArtifact) *SnapshotArtifact {
	return &SnapshotArtifact{
		ID:          row.ID,
		SnapshotID:  row.SnapshotID,
		Kind:        row.Kind,
		Format:      stringPtrFromNull(row.Format),
		ToolName:    stringPtrFromNull(row.ToolName),
		ObjectKey:   row.ObjectKey,
		SHA256:      stringPtrFromNull(row.Sha256),
		SizeBytes:   row.SizeBytes,
		ContentType: stringPtrFromNull(row.ContentType),
		Filename:    row.Filename,
		CreatedAt:   row.CreatedAt,
	}
}
