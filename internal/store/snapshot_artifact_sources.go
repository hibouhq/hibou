package store

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// Artifact origins (ADR-045 §5.2): where an inventory source came from.
const (
	ArtifactOriginCI     = "ci"
	ArtifactOriginServer = "hibou"
	ArtifactOriginManual = "manual"
)

// SetSnapshotArtifactSource records the origin, the recorder and the
// deliverable metadata of an artifact.
func (q *Queries) SetSnapshotArtifactSource(ctx context.Context, artifactID uuid.UUID, origin string, createdBy *uuid.UUID, metadata json.RawMessage) error {
	return q.db.SetSnapshotArtifactSource(ctx, dbgen.SetSnapshotArtifactSourceParams{
		ID:        artifactID,
		Origin:    origin,
		CreatedBy: nullUUIDFromPtr(createdBy),
		Metadata:  rawJSONOrEmpty(metadata),
	})
}

func rawJSONOrEmpty(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage("{}")
	}
	return raw
}

// RevokeSnapshotArtifact marks an artifact revoked; false when it was
// already revoked or does not exist.
func (q *Queries) RevokeSnapshotArtifact(ctx context.Context, artifactID uuid.UUID, revokedBy *uuid.UUID, reason string) (bool, error) {
	rows, err := q.db.RevokeSnapshotArtifact(ctx, dbgen.RevokeSnapshotArtifactParams{ID: artifactID, RevokedBy: nullUUIDFromPtr(revokedBy), Reason: sql.NullString{String: reason, Valid: true}})
	if err != nil {
		return false, err
	}
	return rows > 0, nil
}

// RestoreSnapshotArtifact lifts a revocation.
func (q *Queries) RestoreSnapshotArtifact(ctx context.Context, artifactID uuid.UUID) (bool, error) {
	rows, err := q.db.RestoreSnapshotArtifact(ctx, artifactID)
	if err != nil {
		return false, err
	}
	return rows > 0, nil
}

// CountSnapshotComponentsBySourceLabel counts the components an artifact
// reports ("sbom:<filename>").
func (q *Queries) CountSnapshotComponentsBySourceLabel(ctx context.Context, snapshotID uuid.UUID, label string) (int, error) {
	count, err := q.db.CountSnapshotComponentsBySourceLabel(ctx, dbgen.CountSnapshotComponentsBySourceLabelParams{SnapshotID: snapshotID, Label: label})
	return int(count), err
}
