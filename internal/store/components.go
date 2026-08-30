package store

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

func (q *Queries) UpsertComponent(ctx context.Context, purl, name, version, ecosystem string, licenses []string) (dbgen.Component, error) {
	if licenses == nil {
		licenses = []string{}
	}
	return q.db.UpsertComponent(ctx, dbgen.UpsertComponentParams{
		Purl:      purl,
		Name:      name,
		Version:   version,
		Ecosystem: ecosystem,
		Licenses:  licenses,
	})
}

// AttachComponentToSnapshot records a component's presence in a snapshot.
// labels may be nil; when set it is merged into any labels already recorded for
// this pair (see the query for why the merge is shallow).
func (q *Queries) AttachComponentToSnapshot(ctx context.Context, snapshotID, componentID uuid.UUID, labels json.RawMessage) error {
	return q.db.AttachComponentToSnapshot(ctx, dbgen.AttachComponentToSnapshotParams{
		SnapshotID:  snapshotID,
		ComponentID: componentID,
		Labels:      labels,
	})
}

func (q *Queries) UpsertComponentDependency(ctx context.Context, snapshotID, componentID, dependsOnComponentID uuid.UUID) error {
	return q.db.UpsertComponentDependency(ctx, dbgen.UpsertComponentDependencyParams{
		SnapshotID:           snapshotID,
		ComponentID:          componentID,
		DependsOnComponentID: dependsOnComponentID,
	})
}

func (q *Queries) UpsertSnapshotDependencyRoot(ctx context.Context, snapshotID, componentID uuid.UUID) error {
	return q.db.UpsertSnapshotDependencyRoot(ctx, dbgen.UpsertSnapshotDependencyRootParams{
		SnapshotID:  snapshotID,
		ComponentID: componentID,
	})
}
