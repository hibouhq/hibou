package store

import (
	"context"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

func (q *Queries) UpsertComponent(ctx context.Context, purl, name, version, ecosystem string) (dbgen.Component, error) {
	return q.db.UpsertComponent(ctx, dbgen.UpsertComponentParams{
		Purl:      purl,
		Name:      name,
		Version:   version,
		Ecosystem: ecosystem,
		Licenses:  []string{},
	})
}

func (q *Queries) AttachComponentToSnapshot(ctx context.Context, snapshotID, componentID uuid.UUID) error {
	return q.db.AttachComponentToSnapshot(ctx, dbgen.AttachComponentToSnapshotParams{
		SnapshotID:  snapshotID,
		ComponentID: componentID,
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
