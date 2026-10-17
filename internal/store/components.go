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

// ListSnapshotComponentLabels returns each component's provenance labels in
// the snapshot, keyed by component id.
func (q *Queries) ListSnapshotComponentLabels(ctx context.Context, snapshotID uuid.UUID) (map[uuid.UUID]json.RawMessage, error) {
	rows, err := q.db.ListSnapshotComponentLabels(ctx, snapshotID)
	if err != nil {
		return nil, err
	}
	out := make(map[uuid.UUID]json.RawMessage, len(rows))
	for _, row := range rows {
		out[row.ComponentID] = row.Labels
	}
	return out, nil
}
