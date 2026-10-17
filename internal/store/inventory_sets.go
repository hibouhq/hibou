package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// Inventory sets (ADR-045, Database section, option B). An inventory is an
// immutable, content-addressed list of components shared by every snapshot
// with the same content. Writers stage rows under a key and seal them:
// the database computes the digest, returns the existing set when it
// knows the content, and copies the rows otherwise. A snapshot's sources
// (uploaded SBOMs, the built-in extraction, recorded deliverables) each
// point at their own set; the snapshot points at the effective set, the
// merge of its active sources, which is the source set itself when there
// is one source.

// InventoryRow is one component with its flat label set.
type InventoryRow struct {
	ComponentID uuid.UUID
	Labels      json.RawMessage
}

// InventoryEdge is one dependency edge.
type InventoryEdge struct {
	ComponentID          uuid.UUID
	DependsOnComponentID uuid.UUID
}

// InventoryDocument is what one source contributes.
type InventoryDocument struct {
	Rows  []InventoryRow
	Edges []InventoryEdge
	Root  *uuid.UUID
}

// InventorySource is one piece of evidence of a snapshot.
type InventorySource struct {
	ID              int64
	Label           string
	SetID           *int64
	ArtifactID      *uuid.UUID
	ExtractionRunID *uuid.UUID
	Revoked         bool
}

const inventoryStageBatch = 2000

// StoreInventorySet seals the document as a set of the organisation and
// returns its id: the existing set when the content is known, a new one
// otherwise. Labels of a component listed twice merge.
func (q *Queries) StoreInventorySet(ctx context.Context, orgID uuid.UUID, doc InventoryDocument) (int64, error) {
	key := uuid.New()
	if err := q.stageInventory(ctx, key, doc); err != nil {
		_ = q.db.DiscardStagedInventoryComponents(ctx, key)
		_ = q.db.DiscardStagedInventoryEdges(ctx, key)
		return 0, err
	}
	return q.db.SealStagedInventory(ctx, dbgen.SealStagedInventoryParams{OrgID: orgID, StagingKey: key, RootComponentID: nullUUID(doc.Root)})
}

func (q *Queries) stageInventory(ctx context.Context, key uuid.UUID, doc InventoryDocument) error {
	exec := q.execer()
	for start := 0; start < len(doc.Rows); start += inventoryStageBatch {
		end := min(start+inventoryStageBatch, len(doc.Rows))
		ids := make([]string, 0, end-start)
		labels := make([]string, 0, end-start)
		for _, row := range doc.Rows[start:end] {
			ids = append(ids, row.ComponentID.String())
			if len(row.Labels) == 0 {
				labels = append(labels, "{}")
			} else {
				labels = append(labels, string(row.Labels))
			}
		}
		if _, err := exec.ExecContext(ctx, `
			INSERT INTO inventory_staging_components (staging_key, component_id, labels)
			SELECT $1, c.component_id, c.labels::jsonb
			FROM unnest($2::uuid[], $3::text[]) AS c(component_id, labels)
			ON CONFLICT (staging_key, component_id) DO UPDATE
			SET labels = inventory_staging_components.labels || EXCLUDED.labels`, key, pq.Array(ids), pq.Array(labels)); err != nil {
			return fmt.Errorf("stage inventory rows: %w", err)
		}
	}
	for start := 0; start < len(doc.Edges); start += inventoryStageBatch {
		end := min(start+inventoryStageBatch, len(doc.Edges))
		from := make([]string, 0, end-start)
		to := make([]string, 0, end-start)
		for _, edge := range doc.Edges[start:end] {
			from = append(from, edge.ComponentID.String())
			to = append(to, edge.DependsOnComponentID.String())
		}
		if _, err := exec.ExecContext(ctx, `
			INSERT INTO inventory_staging_edges (staging_key, component_id, depends_on_component_id)
			SELECT $1, e.component_id, e.depends_on_component_id
			FROM unnest($2::uuid[], $3::uuid[]) AS e(component_id, depends_on_component_id)
			ON CONFLICT DO NOTHING`, key, pq.Array(from), pq.Array(to)); err != nil {
			return fmt.Errorf("stage inventory edges: %w", err)
		}
	}
	return nil
}

// AttachInventorySource records that the snapshot has this source, with
// the set it contributed (nil for a source known through its label only).
func (q *Queries) AttachInventorySource(ctx context.Context, snapshotID uuid.UUID, label string, setID *int64, artifactID, extractionRunID *uuid.UUID) error {
	var set sql.NullInt64
	if setID != nil {
		set = sql.NullInt64{Int64: *setID, Valid: true}
	}
	_, err := q.db.UpsertInventorySource(ctx, dbgen.UpsertInventorySourceParams{
		SnapshotID: snapshotID, Label: label, SetID: set, ArtifactID: nullUUID(artifactID), ExtractionRunID: nullUUID(extractionRunID),
	})
	return err
}

// ListInventorySources lists the snapshot's sources, oldest first.
func (q *Queries) ListInventorySources(ctx context.Context, snapshotID uuid.UUID) ([]InventorySource, error) {
	rows, err := q.db.ListInventorySourcesBySnapshot(ctx, snapshotID)
	if err != nil {
		return nil, err
	}
	out := make([]InventorySource, 0, len(rows))
	for _, row := range rows {
		source := InventorySource{ID: row.ID, Label: row.Label, Revoked: row.Revoked}
		if row.SetID.Valid {
			id := row.SetID.Int64
			source.SetID = &id
		}
		if row.ArtifactID.Valid {
			id := row.ArtifactID.UUID
			source.ArtifactID = &id
		}
		if row.ExtractionRunID.Valid {
			id := row.ExtractionRunID.UUID
			source.ExtractionRunID = &id
		}
		out = append(out, source)
	}
	return out, nil
}

// InventorySourceSet returns the set one source of a snapshot contributed,
// nil when the source is unknown or predates inventory sets.
func (q *Queries) InventorySourceSet(ctx context.Context, snapshotID uuid.UUID, label string) (*int64, error) {
	sources, err := q.ListInventorySources(ctx, snapshotID)
	if err != nil {
		return nil, err
	}
	for _, source := range sources {
		if source.Label == label {
			return source.SetID, nil
		}
	}
	return nil, nil
}

// RecomputeSnapshotInventory points the snapshot at the merge of its active
// sources: the source's own set when there is one, nothing when there is
// none, a merged set otherwise. Returns the effective set id (nil when
// the snapshot has no inventory) and whether it changed.
func (q *Queries) RecomputeSnapshotInventory(ctx context.Context, snapshotID uuid.UUID) (*int64, bool, error) {
	snapshot, err := q.db.GetSnapshotByID(ctx, snapshotID)
	if err != nil {
		return nil, false, fmt.Errorf("load snapshot: %w", err)
	}
	sources, err := q.ListInventorySources(ctx, snapshotID)
	if err != nil {
		return nil, false, err
	}
	var current *int64
	if snapshot.InventorySetID.Valid {
		id := snapshot.InventorySetID.Int64
		current = &id
	}
	active := make([]InventorySource, 0, len(sources))
	for _, source := range sources {
		if !source.Revoked {
			active = append(active, source)
		}
	}
	var next *int64
	switch {
	case len(active) == 0:
		next = nil
	case len(active) == 1 && active[0].SetID != nil:
		next = active[0].SetID
	default:
		key := uuid.New()
		if err := q.db.StageEffectiveInventoryComponents(ctx, dbgen.StageEffectiveInventoryComponentsParams{StagingKey: key, SnapshotID: snapshotID}); err != nil {
			return nil, false, fmt.Errorf("stage effective inventory: %w", err)
		}
		if err := q.db.StageEffectiveInventoryEdges(ctx, dbgen.StageEffectiveInventoryEdgesParams{StagingKey: key, SnapshotID: snapshotID}); err != nil {
			_ = q.db.DiscardStagedInventoryComponents(ctx, key)
			return nil, false, fmt.Errorf("stage effective edges: %w", err)
		}
		root, err := q.db.GetEffectiveInventoryRoot(ctx, snapshotID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			_ = q.db.DiscardStagedInventoryComponents(ctx, key)
			_ = q.db.DiscardStagedInventoryEdges(ctx, key)
			return nil, false, fmt.Errorf("effective root: %w", err)
		}
		var rootID uuid.NullUUID
		if root != uuid.Nil {
			rootID = uuid.NullUUID{UUID: root, Valid: true}
		}
		id, err := q.db.SealStagedInventory(ctx, dbgen.SealStagedInventoryParams{OrgID: snapshot.OrgID, StagingKey: key, RootComponentID: rootID})
		if err != nil {
			return nil, false, fmt.Errorf("seal effective inventory: %w", err)
		}
		next = &id
	}
	if (current == nil && next == nil) || (current != nil && next != nil && *current == *next) {
		return next, false, nil
	}
	var set sql.NullInt64
	if next != nil {
		set = sql.NullInt64{Int64: *next, Valid: true}
	}
	if err := q.db.SetSnapshotInventorySet(ctx, dbgen.SetSnapshotInventorySetParams{SetID: set, SnapshotID: snapshotID}); err != nil {
		return nil, false, fmt.Errorf("point snapshot at inventory set: %w", err)
	}
	return next, true, nil
}

// IngestInventorySource stores the document as the source's set, records
// the source on the snapshot and recomputes the effective inventory.
// Returns the number of components the source contributed.
func (q *Queries) IngestInventorySource(ctx context.Context, snapshotID uuid.UUID, label string, artifactID, extractionRunID *uuid.UUID, doc InventoryDocument) (int, error) {
	snapshot, err := q.db.GetSnapshotByID(ctx, snapshotID)
	if err != nil {
		return 0, fmt.Errorf("load snapshot: %w", err)
	}
	setID, err := q.StoreInventorySet(ctx, snapshot.OrgID, doc)
	if err != nil {
		return 0, fmt.Errorf("store inventory set: %w", err)
	}
	if err := q.AttachInventorySource(ctx, snapshotID, label, &setID, artifactID, extractionRunID); err != nil {
		return 0, fmt.Errorf("attach inventory source: %w", err)
	}
	if _, _, err := q.RecomputeSnapshotInventory(ctx, snapshotID); err != nil {
		return 0, err
	}
	set, err := q.db.GetInventorySet(ctx, setID)
	if err != nil {
		return 0, err
	}
	return int(set.TotalCount.Int32), nil
}

// ReuseInventorySource makes the snapshot share a source of another
// snapshot (digest reuse, ADR-045 §4.1): one source row, no component
// rows. A source from before inventory sets is rebuilt from its label
// first. Returns the component count of the shared set.
func (q *Queries) ReuseInventorySource(ctx context.Context, fromSnapshotID, toSnapshotID uuid.UUID, label string, extractionRunID *uuid.UUID) (int, error) {
	setID, err := q.InventorySourceSet(ctx, fromSnapshotID, label)
	if err != nil {
		return 0, err
	}
	if setID == nil {
		rebuilt, err := q.rebuildLegacyInventorySource(ctx, fromSnapshotID, label)
		if err != nil {
			return 0, err
		}
		if rebuilt == nil {
			return 0, nil
		}
		setID = rebuilt
	}
	if err := q.AttachInventorySource(ctx, toSnapshotID, label, setID, nil, extractionRunID); err != nil {
		return 0, fmt.Errorf("attach reused source: %w", err)
	}
	if _, _, err := q.RecomputeSnapshotInventory(ctx, toSnapshotID); err != nil {
		return 0, err
	}
	set, err := q.db.GetInventorySet(ctx, *setID)
	if err != nil {
		return 0, err
	}
	return int(set.TotalCount.Int32), nil
}

// rebuildLegacyInventorySource seals the rows a pre-sets source
// contributed, read from the effective rows that carry its label, and
// records the set on the source. Returns nil when no row carries the label.
func (q *Queries) rebuildLegacyInventorySource(ctx context.Context, snapshotID uuid.UUID, label string) (*int64, error) {
	snapshot, err := q.db.GetSnapshotByID(ctx, snapshotID)
	if err != nil {
		return nil, fmt.Errorf("load snapshot: %w", err)
	}
	key := uuid.New()
	staged, err := q.db.StageInventorySourceFromLabel(ctx, dbgen.StageInventorySourceFromLabelParams{StagingKey: key, Label: label, SnapshotID: snapshotID})
	if err != nil {
		return nil, fmt.Errorf("stage legacy source: %w", err)
	}
	if staged == 0 {
		_ = q.db.DiscardStagedInventoryComponents(ctx, key)
		return nil, nil
	}
	if err := q.db.StageInventorySourceEdgesFromLabel(ctx, dbgen.StageInventorySourceEdgesFromLabelParams{StagingKey: key, Label: label, SnapshotID: snapshotID}); err != nil {
		_ = q.db.DiscardStagedInventoryComponents(ctx, key)
		return nil, fmt.Errorf("stage legacy edges: %w", err)
	}
	var root uuid.NullUUID
	if snapshot.InventorySetID.Valid {
		if set, err := q.db.GetInventorySet(ctx, snapshot.InventorySetID.Int64); err == nil {
			root = set.RootComponentID
		}
	}
	setID, err := q.db.SealStagedInventory(ctx, dbgen.SealStagedInventoryParams{OrgID: snapshot.OrgID, StagingKey: key, RootComponentID: root})
	if err != nil {
		return nil, fmt.Errorf("seal legacy source: %w", err)
	}
	if err := q.AttachInventorySource(ctx, snapshotID, label, &setID, nil, nil); err != nil {
		return nil, err
	}
	return &setID, nil
}

// RemoveSnapshotComponentSource recomputes the snapshot's inventory after
// one of its sources was revoked and returns how many components left it.
func (q *Queries) RemoveSnapshotComponentSource(ctx context.Context, snapshotID uuid.UUID, _ string) (int, error) {
	before, err := q.db.CountComponentsBySnapshot(ctx, snapshotID)
	if err != nil {
		return 0, err
	}
	if _, _, err := q.RecomputeSnapshotInventory(ctx, snapshotID); err != nil {
		return 0, err
	}
	after, err := q.db.CountComponentsBySnapshot(ctx, snapshotID)
	if err != nil {
		return 0, err
	}
	return int(max(before-after, 0)), nil
}

// ListInventorySetComponents reads a set's rows.
func (q *Queries) ListInventorySetComponents(ctx context.Context, setID int64) ([]InventoryRow, error) {
	rows, err := q.db.ListInventorySetComponents(ctx, setID)
	if err != nil {
		return nil, err
	}
	out := make([]InventoryRow, 0, len(rows))
	for _, row := range rows {
		out = append(out, InventoryRow{ComponentID: row.ComponentID, Labels: row.Labels})
	}
	return out, nil
}

// ListInventorySetEdges reads a set's edges.
func (q *Queries) ListInventorySetEdges(ctx context.Context, setID int64) ([]InventoryEdge, error) {
	rows, err := q.db.ListInventorySetEdges(ctx, setID)
	if err != nil {
		return nil, err
	}
	out := make([]InventoryEdge, 0, len(rows))
	for _, row := range rows {
		out = append(out, InventoryEdge{ComponentID: row.ComponentID, DependsOnComponentID: row.DependsOnComponentID})
	}
	return out, nil
}

// InventorySetStats is the monitoring view of the sets (ADR-039).
type InventorySetStats struct {
	Sets                   int64 `json:"sets"`
	ComponentRows          int64 `json:"component_rows"`
	EdgeRows               int64 `json:"edge_rows"`
	SnapshotsWithInventory int64 `json:"snapshots_with_inventory"`
}

// InventorySetStats counts the sets and what shares them.
func (q *Queries) InventorySetStats(ctx context.Context) (InventorySetStats, error) {
	row, err := q.db.InventorySetStats(ctx)
	if err != nil {
		return InventorySetStats{}, err
	}
	return InventorySetStats{Sets: row.Sets, ComponentRows: row.ComponentRows, EdgeRows: row.EdgeRows, SnapshotsWithInventory: row.SnapshotsWithInventory}, nil
}

// CollectInventorySets deletes up to limit sets nothing references any
// more, in its own transaction with the guard flag the immutability
// triggers require. Returns how many sets went.
func (q *Queries) CollectInventorySets(ctx context.Context, limit int) (int64, error) {
	if q.sqlDB == nil {
		return 0, errors.New("inventory collection needs a database handle")
	}
	tx, err := q.sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, "SET LOCAL hibou.inventory_gc = 'on'"); err != nil {
		_ = tx.Rollback()
		return 0, err
	}
	deleted, err := q.db.WithTx(tx).CollectInventorySets(ctx, int32(limit)) // #nosec G115 -- a small page size
	if err != nil {
		_ = tx.Rollback()
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		_ = tx.Rollback()
		return 0, err
	}
	return deleted, nil
}

// ---- One row at a time: tests and the development seed. Ingestion
// stages a whole document; these rebuild the snapshot's set per call.

// AttachComponentToSnapshot records a component's presence in a snapshot,
// merging labels into those already recorded for the pair. The snapshot's
// own single source is "manual"; a snapshot that has real sources is
// extended through that source's label instead.
func (q *Queries) AttachComponentToSnapshot(ctx context.Context, snapshotID, componentID uuid.UUID, labels json.RawMessage) error {
	return q.rebuildSnapshotInventory(ctx, snapshotID, func(doc *InventoryDocument) {
		for i := range doc.Rows {
			if doc.Rows[i].ComponentID == componentID {
				doc.Rows[i].Labels = mergeLabels(doc.Rows[i].Labels, labels)
				return
			}
		}
		doc.Rows = append(doc.Rows, InventoryRow{ComponentID: componentID, Labels: mergeLabels(nil, labels)})
	})
}

// UpsertComponentDependency adds one edge to the snapshot's inventory.
func (q *Queries) UpsertComponentDependency(ctx context.Context, snapshotID, componentID, dependsOnComponentID uuid.UUID) error {
	return q.rebuildSnapshotInventory(ctx, snapshotID, func(doc *InventoryDocument) {
		for _, edge := range doc.Edges {
			if edge.ComponentID == componentID && edge.DependsOnComponentID == dependsOnComponentID {
				return
			}
		}
		doc.Edges = append(doc.Edges, InventoryEdge{ComponentID: componentID, DependsOnComponentID: dependsOnComponentID})
	})
}

// UpsertSnapshotDependencyRoot sets the snapshot's dependency root.
func (q *Queries) UpsertSnapshotDependencyRoot(ctx context.Context, snapshotID, componentID uuid.UUID) error {
	return q.rebuildSnapshotInventory(ctx, snapshotID, func(doc *InventoryDocument) {
		root := componentID
		doc.Root = &root
	})
}

const manualInventoryLabel = "sbom:manual"

// rebuildSnapshotInventory applies edit to the snapshot's effective
// document and stores it back as the snapshot's single "manual" source.
func (q *Queries) rebuildSnapshotInventory(ctx context.Context, snapshotID uuid.UUID, edit func(*InventoryDocument)) error {
	snapshot, err := q.db.GetSnapshotByID(ctx, snapshotID)
	if err != nil {
		return fmt.Errorf("load snapshot: %w", err)
	}
	var doc InventoryDocument
	if snapshot.InventorySetID.Valid {
		set, err := q.db.GetInventorySet(ctx, snapshot.InventorySetID.Int64)
		if err != nil {
			return err
		}
		if set.RootComponentID.Valid {
			root := set.RootComponentID.UUID
			doc.Root = &root
		}
		if doc.Rows, err = q.ListInventorySetComponents(ctx, set.ID); err != nil {
			return err
		}
		if doc.Edges, err = q.ListInventorySetEdges(ctx, set.ID); err != nil {
			return err
		}
	}
	edit(&doc)
	sort.Slice(doc.Rows, func(i, j int) bool { return doc.Rows[i].ComponentID.String() < doc.Rows[j].ComponentID.String() })
	setID, err := q.StoreInventorySet(ctx, snapshot.OrgID, doc)
	if err != nil {
		return err
	}
	// The snapshot's other sources keep their rows through the merge; the
	// manual source carries everything, so the effective set is this one.
	if err := q.AttachInventorySource(ctx, snapshotID, manualInventoryLabel, &setID, nil, nil); err != nil {
		return err
	}
	return q.db.SetSnapshotInventorySet(ctx, dbgen.SetSnapshotInventorySetParams{SetID: sql.NullInt64{Int64: setID, Valid: true}, SnapshotID: snapshotID})
}

func mergeLabels(base, extra json.RawMessage) json.RawMessage {
	merged := map[string]any{}
	if len(base) > 0 {
		_ = json.Unmarshal(base, &merged)
	}
	if len(extra) > 0 {
		more := map[string]any{}
		_ = json.Unmarshal(extra, &more)
		for k, v := range more {
			merged[k] = v
		}
	}
	encoded, err := json.Marshal(merged)
	if err != nil {
		return json.RawMessage("{}")
	}
	return encoded
}

func nullUUID(id *uuid.UUID) uuid.NullUUID {
	if id == nil {
		return uuid.NullUUID{}
	}
	return uuid.NullUUID{UUID: *id, Valid: true}
}
