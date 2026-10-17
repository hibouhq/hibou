package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func openInventoryTestDB(t *testing.T) (*sql.DB, *Queries) {
	t.Helper()
	databaseURL := os.Getenv("HIBOU_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = testDatabaseURL
	}
	var (
		db  *sql.DB
		err error
	)
	for range 10 {
		db, err = New(databaseURL)
		if err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		t.Skipf("database not available: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate() returned error: %v", err)
	}
	return db, NewQueries(db)
}

func inventoryLabels(t *testing.T, raw json.RawMessage) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("labels %s: %v", raw, err)
	}
	return out
}

// Identical content is one set; a second source merges into a new
// effective set; reuse by digest writes a pointer, not rows; revocation
// recomputes; purge releases; the collector frees what nothing references.
func TestInventorySetsLifecycle(t *testing.T) {
	db, queries := openInventoryTestDB(t)
	ctx := context.Background()
	first := createSnapshotForStatusTest(t, ctx, queries, SnapshotStatusComplete)
	snapshotRow, err := queries.db.GetSnapshotByID(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	orgID := snapshotRow.OrgID
	// A second snapshot of the same repository.
	ref, err := queries.CreateRef(ctx, snapshotRow.RepoID, "feature", RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := queries.CreateSnapshot(ctx, ref.ID, uniqueStoreTestName(t, "commit"), SnapshotStatusComplete)
	if err != nil {
		t.Fatal(err)
	}

	lodash, _ := queries.UpsertComponent(ctx, "pkg:npm/lodash@4.17.21", "lodash", "4.17.21", "npm", nil)
	react, _ := queries.UpsertComponent(ctx, "pkg:npm/react@18.2.0", "react", "18.2.0", "npm", nil)
	jest, _ := queries.UpsertComponent(ctx, "pkg:npm/jest@29.0.0", "jest", "29.0.0", "npm", nil)
	const extraction = "sbom:hibou-depinventory.cdx.json"
	extracted := InventoryDocument{
		Rows: []InventoryRow{
			{ComponentID: lodash.ID, Labels: json.RawMessage(`{"` + extraction + `":true,"relationship:direct":true,"module:.":true}`)},
			{ComponentID: react.ID, Labels: json.RawMessage(`{"` + extraction + `":true,"relationship:indirect":true,"module:.":true}`)},
		},
		Edges: []InventoryEdge{{ComponentID: lodash.ID, DependsOnComponentID: react.ID}},
	}

	// 1. The same document twice is one set.
	setA, err := queries.StoreInventorySet(ctx, orgID, extracted)
	if err != nil {
		t.Fatal(err)
	}
	setB, err := queries.StoreInventorySet(ctx, orgID, extracted)
	if err != nil {
		t.Fatal(err)
	}
	if setA != setB {
		t.Fatalf("identical content stored twice: sets %d and %d", setA, setB)
	}
	set, err := queries.db.GetInventorySet(ctx, setA)
	if err != nil || !set.SealedAt.Valid || set.TotalCount.Int32 != 2 || set.DirectCount.Int32 != 1 || set.IndirectCount.Int32 != 1 {
		t.Fatalf("sealed set %+v (%v)", set, err)
	}
	// A different label set is different content.
	other := extracted
	other.Rows = []InventoryRow{extracted.Rows[0], {ComponentID: react.ID, Labels: json.RawMessage(`{"` + extraction + `":true,"relationship:direct":true}`)}}
	if setC, err := queries.StoreInventorySet(ctx, orgID, other); err != nil || setC == setA {
		t.Fatalf("different labels must be a different set: %d vs %d (%v)", setC, setA, err)
	}

	// 2. Ingest as the first snapshot's extraction: one source, effective
	// set is the source set itself.
	count, err := queries.IngestInventorySource(ctx, first, extraction, nil, nil, extracted)
	if err != nil || count != 2 {
		t.Fatalf("ingest: %d %v", count, err)
	}
	row, _ := queries.db.GetSnapshotByID(ctx, first)
	if !row.InventorySetID.Valid || row.InventorySetID.Int64 != setA {
		t.Fatalf("snapshot points at %v, want %d", row.InventorySetID, setA)
	}
	components, err := queries.ListComponentsBySnapshot(ctx, first)
	if err != nil || len(components) != 2 {
		t.Fatalf("view: %d components %v", len(components), err)
	}
	edges, _ := queries.ListComponentDependencyEdgesBySnapshot(ctx, first)
	if len(edges) != 1 || edges[0].Ref != "pkg:npm/lodash@4.17.21" {
		t.Fatalf("edges through the view: %+v", edges)
	}

	// 3. A CI SBOM arrives: the effective set is the merge, labels of a
	// component both report carry both sources.
	ciArtifact, err := queries.CreateSnapshotArtifact(ctx, CreateSnapshotArtifactParams{SnapshotID: first, Kind: "sbom", ObjectKey: "k/" + uuid.NewString(), Filename: "ci.cdx.json"})
	if err != nil {
		t.Fatal(err)
	}
	ci := InventoryDocument{Rows: []InventoryRow{
		{ComponentID: react.ID, Labels: json.RawMessage(`{"sbom:ci.cdx.json":true}`)},
		{ComponentID: jest.ID, Labels: json.RawMessage(`{"sbom:ci.cdx.json":true}`)},
	}}
	if _, err := queries.IngestInventorySource(ctx, first, "sbom:ci.cdx.json", &ciArtifact.ID, nil, ci); err != nil {
		t.Fatal(err)
	}
	labels, _ := queries.ListSnapshotComponentLabels(ctx, first)
	if len(labels) != 3 {
		t.Fatalf("merged inventory has %d components, want 3", len(labels))
	}
	reactLabels := inventoryLabels(t, labels[react.ID])
	if !reactLabels[extraction] || !reactLabels["sbom:ci.cdx.json"] || !reactLabels["relationship:indirect"] {
		t.Errorf("react labels after merge: %v", reactLabels)
	}
	row, _ = queries.db.GetSnapshotByID(ctx, first)
	effective := row.InventorySetID.Int64
	if effective == setA {
		t.Fatal("the merge must be its own set")
	}
	if edges, _ := queries.ListComponentDependencyEdgesBySnapshot(ctx, first); len(edges) != 1 {
		t.Errorf("edges after merge: %d", len(edges))
	}

	// 4. Reuse by digest on the second snapshot: a pointer at the same
	// source set, no new component rows.
	before, _ := queries.InventorySetStats(ctx)
	copied, err := queries.ReuseInventorySource(ctx, first, second.ID, extraction, nil)
	if err != nil || copied != 2 {
		t.Fatalf("reuse: %d %v", copied, err)
	}
	after, _ := queries.InventorySetStats(ctx)
	if after.ComponentRows != before.ComponentRows || after.Sets != before.Sets {
		t.Errorf("reuse wrote rows: sets %d→%d rows %d→%d", before.Sets, after.Sets, before.ComponentRows, after.ComponentRows)
	}
	secondRow, _ := queries.db.GetSnapshotByID(ctx, second.ID)
	if secondRow.InventorySetID.Int64 != setA {
		t.Errorf("second snapshot points at %d, want the shared source set %d", secondRow.InventorySetID.Int64, setA)
	}

	// 5. Revoking the CI SBOM recomputes: jest leaves, react keeps the
	// extraction's labels only, the effective set is the extraction's.
	if _, err := queries.RevokeSnapshotArtifact(ctx, ciArtifact.ID, nil, "wrong file"); err != nil {
		t.Fatal(err)
	}
	removed, err := queries.RemoveSnapshotComponentSource(ctx, first, "sbom:ci.cdx.json")
	if err != nil || removed != 1 {
		t.Fatalf("revocation removed %d (%v), want 1", removed, err)
	}
	row, _ = queries.db.GetSnapshotByID(ctx, first)
	if row.InventorySetID.Int64 != setA {
		t.Errorf("after revocation the snapshot points at %d, want %d", row.InventorySetID.Int64, setA)
	}

	// 6. Sealed sets are immutable.
	if _, err := db.ExecContext(ctx, "UPDATE inventory_set_components SET labels = '{}' WHERE set_id = $1", setA); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Errorf("row update must be rejected: %v", err)
	}
	if _, err := db.ExecContext(ctx, "DELETE FROM inventory_sets WHERE id = $1", effective); err == nil || !strings.Contains(err.Error(), "garbage collector") {
		t.Errorf("set delete outside the collector must be rejected: %v", err)
	}

	// 7. The merged set is referenced by nothing now; the collector frees
	// it once it is old enough, and nothing else.
	if _, err := db.ExecContext(ctx, "UPDATE inventory_sets SET created_at = now() - interval '2 hours' WHERE id = $1 AND sealed_at IS NOT NULL", effective); err != nil {
		// The guard rejects updates of sealed sets; age it through the
		// collector's own flag instead.
		tx, _ := db.BeginTx(ctx, nil)
		_, _ = tx.ExecContext(ctx, "SET LOCAL hibou.inventory_gc = 'on'")
		_, _ = tx.ExecContext(ctx, "ALTER TABLE inventory_sets DISABLE TRIGGER inventory_sets_guard")
		_, _ = tx.ExecContext(ctx, "UPDATE inventory_sets SET created_at = now() - interval '2 hours' WHERE id = $1", effective)
		_, _ = tx.ExecContext(ctx, "ALTER TABLE inventory_sets ENABLE TRIGGER inventory_sets_guard")
		_ = tx.Commit()
	}
	if _, err := queries.CollectInventorySets(ctx, 100); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if _, err := queries.db.GetInventorySet(ctx, effective); err == nil {
		t.Error("the unreferenced merged set survived collection")
	}
	if _, err := queries.db.GetInventorySet(ctx, setA); err != nil {
		t.Errorf("the shared set must survive: %v", err)
	}

	// 8. Purging the first snapshot releases its inventory; the second
	// still shares the set.
	if err := queries.PurgeSnapshot(ctx, first); err != nil {
		t.Fatal(err)
	}
	row, _ = queries.db.GetSnapshotByID(ctx, first)
	if row.InventorySetID.Valid {
		t.Error("a purged snapshot keeps no inventory")
	}
	if sources, _ := queries.ListInventorySources(ctx, first); len(sources) != 0 {
		t.Errorf("purged snapshot keeps %d sources", len(sources))
	}
	if components, _ := queries.ListComponentsBySnapshot(ctx, second.ID); len(components) != 2 {
		t.Errorf("the second snapshot lost its inventory: %d", len(components))
	}

	// 9. One row at a time (tests, seed): labels merge, edges and root land.
	third := createSnapshotForStatusTest(t, ctx, queries, SnapshotStatusComplete)
	if err := queries.AttachComponentToSnapshot(ctx, third, lodash.ID, json.RawMessage(`{"sbom:a.cdx.json":true}`)); err != nil {
		t.Fatal(err)
	}
	if err := queries.AttachComponentToSnapshot(ctx, third, lodash.ID, json.RawMessage(`{"relationship:direct":true}`)); err != nil {
		t.Fatal(err)
	}
	if err := queries.AttachComponentToSnapshot(ctx, third, react.ID, nil); err != nil {
		t.Fatal(err)
	}
	if err := queries.UpsertComponentDependency(ctx, third, lodash.ID, react.ID); err != nil {
		t.Fatal(err)
	}
	if err := queries.UpsertSnapshotDependencyRoot(ctx, third, lodash.ID); err != nil {
		t.Fatal(err)
	}
	labels, _ = queries.ListSnapshotComponentLabels(ctx, third)
	if l := inventoryLabels(t, labels[lodash.ID]); len(labels) != 2 || !l["sbom:a.cdx.json"] || !l["relationship:direct"] {
		t.Errorf("row-at-a-time labels: %v (%d components)", l, len(labels))
	}
	if root, _ := queries.GetSnapshotDependencyRoot(ctx, third); root == nil || *root != "pkg:npm/lodash@4.17.21" {
		t.Errorf("root %v", root)
	}
	if edges, _ := queries.ListComponentDependencyEdgesBySnapshot(ctx, third); len(edges) != 1 {
		t.Errorf("edges %d", len(edges))
	}
}

// Sources from before inventory sets are known through their label only;
// recomputation and reuse rebuild them from the effective rows.
func TestInventorySetsLegacySources(t *testing.T) {
	db, queries := openInventoryTestDB(t)
	ctx := context.Background()
	snapshotID := createSnapshotForStatusTest(t, ctx, queries, SnapshotStatusComplete)
	a, _ := queries.UpsertComponent(ctx, "pkg:npm/a@1.0.0", "a", "1.0.0", "npm", nil)
	b, _ := queries.UpsertComponent(ctx, "pkg:npm/b@1.0.0", "b", "1.0.0", "npm", nil)
	c, _ := queries.UpsertComponent(ctx, "pkg:npm/c@1.0.0", "c", "1.0.0", "npm", nil)
	// The effective rows as the backfill left them: merged labels, no set
	// per source.
	for _, row := range []struct {
		id     uuid.UUID
		labels string
	}{
		{a.ID, `{"sbom:x.cdx.json":true,"sbom:y.cdx.json":true,"relationship:direct":true}`},
		{b.ID, `{"sbom:x.cdx.json":true}`},
		{c.ID, `{"sbom:y.cdx.json":true}`},
	} {
		if err := queries.AttachComponentToSnapshot(ctx, snapshotID, row.id, json.RawMessage(row.labels)); err != nil {
			t.Fatal(err)
		}
	}
	if err := queries.UpsertComponentDependency(ctx, snapshotID, a.ID, b.ID); err != nil {
		t.Fatal(err)
	}
	// Replace the manual source with two label-only sources, as the
	// migration records them.
	x, err := queries.CreateSnapshotArtifact(ctx, CreateSnapshotArtifactParams{SnapshotID: snapshotID, Kind: "sbom", ObjectKey: "k/" + uuid.NewString(), Filename: "x.cdx.json"})
	if err != nil {
		t.Fatal(err)
	}
	y, err := queries.CreateSnapshotArtifact(ctx, CreateSnapshotArtifactParams{SnapshotID: snapshotID, Kind: "sbom", ObjectKey: "k/" + uuid.NewString(), Filename: "y.cdx.json"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "DELETE FROM inventory_sources WHERE snapshot_id = $1", snapshotID); err != nil {
		t.Fatal(err)
	}
	if err := queries.AttachInventorySource(ctx, snapshotID, "sbom:x.cdx.json", nil, &x.ID, nil); err != nil {
		t.Fatal(err)
	}
	if err := queries.AttachInventorySource(ctx, snapshotID, "sbom:y.cdx.json", nil, &y.ID, nil); err != nil {
		t.Fatal(err)
	}

	// Revoking y keeps a (x reports it) without y's label, keeps b, drops c.
	if _, err := queries.RevokeSnapshotArtifact(ctx, y.ID, nil, "wrong"); err != nil {
		t.Fatal(err)
	}
	removed, err := queries.RemoveSnapshotComponentSource(ctx, snapshotID, "sbom:y.cdx.json")
	if err != nil || removed != 1 {
		t.Fatalf("removed %d (%v)", removed, err)
	}
	labels, _ := queries.ListSnapshotComponentLabels(ctx, snapshotID)
	if len(labels) != 2 {
		t.Fatalf("%d components after revocation, want 2", len(labels))
	}
	if l := inventoryLabels(t, labels[a.ID]); l["sbom:y.cdx.json"] || !l["sbom:x.cdx.json"] || !l["relationship:direct"] {
		t.Errorf("a's labels after revocation: %v", l)
	}
	if edges, _ := queries.ListComponentDependencyEdgesBySnapshot(ctx, snapshotID); len(edges) != 1 {
		t.Errorf("edge between x's components lost: %d", len(edges))
	}

	// Reusing x on another snapshot rebuilds x's set from its label.
	snapshotRow, _ := queries.db.GetSnapshotByID(ctx, snapshotID)
	ref, _ := queries.CreateRef(ctx, snapshotRow.RepoID, "other", RefTypeBranch, nil, nil, nil)
	other, _ := queries.CreateSnapshot(ctx, ref.ID, uniqueStoreTestName(t, "commit"), SnapshotStatusComplete)
	count, err := queries.ReuseInventorySource(ctx, snapshotID, other.ID, "sbom:x.cdx.json", nil)
	if err != nil || count != 2 {
		t.Fatalf("reuse legacy: %d %v", count, err)
	}
	if set, _ := queries.InventorySourceSet(ctx, snapshotID, "sbom:x.cdx.json"); set == nil {
		t.Error("the legacy source did not get its set recorded")
	}
	if components, _ := queries.ListComponentsBySnapshot(ctx, other.ID); len(components) != 2 {
		t.Errorf("reused legacy source gives %d components", len(components))
	}
}

// Deleting an organisation takes its sets with it without the collector.
func TestInventorySetsGoWithOrganization(t *testing.T) {
	_, queries := openInventoryTestDB(t)
	ctx := context.Background()
	snapshotID := createSnapshotForStatusTest(t, ctx, queries, SnapshotStatusComplete)
	a, _ := queries.UpsertComponent(ctx, "pkg:npm/gone@1.0.0", "gone", "1.0.0", "npm", nil)
	if err := queries.AttachComponentToSnapshot(ctx, snapshotID, a.ID, json.RawMessage(`{"sbom:z.cdx.json":true}`)); err != nil {
		t.Fatal(err)
	}
	row, _ := queries.db.GetSnapshotByID(ctx, snapshotID)
	if err := queries.DeleteOrganization(ctx, row.OrgID); err != nil {
		t.Fatalf("delete organization with inventory sets: %v", err)
	}
	if _, err := queries.db.GetInventorySet(ctx, row.InventorySetID.Int64); err == nil {
		t.Error("the organisation's set survived its deletion")
	}
}
