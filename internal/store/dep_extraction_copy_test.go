package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// Digest reuse copies only the extractor's rows and labels, never another
// artifact's (ADR-045 §4.1).
func TestCopyExtractedInventory(t *testing.T) {
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
	ctx := context.Background()
	queries := NewQueries(db)
	from := createSnapshotForStatusTest(t, ctx, queries, SnapshotStatusComplete)
	to := createSnapshotForStatusTest(t, ctx, queries, SnapshotStatusPending)

	const source = "sbom:hibou-depinventory.cdx.json"
	extracted, err := queries.UpsertComponent(ctx, "pkg:npm/lodash@4.17.21", "lodash", "4.17.21", "npm", nil)
	if err != nil {
		t.Fatal(err)
	}
	both, err := queries.UpsertComponent(ctx, "pkg:npm/react@18.2.0", "react", "18.2.0", "npm", nil)
	if err != nil {
		t.Fatal(err)
	}
	uploadedOnly, err := queries.UpsertComponent(ctx, "pkg:npm/jest@29.0.0", "jest", "29.0.0", "npm", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := queries.AttachComponentToSnapshot(ctx, from, extracted.ID, json.RawMessage(`{"`+source+`":true,"relationship:direct":true,"module:.":true,"path:package-lock.json":true}`)); err != nil {
		t.Fatal(err)
	}
	if err := queries.AttachComponentToSnapshot(ctx, from, both.ID, json.RawMessage(`{"`+source+`":true,"sbom:ci.cdx.json":true,"relationship:indirect":true,"module:.":true}`)); err != nil {
		t.Fatal(err)
	}
	if err := queries.AttachComponentToSnapshot(ctx, from, uploadedOnly.ID, json.RawMessage(`{"sbom:ci.cdx.json":true}`)); err != nil {
		t.Fatal(err)
	}
	if err := queries.UpsertComponentDependency(ctx, from, extracted.ID, both.ID); err != nil {
		t.Fatal(err)
	}
	if err := queries.UpsertComponentDependency(ctx, from, both.ID, uploadedOnly.ID); err != nil {
		t.Fatal(err)
	}

	copied, err := queries.CopyExtractedInventory(ctx, from, to, source)
	if err != nil {
		t.Fatal(err)
	}
	if copied != 2 {
		t.Fatalf("copied %d components, want 2 (the uploaded-only one stays behind)", copied)
	}
	labels, err := queries.ListSnapshotComponentLabels(ctx, to)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := labels[uploadedOnly.ID]; present {
		t.Error("a component only an upload reported must not be copied")
	}
	var bothLabels map[string]bool
	if err := json.Unmarshal(labels[both.ID], &bothLabels); err != nil {
		t.Fatal(err)
	}
	if bothLabels["sbom:ci.cdx.json"] || !bothLabels[source] || !bothLabels["relationship:indirect"] {
		t.Errorf("copied labels must keep the extractor's keys only: %v", bothLabels)
	}
	edges, err := queries.ListComponentDependencyEdgesBySnapshot(ctx, to)
	if err != nil {
		t.Fatal(err)
	}
	if len(edges) != 1 {
		t.Errorf("edges copied: %d, want 1 (only between extracted components)", len(edges))
	}
}
