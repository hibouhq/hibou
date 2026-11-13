package store

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

func TestTrivyRangeLowerBoundsMigration(t *testing.T) {
	databaseURL := os.Getenv("HIBOU_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = testDatabaseURL
	}
	db, err := New(databaseURL)
	if err != nil {
		t.Skipf("database not available for migration test: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()

	// Temporary tables shadow the real tables; no persistent data is changed.
	if _, err := tx.ExecContext(ctx, `
		CREATE TEMP TABLE affected_ranges (
			id uuid PRIMARY KEY, source text, introduced text
		) ON COMMIT DROP;
		CREATE TEMP TABLE advisory_cache (provider text) ON COMMIT DROP;
		CREATE TEMP TABLE findings (
			id uuid PRIMARY KEY, type text, status text,
			primary_identifier_value text,
			affected_range_id uuid REFERENCES affected_ranges(id) ON DELETE SET NULL
		) ON COMMIT DROP;
		CREATE TEMP TABLE snapshot_findings (
			snapshot_id uuid, finding_id uuid REFERENCES findings(id), resolved_at timestamptz
		) ON COMMIT DROP;
	`); err != nil {
		t.Fatal(err)
	}
	unsafeRangeID := uuid.New()
	safeRangeID := uuid.New()
	for _, rng := range []struct {
		id         uuid.UUID
		source     string
		introduced string
	}{
		{unsafeRangeID, "trivy", "0"},
		{uuid.New(), "trivy", ""},
		{safeRangeID, "trivy", "3.4.0"},
		{uuid.New(), "osv", "0"},
		{uuid.New(), "cve", ""},
	} {
		if _, err := tx.ExecContext(ctx, `INSERT INTO affected_ranges VALUES ($1, $2, $3)`, rng.id, rng.source, rng.introduced); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO advisory_cache VALUES ('trivy'), ('osv')`); err != nil {
		t.Fatal(err)
	}
	staleID, freshID, snapshotID := uuid.New(), uuid.New(), uuid.New()
	for _, finding := range []struct{ id, rangeID uuid.UUID }{
		{staleID, unsafeRangeID}, {freshID, safeRangeID},
	} {
		if _, err := tx.ExecContext(ctx, `INSERT INTO findings VALUES ($1, 'dependency', 'detected', 'TEST-1', $2)`, finding.id, finding.rangeID); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO snapshot_findings VALUES ($1, $2, NULL)`, snapshotID, finding.id); err != nil {
			t.Fatal(err)
		}
	}
	for _, direction := range []string{"up", "down", "up"} {
		script, err := migrationsFS.ReadFile("migrations/00082_trivy_range_lower_bounds." + direction + ".sql")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, string(script)); err != nil {
			t.Fatalf("%s migration: %v", direction, err)
		}
	}
	var ranges, caches int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM affected_ranges`).Scan(&ranges); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM advisory_cache WHERE provider = 'osv'`).Scan(&caches); err != nil {
		t.Fatal(err)
	}
	if ranges != 3 || caches != 1 {
		t.Fatalf("retained ranges=%d, OSV caches=%d; want 3 and 1", ranges, caches)
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM advisory_cache WHERE provider = 'trivy'`).Scan(&caches); err != nil {
		t.Fatal(err)
	}
	if caches != 0 {
		t.Fatalf("retained %d Trivy caches, want none", caches)
	}

	resolved, err := dbgen.New(tx).MarkStaleVulnerabilities(ctx, dbgen.MarkStaleVulnerabilitiesParams{
		SnapshotID: snapshotID, VulnType: "dependency", FreshIds: []uuid.UUID{freshID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != 1 || resolved[0] != "TEST-1" {
		t.Fatalf("resolved identifiers=%v, want [TEST-1]", resolved)
	}
	for _, id := range []uuid.UUID{staleID, freshID} {
		var resolved bool
		if err := tx.QueryRowContext(ctx, `SELECT resolved_at IS NOT NULL FROM snapshot_findings WHERE finding_id = $1`, id).Scan(&resolved); err != nil {
			t.Fatal(err)
		}
		if want := id == staleID; resolved != want {
			t.Fatalf("finding %s resolved=%v, want %v", id, resolved, want)
		}
	}
}
