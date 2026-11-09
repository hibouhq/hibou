package store

import (
	"context"
	"database/sql"
	"testing"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// vulnerabilities is a view (ADR-049): a re-rating writes the finding and
// every occurrence, and a manual override keeps its severity while the
// original severity follows the data.
func TestSetFindingRatingWritesThroughTheView(t *testing.T) {
	db, queries := openInventoryTestDB(t)
	ctx := context.Background()
	first := createSnapshotForStatusTest(t, ctx, queries, SnapshotStatusComplete)
	row, err := queries.db.GetSnapshotByID(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	second, err := queries.CreateSnapshot(ctx, row.RefID, uniqueStoreTestName(t, "c2"), SnapshotStatusComplete)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := uniqueStoreTestName(t, "fp")
	finding, err := queries.CreateVulnerability(ctx, findingParams(first, fingerprint, "parser", "low", "detected"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := queries.CreateVulnerability(ctx, findingParams(second.ID, fingerprint, "parser", "low", "detected")); err != nil {
		t.Fatal(err)
	}

	rate := func(severity string) {
		t.Helper()
		if err := queries.SetFindingRating(ctx, dbgen.SetFindingRatingParams{
			Severity:    dbgen.SeverityLevel(severity),
			CvssScore:   sql.NullString{String: "8.1", Valid: true},
			CvssVersion: dbgen.NullCvssVersion{CvssVersion: dbgen.CvssVersionV31, Valid: true},
			CvssVector:  "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
			RatedBy:     "nvd",
			ID:          finding.ID,
		}); err != nil {
			t.Fatal(err)
		}
	}
	rate("high")
	for _, snapshotID := range []any{first, second.ID} {
		var severity, original, score, vector, ratedBy string
		if err := db.QueryRowContext(ctx, `SELECT severity, original_severity, cvss_score::text, cvss_vector, rated_by FROM vulnerabilities WHERE id = $1 AND snapshot_id = $2`, finding.ID, snapshotID).
			Scan(&severity, &original, &score, &vector, &ratedBy); err != nil {
			t.Fatal(err)
		}
		if severity != "high" || original != "high" || score != "8.10" || vector == "" || ratedBy != "nvd" {
			t.Fatalf("occurrence %v: severity %s original %s score %s vector %q rated_by %s", snapshotID, severity, original, score, vector, ratedBy)
		}
	}

	if _, err := db.ExecContext(ctx, `UPDATE findings SET severity = 'info', severity_override_by = (SELECT id FROM users LIMIT 1) WHERE id = $1`, finding.ID); err != nil {
		t.Fatal(err)
	}
	rate("critical")
	var severity, original string
	if err := db.QueryRowContext(ctx, `SELECT severity, original_severity FROM vulnerabilities WHERE id = $1 AND snapshot_id = $2`, finding.ID, first).Scan(&severity, &original); err != nil {
		t.Fatal(err)
	}
	if severity != "info" || original != "critical" {
		t.Fatalf("override: severity %s original %s, want info/critical", severity, original)
	}
}
