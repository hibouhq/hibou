package server

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/advisorydb"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// The exported database must give a local match the same answer as the
// server for the same advisory: ranges, ratings, aliases and fixes travel.
func TestWriteAdvisoryExportRoundTrip(t *testing.T) {
	databaseURL := os.Getenv("HIBOU_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = testDatabaseURL
	}
	db, err := store.New(databaseURL)
	if err != nil {
		t.Skipf("database not available: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := store.Migrate(db); err != nil {
		t.Fatalf("migrate database: %v", err)
	}
	ctx := context.Background()
	queries := store.NewQueries(db)

	suffix := uuid.NewString()[:8]
	pkg := "export-" + suffix
	record, err := queries.UpsertAdvisory(ctx, dbgen.UpsertAdvisoryParams{
		CanonicalID: "GHSA-export-" + suffix, Title: "Export round trip",
		PublishedAt: sql.NullTime{Time: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC), Valid: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := queries.CreateAffectedRange(ctx, dbgen.CreateAffectedRangeParams{AdvisoryID: record.ID, Ecosystem: "npm", PackageName: pkg, Introduced: "1.0.0", Fixed: "1.4.2", Source: "osv"}); err != nil {
		t.Fatal(err)
	}
	if err := queries.UpsertAdvisoryAlias(ctx, dbgen.UpsertAdvisoryAliasParams{AdvisoryID: record.ID, Alias: "CVE-2026-" + suffix}); err != nil {
		t.Fatal(err)
	}
	sourceID, err := queries.UpsertAdvisorySource(ctx, dbgen.UpsertAdvisorySourceParams{AdvisoryID: record.ID, Provider: "osv", ProviderID: record.CanonicalID, RawData: []byte(`{}`), FetchedAt: time.Now(), RatingsVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := queries.SyncAdvisorySourceRatings(ctx, dbgen.SyncAdvisorySourceRatingsParams{AdvisorySourceID: sourceID, Raters: []string{"nvd"}, Versions: []string{"v3.1"}, Vectors: []string{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}, Scores: []string{"9.8"}, Labels: []string{"critical"}}); err != nil {
		t.Fatal(err)
	}
	// A withdrawn advisory on the same package is exported as withdrawn and
	// never matches.
	withdrawn, err := queries.UpsertAdvisory(ctx, dbgen.UpsertAdvisoryParams{CanonicalID: "GHSA-withdrawn-" + suffix, Title: "Withdrawn", WithdrawnAt: sql.NullTime{Time: time.Now(), Valid: true}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := queries.CreateAffectedRange(ctx, dbgen.CreateAffectedRangeParams{AdvisoryID: withdrawn.ID, Ecosystem: "npm", PackageName: pkg, Introduced: "0", Source: "osv"}); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	count, err := writeAdvisoryExport(ctx, queries, &buf, advisorydb.Header{Org: "github/acme"}, []string{"npm"})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if count < 2 {
		t.Fatalf("exported %d records, want at least the two of this test", count)
	}
	loaded, err := advisorydb.Read(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Header.Org != "github/acme" || len(loaded.Header.Ecosystems) != 1 || loaded.Header.Ecosystems[0] != "npm" {
		t.Errorf("header %+v", loaded.Header)
	}
	match := loaded.Match("pkg:npm/" + pkg + "@1.2.0")
	if !match.Supported || len(match.Advisories) != 1 {
		t.Fatalf("match %+v", match)
	}
	got := match.Advisories[0]
	if got.CanonicalID != record.CanonicalID || got.Severity != "critical" || got.CVSS == nil || *got.CVSS != 9.8 || got.RatedBy != "nvd" || got.PublishedAt == nil || len(got.FixedVersions) != 1 || got.FixedVersions[0] != "1.4.2" {
		t.Errorf("advisory %+v", got)
	}
	if fixed := loaded.Match("pkg:npm/" + pkg + "@1.4.2"); len(fixed.Advisories) != 0 {
		t.Errorf("fixed version matched %+v", fixed.Advisories)
	}
	if !strings.Contains(buf.String(), `"CVE-2026-`+suffix+`"`) {
		t.Error("alias missing from the export")
	}
	// A maven-only export leaves the npm advisory out.
	buf.Reset()
	if _, err := writeAdvisoryExport(ctx, queries, &buf, advisorydb.Header{}, []string{"maven"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), record.CanonicalID) {
		t.Error("an npm advisory appeared in the maven export")
	}
}
