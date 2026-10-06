package store

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/kev"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// End-to-end over the real schema: replace two catalogs side by side, match an
// advisory by canonical id and by alias, check source isolation on replace,
// and check withdrawal removes the row.
func TestKEVCatalogRoundTrip(t *testing.T) {
	db := openStoreTestDB(t, "kev catalog round trip")
	queries := NewQueries(db)
	ctx := context.Background()

	// Fictitious ids so the test never collides with a synced real catalog.
	const sharedCVE = "CVE-2099-10001"   // listed by both sources
	const cisaOnlyCVE = "CVE-2099-10002" // withdrawn later
	const euvdOnlyCVE = "CVE-2099-10003"
	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, `DELETE FROM kev_entries WHERE cve_id IN ($1, $2, $3)`, sharedCVE, cisaOnlyCVE, euvdOnlyCVE)
		_, _ = db.ExecContext(ctx, `DELETE FROM advisories WHERE canonical_id IN ('CVE-2099-10001', 'GHSA-kev0-test-0001')`)
	})

	cisaEntries := []kev.Entry{
		{
			CVEID: sharedCVE, VendorProject: "Acme", Product: "Widget",
			VulnerabilityName:          "Acme Widget RCE",
			DateAdded:                  time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
			DueDate:                    time.Date(2026, 1, 23, 0, 0, 0, 0, time.UTC),
			KnownRansomwareCampaignUse: true,
		},
		{CVEID: cisaOnlyCVE, VendorProject: "Acme", Product: "Gadget"},
	}
	euvdEntries := []kev.Entry{
		{CVEID: sharedCVE, VulnerabilityName: "EUVD-2099-00001"},
		{CVEID: euvdOnlyCVE, VulnerabilityName: "EUVD-2099-00002"},
	}
	if err := queries.ReplaceKEVSource(ctx, db, "cisa", cisaEntries, 0); err != nil {
		t.Fatalf("ReplaceKEVSource (cisa): %v", err)
	}
	if err := queries.ReplaceKEVSource(ctx, db, "euvd", euvdEntries, 24*time.Hour); err != nil {
		t.Fatalf("ReplaceKEVSource (euvd): %v", err)
	}

	// Identifier membership is a union across sources, each id once.
	hits, err := queries.FilterKEVIdentifiers(ctx, []string{sharedCVE, euvdOnlyCVE, "CVE-2099-99999"})
	if err != nil {
		t.Fatalf("FilterKEVIdentifiers: %v", err)
	}
	if len(hits) != 2 {
		t.Fatalf("identifier hits = %v, want the two listed ids once each", hits)
	}

	// Advisory matched through its canonical id.
	direct, err := queries.UpsertAdvisory(ctx, dbgen.UpsertAdvisoryParams{
		CanonicalID: sharedCVE, Title: "direct", Severity: dbgen.SeverityLevelHigh,
		CweIds: []string{},
	})
	if err != nil {
		t.Fatalf("UpsertAdvisory (direct): %v", err)
	}
	// Advisory matched only through a CVE alias, the GHSA-canonical case.
	aliased, err := queries.UpsertAdvisory(ctx, dbgen.UpsertAdvisoryParams{
		CanonicalID: "GHSA-kev0-test-0001", Title: "aliased", Severity: dbgen.SeverityLevelMedium,
		CweIds: []string{},
	})
	if err != nil {
		t.Fatalf("UpsertAdvisory (aliased): %v", err)
	}
	if err := queries.UpsertAdvisoryAlias(ctx, dbgen.UpsertAdvisoryAliasParams{
		AdvisoryID: aliased.ID, Alias: sharedCVE,
	}); err != nil {
		t.Fatalf("UpsertAdvisoryAlias: %v", err)
	}
	unlisted := uuid.New()

	listed, err := queries.FilterKEVAdvisoryIDs(ctx, []uuid.UUID{direct.ID, aliased.ID, unlisted})
	if err != nil {
		t.Fatalf("FilterKEVAdvisoryIDs: %v", err)
	}
	got := map[uuid.UUID]bool{}
	for _, id := range listed {
		got[id] = true
	}
	if len(listed) != 2 || !got[direct.ID] || !got[aliased.ID] {
		t.Fatalf("advisory hits = %v, want exactly direct %s and aliased %s", listed, direct.ID, aliased.ID)
	}

	// The detail lookup returns one row per listing source, cisa first so the
	// richest row (due date, ransomware use) leads.
	entries, err := queries.ListKEVEntriesForIdentifiers(ctx, []string{"GHSA-KEV0-TEST-0001", sharedCVE})
	if err != nil {
		t.Fatalf("ListKEVEntriesForIdentifiers: %v", err)
	}
	if len(entries) != 2 || entries[0].Source != "cisa" || entries[1].Source != "euvd" {
		t.Fatalf("entries = %+v, want cisa then euvd", entries)
	}
	if !entries[0].KnownRansomwareCampaignUse || !entries[0].DateAdded.Valid ||
		entries[0].DateAdded.Time.UTC().Format("2006-01-02") != "2026-01-02" {
		t.Fatalf("cisa entry = %+v, want ransomware use and date added 2026-01-02", entries[0])
	}

	// CISA withdrawing an entry must remove it on the next replace (grace 0:
	// the catalog is one atomic document) — and must not touch the other
	// source's rows.
	if err := queries.ReplaceKEVSource(ctx, db, "cisa", cisaEntries[:1], 0); err != nil {
		t.Fatalf("ReplaceKEVSource (withdrawal): %v", err)
	}
	hits, err = queries.FilterKEVIdentifiers(ctx, []string{cisaOnlyCVE, euvdOnlyCVE})
	if err != nil {
		t.Fatalf("FilterKEVIdentifiers after withdrawal: %v", err)
	}
	if len(hits) != 1 || hits[0] != euvdOnlyCVE {
		t.Fatalf("hits after withdrawal = %v, want only the euvd-listed id", hits)
	}

	// EUVD's grace window: an entry absent from one fetch SURVIVES while its
	// last-seen is fresh (a skipped page must not un-list an exploited CVE)…
	if err := queries.ReplaceKEVSource(ctx, db, "euvd", euvdEntries[:1], 24*time.Hour); err != nil {
		t.Fatalf("ReplaceKEVSource (euvd, graced withdrawal): %v", err)
	}
	hits, err = queries.FilterKEVIdentifiers(ctx, []string{euvdOnlyCVE})
	if err != nil {
		t.Fatalf("FilterKEVIdentifiers within grace: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("entry inside the grace window was deleted: %v", hits)
	}
	// …and is deleted once it has been unseen past the window.
	if _, err := db.ExecContext(ctx, `UPDATE kev_entries SET updated_at = NOW() - interval '25 hours' WHERE source = 'euvd' AND cve_id = $1`, euvdOnlyCVE); err != nil {
		t.Fatalf("backdate euvd entry: %v", err)
	}
	if err := queries.ReplaceKEVSource(ctx, db, "euvd", euvdEntries[:1], 24*time.Hour); err != nil {
		t.Fatalf("ReplaceKEVSource (euvd, expired grace): %v", err)
	}
	hits, err = queries.FilterKEVIdentifiers(ctx, []string{euvdOnlyCVE})
	if err != nil {
		t.Fatalf("FilterKEVIdentifiers after grace: %v", err)
	}
	if len(hits) != 0 {
		t.Fatalf("entry unseen past the grace window still listed: %v", hits)
	}

	// Disabling a source must stop it gating: the active-sources purge deletes
	// everyone else's rows.
	if err := queries.PurgeKEVSourcesExcept(ctx, []string{"cisa"}); err != nil {
		t.Fatalf("PurgeKEVSourcesExcept: %v", err)
	}
	hits, err = queries.FilterKEVIdentifiers(ctx, []string{sharedCVE})
	if err != nil {
		t.Fatalf("FilterKEVIdentifiers after purge: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("cisa row must survive the purge of other sources: %v", hits)
	}
	entries, err = queries.ListKEVEntriesForIdentifiers(ctx, []string{sharedCVE})
	if err != nil {
		t.Fatalf("ListKEVEntriesForIdentifiers after purge: %v", err)
	}
	if len(entries) != 1 || entries[0].Source != "cisa" {
		t.Fatalf("entries after purge = %+v, want only cisa's row", entries)
	}

	// The guard against clearing a source on a bad fetch.
	if err := queries.ReplaceKEVSource(ctx, db, "cisa", nil, 0); err == nil {
		t.Fatal("ReplaceKEVSource with zero entries must refuse")
	}
}
