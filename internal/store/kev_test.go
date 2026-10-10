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
	seed, err := queries.ReplaceKEVSource(ctx, db, "cisa", cisaEntries, 0)
	if err != nil {
		t.Fatalf("ReplaceKEVSource (cisa): %v", err)
	}
	// Day-one population: everything is "added" but flagged as the seed, so
	// the caller does not flood the timeline.
	if !seed.InitialSeed || len(seed.Added) != 2 {
		t.Fatalf("seed diff = %+v, want initial seed with 2 added", seed)
	}
	if _, err := queries.ReplaceKEVSource(ctx, db, "euvd", euvdEntries, 24*time.Hour); err != nil {
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
	direct, err := upsertRatedAdvisory(ctx, queries, dbgen.UpsertAdvisoryParams{
		CanonicalID: sharedCVE, Title: "direct",
	}, dbgen.SetAdvisoryRatingParams{Severity: dbgen.SeverityLevelHigh})
	if err != nil {
		t.Fatalf("UpsertAdvisory (direct): %v", err)
	}
	// Advisory matched only through a CVE alias, the GHSA-canonical case.
	aliased, err := upsertRatedAdvisory(ctx, queries, dbgen.UpsertAdvisoryParams{
		CanonicalID: "GHSA-kev0-test-0001", Title: "aliased",
	}, dbgen.SetAdvisoryRatingParams{Severity: dbgen.SeverityLevelMedium})
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
	withdrawal, err := queries.ReplaceKEVSource(ctx, db, "cisa", cisaEntries[:1], 0)
	if err != nil {
		t.Fatalf("ReplaceKEVSource (withdrawal): %v", err)
	}
	if withdrawal.InitialSeed || len(withdrawal.Added) != 0 || len(withdrawal.Removed) != 1 || withdrawal.Removed[0] != cisaOnlyCVE {
		t.Fatalf("withdrawal diff = %+v, want exactly the withdrawn CVE removed", withdrawal)
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
	graced, err := queries.ReplaceKEVSource(ctx, db, "euvd", euvdEntries[:1], 24*time.Hour)
	if err != nil {
		t.Fatalf("ReplaceKEVSource (euvd, graced withdrawal): %v", err)
	}
	if len(graced.Removed) != 0 {
		t.Fatalf("a grace-protected entry must not report as removed: %+v", graced)
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
	expired, err := queries.ReplaceKEVSource(ctx, db, "euvd", euvdEntries[:1], 24*time.Hour)
	if err != nil {
		t.Fatalf("ReplaceKEVSource (euvd, expired grace): %v", err)
	}
	if len(expired.Removed) != 1 || expired.Removed[0] != euvdOnlyCVE {
		t.Fatalf("expired-grace diff = %+v, want the unseen CVE removed", expired)
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
	if _, err := queries.ReplaceKEVSource(ctx, db, "cisa", nil, 0); err == nil {
		t.Fatal("ReplaceKEVSource with zero entries must refuse")
	}
}

// PLAN addendum (alpha.82 incident): on a snapshot with ZERO scans the enum
// column made COALESCE(status, ”) unparseable, the readiness read errored,
// and the gate guard silently degraded open — a mid-scan "passed" shipped.
// The ::text cast is load-bearing.
func TestGateScanReadinessOnScanlessSnapshot(t *testing.T) {
	db := openStoreTestDB(t, "gate scan readiness scanless")
	queries := NewQueries(db)
	ctx := context.Background()

	row, err := queries.GetGateScanReadiness(ctx, uuid.New())
	if err != nil {
		t.Fatalf("readiness on a scan-less snapshot errored: %v", err)
	}
	if row.HasCompleteScan || row.HasAnyScan || row.HasComponents || row.LatestStatus != "" {
		t.Fatalf("zero row expected, got %+v", row)
	}
}
