package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/kev"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// ReplaceKEVSource makes one source's stored rows equal to its fetched
// catalog: every entry upserted (one batched statement), then rows the catalog
// no longer carries deleted. Scoped to the source so catalogs never clobber
// each other, and all in one transaction so a reader never sees the rows
// mid-replacement — a failed sync leaves the previous catalog intact rather
// than a half-written one.
//
// grace defers the delete of an unseen row until it has been missing for the
// window. Zero means absence IS withdrawal (CISA: one atomic document). A
// positive grace is for sources walked through unstable pagination (EUVD),
// where a record can be skipped once without having been withdrawn —
// un-listing an exploited CVE over a pagination artifact is the worse error.
//
// The caller (via each kev.Source's Fetch) guarantees entries is non-empty, so
// the delete can never clear the source; the guard here keeps that invariant
// local.
func (q *Queries) ReplaceKEVSource(ctx context.Context, db *sql.DB, source string, entries []kev.Entry, grace time.Duration) error {
	if source == "" {
		return errors.New("kev source name is required")
	}
	if len(entries) == 0 {
		return fmt.Errorf("refusing to replace kev source %q with zero entries", source)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin kev catalog tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	queries := q.WithTx(tx)

	params := dbgen.UpsertKEVEntriesParams{
		Source:             source,
		CveIds:             make([]string, 0, len(entries)),
		VendorProjects:     make([]string, 0, len(entries)),
		Products:           make([]string, 0, len(entries)),
		VulnerabilityNames: make([]string, 0, len(entries)),
		DatesAdded:         make([]string, 0, len(entries)),
		DueDates:           make([]string, 0, len(entries)),
		RansomwareUses:     make([]bool, 0, len(entries)),
	}
	for _, entry := range entries {
		params.CveIds = append(params.CveIds, entry.CVEID)
		params.VendorProjects = append(params.VendorProjects, entry.VendorProject)
		params.Products = append(params.Products, entry.Product)
		params.VulnerabilityNames = append(params.VulnerabilityNames, entry.VulnerabilityName)
		params.DatesAdded = append(params.DatesAdded, dateOrEmpty(entry.DateAdded))
		params.DueDates = append(params.DueDates, dateOrEmpty(entry.DueDate))
		params.RansomwareUses = append(params.RansomwareUses, entry.KnownRansomwareCampaignUse)
	}
	if err := queries.db.UpsertKEVEntries(ctx, params); err != nil {
		return fmt.Errorf("upsert kev entries for %s: %w", source, err)
	}
	if err := queries.db.DeleteKEVSourceEntriesNotSeen(ctx, dbgen.DeleteKEVSourceEntriesNotSeenParams{
		Source:       source,
		Keep:         params.CveIds,
		GraceSeconds: int32(grace / time.Second), // #nosec G115 -- grace is a small constant per source
	}); err != nil {
		return fmt.Errorf("delete withdrawn kev entries for %s: %w", source, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit kev catalog for %s: %w", source, err)
	}
	return nil
}

// dateOrEmpty encodes a date for the text[] leg of the batch upsert; ” maps
// to NULL in SQL (sqlc's date[] binding cannot carry NULLs).
func dateOrEmpty(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format("2006-01-02")
}

// PurgeKEVSourcesExcept deletes every row not owned by an active source. A
// disabled source's sync no longer runs, so its rows would otherwise be a
// frozen catalog that keeps gating with no withdrawal path.
func (q *Queries) PurgeKEVSourcesExcept(ctx context.Context, activeSources []string) error {
	return q.db.DeleteKEVEntriesForOtherSources(ctx, activeSources)
}

// PurgeAllKEVEntries clears the mirror entirely — the kev.enabled=false path,
// where no sync runs at all and stored rows would block forever on data nobody
// refreshes. Disabling then genuinely degrades to the pre-KEV behaviour.
func (q *Queries) PurgeAllKEVEntries(ctx context.Context) error {
	return q.db.DeleteAllKEVEntries(ctx)
}

// FilterKEVAdvisoryIDs returns the subset of advisory ids listed on ANY
// exploited catalog, matched through the canonical id and every alias.
func (q *Queries) FilterKEVAdvisoryIDs(ctx context.Context, advisoryIDs []uuid.UUID) ([]uuid.UUID, error) {
	if len(advisoryIDs) == 0 {
		return nil, nil
	}
	return q.db.FilterKEVAdvisoryIDs(ctx, advisoryIDs)
}

// FilterKEVIdentifiers returns the subset of identifiers (uppercased by the
// caller) present on any exploited catalog.
func (q *Queries) FilterKEVIdentifiers(ctx context.Context, identifiers []string) ([]string, error) {
	if len(identifiers) == 0 {
		return nil, nil
	}
	return q.db.FilterKEVIdentifiers(ctx, identifiers)
}

// ListKEVEntriesForIdentifiers returns every catalog entry matching any of the
// given identifiers (uppercased by the caller), one row per (source, cve),
// 'cisa' first.
func (q *Queries) ListKEVEntriesForIdentifiers(ctx context.Context, identifiers []string) ([]dbgen.KevEntry, error) {
	if len(identifiers) == 0 {
		return nil, nil
	}
	return q.db.ListKEVEntriesForIdentifiers(ctx, identifiers)
}

// CountKEVEntries reports the stored catalog size across sources, for sync
// health.
func (q *Queries) CountKEVEntries(ctx context.Context) (int64, error) {
	return q.db.CountKEVEntries(ctx)
}
