package server

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/advisory"
	"github.com/hibouhq/hibou/internal/advisorydb"
	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// Offline advisory database (ADR-046 step 6): the organisation's advisory
// view as one streamed file, for `hibou deps scan --advisory-db` on a
// runner without access to the server. It carries advisories, ranges,
// ratings, aliases, the exploited catalog and EPSS; it does not carry the
// repository's triage, which stays on the server.

const advisoryExportPageSize = 500

// @Summary      Export the advisory database for offline scans
// @Description  Streams newline-delimited JSON: a header, then one record per advisory with its affected ranges, ratings, aliases, KEV flag and EPSS score (ADR-046 step 6). `ecosystem` limits the export (repeatable or comma-separated); without it every ecosystem is exported. Audit-logged.
// @Tags         advisories
// @Produce      application/x-ndjson
// @Param        provider   path      string  true   "Forge provider"
// @Param        slug       path      string  true   "Organization slug"
// @Param        ecosystem  query     string  false  "Ecosystems to export, e.g. npm,maven"
// @Success      200        {string}  string  "NDJSON stream"
// @Router       /orgs/{provider}/{slug}/advisories/export [get]
func (s *Server) handleExportAdvisories(w http.ResponseWriter, r *http.Request) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok {
		return
	}
	if !s.enforceOrgWideCapability(w, r, apitoken.CapVulnerabilities, apitoken.AccessRead, org.Slug) {
		return
	}
	var ecosystems []string
	for _, raw := range r.URL.Query()["ecosystem"] {
		for _, value := range strings.Split(raw, ",") {
			if value = strings.ToLower(strings.TrimSpace(value)); value != "" {
				ecosystems = append(ecosystems, value)
			}
		}
	}
	header := advisorydb.Header{ExportedAt: time.Now().UTC(), Org: org.Provider + "/" + org.Slug, Ecosystems: ecosystems, Server: strings.TrimSpace(s.cfg.BaseURL)}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", `attachment; filename="hibou-advisories-`+header.ExportedAt.Format("20060102")+`.ndjson"`)
	w.Header().Set("X-Hibou-Export-Format", advisorydb.Format+"/"+strconv.Itoa(advisorydb.Version))
	w.WriteHeader(http.StatusOK)
	records, err := writeAdvisoryExport(r.Context(), s.queries, w, header, ecosystems)
	if err != nil {
		// The status is sent; the client sees a truncated file and the
		// CLI refuses it (no trailing newline check is possible on NDJSON,
		// so the log is the trace).
		s.log.Error().Err(err).Str("org_id", org.ID.String()).Msg("advisory export failed")
		return
	}
	context := map[string]any{"advisories": records}
	if len(ecosystems) > 0 {
		context["ecosystems"] = ecosystems
	}
	s.writeAuditLog(r, UserFromContext(r.Context()), orgAuditID(org.ID), auditEntry{Action: audit.ActionAdvisoryExport, ResourceType: "organization", ResourceID: org.ID.String(), Context: context})
}

// writeAdvisoryExport streams the database and returns the record count.
func writeAdvisoryExport(ctx context.Context, queries *store.Queries, w io.Writer, header advisorydb.Header, ecosystems []string) (int, error) {
	header.Ecosystems = ecosystems
	writer, err := advisorydb.NewWriter(w, header)
	if err != nil {
		return 0, err
	}
	after := uuid.Nil
	for {
		ids, err := queries.ListAdvisoryIDsForExport(ctx, ecosystems, after, advisoryExportPageSize)
		if err != nil {
			return writer.Records(), fmt.Errorf("list advisories: %w", err)
		}
		if len(ids) == 0 {
			break
		}
		if err := writeAdvisoryPage(ctx, queries, writer, ids); err != nil {
			return writer.Records(), err
		}
		after = ids[len(ids)-1]
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	}
	return writer.Records(), writer.Flush()
}

func writeAdvisoryPage(ctx context.Context, queries *store.Queries, writer *advisorydb.Writer, ids []uuid.UUID) error {
	advisories, err := queries.GetAdvisoriesByIDs(ctx, ids)
	if err != nil {
		return fmt.Errorf("load advisories: %w", err)
	}
	ranges, err := queries.ListAffectedRangesByAdvisoryIDs(ctx, ids)
	if err != nil {
		return fmt.Errorf("load ranges: %w", err)
	}
	aliases, err := queries.ListAliasesByAdvisoryIDs(ctx, ids)
	if err != nil {
		return fmt.Errorf("load aliases: %w", err)
	}
	ratingRows, err := queries.ListAdvisoryRatings(ctx, ids)
	if err != nil {
		return fmt.Errorf("load ratings: %w", err)
	}
	kevIDs, err := queries.FilterKEVAdvisoryIDs(ctx, ids)
	if err != nil {
		return fmt.Errorf("load exploited catalog: %w", err)
	}
	epssRows, err := queries.ListEPSSForAdvisories(ctx, ids)
	if err != nil {
		return fmt.Errorf("load epss: %w", err)
	}

	rangesBy := make(map[uuid.UUID][]advisorydb.Range, len(ids))
	for _, affected := range ranges {
		rangesBy[affected.AdvisoryID] = append(rangesBy[affected.AdvisoryID], advisorydb.Range{
			Ecosystem: affected.Ecosystem, Package: affected.PackageName,
			Introduced: affected.Introduced, Fixed: affected.Fixed, LastAffected: affected.LastAffected, Release: affected.Release,
		})
	}
	aliasesBy := make(map[uuid.UUID][]string, len(ids))
	for _, alias := range aliases {
		aliasesBy[alias.AdvisoryID] = append(aliasesBy[alias.AdvisoryID], alias.Alias)
	}
	ratingsBy := make(map[uuid.UUID][]advisory.Rating, len(ids))
	for _, row := range ratingRows {
		ratingsBy[row.AdvisoryID] = append(ratingsBy[row.AdvisoryID], advisory.RatingsFromRows([]dbgen.ListAdvisoryRatingsRow{row})...)
	}
	kev := make(map[uuid.UUID]bool, len(kevIDs))
	for _, id := range kevIDs {
		kev[id] = true
	}
	epss := make(map[uuid.UUID]float64, len(epssRows))
	for _, row := range epssRows {
		if score, err := strconv.ParseFloat(row.Score, 64); err == nil {
			epss[row.AdvisoryID] = score
		}
	}
	for _, record := range advisories {
		out := advisorydb.Record{
			ID:          record.ID.String(),
			CanonicalID: record.CanonicalID,
			Aliases:     aliasesBy[record.ID],
			Title:       strings.TrimSpace(record.Title),
			IsMalware:   record.IsMalware,
			Withdrawn:   record.WithdrawnAt.Valid,
			KEV:         kev[record.ID],
			Ratings:     advisorydb.FromRatings(ratingsBy[record.ID]),
			Ranges:      rangesBy[record.ID],
		}
		if out.Ranges == nil {
			out.Ranges = []advisorydb.Range{}
		}
		if record.MalwareType.Valid {
			out.MalwareType = string(record.MalwareType.MalwareType)
		}
		if record.PublishedAt.Valid {
			published := record.PublishedAt.Time
			out.PublishedAt = &published
		}
		if score, ok := epss[record.ID]; ok {
			out.EPSS = &score
		}
		if err := writer.Write(out); err != nil {
			return err
		}
	}
	return nil
}
