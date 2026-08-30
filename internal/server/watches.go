package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/cvefeed"
	"github.com/hibouhq/hibou/internal/rbac"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// Watches: products tracked by the name their vendor publishes advisories
// under, because those advisories may carry no package coordinates.
//
// Instance-scoped, with no per-watch choice. "Apache Tomcat means these Maven
// artifacts" is a fact about the world rather than about one organization, and
// making scope a per-row field bought nothing while creating a path for one
// tenant to decide what the others are told.

type watch struct {
	ID          uuid.UUID `json:"id"`
	Label       string    `json:"label"`
	ProductKeys []string  `json:"product_keys"`
	VendorKeys  []string  `json:"vendor_keys"`
	// LastMatchedAt is the field that makes silence readable: a watch that has
	// never matched is either safe or watching a name its vendor does not file
	// under, and nothing else distinguishes those.
	LastMatchedAt *string `json:"last_matched_at"`
	CreatedAt     string  `json:"created_at"`
	PendingTriage int64   `json:"pending_triage"`
}

type watchPreview struct {
	Total   int64              `json:"total"`
	Matches []watchPreviewItem `json:"matches"`
}

type watchPreviewItem struct {
	CVEID       string  `json:"cve_id"`
	PublishedAt *string `json:"published_at"`
	Severity    string  `json:"severity"`
	CVSSScore   *string `json:"cvss_score"`
	Summary     string  `json:"summary"`
}

type createWatchRequest struct {
	Label       string   `json:"label"`
	ProductKeys []string `json:"product_keys"`
	VendorKeys  []string `json:"vendor_keys"`
}

func (s *Server) handleListWatches(w http.ResponseWriter, r *http.Request) {
	rows, err := s.queries.ListCVESubscriptions(r.Context())
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list watches")
		return
	}
	out := make([]watch, 0, len(rows))
	for _, row := range rows {
		out = append(out, toWatch(row))
	}
	api.JSON(w, http.StatusOK, out)
}

// handleListAdvisories answers "which advisories name this product?".
//
// Refuses an unfiltered list (§13: the mirror is infrastructure, not a browser).
// The filtered query is what makes a wrong watch name visible before the watch
// exists — a typo otherwise produces silence, which looks like safety.
func (s *Server) handleListAdvisories(w http.ResponseWriter, r *http.Request) {
	keys := normalizedKeys(r.URL.Query()["product"])
	if len(keys) == 0 {
		api.JSONError(w, http.StatusBadRequest,
			"a product filter is required: this is not an advisory browser")
		return
	}
	limit := int32(10)
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 && parsed <= 100 {
			limit = int32(parsed) // #nosec G109 G115 -- bounded to 1..100 above
		}
	}
	rows, total, err := s.queries.PreviewSubscription(r.Context(), keys, limit)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to search advisories")
		return
	}
	matches := make([]watchPreviewItem, 0, len(rows))
	for _, row := range rows {
		matches = append(matches, watchPreviewItem{
			CVEID:       row.CveID,
			PublishedAt: nullTimeString(row.PublishedAt),
			Severity:    row.Severity,
			CVSSScore:   nullStringPtr(row.CvssScore),
			Summary:     row.Summary,
		})
	}
	api.JSON(w, http.StatusOK, watchPreview{Total: total, Matches: matches})
}

type watchCandidate struct {
	Name         string `json:"name"`
	Ecosystem    string `json:"ecosystem"`
	RepoCount    int64  `json:"repo_count"`
	VersionCount int64  `json:"version_count"`
}

// handleListWatchCandidates surfaces components no advisory source covers.
//
// It is not proof of a gap — a component with no findings may simply be clean.
// It is the only signal that exists before somebody watches a product, and it
// converts this feature's worst failure from "you were never told" into "you
// were told and did not act", which is a different and more tractable problem.
func (s *Server) handleListWatchCandidates(w http.ResponseWriter, r *http.Request) {
	rows, err := s.queries.ListWatchCandidates(r.Context(), 50)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list uncovered components")
		return
	}
	out := make([]watchCandidate, 0, len(rows))
	for _, row := range rows {
		out = append(out, watchCandidate{
			Name:         row.Name,
			Ecosystem:    row.Ecosystem,
			RepoCount:    row.RepoCount,
			VersionCount: row.VersionCount,
		})
	}
	api.JSON(w, http.StatusOK, out)
}

func (s *Server) handleCreateWatch(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireWatchWriter(w, r)
	if !ok {
		return
	}
	var input createWatchRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	label := strings.TrimSpace(input.Label)
	if label == "" {
		api.JSONError(w, http.StatusBadRequest, "a label is required")
		return
	}
	// Keys are normalized server-side rather than trusted from the client: the
	// stored key is what every match compares against, so it must not differ by
	// case or punctuation from what ingestion produces.
	productKeys := normalizedKeys(append(input.ProductKeys, label))
	if len(productKeys) == 0 {
		api.JSONError(w, http.StatusBadRequest, "a product name is required")
		return
	}

	vendorKeys := normalizedKeys(input.VendorKeys)
	created, err := s.queries.CreateCVESubscription(r.Context(), dbgen.CreateCVESubscriptionParams{
		Label:       label,
		ProductKeys: productKeys,
		VendorKeys:  vendorKeys,
		CreatedBy:   uuid.NullUUID{UUID: user.ID, Valid: true},
	})
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to create the watch")
		return
	}

	// Backfill against the stored corpus. The sweeper only sees records the
	// feed revises and the seed deliberately queues nothing, so without this a
	// watch created today never matches a CVE published yesterday — it reads
	// "never matched" while the very record it was created for sits in the
	// corpus, waiting for a vendor revision that may never come.
	//
	// Capped, newest first, honouring the seed's principle: a new watch on a
	// twenty-year-old product must not dump its whole history on a person. One
	// triage decision plus auto-apply is the intended way through the rest.
	queued := 0
	matches, backfillErr := s.queries.BackfillSubscriptionMatches(r.Context(), productKeys, vendorKeys, watchBackfillCap)
	if backfillErr != nil {
		// The watch itself was created; a failed backfill degrades to the old
		// behaviour rather than failing the request, but it must say so.
		s.log.Error().Err(backfillErr).Str("label", label).Msg("watch created but the corpus backfill failed; existing records will not be queued")
	} else {
		for _, cveID := range matches {
			if queueErr := s.queries.QueueTriageItem(r.Context(), created.ID, cveID); queueErr != nil {
				s.log.Error().Err(queueErr).Str("cve_id", cveID).Msg("failed to queue a backfilled triage item")
				continue
			}
			queued++
		}
		if queued > 0 {
			// The corpus matched, and "last matched: never" would be false.
			if touchErr := s.queries.TouchSubscriptionMatched(r.Context(), created.ID); touchErr != nil {
				s.log.Warn().Err(touchErr).Msg("failed to update the watch's last-matched time")
			}
		}
	}

	lastMatched := created.LastMatchedAt
	if queued > 0 {
		// The touch above set it; the create RETURNING predates that write, and
		// answering "never matched" beside a non-zero queue would be false.
		lastMatched = sql.NullTime{Time: time.Now().UTC(), Valid: true}
	}
	response := toWatch(dbgen.ListCVESubscriptionsRow{
		ID:            created.ID,
		Label:         created.Label,
		ProductKeys:   created.ProductKeys,
		VendorKeys:    created.VendorKeys,
		CreatedBy:     created.CreatedBy,
		CreatedAt:     created.CreatedAt,
		LastMatchedAt: lastMatched,
	})
	response.PendingTriage = int64(queued)
	api.JSON(w, http.StatusCreated, response)
}

// watchBackfillCap bounds how much history a new watch queues. Big enough that
// a product's recent advisories all surface, small enough that watching
// something with two decades of CVEs stays a work list rather than a wall.
const watchBackfillCap = 100

func (s *Server) handleDeleteWatch(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireWatchWriter(w, r); !ok {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "watchID"))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid watch id")
		return
	}
	// Confirm it exists before deleting, so a wrong id is a 404 rather than a
	// silent no-op the caller reads as success.
	if _, err := s.queries.GetCVESubscription(r.Context(), id); errors.Is(err, sql.ErrNoRows) {
		api.JSONError(w, http.StatusNotFound, "watch not found")
		return
	} else if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load the watch")
		return
	}
	if err := s.queries.DeleteCVESubscription(r.Context(), id); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to delete the watch")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// requireInstanceAuthority gates changes to instance-wide state.
//
// The admin list, because roles are granted through this same gate: requiring a
// granted role to pass it closes a loop with no entry point.
func (s *Server) requireInstanceAuthority(w http.ResponseWriter, r *http.Request) (*store.User, bool) {
	user := UserFromContext(r.Context())
	if user == nil {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return nil, false
	}
	if !s.isInstanceAdmin(r) {
		api.JSONError(w, http.StatusForbidden, "instance admin required")
		return nil, false
	}
	return user, true
}

// requireWatchWriter gates changes to what the instance watches.
//
// Write, not admin: a watch queues triage items and authors nothing.
func (s *Server) requireWatchWriter(w http.ResponseWriter, r *http.Request) (*store.User, bool) {
	user := UserFromContext(r.Context())
	if user == nil {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return nil, false
	}
	if s.isInstanceAdmin(r) {
		return user, true
	}
	allowed, err := s.enforcer.CheckPermission(user.ID.String(), rbac.InstanceObject, rbac.ActionWrite)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to check permissions")
		return nil, false
	}
	if !allowed {
		api.JSONError(w, http.StatusForbidden,
			"changing what this instance watches needs the "+rbac.RoleSubscriptionWriter+
				" role, granted from instance settings")
		return nil, false
	}
	return user, true
}

func toWatch(row dbgen.ListCVESubscriptionsRow) watch {
	return watch{
		ID:            row.ID,
		Label:         row.Label,
		ProductKeys:   row.ProductKeys,
		VendorKeys:    row.VendorKeys,
		LastMatchedAt: nullTimeString(row.LastMatchedAt),
		CreatedAt:     row.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		PendingTriage: row.PendingTriage,
	}
}

// normalizedKeys folds free-text names into the key matching uses, dropping
// duplicates and anything that normalizes away to nothing.
func normalizedKeys(values []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, value := range values {
		key := cvefeed.ProductKey(value)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	return out
}

func nullTimeString(value sql.NullTime) *string {
	if !value.Valid {
		return nil
	}
	formatted := value.Time.UTC().Format("2006-01-02T15:04:05Z")
	return &formatted
}

func nullStringPtr(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}
	return &value.String
}
