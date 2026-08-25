package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

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
// Refuses an unfiltered list: §13 keeps the mirror as infrastructure, and a
// browser over 382,000 records is a product nobody asked for. The filtered query
// is what makes a wrong watch name visible before the watch exists — a typo
// otherwise produces silence, which looks exactly like safety.
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
	user, ok := s.requireInstanceAuthority(w, r)
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

	created, err := s.queries.CreateCVESubscription(r.Context(), dbgen.CreateCVESubscriptionParams{
		Label:       label,
		ProductKeys: productKeys,
		VendorKeys:  normalizedKeys(input.VendorKeys),
		CreatedBy:   uuid.NullUUID{UUID: user.ID, Valid: true},
	})
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to create the watch")
		return
	}
	api.JSON(w, http.StatusCreated, toWatch(dbgen.ListCVESubscriptionsRow{
		ID:          created.ID,
		Label:       created.Label,
		ProductKeys: created.ProductKeys,
		VendorKeys:  created.VendorKeys,
		CreatedBy:   created.CreatedBy,
		CreatedAt:   created.CreatedAt,
	}))
}

func (s *Server) handleDeleteWatch(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireInstanceAuthority(w, r); !ok {
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

// requireInstanceAuthority gates the writes that change what every organization
// on this instance is told about.
func (s *Server) requireInstanceAuthority(w http.ResponseWriter, r *http.Request) (*store.User, bool) {
	user := UserFromContext(r.Context())
	if user == nil {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return nil, false
	}
	allowed, err := s.enforcer.CheckPermission(user.ID.String(), rbac.InstanceObject, rbac.ActionAdmin)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to check permissions")
		return nil, false
	}
	if !allowed {
		api.JSONError(w, http.StatusForbidden,
			"changing what this instance watches requires instance authority")
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
