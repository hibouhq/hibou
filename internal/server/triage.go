package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/cvefeed"
	"github.com/hibouhq/hibou/internal/cvetriage"
	"github.com/hibouhq/hibou/internal/rbac"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type triageQueueItem struct {
	ID          uuid.UUID `json:"id"`
	CVEID       string    `json:"cve_id"`
	Label       string    `json:"label"`
	Severity    string    `json:"severity"`
	CVSSScore   *string   `json:"cvss_score"`
	Summary     string    `json:"summary"`
	PublishedAt *string   `json:"published_at"`
	QueuedAt    string    `json:"queued_at"`
}

type triageDetail struct {
	triageQueueItem
	Assigner string `json:"assigner"`
	// Dates are grouped by whose clock they are on. Rendering them together
	// without that distinction is how "first detected" and "published" get
	// confused, and the gap between the two is the number worth seeing.
	RecordUpdatedAt *string             `json:"record_updated_at"`
	FirstSeenAt     string              `json:"first_seen_at"`
	Ranges          []triageRange       `json:"ranges"`
	Candidates      []triageCandidate   `json:"candidates"`
	Existing        []cvetriage.Package `json:"existing_mapping"`
}

type triageRange struct {
	Product      string `json:"product"`
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
}

type triageCandidate struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
	Version   string `json:"version"`
	RepoCount int64  `json:"repo_count"`
}

type triageDecisionRequest struct {
	Packages []cvetriage.Package `json:"packages"`
	// Dismiss records "this advisory does not affect us" — a decision worth
	// keeping, because the next revision should not silently re-ask it.
	Dismiss bool   `json:"dismiss"`
	Scope   string `json:"scope"`
}

func (s *Server) handleListTriageQueue(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.loadAuthorizedOrg(r, w); !ok {
		return
	}
	rows, err := s.queries.ListPendingTriage(r.Context(), 100)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list the triage queue")
		return
	}
	out := make([]triageQueueItem, 0, len(rows))
	for _, row := range rows {
		out = append(out, triageQueueItem{
			ID:          row.ID,
			CVEID:       row.CveID,
			Label:       row.Label,
			Severity:    row.Severity,
			CVSSScore:   nullStringPtr(row.CvssScore),
			Summary:     row.Summary,
			PublishedAt: nullTimeString(row.PublishedAt),
			QueuedAt:    row.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		})
	}
	api.JSON(w, http.StatusOK, out)
}

// handleGetTriageItem assembles everything a decision needs on one screen.
//
// The budget is a minute per advisory. If a triager has to leave this response
// to find the version ranges, or to work out which components exist, the queue
// stops being worked and the feature fails on that alone — so the ranges, the
// ranked candidates and any stored mapping all arrive together.
func (s *Server) handleGetTriageItem(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.loadAuthorizedOrg(r, w); !ok {
		return
	}
	itemID, err := uuid.Parse(chi.URLParam(r, "itemID"))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid triage item id")
		return
	}
	item, err := s.queries.GetTriageItem(r.Context(), itemID)
	if errors.Is(err, sql.ErrNoRows) {
		api.JSONError(w, http.StatusNotFound, "triage item not found")
		return
	}
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load triage item")
		return
	}
	affected, err := s.queries.ListCVEAffected(r.Context(), item.CveID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load affected versions")
		return
	}
	ranges := make([]triageRange, 0, len(affected))
	for _, row := range affected {
		ranges = append(ranges, triageRange{
			Product:      row.Product,
			Introduced:   row.Introduced,
			Fixed:        row.Fixed,
			LastAffected: row.LastAffected,
		})
	}

	detail := triageDetail{
		triageQueueItem: triageQueueItem{
			ID:          item.ID,
			CVEID:       item.CveID,
			Label:       item.Label,
			Severity:    item.Severity,
			CVSSScore:   nullStringPtr(item.CvssScore),
			Summary:     item.Summary,
			PublishedAt: nullTimeString(item.PublishedAt),
			QueuedAt:    item.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		},
		Assigner:        item.Assigner,
		RecordUpdatedAt: nullTimeString(item.RecordUpdatedAt),
		FirstSeenAt:     item.FirstSeenAt.UTC().Format("2006-01-02T15:04:05Z"),
		Ranges:          ranges,
		Candidates:      s.triageCandidates(r, item.Label),
		Existing:        s.existingMapping(r, item.SubscriptionID),
	}
	api.JSON(w, http.StatusOK, detail)
}

// triageCandidates ranks inventory components that plausibly ship the product.
// A failure here degrades the screen rather than breaking it: the triager can
// still type a coordinate, and an empty list is honest.
func (s *Server) triageCandidates(r *http.Request, label string) []triageCandidate {
	pattern := "%" + strings.ReplaceAll(firstWord(label), "%", `\%`) + "%"
	rows, err := s.queries.ListTriageCandidates(r.Context(), pattern, 40)
	if err != nil {
		s.log.Warn().Err(err).Msg("failed to rank triage candidates")
		return []triageCandidate{}
	}
	out := make([]triageCandidate, 0, len(rows))
	for _, row := range rows {
		out = append(out, triageCandidate{
			Name:      row.Name,
			Ecosystem: row.Ecosystem,
			Version:   row.Version,
			RepoCount: row.RepoCount,
		})
	}
	return out
}

// existingMapping pre-fills the form from an earlier decision about the same
// product. This is where "map once per product" stops being a claim: the second
// advisory for a product arrives already answered.
func (s *Server) existingMapping(r *http.Request, subscriptionID uuid.UUID) []cvetriage.Package {
	mapping, err := s.queries.GetActiveMapping(r.Context(), subscriptionID)
	if err != nil {
		return []cvetriage.Package{}
	}
	packages := []cvetriage.Package{}
	if err := json.Unmarshal(mapping.Packages, &packages); err != nil {
		return []cvetriage.Package{}
	}
	return packages
}

// handleDecideTriageItem records a decision and authors the advisory data.
func (s *Server) handleDecideTriageItem(w http.ResponseWriter, r *http.Request) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok {
		return
	}
	user := UserFromContext(r.Context())
	if user == nil {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	// Authoring a mapping creates findings on every repository using the
	// package, so it is an explicit grant rather than anything a base role
	// confers — see rbac.RoleCVETriager.
	allowed, err := s.enforcer.CanTriage(user.ID, org.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to check permissions")
		return
	}
	if !allowed {
		api.JSONError(w, http.StatusForbidden,
			"authoring advisory data requires the "+rbac.RoleCVETriager+" role")
		return
	}

	itemID, err := uuid.Parse(chi.URLParam(r, "itemID"))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid triage item id")
		return
	}
	var input triageDecisionRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	item, err := s.queries.GetTriageItem(r.Context(), itemID)
	if errors.Is(err, sql.ErrNoRows) {
		api.JSONError(w, http.StatusNotFound, "triage item not found")
		return
	}
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load triage item")
		return
	}

	if input.Dismiss {
		if err := s.queries.DecideTriageItem(r.Context(), itemID, "dismissed", user.ID); err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to record the decision")
			return
		}
		s.auditTriage(r, org.ID, user, item.CveID, "advisory.triage.dismissed", nil)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	decision := cvetriage.Decision{CVEID: item.CveID, Packages: input.Packages, ActorID: user.ID}
	if err := decision.Validate(); err != nil {
		api.JSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	record, err := s.loadProjection(r, item.CveID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load the advisory record")
		return
	}
	if _, err := cvetriage.Apply(r.Context(), s.advisoryIngester, decision, record); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to author advisory data")
		return
	}

	packages, err := json.Marshal(decision.Packages)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to record the mapping")
		return
	}
	if _, err := s.queries.CreateMapping(r.Context(), dbgen.CreateProductPackageMappingParams{
		SubscriptionID: item.SubscriptionID,
		Packages:       packages,
		DecidedFromCve: item.CveID,
		DecidedBy:      uuid.NullUUID{UUID: user.ID, Valid: true},
	}); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to store the mapping")
		return
	}
	if err := s.queries.DecideTriageItem(r.Context(), itemID, "mapped", user.ID); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to record the decision")
		return
	}
	s.auditTriage(r, org.ID, user, item.CveID, "advisory.triage.mapped", decision.Packages)
	w.WriteHeader(http.StatusNoContent)
}

// auditTriage records who authored advisory data.
//
// This is deliberately separate from the advisory timeline. The timeline is a
// narrative that includes upstream activity nobody here caused; the audit log
// answers "who did this, from where" under its own retention. A triage decision
// writes to both; a CNA revision writes only to the timeline.
//
// Best-effort: a decision that has already been applied must not be reported as
// failed because its audit row could not be written. The failure is logged
// instead, which is the honest trade — losing the record is bad, but telling a
// user their decision failed when it did not is worse.
func (s *Server) auditTriage(r *http.Request, orgID uuid.UUID, user *store.User, cveID, action string, packages []cvetriage.Package) {
	ipAddress, userAgent := audit.RequestContext(r)
	actorID := user.ID
	context := json.RawMessage(`{}`)
	if len(packages) > 0 {
		if encoded, err := json.Marshal(map[string]any{"packages": packages}); err == nil {
			context = encoded
		}
	}
	if _, err := s.queries.CreateAuditLog(r.Context(), dbgen.CreateAuditLogParams{
		ActorID:      uuid.NullUUID{UUID: actorID, Valid: true},
		ActorType:    audit.ActorUser,
		ActorDisplay: actorDisplay(user),
		Action:       action,
		ResourceType: "advisory",
		ResourceID:   cveID,
		OrgID:        uuid.NullUUID{UUID: orgID, Valid: true},
		Context:      context,
		IpAddress:    ipAddress,
		UserAgent:    userAgent,
	}); err != nil {
		s.log.Error().Err(err).Str("cve_id", cveID).Str("action", action).
			Msg("failed to audit a triage decision")
	}
}

// loadProjection rebuilds the decoded record the decision authors from.
func (s *Server) loadProjection(r *http.Request, cveID string) (cvefeed.Projection, error) {
	stored, err := s.queries.GetCVERecord(r.Context(), cveID)
	if err != nil {
		return cvefeed.Projection{}, err
	}
	affected, err := s.queries.ListCVEAffected(r.Context(), cveID)
	if err != nil {
		return cvefeed.Projection{}, err
	}
	projection := cvefeed.Projection{
		ID:          stored.CveID,
		State:       stored.State,
		Assigner:    stored.Assigner,
		Description: stored.Summary,
		CWEs:        stored.CweIds,
	}
	if stored.PublishedAt.Valid {
		projection.Published = stored.PublishedAt.Time
	}
	if stored.RecordUpdatedAt.Valid {
		projection.Updated = stored.RecordUpdatedAt.Time
	}
	projection.Severity = cvefeed.Severity{
		Vector: stored.CvssVector,
		Label:  stored.Severity,
	}
	byProduct := map[string]int{}
	for _, row := range affected {
		index, seen := byProduct[row.ProductKey]
		if !seen {
			projection.Affected = append(projection.Affected, cvefeed.AffectedProduct{
				Vendor: row.Vendor, Product: row.Product,
				VendorKey: row.VendorKey, ProductKey: row.ProductKey,
			})
			index = len(projection.Affected) - 1
			byProduct[row.ProductKey] = index
		}
		projection.Affected[index].Ranges = append(projection.Affected[index].Ranges,
			cvefeed.VersionRange{
				Introduced:   row.Introduced,
				Fixed:        row.Fixed,
				LastAffected: row.LastAffected,
			})
	}
	return projection, nil
}

func firstWord(value string) string {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return value
	}
	// "Apache Tomcat" -> "tomcat": the distinguishing half is usually the second
	// word, since the first is the foundation or vendor name.
	if len(fields) > 1 {
		return fields[len(fields)-1]
	}
	return fields[0]
}
