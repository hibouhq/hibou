package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/cooldown"
	"github.com/hibouhq/hibou/internal/provenance"
	"github.com/hibouhq/hibou/internal/repoconfig"
	"github.com/hibouhq/hibou/internal/shipped"
	"github.com/hibouhq/hibou/internal/store"
)

// The shipped attribute (ADR-045 §6): which components reach clients.
// Evidence first (an uploaded SBOM), then the not-shipped lists in
// precedence order (built-in defaults, organization, repository entries
// recorded in the UI, the repository's .hibou.yaml), then trusted declared
// scopes. Everything stays listed; the attribute filters.

// shippingEntryResponse is one list entry with where it comes from.
type shippingEntryResponse struct {
	ID        *uuid.UUID `json:"id,omitempty"`
	Pattern   string     `json:"pattern"`
	Reason    string     `json:"reason,omitempty"`
	Source    string     `json:"source"`
	CreatedBy *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt string     `json:"created_at,omitempty"`
	// Overridden is true when the repository's `shipped` list cancels it.
	Overridden bool `json:"overridden,omitempty"`
}

// shippingResponse is GET .../dependencies/shipping.
type shippingResponse struct {
	Entries []shippingEntryResponse `json:"entries"`
	// Overrides are the repository's `dependencies.shipped` patterns.
	Overrides []string `json:"overrides,omitempty"`
	// UploadedSBOM says an SBOM from the team's own build exists for the
	// snapshot; SBOMCovers is what .hibou.yaml says it describes.
	UploadedSBOM bool     `json:"uploaded_sbom"`
	SBOMCovers   []string `json:"sbom_covers,omitempty"`
	// UndeclaredModules are extraction modules the uploaded SBOM does not
	// mention while nothing says what it covers: "shipped or not?".
	UndeclaredModules []string `json:"undeclared_modules,omitempty"`
	TrustedScopes     []string `json:"trusted_declared_scopes,omitempty"`
	// CanEdit says whether the caller may add or remove repository entries.
	CanEdit bool `json:"can_edit"`
}

// shippingContext is the policy with the material it was built from.
type shippingContext struct {
	policy  *shipped.Policy
	entries []shippingEntryResponse
	cfg     *repoconfig.RepoConfig
}

// buildShippingPolicy assembles the policy for one snapshot's labels.
func (s *Server) buildShippingPolicy(ctx context.Context, org *store.Organization, repo *store.Repository, cfg *repoconfig.RepoConfig, labels map[uuid.UUID]json.RawMessage) *shippingContext {
	out := &shippingContext{policy: &shipped.Policy{ExtractorSource: depInventoryArtifactFilename}, cfg: cfg}
	var overrides *shipped.List
	if cfg != nil && cfg.Dependencies != nil {
		if list, err := shipped.Parse(cfg.Dependencies.Shipped); err == nil {
			overrides = list
		}
		out.policy.Overrides = overrides
		out.policy.Covers = cfg.Dependencies.SBOMCovers
	}
	overridden := func(pattern string) bool {
		if overrides == nil {
			return false
		}
		for _, p := range overrides.Patterns() {
			if p == pattern {
				return true
			}
		}
		return false
	}
	addSource := func(name string, patterns []string) {
		if len(patterns) == 0 {
			return
		}
		kept := make([]string, 0, len(patterns))
		for _, pattern := range patterns {
			if overridden(pattern) {
				continue
			}
			kept = append(kept, pattern)
		}
		if list, err := shipped.Parse(kept); err == nil && !list.Empty() {
			out.policy.Sources = append(out.policy.Sources, shipped.Source{Name: name, List: list})
		}
	}
	for _, pattern := range shipped.DefaultPatterns {
		out.entries = append(out.entries, shippingEntryResponse{Pattern: pattern, Source: shipped.SourceDefault, Reason: "built-in: infrastructure and CI code is not a client deliverable", Overridden: overridden(pattern)})
	}
	addSource(shipped.SourceDefault, shipped.DefaultPatterns)

	var orgPatterns, repoPatterns []string
	if org != nil {
		var repoID *uuid.UUID
		if repo != nil {
			repoID = &repo.ID
		}
		if entries, err := s.queries.ListNotShippedEntries(ctx, org.ID, repoID); err == nil {
			for _, entry := range entries {
				id := entry.ID
				response := shippingEntryResponse{ID: &id, Pattern: entry.Pattern, Reason: entry.Reason, CreatedBy: entry.CreatedBy, CreatedAt: entry.CreatedAt.Format("2006-01-02T15:04:05Z07:00"), Overridden: overridden(entry.Pattern)}
				if entry.RepoID == nil {
					response.Source = shipped.SourceOrganization
					orgPatterns = append(orgPatterns, entry.Pattern)
				} else {
					response.Source = shipped.SourceRepository
					repoPatterns = append(repoPatterns, entry.Pattern)
				}
				out.entries = append(out.entries, response)
			}
		} else {
			s.log.Warn().Err(err).Str("org_id", org.ID.String()).Msg("list not-shipped entries")
		}
		defaults := cooldown.ParseOrgDefaults(org.Settings)
		if len(defaults.TrustedDeclaredScopes) > 0 {
			out.policy.TrustedScopes = make(map[string]bool, len(defaults.TrustedDeclaredScopes))
			for _, ecosystem := range defaults.TrustedDeclaredScopes {
				out.policy.TrustedScopes[strings.ToLower(strings.TrimSpace(ecosystem))] = true
			}
		}
	}
	addSource(shipped.SourceOrganization, orgPatterns)
	addSource(shipped.SourceRepository, repoPatterns)
	if cfg != nil && cfg.Dependencies != nil {
		for _, pattern := range cfg.Dependencies.NotShipped {
			out.entries = append(out.entries, shippingEntryResponse{Pattern: pattern, Source: shipped.SourceConfig})
		}
		addSource(shipped.SourceConfig, cfg.Dependencies.NotShipped)
	}
	for _, raw := range labels {
		for _, source := range provenance.FromLabels(raw).InventorySources {
			if source != depInventoryArtifactFilename {
				out.policy.UploadedSBOM = true
				break
			}
		}
		if out.policy.UploadedSBOM {
			break
		}
	}
	return out
}

// shippedDecisions decides every component of a snapshot, by component id.
func (s *Server) shippedDecisions(ctx context.Context, org *store.Organization, repo *store.Repository, snapshotID uuid.UUID) (map[uuid.UUID]shipped.Decision, *shippingContext, error) {
	labels, err := s.queries.ListSnapshotComponentLabels(ctx, snapshotID)
	if err != nil {
		return nil, nil, err
	}
	components, err := s.queries.ListComponentsBySnapshot(ctx, snapshotID)
	if err != nil {
		return nil, nil, err
	}
	var cfg *repoconfig.RepoConfig
	if loaded, _, err := s.loadBoundRepoConfig(ctx, repo); err == nil {
		cfg = loaded
	}
	shipping := s.buildShippingPolicy(ctx, org, repo, cfg, labels)
	decisions := make(map[uuid.UUID]shipped.Decision, len(components))
	for _, component := range components {
		prov := provenance.FromLabels(labels[component.ID])
		decisions[component.ID] = shipping.policy.Decide(shippedCandidate(component.Purl, component.Ecosystem, prov))
	}
	return decisions, shipping, nil
}

func shippedCandidate(purl, ecosystem string, prov provenance.Provenance) shipped.Candidate {
	return shipped.Candidate{Purl: purl, Ecosystem: ecosystem, Sources: prov.InventorySources, Modules: prov.Modules, Paths: prov.Paths, Scopes: prov.Scopes}
}

// notShippedComponentIDs lists the snapshot's components the policy marks
// not shipped, for the vulnerability list's shipped filter.
func (s *Server) notShippedComponentIDs(ctx context.Context, org *store.Organization, repo *store.Repository, snapshotID uuid.UUID) ([]uuid.UUID, error) {
	decisions, _, err := s.shippedDecisions(ctx, org, repo, snapshotID)
	if err != nil {
		return nil, err
	}
	out := make([]uuid.UUID, 0)
	for id, decision := range decisions {
		if !decision.Shipped {
			out = append(out, id)
		}
	}
	return out, nil
}

// attachShipped sets the shipped attribute on component-backed findings
// of one snapshot (ADR-045 §12: a "not shipped" badge, never a hidden row).
func (s *Server) attachShipped(ctx context.Context, org *store.Organization, repo *store.Repository, snapshotID uuid.UUID, vulnerabilities []store.Vulnerability) {
	needed := false
	for _, vuln := range vulnerabilities {
		if vuln.ComponentID != nil {
			needed = true
			break
		}
	}
	if !needed {
		return
	}
	decisions, _, err := s.shippedDecisions(ctx, org, repo, snapshotID)
	if err != nil {
		s.log.Warn().Err(err).Str("snapshot_id", snapshotID.String()).Msg("shipped attribute for findings")
		return
	}
	for i := range vulnerabilities {
		id := vulnerabilities[i].ComponentID
		if id == nil {
			continue
		}
		if decision, ok := decisions[*id]; ok {
			value := decision.Shipped
			vulnerabilities[i].Shipped = &value
			vulnerabilities[i].ShippedReason = decision.Reason
		}
	}
}

// shippedFilterFromQuery reads ?shipped=yes|no and a `shipped:yes|no`
// token inside q; the token is removed from q so the parser never sees a
// qualifier it does not know.
func shippedFilterFromQuery(r *http.Request) (shippedFilter, q string) {
	q = strings.TrimSpace(r.URL.Query().Get("q"))
	shippedFilter = strings.ToLower(strings.TrimSpace(r.URL.Query().Get("shipped")))
	if q == "" {
		return shippedFilter, q
	}
	kept := make([]string, 0, 8)
	for _, token := range strings.Fields(q) {
		lower := strings.ToLower(token)
		if strings.HasPrefix(lower, "shipped:") {
			shippedFilter = strings.TrimPrefix(lower, "shipped:")
			continue
		}
		kept = append(kept, token)
	}
	return shippedFilter, strings.Join(kept, " ")
}

// ---- Endpoints ----

// handleGetDependencyShipping returns the lists that decide the shipped
// attribute for a ref or snapshot and the SBOM facts behind it.
func (s *Server) handleGetDependencyShipping(w http.ResponseWriter, r *http.Request) {
	org, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}
	var labels map[uuid.UUID]json.RawMessage
	var modules []string
	modulesWithUpload := map[string]bool{}
	snapshot, ok := s.resolveSnapshotForRequestWithFallback(r, w, repo, s.queries.GetLatestSnapshotWithComponentsByRef)
	if !ok {
		return
	}
	if snapshot != nil {
		loaded, err := s.queries.ListSnapshotComponentLabels(r.Context(), snapshot.ID)
		if err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to load component provenance")
			return
		}
		labels = loaded
		seen := map[string]bool{}
		for _, raw := range labels {
			prov := provenance.FromLabels(raw)
			fromUpload := false
			for _, source := range prov.InventorySources {
				if source != depInventoryArtifactFilename {
					fromUpload = true
				}
			}
			for _, module := range prov.Modules {
				if !seen[module] {
					seen[module] = true
					modules = append(modules, module)
				}
				if fromUpload {
					modulesWithUpload[module] = true
				}
			}
		}
	}
	var cfg *repoconfig.RepoConfig
	if loaded, _, err := s.loadBoundRepoConfig(r.Context(), repo); err == nil {
		cfg = loaded
	}
	shipping := s.buildShippingPolicy(r.Context(), org, repo, cfg, labels)
	response := shippingResponse{
		Entries:           shipping.entries,
		UploadedSBOM:      shipping.policy.UploadedSBOM,
		SBOMCovers:        shipping.policy.Covers,
		UndeclaredModules: shipped.UndeclaredModules(shipping.policy, modulesWithUpload, modules),
		CanEdit:           s.canManageShipping(r, org.ID),
	}
	if shipping.policy.Overrides != nil {
		response.Overrides = shipping.policy.Overrides.Patterns()
	}
	for ecosystem := range shipping.policy.TrustedScopes {
		response.TrustedScopes = append(response.TrustedScopes, ecosystem)
	}
	if response.Entries == nil {
		response.Entries = []shippingEntryResponse{}
	}
	api.JSON(w, http.StatusOK, response)
}

// canManageShipping: admins and release managers decide what ships
// (ADR-045 §6), in the style of triage acceptance.
func (s *Server) canManageShipping(r *http.Request, orgID uuid.UUID) bool {
	role, err := s.principalOrgRole(r, orgID)
	if err != nil {
		return false
	}
	return role == "admin" || role == "release_manager"
}

type notShippedEntriesRequest struct {
	Entries []struct {
		Pattern string `json:"pattern"`
		Reason  string `json:"reason"`
	} `json:"entries"`
}

var errInvalidNotShippedEntry = errors.New("invalid not-shipped entry")

func parseNotShippedEntries(r *http.Request) ([]store.UpsertNotShippedEntryParams, error) {
	var body notShippedEntriesRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return nil, errInvalidNotShippedEntry
	}
	if len(body.Entries) == 0 || len(body.Entries) > 500 {
		return nil, errInvalidNotShippedEntry
	}
	out := make([]store.UpsertNotShippedEntryParams, 0, len(body.Entries))
	for _, entry := range body.Entries {
		pattern := strings.TrimSpace(entry.Pattern)
		if err := shipped.ValidPattern(pattern); err != nil {
			return nil, err
		}
		reason := strings.TrimSpace(entry.Reason)
		if reason == "" {
			return nil, errors.New("a reason is required for every entry")
		}
		out = append(out, store.UpsertNotShippedEntryParams{Pattern: pattern, Reason: reason})
	}
	return out, nil
}

// handleAddRepoNotShipped records repository entries (admins and release
// managers), audit-logged like a triage acceptance.
func (s *Server) handleAddRepoNotShipped(w http.ResponseWriter, r *http.Request) {
	org, repo, user, ok := s.loadAuthorizedRepoWithUser(w, r, false)
	if !ok {
		return
	}
	if !s.canManageShipping(r, org.ID) {
		api.JSONError(w, http.StatusForbidden, "admin or release manager role required")
		return
	}
	s.addNotShippedEntries(w, r, org, repo, user)
}

// handleAddOrgNotShipped records organization-wide entries (admins).
func (s *Server) handleAddOrgNotShipped(w http.ResponseWriter, r *http.Request) {
	org, user, ok := s.loadOrgAdminUser(r, w)
	if !ok {
		return
	}
	s.addNotShippedEntries(w, r, org, nil, user)
}

func (s *Server) addNotShippedEntries(w http.ResponseWriter, r *http.Request, org *store.Organization, repo *store.Repository, user *store.User) {
	entries, err := parseNotShippedEntries(r)
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	var repoID *uuid.UUID
	if repo != nil {
		repoID = &repo.ID
	}
	var createdBy *uuid.UUID
	if user != nil {
		createdBy = &user.ID
	}
	created := make([]store.NotShippedEntry, 0, len(entries))
	for _, params := range entries {
		params.OrgID = org.ID
		params.RepoID = repoID
		params.CreatedBy = createdBy
		entry, err := s.queries.UpsertNotShippedEntry(r.Context(), params)
		if err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to record not-shipped entry")
			return
		}
		created = append(created, *entry)
		context := map[string]any{"pattern": entry.Pattern, "reason": entry.Reason, "scope": "organization"}
		resourceType, resourceID := "organization", org.ID.String()
		if repo != nil {
			context["scope"], context["repo"] = "repository", repo.Slug
			resourceType, resourceID = "repository", repo.ID.String()
		}
		s.writeAuditLog(r, user, orgAuditID(org.ID), auditEntry{Action: audit.ActionNotShippedAdded, ResourceType: resourceType, ResourceID: resourceID, Context: context})
	}
	api.JSON(w, http.StatusCreated, created)
}

// handleDeleteRepoNotShipped removes one repository entry.
func (s *Server) handleDeleteRepoNotShipped(w http.ResponseWriter, r *http.Request) {
	org, repo, user, ok := s.loadAuthorizedRepoWithUser(w, r, false)
	if !ok {
		return
	}
	if !s.canManageShipping(r, org.ID) {
		api.JSONError(w, http.StatusForbidden, "admin or release manager role required")
		return
	}
	s.deleteNotShippedEntry(w, r, org, repo, user)
}

// handleDeleteOrgNotShipped removes one organization entry (admins).
func (s *Server) handleDeleteOrgNotShipped(w http.ResponseWriter, r *http.Request) {
	org, user, ok := s.loadOrgAdminUser(r, w)
	if !ok {
		return
	}
	s.deleteNotShippedEntry(w, r, org, nil, user)
}

func (s *Server) deleteNotShippedEntry(w http.ResponseWriter, r *http.Request, org *store.Organization, repo *store.Repository, user *store.User) {
	id, err := uuid.Parse(chi.URLParam(r, "entryID"))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid entry id")
		return
	}
	entry, err := s.queries.GetNotShippedEntry(r.Context(), org.ID, id)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load entry")
		return
	}
	if entry == nil {
		api.JSONError(w, http.StatusNotFound, "entry not found")
		return
	}
	// A repository route removes only its own rows; the organization's rows
	// need the organization route and an admin.
	if repo != nil && (entry.RepoID == nil || *entry.RepoID != repo.ID) {
		api.JSONError(w, http.StatusNotFound, "entry not found")
		return
	}
	if repo == nil && entry.RepoID != nil {
		api.JSONError(w, http.StatusNotFound, "entry not found")
		return
	}
	if _, err := s.queries.DeleteNotShippedEntry(r.Context(), org.ID, id); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to delete entry")
		return
	}
	resourceType, resourceID := "organization", org.ID.String()
	context := map[string]any{"pattern": entry.Pattern}
	if repo != nil {
		resourceType, resourceID = "repository", repo.ID.String()
		context["repo"] = repo.Slug
	}
	s.writeAuditLog(r, user, orgAuditID(org.ID), auditEntry{Action: audit.ActionNotShippedRemoved, ResourceType: resourceType, ResourceID: resourceID, Context: context})
	w.WriteHeader(http.StatusNoContent)
}

// handleListOrgNotShipped lists the organization's entries.
func (s *Server) handleListOrgNotShipped(w http.ResponseWriter, r *http.Request) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok {
		return
	}
	entries, err := s.queries.ListNotShippedEntries(r.Context(), org.ID, nil)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list entries")
		return
	}
	api.JSON(w, http.StatusOK, entries)
}
