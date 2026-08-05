package server

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/comparison"
	"github.com/hibouhq/hibou/internal/delta"
	"github.com/hibouhq/hibou/internal/store"
)

type enrollRepoRequest struct {
	Name          string     `json:"name"`
	Slug          string     `json:"slug"`
	ProviderID    string     `json:"provider_id"`
	DefaultBranch string     `json:"default_branch,omitempty"`
	TeamID        *uuid.UUID `json:"team_id,omitempty"`
}

type updateRepoRequest struct {
	Name          *string    `json:"name,omitempty"`
	DefaultBranch *string    `json:"default_branch,omitempty"`
	TeamID        *uuid.UUID `json:"team_id,omitempty"`

	teamIDSet bool
}

func (r *updateRepoRequest) UnmarshalJSON(data []byte) error {
	type alias updateRepoRequest
	var payload alias
	if err := json.Unmarshal(data, &payload); err != nil {
		return err
	}

	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return err
	}

	*r = updateRepoRequest(payload)
	_, r.teamIDSet = probe["team_id"]
	return nil
}

type comparePRInfo struct {
	Number       int    `json:"number"`
	Title        string `json:"title"`
	SourceBranch string `json:"source_branch"`
	TargetBranch string `json:"target_branch"`
	State        string `json:"state"`
}

type refSnapshotResponse struct {
	RefName    string    `json:"ref_name"`
	SnapshotID uuid.UUID `json:"snapshot_id"`
	CommitSHA  string    `json:"commit_sha"`
	Date       time.Time `json:"date"`
	// ScanStatus is the latest advisory scan's state for this snapshot
	// (running|complete|failed|none) so the UI can say "scanning components…"
	// instead of rendering zero vulnerabilities as a final answer.
	ScanStatus string `json:"scan_status,omitempty"`
}

type componentEntryResponse struct {
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Ecosystem string   `json:"ecosystem"`
	Purl      string   `json:"purl"`
	VulnCount int      `json:"vuln_count"`
	Licenses  []string `json:"licenses"`
}

type componentUpdateResponse struct {
	Name          string   `json:"name"`
	Ecosystem     string   `json:"ecosystem"`
	Purl          string   `json:"purl"`
	BaseVersion   string   `json:"base_version"`
	HeadVersion   string   `json:"head_version"`
	BaseVulnCount int      `json:"base_vuln_count"`
	HeadVulnCount int      `json:"head_vuln_count"`
	Licenses      []string `json:"licenses"`
}

type componentDiffResponse struct {
	Added     []componentEntryResponse  `json:"added"`
	Removed   []componentEntryResponse  `json:"removed"`
	Updated   []componentUpdateResponse `json:"updated"`
	Unchanged int                       `json:"unchanged"`
}

type compareResultResponse struct {
	Base          refSnapshotResponse       `json:"base"`
	Head          refSnapshotResponse       `json:"head"`
	Delta         *delta.DeltaResult        `json:"delta"`
	ComponentDiff componentDiffResponse     `json:"component_diff"`
	CoverageDiff  *comparison.CoverageDiff  `json:"coverage_diff"`
	PatchCoverage *comparison.PatchCoverage `json:"patch_coverage,omitempty"`
	TestDiff      *comparison.TestDiff      `json:"test_diff"`
	Gate          *delta.GateResult         `json:"gate,omitempty"`
	PR            *comparePRInfo            `json:"pr,omitempty"`
}

type trendPointResponse struct {
	SnapshotID       uuid.UUID `json:"snapshot_id"`
	Date             time.Time `json:"date"`
	CommitSHA        string    `json:"commit_sha"`
	FindingsCritical int       `json:"findings_critical"`
	FindingsHigh     int       `json:"findings_high"`
	FindingsMedium   int       `json:"findings_medium"`
	FindingsLow      int       `json:"findings_low"`
	FindingsInfo     int       `json:"findings_info"`
	VulnsCritical    int       `json:"vulns_critical"`
	VulnsHigh        int       `json:"vulns_high"`
	VulnsMedium      int       `json:"vulns_medium"`
	VulnsLow         int       `json:"vulns_low"`
	VulnsInfo        int       `json:"vulns_info"`
	ComponentsTotal  int       `json:"components_total"`
}

// @Summary      Enroll repository
// @Description  Enroll a repository in an organization when the caller is an admin
// @Tags         repositories
// @Accept       json
// @Produce      json
// @Param        provider  path      string             true  "Forge provider"
// @Param        slug      path      string             true  "Organization slug"
// @Param        payload   body      enrollRepoRequest  true  "Repository details"
// @Success      201       {object}  api.Response{data=store.Repository}
// @Failure      400       {object}  api.Response
// @Failure      401       {object}  api.Response
// @Failure      403       {object}  api.Response
// @Failure      404       {object}  api.Response
// @Failure      500       {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos [post]
func (s *Server) handleEnrollRepo(w http.ResponseWriter, r *http.Request) {
	user, org, ok := s.loadAdminOrgForEnrollment(w, r)
	if !ok {
		return
	}
	input, ok := decodeEnrollRepoRequest(w, r)
	if !ok {
		return
	}
	provider := chi.URLParam(r, "provider")
	input.ProviderID = s.canonicalEnrollProviderID(r.Context(), provider, org.Slug, input.ProviderID)

	repo, err := s.queries.CreateRepository(
		r.Context(),
		org.ID,
		input.TeamID,
		input.Name,
		input.Slug,
		provider,
		input.ProviderID,
		input.DefaultBranch,
		"enrolled",
	)
	if !handleEnrollRepoCreateError(w, err) {
		return
	}

	s.writeRepositoryAuditLog(r, user, org.ID, repo.ID, audit.ActionRepoEnrolled, map[string]any{
		"name": repo.Name,
		"slug": repo.Slug,
	})

	// Baseline the whole history once at enrolment; pushes only scan their range.
	s.enqueueEnrollmentSecretScan(r.Context(), repo)

	api.JSON(w, http.StatusCreated, repo)
}

func (s *Server) canonicalEnrollProviderID(ctx context.Context, provider, account, providerID string) string {
	providerID = strings.TrimSpace(providerID)
	if providerID == "" {
		return providerID
	}

	inv, err := s.queries.GetForgeRepositoryByProviderRepoID(ctx, provider, providerID)
	if err == nil && inv != nil && strings.TrimSpace(inv.ProviderKey) != "" {
		return inv.ProviderKey
	}

	// Account-independent canonical key match handles owner/name inputs even
	// when the org slug differs from the forge account login.
	if inv, err := s.queries.GetForgeRepositoryByProviderKey(ctx, provider, providerID); err == nil && inv != nil && strings.TrimSpace(inv.ProviderKey) != "" {
		return inv.ProviderKey
	}

	inventory, err := s.queries.ListForgeRepositoriesByAccount(ctx, provider, account)
	if err != nil {
		return providerID
	}

	target := normalizeInventoryRepoKey(providerID)
	for i := range inventory {
		inv := inventory[i]
		if strings.TrimSpace(inv.ProviderKey) == "" {
			continue
		}
		if normalizeInventoryRepoKey(inv.ProviderKey) == target || normalizeInventoryRepoKey(inv.FullName) == target {
			return inv.ProviderKey
		}
	}

	return providerID
}

func (s *Server) loadAdminOrgForEnrollment(w http.ResponseWriter, r *http.Request) (*store.User, *store.Organization, bool) {
	if !s.hasPrincipal(r) {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return nil, nil, false
	}
	user := UserFromContext(r.Context())
	org, err := s.resolveOrg(r)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load organization")
		return nil, nil, false
	}
	if org == nil {
		api.JSONError(w, http.StatusNotFound, "organization not found")
		return nil, nil, false
	}
	role, err := s.principalOrgRole(r, org.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load organization")
		return nil, nil, false
	}
	if role != "admin" {
		api.JSONError(w, http.StatusForbidden, "admin access required")
		return nil, nil, false
	}
	return user, org, true
}

func decodeEnrollRepoRequest(w http.ResponseWriter, r *http.Request) (enrollRepoRequest, bool) {
	var input enrollRepoRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return enrollRepoRequest{}, false
	}
	input.Name = strings.TrimSpace(input.Name)
	input.Slug = strings.TrimSpace(input.Slug)
	input.ProviderID = strings.TrimSpace(input.ProviderID)
	input.DefaultBranch = strings.TrimSpace(input.DefaultBranch)
	if input.DefaultBranch == "" {
		input.DefaultBranch = "main"
	}
	if input.Name == "" {
		api.JSONError(w, http.StatusBadRequest, "name is required")
		return enrollRepoRequest{}, false
	}
	if input.Slug == "" {
		api.JSONError(w, http.StatusBadRequest, "slug is required")
		return enrollRepoRequest{}, false
	}
	if !api.IsValidSlug(input.Slug) {
		api.JSONError(w, http.StatusBadRequest, "slug must be 2-63 characters of lowercase letters, numbers, or hyphens")
		return enrollRepoRequest{}, false
	}
	if input.ProviderID == "" {
		api.JSONError(w, http.StatusBadRequest, "provider_id is required")
		return enrollRepoRequest{}, false
	}
	return input, true
}

func handleEnrollRepoCreateError(w http.ResponseWriter, err error) bool {
	if err == nil {
		return true
	}
	if isUniqueViolation(err) {
		if constraintName(err) == "repositories_provider_identity_key" {
			api.JSONError(w, http.StatusBadRequest, "repository with this provider_id already exists in this organization")
		} else {
			api.JSONError(w, http.StatusBadRequest, "repository slug already exists in this organization")
		}
		return false
	}
	if isForeignKeyViolation(err) {
		api.JSONError(w, http.StatusBadRequest, "team_id references an unknown team")
		return false
	}
	api.JSONError(w, http.StatusInternalServerError, "failed to create repository")
	return false
}

// @Summary      List repositories
// @Description  List repositories in an organization visible to organization members
// @Tags         repositories
// @Produce      json
// @Param        provider  path      string  true   "Forge provider"
// @Param        slug      path      string  true   "Organization slug"
// @Param        page      query     int     false  "Page number"
// @Param        per_page  query     int     false  "Items per page"
// @Success      200       {object}  api.ListResponse{data=[]repositoryInventoryEntry}
// @Failure      401       {object}  api.Response
// @Failure      404       {object}  api.Response
// @Failure      500       {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos [get]
func (s *Server) handleListRepos(w http.ResponseWriter, r *http.Request) {
	if !s.hasPrincipal(r) {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	org, err := s.resolveOrg(r)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load organization")
		return
	}
	if org == nil {
		api.JSONError(w, http.StatusNotFound, "organization not found")
		return
	}

	role, err := s.principalOrgRole(r, org.ID)
	if err != nil || role == "" {
		api.JSONError(w, http.StatusNotFound, "organization not found")
		return
	}

	pagination := api.ParsePagination(r)
	repos, _, err := s.listRepositoryInventory(r, org)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list repositories")
		return
	}

	api.JSONList(w, paginateSlice(repos, pagination.Offset, pagination.PerPage), pagination.Page, pagination.PerPage, len(repos))
}

// @Summary      Get repository
// @Description  Get a repository by slug when the caller belongs to the organization
// @Tags         repositories
// @Produce      json
// @Param        provider  path      string  true  "Forge provider"
// @Param        slug      path      string  true  "Organization slug"
// @Param        repoSlug  path      string  true  "Repository slug"
// @Success      200       {object}  api.Response{data=store.Repository}
// @Failure      401       {object}  api.Response
// @Failure      404       {object}  api.Response
// @Failure      500       {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug} [get]
func (s *Server) handleGetRepo(w http.ResponseWriter, r *http.Request) {
	if !s.hasPrincipal(r) {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	org, err := s.resolveOrg(r)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load organization")
		return
	}
	if org == nil {
		api.JSONError(w, http.StatusNotFound, "organization not found")
		return
	}

	role, err := s.principalOrgRole(r, org.ID)
	if err != nil || role == "" {
		api.JSONError(w, http.StatusNotFound, "organization not found")
		return
	}

	repo, err := s.queries.GetRepositoryBySlug(r.Context(), org.ID, chi.URLParam(r, "repoSlug"))
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load repository")
		return
	}
	if repo == nil {
		api.JSONError(w, http.StatusNotFound, "repository not found")
		return
	}

	// Repository visibility lives on the forge_repositories sync record, not the
	// core repositories table, so join it onto the detail response. Without this
	// the frontend never receives `private` and renders every repo as Public.
	api.JSON(w, http.StatusOK, s.repoDetailResponse(r.Context(), repo))
}

// repoVisibilityResponse augments store.Repository with the forge visibility.
// store.Repository (the core table) carries no visibility; it is sourced from
// the forge_repositories sync record.
type repoVisibilityResponse struct {
	*store.Repository
	Private    bool   `json:"private"`
	Visibility string `json:"visibility"`
}

func (s *Server) repoDetailResponse(ctx context.Context, repo *store.Repository) repoVisibilityResponse {
	resp := repoVisibilityResponse{Repository: repo, Visibility: "public"}
	if forgeRepo, err := s.queries.GetForgeRepositoryByProviderKey(ctx, repo.Provider, repo.ProviderID); err == nil && forgeRepo != nil {
		resp.Private = forgeRepo.Private
		if forgeRepo.Private {
			resp.Visibility = "private"
		}
	}
	return resp
}

// @Summary      Update repository
// @Description  Update a repository when the caller is an organization admin
// @Tags         repositories
// @Accept       json
// @Produce      json
// @Param        provider  path      string             true  "Forge provider"
// @Param        slug      path      string             true  "Organization slug"
// @Param        repoSlug  path      string             true  "Repository slug"
// @Param        payload   body      updateRepoRequest  true  "Repository updates"
// @Success      200       {object}  api.Response{data=store.Repository}
// @Failure      400       {object}  api.Response
// @Failure      401       {object}  api.Response
// @Failure      403       {object}  api.Response
// @Failure      404       {object}  api.Response
// @Failure      500       {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug} [put]
func (s *Server) handleUpdateRepo(w http.ResponseWriter, r *http.Request) {
	org, repo, user, ok := s.loadAuthorizedRepoWithUser(w, r, true)
	if !ok {
		return
	}

	var input updateRepoRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	name := repo.Name
	if input.Name != nil {
		name = strings.TrimSpace(*input.Name)
		if name == "" {
			api.JSONError(w, http.StatusBadRequest, "name must not be empty")
			return
		}
	}

	defaultBranch := repo.DefaultBranch
	if input.DefaultBranch != nil {
		defaultBranch = strings.TrimSpace(*input.DefaultBranch)
		if defaultBranch == "" {
			api.JSONError(w, http.StatusBadRequest, "default_branch must not be empty")
			return
		}
	}

	teamID := repo.TeamID
	if input.teamIDSet {
		teamID = input.TeamID
	}

	updated, err := s.queries.UpdateRepository(r.Context(), repo.ID, teamID, name, repo.Slug, defaultBranch, repo.SyncState)
	if err != nil {
		if isForeignKeyViolation(err) {
			api.JSONError(w, http.StatusBadRequest, "team_id references an unknown team")
			return
		}
		api.JSONError(w, http.StatusInternalServerError, "failed to update repository")
		return
	}
	if updated == nil {
		api.JSONError(w, http.StatusNotFound, "repository not found")
		return
	}

	s.writeRepositoryAuditLog(r, user, org.ID, updated.ID, audit.ActionRepoUpdated, map[string]any{
		"name": updated.Name,
		"slug": updated.Slug,
	})

	api.JSON(w, http.StatusOK, updated)
}

// @Summary      Remove repository
// @Description  Remove a repository when the caller is an organization admin
// @Tags         repositories
// @Produce      json
// @Param        provider  path  string  true  "Forge provider"
// @Param        slug      path  string  true  "Organization slug"
// @Param        repoSlug  path  string  true  "Repository slug"
// @Success      204       "No Content"
// @Failure      401       {object}  api.Response
// @Failure      403       {object}  api.Response
// @Failure      404       {object}  api.Response
// @Failure      500       {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug} [delete]
// purgeObjectStoreKeys best-effort deletes artifact bytes from the object store
// before a hard delete cascades the snapshot_artifacts metadata rows away,
// preventing orphaned objects. A missing object is fine; other failures are
// logged but not fatal, so a transient store error never blocks the delete (the
// worst case is a re-cleanable orphan, which beats an un-deletable repo/org).
func (s *Server) purgeObjectStoreKeys(ctx context.Context, keys []string) {
	if s.objStore == nil {
		return
	}
	for _, key := range keys {
		if key == "" {
			continue
		}
		if err := s.objStore.Delete(ctx, key); err != nil && !errors.Is(err, fs.ErrNotExist) {
			s.log.Warn().Err(err).Str("object_key", key).Msg("failed to delete artifact object during hard delete; object may be orphaned")
		}
	}
}

func (s *Server) handleRemoveRepo(w http.ResponseWriter, r *http.Request) {
	org, repo, user, ok := s.loadAuthorizedRepoWithUser(w, r, true)
	if !ok {
		return
	}

	// Hard-deleting the repository cascades the snapshot_artifacts rows away, so
	// the object-store bytes must be purged first or they orphan forever.
	objectKeys, err := s.queries.ListSnapshotArtifactObjectKeysByRepo(r.Context(), repo.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to enumerate repository artifacts")
		return
	}
	s.purgeObjectStoreKeys(r.Context(), objectKeys)

	if err := s.queries.DeleteRepository(r.Context(), repo.ID); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to delete repository")
		return
	}

	s.writeRepositoryAuditLog(r, user, org.ID, repo.ID, audit.ActionRepoRemoved, map[string]any{
		"name": repo.Name,
		"slug": repo.Slug,
	})

	w.WriteHeader(http.StatusNoContent)
}

// @Summary      List repository refs
// @Description  List refs for a repository when the caller belongs to the organization
// @Tags         repositories
// @Produce      json
// @Param        provider  path      string  true   "Forge provider"
// @Param        slug      path      string  true   "Organization slug"
// @Param        repoSlug  path      string  true   "Repository slug"
// @Param        page      query     int     false  "Page number"
// @Param        per_page  query     int     false  "Items per page"
// @Success      200       {object}  api.ListResponse{data=[]store.Ref}
// @Failure      401       {object}  api.Response
// @Failure      404       {object}  api.Response
// @Failure      500       {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/refs [get]
func (s *Server) handleListRefs(w http.ResponseWriter, r *http.Request) {
	if !s.hasPrincipal(r) {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	org, err := s.resolveOrg(r)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load organization")
		return
	}
	if org == nil {
		api.JSONError(w, http.StatusNotFound, "organization not found")
		return
	}

	role, err := s.principalOrgRole(r, org.ID)
	if err != nil || role == "" {
		api.JSONError(w, http.StatusNotFound, "organization not found")
		return
	}

	repo, err := s.queries.GetRepositoryBySlug(r.Context(), org.ID, chi.URLParam(r, "repoSlug"))
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load repository")
		return
	}
	if repo == nil {
		api.JSONError(w, http.StatusNotFound, "repository not found")
		return
	}

	pagination := api.ParsePagination(r)
	refs, total, err := s.queries.ListRefsByRepo(r.Context(), repo.ID, pagination.PerPage, pagination.Offset)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list refs")
		return
	}

	api.JSONList(w, refs, pagination.Page, pagination.PerPage, total)
}

func (s *Server) writeRepositoryAuditLog(r *http.Request, user *store.User, orgID, repoID uuid.UUID, action string, context map[string]any) {
	s.writeAuditLog(r, user, orgAuditID(orgID), auditEntry{
		Action:       action,
		ResourceType: "repository",
		ResourceID:   repoID.String(),
		Context:      context,
	})
}

func (s *Server) handleListRefsEnhanced(w http.ResponseWriter, r *http.Request) {
	_, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}

	pagination := api.ParsePagination(r)
	refs, total, err := s.queries.ListRefsEnhanced(r.Context(), repo.ID, pagination.PerPage, pagination.Offset)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list refs")
		return
	}

	api.JSONList(w, refs, pagination.Page, pagination.PerPage, total)
}

func (s *Server) handleListSnapshots(w http.ResponseWriter, r *http.Request) {
	_, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}

	refName := r.URL.Query().Get("ref")
	if refName == "" {
		refName = repo.DefaultBranch
	}
	ref, err := s.resolveRefForRepo(r, repo, refName)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load repository reference")
		return
	}
	if ref == nil {
		api.JSONError(w, http.StatusNotFound, "ref not found")
		return
	}

	pagination := api.ParsePagination(r)
	snapshots, total, err := s.queries.ListSnapshotsByRef(r.Context(), ref.ID, pagination.PerPage, pagination.Offset)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list snapshots")
		return
	}

	api.JSONList(w, snapshots, pagination.Page, pagination.PerPage, total)
}

// resolveCompareSide resolves one side of a comparison. A snapshot ID (when
// given) selects an exact snapshot; otherwise the ref's latest snapshot is used.
func (s *Server) resolveCompareSide(r *http.Request, w http.ResponseWriter, repo *store.Repository, refName, snapshotID, side string) (*store.Ref, *store.Snapshot, bool) {
	if snapshotID != "" {
		snapshot, status, message := s.loadSnapshotForRepoByID(r, repo, snapshotID)
		if status != 0 {
			api.JSONError(w, status, message)
			return nil, nil, false
		}
		ref, err := s.queries.GetRefByID(r.Context(), snapshot.RefID)
		if err != nil || ref == nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to load "+side+" ref")
			return nil, nil, false
		}
		return ref, snapshot, true
	}

	ref, snapshot, err := s.resolveSnapshotForRepo(r, repo, refName)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load "+side+" ref")
		return nil, nil, false
	}
	if ref == nil {
		api.JSONError(w, http.StatusNotFound, side+" ref not found")
		return nil, nil, false
	}
	if snapshot == nil {
		api.JSONError(w, http.StatusNotFound, side+" ref has no snapshots")
		return nil, nil, false
	}
	return ref, snapshot, true
}

func (s *Server) handleCompareRefs(w http.ResponseWriter, r *http.Request) {
	org, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}
	if s.deltaSvc == nil {
		api.JSONError(w, http.StatusInternalServerError, "delta service is not configured")
		return
	}

	baseName := r.URL.Query().Get("base")
	headName := r.URL.Query().Get("head")
	baseSnapshotID := r.URL.Query().Get("base_snapshot")
	headSnapshotID := r.URL.Query().Get("head_snapshot")
	if (baseName == "" && baseSnapshotID == "") || (headName == "" && headSnapshotID == "") {
		api.JSONError(w, http.StatusBadRequest, "base and head (ref or snapshot) are required")
		return
	}

	baseRef, baseSnapshot, ok := s.resolveCompareSide(r, w, repo, baseName, baseSnapshotID, "base")
	if !ok {
		return
	}
	headRef, headSnapshot, ok := s.resolveCompareSide(r, w, repo, headName, headSnapshotID, "head")
	if !ok {
		return
	}

	deltaResult, err := s.deltaSvc.ComputeDelta(r.Context(), headSnapshot.ID, baseSnapshot.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to compute ref comparison")
		return
	}

	baseComponents, err := s.queries.ListComponentsBySnapshotWithVulns(r.Context(), baseSnapshot.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load base components")
		return
	}
	headComponents, err := s.queries.ListComponentsBySnapshotWithVulns(r.Context(), headSnapshot.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load head components")
		return
	}

	componentDiff := buildComponentDiff(baseComponents, headComponents)

	coverageDiff, err := s.buildSnapshotCoverageDiff(r.Context(), repo.Slug, baseSnapshot.ID, headSnapshot.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to compare coverage")
		return
	}
	testDiff, err := s.buildSnapshotTestDiff(r.Context(), baseSnapshot.ID, headSnapshot.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to compare test results")
		return
	}

	response := compareResultResponse{
		Base: refSnapshotResponse{
			RefName:    baseRef.Name,
			SnapshotID: baseSnapshot.ID,
			CommitSHA:  baseSnapshot.CommitSHA,
			Date:       baseSnapshot.CreatedAt,
		},
		Head: refSnapshotResponse{
			RefName:    headRef.Name,
			SnapshotID: headSnapshot.ID,
			CommitSHA:  headSnapshot.CommitSHA,
			Date:       headSnapshot.CreatedAt,
			ScanStatus: s.latestScanStatus(r.Context(), headSnapshot.ID),
		},
		Delta:         deltaResult,
		ComponentDiff: componentDiff,
		CoverageDiff:  coverageDiff,
		TestDiff:      testDiff,
	}

	// New-code lens (ADR-019): applies to every comparison, PR or branch↔branch,
	// so "is the code this change introduced tested?" is answerable everywhere.
	s.applyNewCodeLens(r.Context(), repo, coverageDiff, baseSnapshot, headSnapshot, s.loadCompareRepoConfig(r.Context(), repo))

	// Auto-detect PR: if head ref is a pull request, enrich with gate + PR
	// metadata + line-level patch coverage.
	if headRef.RefType == store.RefTypePullRequest {
		if !s.enrichComparePR(r, w, comparePREnrichment{
			org:          org,
			repo:         repo,
			baseRef:      baseRef,
			headRef:      headRef,
			baseSnapshot: baseSnapshot,
			headSnapshot: headSnapshot,
			deltaResult:  deltaResult,
			coverageDiff: coverageDiff,
		}, &response) {
			return
		}
	}

	api.JSON(w, http.StatusOK, response)
}

// comparePREnrichment bundles the inputs enrichComparePR needs so the handler
// stays flat and the helper stays under the parameter limit.
type comparePREnrichment struct {
	org          *store.Organization
	repo         *store.Repository
	baseRef      *store.Ref
	headRef      *store.Ref
	baseSnapshot *store.Snapshot
	headSnapshot *store.Snapshot
	deltaResult  *delta.DeltaResult
	coverageDiff *comparison.CoverageDiff
}

// enrichComparePR fills the PR-specific parts of a compare response: the
// quality gate (vulnerability/weakness + coverage), PR metadata, and
// line-level patch coverage. It writes an HTTP error and returns false only
// when gate evaluation fails; all coverage enrichment degrades gracefully.
func (s *Server) enrichComparePR(r *http.Request, w http.ResponseWriter, in comparePREnrichment, response *compareResultResponse) bool {
	gateConfig := s.resolveRepoGateConfig(r.Context(), in.repo.Provider, in.repo.DefaultBranch, in.repo.ProviderID, in.repo.Name, in.repo.Slug, in.baseSnapshot.ID)
	if gateConfig == nil {
		gateConfig = &delta.GateConfig{}
	}
	gateConfig.HeadSnapshotID = in.headSnapshot.ID
	gate, err := s.deltaSvc.EvaluateGatesWithConfig(r.Context(), in.repo.ID, in.org.ID, in.deltaResult, gateConfig)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to evaluate pull request gate")
		return false
	}
	response.Gate = gate

	prNum := extractPRNumberFromRefName(in.headRef.Name)
	if in.headRef.PrNumber != nil {
		prNum, _ = strconv.Atoi(*in.headRef.PrNumber)
	}
	response.PR = &comparePRInfo{
		Number:       prNum,
		Title:        in.headRef.PrTitle,
		SourceBranch: in.headRef.PrSourceBranch,
		TargetBranch: in.baseRef.Name,
		State:        optionalStringValue(in.headRef.PrState),
	}

	// Line-level patch coverage + coverage quality gate matched from
	// .hibou.yaml against the PR target branch. Both degrade to nil/no-op.
	cfg := s.loadCompareRepoConfig(r.Context(), in.repo)
	response.PatchCoverage = s.buildPatchCoverage(r.Context(), in.repo, in.baseSnapshot, in.headSnapshot, cfg)
	if coverageGateConfigured(cfg, in.baseRef.Name) {
		if response.Gate == nil {
			response.Gate = &delta.GateResult{Passed: true}
		}
		response.Gate.Configured = true
		if reasons := evaluateCoverageGate(cfg, in.baseRef.Name, in.coverageDiff, response.PatchCoverage); len(reasons) > 0 {
			response.Gate.Reasons = append(response.Gate.Reasons, reasons...)
			response.Gate.Passed = len(response.Gate.Reasons) == 0
		}
	}
	return true
}

// latestScanStatus reports the newest advisory scan's status for a snapshot.
func (s *Server) latestScanStatus(ctx context.Context, snapshotID uuid.UUID) string {
	scans, err := s.queries.ListScansBySnapshot(ctx, snapshotID)
	if err != nil || len(scans) == 0 {
		return "none"
	}
	return scans[0].Status
}

func (s *Server) handleGetTrends(w http.ResponseWriter, r *http.Request) {
	_, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}

	query, err := parseTrendQuery(r, repo)
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	ref, err := s.resolveRefForRepo(r, repo, query.refName)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load repository reference")
		return
	}
	if ref == nil {
		api.JSONError(w, http.StatusNotFound, "ref not found")
		return
	}

	snapshots, err := s.listTrendSnapshots(r, ref.ID, query.limit, query.since)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load trend snapshots")
		return
	}

	points := make([]trendPointResponse, 0, len(snapshots))
	for _, snapshot := range snapshots {
		point, err := s.buildTrendPoint(r, snapshot)
		if err != nil {
			api.JSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		points = append(points, point)
	}

	api.JSON(w, http.StatusOK, points)
}

func (s *Server) listTrendSnapshots(r *http.Request, refID uuid.UUID, limit int, since *time.Time) ([]store.Snapshot, error) {
	collected, err := s.collectTrendSnapshots(r, refID, limit, since)
	if err != nil {
		return nil, err
	}
	reverseSnapshots(collected)
	return collected, nil
}

type trendQuery struct {
	refName string
	limit   int
	since   *time.Time
}

// extractPRNumberFromRefName parses the number from refs/pull/N or refs/merge-requests/N.
func extractPRNumberFromRefName(name string) int {
	for _, prefix := range []string{"refs/pull/", "refs/merge-requests/"} {
		if strings.HasPrefix(name, prefix) {
			rest := strings.TrimPrefix(name, prefix)
			if idx := strings.IndexByte(rest, '/'); idx > 0 {
				rest = rest[:idx]
			}
			if n, err := strconv.Atoi(rest); err == nil {
				return n
			}
		}
	}
	return 0
}

func parseTrendQuery(r *http.Request, repo *store.Repository) (*trendQuery, error) {
	query := &trendQuery{refName: r.URL.Query().Get("ref")}
	if query.refName == "" {
		query.refName = repo.DefaultBranch
	}
	if query.refName == "" {
		return nil, errors.New("ref is required")
	}
	limit, err := parseTrendLimit(r.URL.Query().Get("limit"))
	if err != nil {
		return nil, err
	}
	since, err := parseTrendSince(r.URL.Query().Get("since"))
	if err != nil {
		return nil, err
	}
	query.limit = limit
	query.since = since
	if query.since == nil && query.limit == 0 {
		query.limit = 30
	}
	return query, nil
}

func parseTrendLimit(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed <= 0 {
		return 0, errors.New("invalid limit")
	}
	if parsed > 365 {
		parsed = 365
	}
	return parsed, nil
}

func parseTrendSince(raw string) (*time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, errors.New("invalid since")
	}
	parsed = parsed.UTC()
	return &parsed, nil
}

func (s *Server) buildTrendPoint(r *http.Request, snapshot store.Snapshot) (trendPointResponse, error) {
	vulnerabilities, err := s.queries.ListAllVulnerabilitiesBySnapshot(r.Context(), snapshot.ID)
	if err != nil {
		return trendPointResponse{}, errors.New("failed to load vulnerability trends")
	}
	componentCount, err := s.queries.CountComponentsBySnapshot(r.Context(), snapshot.ID)
	if err != nil {
		return trendPointResponse{}, errors.New("failed to load component trends")
	}
	findings, vulns := countTrendSnapshotSeverities(vulnerabilities)
	return trendPointResponse{
		SnapshotID:       snapshot.ID,
		Date:             snapshot.CreatedAt,
		CommitSHA:        snapshot.CommitSHA,
		FindingsCritical: findings.Critical,
		FindingsHigh:     findings.High,
		FindingsMedium:   findings.Medium,
		FindingsLow:      findings.Low,
		FindingsInfo:     findings.Info,
		VulnsCritical:    vulns.Critical,
		VulnsHigh:        vulns.High,
		VulnsMedium:      vulns.Medium,
		VulnsLow:         vulns.Low,
		VulnsInfo:        vulns.Info,
		ComponentsTotal:  int(componentCount),
	}, nil
}

func countTrendSnapshotSeverities(vulnerabilities []store.Vulnerability) (severityCounts, severityCounts) {
	findings := severityCounts{}
	vulns := severityCounts{}
	for _, vulnerability := range vulnerabilities {
		if vulnerability.Status == "resolved" || vulnerability.Status == "dismissed" {
			continue
		}
		if vulnerability.Type == "dependency" || vulnerability.Type == "malware" {
			incrementSeverity(&vulns, string(vulnerability.Severity))
			continue
		}
		if vulnerability.Type == "secret" || vulnerability.Type == "manual" {
			continue
		}
		incrementSeverity(&findings, string(vulnerability.Severity))
	}
	return findings, vulns
}

func (s *Server) collectTrendSnapshots(r *http.Request, refID uuid.UUID, limit int, since *time.Time) ([]store.Snapshot, error) {
	offset := 0
	collected := make([]store.Snapshot, 0, trendSnapshotCapacity(limit))
	for limit == 0 || len(collected) < limit {
		snapshots, total, err := s.loadTrendSnapshotPage(r, refID, limit, offset)
		if err != nil {
			return nil, err
		}
		if len(snapshots) == 0 {
			break
		}
		stop := appendTrendSnapshots(&collected, snapshots, limit, since)
		if stop {
			break
		}
		offset += len(snapshots)
		if offset >= total {
			break
		}
	}
	return collected, nil
}

func trendSnapshotCapacity(limit int) int {
	if limit > 0 {
		return limit
	}
	return 16
}

func (s *Server) loadTrendSnapshotPage(r *http.Request, refID uuid.UUID, limit, offset int) ([]store.Snapshot, int, error) {
	pageSize := limit
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 100
	}
	if pageSize < 10 {
		pageSize = 10
	}
	return s.queries.ListSnapshotsByRef(r.Context(), refID, pageSize, offset)
}

func appendTrendSnapshots(collected *[]store.Snapshot, snapshots []store.Snapshot, limit int, since *time.Time) bool {
	for _, snapshot := range snapshots {
		if since != nil && snapshot.CreatedAt.Before(*since) {
			return true
		}
		if !isTrendSnapshotVisible(snapshot) {
			continue
		}
		*collected = append(*collected, snapshot)
		if limit > 0 && len(*collected) == limit {
			return true
		}
	}
	return false
}

func isTrendSnapshotVisible(snapshot store.Snapshot) bool {
	return snapshot.Status == store.SnapshotStatusComplete || snapshot.Status == store.SnapshotStatusActive
}

func reverseSnapshots(snapshots []store.Snapshot) {
	for left, right := 0, len(snapshots)-1; left < right; left, right = left+1, right-1 {
		snapshots[left], snapshots[right] = snapshots[right], snapshots[left]
	}
}

func buildComponentDiff(baseRows, headRows []store.ListComponentsBySnapshotWithVulnsRow) componentDiffResponse {
	toEntry := func(row store.ListComponentsBySnapshotWithVulnsRow) componentEntryResponse {
		licenses := row.Licenses
		if licenses == nil {
			licenses = []string{}
		}
		return componentEntryResponse{
			Name:      row.Name,
			Version:   row.Version,
			Ecosystem: row.Ecosystem,
			Purl:      row.Purl,
			VulnCount: int(row.VulnCount),
			Licenses:  licenses,
		}
	}
	baseByKey := make(map[string]componentEntryResponse, len(baseRows))
	for _, row := range baseRows {
		entry := toEntry(row)
		baseByKey[componentDiffKey(entry)] = entry
	}
	headByKey := make(map[string]componentEntryResponse, len(headRows))
	for _, row := range headRows {
		entry := toEntry(row)
		headByKey[componentDiffKey(entry)] = entry
	}

	// Initialize as empty (not nil) so the JSON arrays are [] rather than null,
	// which the frontend maps over directly.
	result := componentDiffResponse{
		Added:   []componentEntryResponse{},
		Removed: []componentEntryResponse{},
		Updated: []componentUpdateResponse{},
	}
	for key, head := range headByKey {
		base, ok := baseByKey[key]
		if !ok {
			result.Added = append(result.Added, head)
			continue
		}
		if base.Version == head.Version {
			result.Unchanged++
			continue
		}
		// Same package, different version: an update, not an add+remove pair.
		result.Updated = append(result.Updated, componentUpdateResponse{
			Name:          head.Name,
			Ecosystem:     head.Ecosystem,
			Purl:          head.Purl,
			BaseVersion:   base.Version,
			HeadVersion:   head.Version,
			BaseVulnCount: base.VulnCount,
			HeadVulnCount: head.VulnCount,
			Licenses:      head.Licenses,
		})
	}
	for key, entry := range baseByKey {
		if _, ok := headByKey[key]; ok {
			continue
		}
		result.Removed = append(result.Removed, entry)
	}

	sort.Slice(result.Added, func(i, j int) bool {
		return componentDiffKey(result.Added[i]) < componentDiffKey(result.Added[j])
	})
	sort.Slice(result.Removed, func(i, j int) bool {
		return componentDiffKey(result.Removed[i]) < componentDiffKey(result.Removed[j])
	})
	sort.Slice(result.Updated, func(i, j int) bool {
		u, v := result.Updated[i], result.Updated[j]
		return u.Ecosystem+":"+u.Name < v.Ecosystem+":"+v.Name
	})

	return result
}

// componentDiffKey identifies a package independent of its version, so a
// version bump pairs into one "updated" row instead of an add+remove.
func componentDiffKey(entry componentEntryResponse) string {
	if entry.Purl != "" {
		if at := strings.LastIndex(entry.Purl, "@"); at > 0 {
			return entry.Purl[:at]
		}
		return entry.Purl
	}
	return entry.Ecosystem + ":" + entry.Name
}

// buildSnapshotCoverageDiff loads the primary coverage report for each snapshot
// (the report with the most valid lines, mirroring the Coverage tab) and diffs
// them. It returns nil when neither snapshot has coverage data.
func (s *Server) buildSnapshotCoverageDiff(ctx context.Context, repoSlug string, baseSnapshotID, headSnapshotID uuid.UUID) (*comparison.CoverageDiff, error) {
	baseInput, err := s.loadCoverageInput(ctx, baseSnapshotID, repoSlug)
	if err != nil {
		return nil, err
	}
	headInput, err := s.loadCoverageInput(ctx, headSnapshotID, repoSlug)
	if err != nil {
		return nil, err
	}
	return comparison.BuildCoverageDiff(baseInput, headInput), nil
}

// loadCoverageInput aggregates EVERY coverage report of the snapshot, keyed by
// canonical path. Diffing only a single "primary" report meant a multi-language
// repo could compare one language's report against another's whenever a change
// shifted which report had the most instrumented lines — producing large fake
// regressions and files falsely reported added/removed.
func (s *Server) loadCoverageInput(ctx context.Context, snapshotID uuid.UUID, repoSlug string) (comparison.CoverageInput, error) {
	reports, err := s.queries.ListCoverageReportsBySnapshot(ctx, snapshotID)
	if err != nil {
		return comparison.CoverageInput{}, err
	}
	if len(reports) == 0 {
		return comparison.CoverageInput{}, nil
	}

	files, err := s.queries.ListCoverageFilesBySnapshot(ctx, snapshotID)
	if err != nil {
		return comparison.CoverageInput{}, err
	}
	// Union keyed by canonical path; on a collision (two tools measuring the
	// same file) the better-covered row wins, matching the summary endpoint.
	best := make(map[string]comparison.CoverageFileInput, len(files))
	for _, file := range files {
		key := canonicalCoveragePath(file.FilePath, repoSlug)
		if key == "" {
			key = file.FilePath
		}
		input := comparison.CoverageFileInput{
			FilePath:     key,
			LineRate:     file.LineRate,
			LinesValid:   file.LinesValid,
			LinesCovered: file.LinesCovered,
		}
		if existing, seen := best[key]; !seen || input.LinesCovered > existing.LinesCovered {
			best[key] = input
		}
	}

	totals := comparison.CoverageInput{HasData: true}
	for _, report := range reports {
		totals.BranchesValid += report.BranchesValid
		totals.BranchesCovered += report.BranchesCovered
	}
	totals.Files = make([]comparison.CoverageFileInput, 0, len(best))
	for _, file := range best {
		totals.Files = append(totals.Files, file)
		totals.LinesValid += file.LinesValid
		totals.LinesCovered += file.LinesCovered
	}
	totals.LineRate = ratio(totals.LinesCovered, totals.LinesValid)
	totals.BranchRate = ratio(totals.BranchesCovered, totals.BranchesValid)
	return totals, nil
}

// buildSnapshotTestDiff loads each snapshot's test report and cases and diffs
// them. It returns nil when neither snapshot has test data.
func (s *Server) buildSnapshotTestDiff(ctx context.Context, baseSnapshotID, headSnapshotID uuid.UUID) (*comparison.TestDiff, error) {
	baseInput, err := s.loadTestInput(ctx, baseSnapshotID)
	if err != nil {
		return nil, err
	}
	headInput, err := s.loadTestInput(ctx, headSnapshotID)
	if err != nil {
		return nil, err
	}
	return comparison.BuildTestDiff(baseInput, headInput), nil
}

func (s *Server) loadTestInput(ctx context.Context, snapshotID uuid.UUID) (comparison.TestReportInput, error) {
	report, err := s.queries.GetTestReportBySnapshot(ctx, snapshotID)
	if err != nil {
		return comparison.TestReportInput{}, err
	}
	if report == nil {
		return comparison.TestReportInput{}, nil
	}

	cases, err := s.queries.ListTestCasesBySnapshot(ctx, snapshotID)
	if err != nil {
		return comparison.TestReportInput{}, err
	}
	caseInputs := make([]comparison.TestCaseInput, len(cases))
	for i, c := range cases {
		caseInputs[i] = comparison.TestCaseInput{
			Suite:           c.Suite,
			Name:            c.Name,
			Classname:       c.Classname,
			Status:          c.Status,
			DurationSeconds: c.DurationSeconds,
			Message:         c.Message,
			FilePath:        c.FilePath,
		}
	}

	return comparison.TestReportInput{
		HasData:         true,
		Format:          report.Format,
		Total:           report.Total,
		Passed:          report.Passed,
		Failed:          report.Failed,
		Skipped:         report.Skipped,
		Errors:          report.Errors,
		DurationSeconds: report.DurationSeconds,
		Cases:           caseInputs,
	}, nil
}
