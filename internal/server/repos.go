package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/lehibou/internal/api"
	"github.com/hibouhq/lehibou/internal/audit"
	"github.com/hibouhq/lehibou/internal/delta"
	"github.com/hibouhq/lehibou/internal/store"
	"github.com/hibouhq/lehibou/internal/store/dbgen"
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

type prSummaryResponse struct {
	Ref              store.EnhancedRef  `json:"ref"`
	PRSnapshotID     *uuid.UUID         `json:"pr_snapshot_id,omitempty"`
	TargetSnapshotID *uuid.UUID         `json:"target_snapshot_id,omitempty"`
	Delta            *delta.DeltaResult `json:"delta,omitempty"`
	Gate             *delta.GateResult  `json:"gate"`
	Summary          refSummaryResponse `json:"summary"`
}

type refSnapshotResponse struct {
	RefName    string    `json:"ref_name"`
	SnapshotID uuid.UUID `json:"snapshot_id"`
	CommitSHA  string    `json:"commit_sha"`
	Date       time.Time `json:"date"`
}

type componentEntryResponse struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
	Purl      string `json:"purl"`
	VulnCount int    `json:"vuln_count"`
}

type componentDiffResponse struct {
	Added     []componentEntryResponse `json:"added"`
	Removed   []componentEntryResponse `json:"removed"`
	Unchanged int                      `json:"unchanged"`
}

type compareResultResponse struct {
	Base          refSnapshotResponse   `json:"base"`
	Head          refSnapshotResponse   `json:"head"`
	Delta         *delta.DeltaResult    `json:"delta"`
	ComponentDiff componentDiffResponse `json:"component_diff"`
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

	repo, err := s.queries.CreateRepository(
		r.Context(),
		org.ID,
		input.TeamID,
		input.Name,
		input.Slug,
		chi.URLParam(r, "provider"),
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

	api.JSON(w, http.StatusCreated, repo)
}

func (s *Server) loadAdminOrgForEnrollment(w http.ResponseWriter, r *http.Request) (*store.User, *store.Organization, bool) {
	user := UserFromContext(r.Context())
	if user == nil {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return nil, nil, false
	}
	org, err := s.resolveOrg(r)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load organization")
		return nil, nil, false
	}
	if org == nil {
		api.JSONError(w, http.StatusNotFound, "organization not found")
		return nil, nil, false
	}
	role, err := s.queries.GetOrgMemberRole(r.Context(), org.ID, user.ID)
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
// @Success      200       {object}  api.ListResponse{data=[]store.Repository}
// @Failure      401       {object}  api.Response
// @Failure      404       {object}  api.Response
// @Failure      500       {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos [get]
func (s *Server) handleListRepos(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
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

	role, err := s.queries.GetOrgMemberRole(r.Context(), org.ID, user.ID)
	if err != nil || role == "" {
		api.JSONError(w, http.StatusNotFound, "organization not found")
		return
	}

	pagination := api.ParsePagination(r)
	repos, total, err := s.queries.ListRepositoriesByOrg(r.Context(), org.ID, pagination.PerPage, pagination.Offset)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list repositories")
		return
	}

	api.JSONList(w, repos, pagination.Page, pagination.PerPage, total)
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
	user := UserFromContext(r.Context())
	if user == nil {
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

	role, err := s.queries.GetOrgMemberRole(r.Context(), org.ID, user.ID)
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

	api.JSON(w, http.StatusOK, repo)
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
func (s *Server) handleRemoveRepo(w http.ResponseWriter, r *http.Request) {
	org, repo, user, ok := s.loadAuthorizedRepoWithUser(w, r, true)
	if !ok {
		return
	}

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
	user := UserFromContext(r.Context())
	if user == nil {
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

	role, err := s.queries.GetOrgMemberRole(r.Context(), org.ID, user.ID)
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
	contextBody, err := json.Marshal(context)
	if err != nil {
		contextBody = json.RawMessage(`{"status":"marshal_error"}`)
	}

	ipAddress, userAgent := audit.RequestContext(r)
	_, _ = s.queries.CreateAuditLog(r.Context(), dbgen.CreateAuditLogParams{
		ActorID:      uuid.NullUUID{UUID: user.ID, Valid: true},
		ActorType:    audit.ActorUser,
		ActorDisplay: actorDisplay(user),
		Action:       action,
		ResourceType: "repository",
		ResourceID:   repoID.String(),
		OrgID:        uuid.NullUUID{UUID: orgID, Valid: true},
		Context:      contextBody,
		IpAddress:    ipAddress,
		UserAgent:    userAgent,
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

func (s *Server) handleGetPRSummary(w http.ResponseWriter, r *http.Request) {
	org, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}

	number, ok := parsePullRequestNumber(chi.URLParam(r, "number"))
	if !ok {
		api.JSONError(w, http.StatusBadRequest, "invalid pull request number")
		return
	}

	ref, prSnapshot, targetRef, targetSnapshot, ok := s.loadPRSummarySnapshots(w, r, repo, number)
	if !ok {
		return
	}
	response := s.newPRSummaryResponse(ref, targetRef, prSnapshot)
	if !s.populatePRSummary(w, r, response, prSnapshot, targetSnapshot) {
		return
	}
	if !s.populatePRSummaryDelta(w, r, response, org, repo, prSnapshot, targetSnapshot) {
		return
	}

	api.JSON(w, http.StatusOK, response)
}

func (s *Server) handleCompareRefs(w http.ResponseWriter, r *http.Request) {
	_, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}
	if s.deltaSvc == nil {
		api.JSONError(w, http.StatusInternalServerError, "delta service is not configured")
		return
	}

	baseName := r.URL.Query().Get("base")
	headName := r.URL.Query().Get("head")
	if baseName == "" || headName == "" {
		api.JSONError(w, http.StatusBadRequest, "base and head refs are required")
		return
	}

	baseRef, baseSnapshot, err := s.resolveSnapshotForRepo(r, repo, baseName)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load base ref")
		return
	}
	if baseRef == nil {
		api.JSONError(w, http.StatusNotFound, "base ref not found")
		return
	}
	if baseSnapshot == nil {
		api.JSONError(w, http.StatusNotFound, "base ref has no snapshots")
		return
	}

	headRef, headSnapshot, err := s.resolveSnapshotForRepo(r, repo, headName)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load head ref")
		return
	}
	if headRef == nil {
		api.JSONError(w, http.StatusNotFound, "head ref not found")
		return
	}
	if headSnapshot == nil {
		api.JSONError(w, http.StatusNotFound, "head ref has no snapshots")
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
		},
		Delta:         deltaResult,
		ComponentDiff: componentDiff,
	}

	api.JSON(w, http.StatusOK, response)
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

func parsePullRequestNumber(raw string) (int, bool) {
	number, err := strconv.Atoi(raw)
	return number, err == nil && number > 0
}

func (s *Server) loadPRSummarySnapshots(w http.ResponseWriter, r *http.Request, repo *store.Repository, number int) (*store.Ref, *store.Snapshot, *store.Ref, *store.Snapshot, bool) {
	ref, ok := s.loadPullRequestRef(w, r, repo, number)
	if !ok {
		return nil, nil, nil, nil, false
	}
	prSnapshot, err := s.queries.GetLatestSnapshotByRef(r.Context(), ref.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load pull request snapshot")
		return nil, nil, nil, nil, false
	}
	targetRef, targetSnapshot, ok := s.loadPRTargetSnapshot(w, r, ref)
	if !ok {
		return nil, nil, nil, nil, false
	}
	return ref, prSnapshot, targetRef, targetSnapshot, true
}

func (s *Server) loadPullRequestRef(w http.ResponseWriter, r *http.Request, repo *store.Repository, number int) (*store.Ref, bool) {
	forgeType := repo.Provider
	if provider, ok := s.forges[repo.Provider]; ok && provider != nil {
		forgeType = provider.ID()
	}
	refName := pullRequestRefName(forgeType, number)
	ref, err := s.queries.GetRefByRepoAndName(r.Context(), repo.ID, refName, store.RefTypePullRequest)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load pull request reference")
		return nil, false
	}
	if ref == nil {
		api.JSONError(w, http.StatusNotFound, "pull request not found")
		return nil, false
	}
	return ref, true
}

func (s *Server) loadPRTargetSnapshot(w http.ResponseWriter, r *http.Request, ref *store.Ref) (*store.Ref, *store.Snapshot, bool) {
	if ref.MergeTargetRefID == nil {
		return nil, nil, true
	}
	targetRef, err := s.queries.GetRefByID(r.Context(), *ref.MergeTargetRefID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load target reference")
		return nil, nil, false
	}
	if targetRef == nil {
		return nil, nil, true
	}
	targetSnapshot, err := s.queries.GetLatestSnapshotByRef(r.Context(), targetRef.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load target snapshot")
		return nil, nil, false
	}
	return targetRef, targetSnapshot, true
}

func (s *Server) newPRSummaryResponse(ref *store.Ref, targetRef *store.Ref, prSnapshot *store.Snapshot) *prSummaryResponse {
	var targetRefName *string
	if targetRef != nil {
		targetRefName = &targetRef.Name
	}
	responseRef := store.EnhancedRef{
		ID:                 ref.ID,
		RepoID:             ref.RepoID,
		Name:               ref.Name,
		RefType:            ref.RefType,
		ProviderID:         ref.ProviderID,
		MergeTargetRefID:   ref.MergeTargetRefID,
		MergeTargetRefName: targetRefName,
		LatestCommitSHA:    ref.LatestCommitSHA,
		PrState:            ref.PrState,
		PrTitle:            ref.PrTitle,
		PrSourceBranch:     ref.PrSourceBranch,
		PrMergedAt:         ref.PrMergedAt,
		PrClosedAt:         ref.PrClosedAt,
		CreatedAt:          ref.CreatedAt,
		UpdatedAt:          ref.UpdatedAt,
	}
	if prSnapshot != nil {
		responseRef.LatestSnapshotID = &prSnapshot.ID
		status := string(prSnapshot.Status)
		responseRef.LatestSnapshotStatus = &status
		responseRef.LatestSnapshotDate = &prSnapshot.CreatedAt
	}
	response := &prSummaryResponse{Ref: responseRef}
	if prSnapshot == nil {
		status := "no_data"
		response.Summary.SnapshotStatus = &status
	}
	return response
}

func (s *Server) populatePRSummary(w http.ResponseWriter, r *http.Request, response *prSummaryResponse, prSnapshot, targetSnapshot *store.Snapshot) bool {
	if prSnapshot != nil {
		response.PRSnapshotID = &prSnapshot.ID
		summary, err := s.buildRefSummary(r, prSnapshot)
		if err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to build pull request summary")
			return false
		}
		response.Summary = summary
	}
	if targetSnapshot != nil {
		response.TargetSnapshotID = &targetSnapshot.ID
	}
	return true
}

func (s *Server) populatePRSummaryDelta(w http.ResponseWriter, r *http.Request, response *prSummaryResponse, org *store.Organization, repo *store.Repository, prSnapshot, targetSnapshot *store.Snapshot) bool {
	if s.deltaSvc == nil || prSnapshot == nil || targetSnapshot == nil {
		return true
	}
	deltaResult, err := s.deltaSvc.ComputeDelta(r.Context(), prSnapshot.ID, targetSnapshot.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to compute pull request delta")
		return false
	}
	response.Delta = deltaResult
	weaknessGate := s.resolveRepoWeaknessGate(r.Context(), repo.Provider, repo.DefaultBranch, repo.ProviderID, repo.Name, repo.Slug, targetSnapshot.ID)
	gate, err := s.deltaSvc.EvaluateGatesWithConfig(r.Context(), repo.ID, org.ID, deltaResult, weaknessGate)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to evaluate pull request gate")
		return false
	}
	response.Gate = gate
	return true
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
	baseByKey := make(map[string]componentEntryResponse, len(baseRows))
	for _, row := range baseRows {
		entry := componentEntryResponse{
			Name:      row.Name,
			Version:   row.Version,
			Ecosystem: row.Ecosystem,
			Purl:      row.Purl,
			VulnCount: int(row.VulnCount),
		}
		baseByKey[componentDiffKey(entry)] = entry
	}

	headByKey := make(map[string]componentEntryResponse, len(headRows))
	for _, row := range headRows {
		entry := componentEntryResponse{
			Name:      row.Name,
			Version:   row.Version,
			Ecosystem: row.Ecosystem,
			Purl:      row.Purl,
			VulnCount: int(row.VulnCount),
		}
		headByKey[componentDiffKey(entry)] = entry
	}

	result := componentDiffResponse{}
	for key, entry := range headByKey {
		if _, ok := baseByKey[key]; ok {
			result.Unchanged++
			continue
		}
		result.Added = append(result.Added, entry)
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

	return result
}

func componentDiffKey(entry componentEntryResponse) string {
	if entry.Purl != "" {
		return entry.Purl
	}
	return entry.Ecosystem + ":" + entry.Name + "@" + entry.Version
}
