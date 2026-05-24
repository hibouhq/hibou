package server

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/lehibou/internal/api"
	"github.com/hibouhq/lehibou/internal/delta"
	"github.com/hibouhq/lehibou/internal/store"
)

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

	number, err := strconv.Atoi(chi.URLParam(r, "number"))
	if err != nil || number <= 0 {
		api.JSONError(w, http.StatusBadRequest, "invalid pull request number")
		return
	}

	refName := pullRequestRefName(repo.Provider, number)
	ref, err := s.queries.GetRefByRepoAndName(r.Context(), repo.ID, refName, store.RefTypePullRequest)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load pull request reference")
		return
	}
	if ref == nil {
		api.JSONError(w, http.StatusNotFound, "pull request not found")
		return
	}

	prSnapshot, err := s.queries.GetLatestSnapshotByRef(r.Context(), ref.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load pull request snapshot")
		return
	}

	var targetRef *store.Ref
	var targetSnapshot *store.Snapshot
	var targetRefName *string
	if ref.MergeTargetRefID != nil {
		targetRef, err = s.queries.GetRefByID(r.Context(), *ref.MergeTargetRefID)
		if err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to load target reference")
			return
		}
		if targetRef != nil {
			targetRefName = &targetRef.Name
			targetSnapshot, err = s.queries.GetLatestSnapshotByRef(r.Context(), targetRef.ID)
			if err != nil {
				api.JSONError(w, http.StatusInternalServerError, "failed to load target snapshot")
				return
			}
		}
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

	response := prSummaryResponse{Ref: responseRef}
	if prSnapshot == nil {
		status := "no_data"
		response.Summary.SnapshotStatus = &status
	}
	if prSnapshot != nil {
		response.PRSnapshotID = &prSnapshot.ID
		summary, err := s.buildRefSummary(r, prSnapshot)
		if err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to build pull request summary")
			return
		}
		response.Summary = summary
	}
	if targetSnapshot != nil {
		response.TargetSnapshotID = &targetSnapshot.ID
	}

	if s.deltaSvc != nil && prSnapshot != nil && targetSnapshot != nil {
		deltaResult, err := s.deltaSvc.ComputeDelta(r.Context(), prSnapshot.ID, targetSnapshot.ID)
		if err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to compute pull request delta")
			return
		}
		response.Delta = deltaResult

		weaknessGate := s.resolveRepoWeaknessGate(r.Context(), repo.Provider, repo.DefaultBranch, repo.ProviderID, repo.Name, repo.Slug, targetSnapshot.ID)
		gate, err := s.deltaSvc.EvaluateGatesWithConfig(r.Context(), repo.ID, org.ID, deltaResult, weaknessGate)
		if err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to evaluate pull request gate")
			return
		}
		response.Gate = gate
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

	refName := r.URL.Query().Get("ref")
	if refName == "" {
		refName = repo.DefaultBranch
	}
	if refName == "" {
		api.JSONError(w, http.StatusBadRequest, "ref is required")
		return
	}

	limit := 0
	if rawLimit := strings.TrimSpace(r.URL.Query().Get("limit")); rawLimit != "" {
		parsed, err := strconv.Atoi(rawLimit)
		if err != nil || parsed <= 0 {
			api.JSONError(w, http.StatusBadRequest, "invalid limit")
			return
		}
		if parsed > 365 {
			parsed = 365
		}
		limit = parsed
	}

	var since *time.Time
	if rawSince := strings.TrimSpace(r.URL.Query().Get("since")); rawSince != "" {
		parsed, err := time.Parse(time.RFC3339, rawSince)
		if err != nil {
			api.JSONError(w, http.StatusBadRequest, "invalid since")
			return
		}
		parsed = parsed.UTC()
		since = &parsed
	}
	if since == nil && limit == 0 {
		limit = 30
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

	snapshots, err := s.listTrendSnapshots(r, ref.ID, limit, since)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load trend snapshots")
		return
	}

	points := make([]trendPointResponse, 0, len(snapshots))
	for _, snapshot := range snapshots {
		findingRows, err := s.queries.CountFindingsBySeverity(r.Context(), snapshot.ID)
		if err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to load finding trends")
			return
		}
		vulnRows, err := s.queries.CountVulnsBySeverity(r.Context(), snapshot.ID)
		if err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to load vulnerability trends")
			return
		}
		componentCount, err := s.queries.CountComponentsBySnapshot(r.Context(), snapshot.ID)
		if err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to load component trends")
			return
		}

		findings := severityCounts{}
		for _, row := range findingRows {
			applySeverityCount(&findings, row.Severity, row.Count)
		}

		vulns := severityCounts{}
		for _, row := range vulnRows {
			applySeverityCount(&vulns, row.Severity, row.Count)
		}

		points = append(points, trendPointResponse{
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
		})
	}

	api.JSON(w, http.StatusOK, points)
}

func (s *Server) listTrendSnapshots(r *http.Request, refID uuid.UUID, limit int, since *time.Time) ([]store.Snapshot, error) {
	offset := 0
	capacity := limit
	if capacity <= 0 {
		capacity = 16
	}
	collected := make([]store.Snapshot, 0, capacity)

	for limit == 0 || len(collected) < limit {
		pageSize := limit
		if pageSize <= 0 || pageSize > 100 {
			pageSize = 100
		}
		if pageSize < 10 {
			pageSize = 10
		}
		snapshots, total, err := s.queries.ListSnapshotsByRef(r.Context(), refID, pageSize, offset)
		if err != nil {
			return nil, err
		}
		if len(snapshots) == 0 {
			break
		}

		stop := false
		for _, snapshot := range snapshots {
			if since != nil && snapshot.CreatedAt.Before(*since) {
				stop = true
				break
			}
			if snapshot.Status != store.SnapshotStatusComplete && snapshot.Status != store.SnapshotStatusActive {
				continue
			}
			collected = append(collected, snapshot)
			if limit > 0 && len(collected) == limit {
				break
			}
		}
		if stop {
			break
		}

		offset += len(snapshots)
		if offset >= total {
			break
		}
	}

	for left, right := 0, len(collected)-1; left < right; left, right = left+1, right-1 {
		collected[left], collected[right] = collected[right], collected[left]
	}

	return collected, nil
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

func applySeverityCount(counts *severityCounts, severity string, count int64) {
	switch severity {
	case "critical":
		counts.Critical = int(count)
	case "high":
		counts.High = int(count)
	case "medium":
		counts.Medium = int(count)
	case "low":
		counts.Low = int(count)
	case "info":
		counts.Info = int(count)
	}
}
