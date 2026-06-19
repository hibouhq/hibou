package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/filterquery"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type severityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

type advisoryResponse struct {
	ID            uuid.UUID `json:"id"`
	CanonicalID   string    `json:"canonical_id"`
	Title         string    `json:"title"`
	Severity      string    `json:"severity"`
	CvssScore     *float64  `json:"cvss_score,omitempty"`
	IsMalware     bool      `json:"is_malware"`
	MalwareType   *string   `json:"malware_type,omitempty"`
	Cwe           *string   `json:"cwe,omitempty"`
	CweName       *string   `json:"cwe_name,omitempty"`
	Summary       *string   `json:"summary,omitempty"`
	FixedVersions []string  `json:"fixed_versions,omitempty"`
	References    []string  `json:"references,omitempty"`
	Source        *string   `json:"source,omitempty"`
}

type componentWithVulnsResponse struct {
	ID              uuid.UUID          `json:"id"`
	Name            string             `json:"name"`
	Version         string             `json:"version"`
	Ecosystem       string             `json:"ecosystem"`
	Purl            string             `json:"purl"`
	VulnCount       int                `json:"vuln_count"`
	HighestSeverity *string            `json:"highest_severity,omitempty"`
	Advisories      []advisoryResponse `json:"advisories,omitempty"`
	Sources         []string           `json:"sources,omitempty"`
	FixedVersions   []string           `json:"fixed_versions,omitempty"`
}

type componentGraphNodeResponse struct {
	Ref       string `json:"ref"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
	VulnCount int    `json:"vuln_count"`
}

type componentGraphEdgeResponse struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"depends_on"`
}

type componentGraphResponse struct {
	RootRef string                       `json:"root_ref"`
	Nodes   []componentGraphNodeResponse `json:"nodes"`
	Edges   []componentGraphEdgeResponse `json:"edges"`
}

type refSummaryResponse struct {
	Vulnerabilities severityCounts `json:"vulnerabilities"`
	ComponentsTotal int            `json:"components_total"`
	SnapshotDate    *time.Time     `json:"snapshot_date,omitempty"`
	SnapshotStatus  *string        `json:"snapshot_status,omitempty"`
}

type repoDashboardEntryResponse struct {
	RepoID          *uuid.UUID     `json:"repo_id,omitempty"`
	RepoName        string         `json:"repo_name"`
	RepoSlug        string         `json:"repo_slug"`
	ProviderID      string         `json:"provider_id"`
	FullName        string         `json:"full_name"`
	Provider        string         `json:"provider"`
	Enrolled        bool           `json:"enrolled"`
	Status          string         `json:"status"`
	Vulnerabilities severityCounts `json:"vulnerabilities"`
	ComponentsTotal int            `json:"components_total"`
	LastScanned     *time.Time     `json:"last_scanned,omitempty"`
	Outdated        bool           `json:"outdated"`
}

type orgDashboardTotalsResponse struct {
	Vulnerabilities severityCounts `json:"vulnerabilities"`
	ComponentsTotal int            `json:"components_total"`
}

type snapshotFallbackLookup func(context.Context, uuid.UUID) (*store.Snapshot, error)

type orgDashboardResponse struct {
	Repos    []repoDashboardEntryResponse `json:"repos"`
	Totals   orgDashboardTotalsResponse   `json:"totals"`
	Coverage repoInventorySummary         `json:"coverage"`
}

func (s *Server) handleGetRefFindings(w http.ResponseWriter, r *http.Request) {
	_, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}

	snapshot, ok := s.resolveSnapshotForRequestWithFallback(r, w, repo, s.queries.GetLatestSnapshotWithVulnerabilitiesByRef)
	if !ok {
		return
	}
	if snapshot == nil {
		pagination := api.ParsePagination(r)
		api.JSONList(w, []store.Vulnerability{}, pagination.Page, pagination.PerPage, 0)
		return
	}

	pagination := api.ParsePagination(r)
	if q := strings.TrimSpace(r.URL.Query().Get("q")); q != "" {
		node, err := filterquery.Parse(q)
		if err != nil {
			api.JSONError(w, http.StatusBadRequest, "invalid filter query")
			return
		}

		sqlResult, err := filterquery.ToSQL(node, 2)
		if err != nil {
			api.JSONError(w, http.StatusBadRequest, "invalid filter query")
			return
		}

		vulnerabilities, total, err := s.queries.ListVulnerabilitiesBySnapshotDynamic(
			r.Context(),
			snapshot.ID,
			sqlResult.Where,
			sqlResult.Params,
			strings.TrimSpace(r.URL.Query().Get("sort")),
			pagination.PerPage,
			pagination.Offset,
		)
		if err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to list vulnerabilities")
			return
		}

		api.JSONList(w, vulnerabilities, pagination.Page, pagination.PerPage, total)
		return
	}

	vulnerabilities, total, err := s.queries.ListVulnerabilitiesBySnapshot(r.Context(), snapshot.ID, store.VulnerabilityListOptions{
		Types:      csvQueryFilterValues(r.URL.Query().Get("type")),
		Severities: csvQueryFilterValues(r.URL.Query().Get("severity")),
		Statuses:   csvQueryFilterValues(r.URL.Query().Get("status")),
		Scanners:   mergeCSVFilters(csvQueryFilterValues(r.URL.Query().Get("scanner")), csvQueryFilterValues(r.URL.Query().Get("tool"))),
		Languages:  csvQueryFilterValues(r.URL.Query().Get("language")),
		FileQuery:  strings.TrimSpace(r.URL.Query().Get("file")),
		Search:     strings.TrimSpace(r.URL.Query().Get("search")),
		Sort:       strings.TrimSpace(r.URL.Query().Get("sort")),
		Limit:      pagination.PerPage,
		Offset:     pagination.Offset,
	})
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list vulnerabilities")
		return
	}

	api.JSONList(w, vulnerabilities, pagination.Page, pagination.PerPage, total)
}

func parseCSVQueryFilter(raw string) map[string]struct{} {
	values := make(map[string]struct{})

	for _, fragment := range strings.Split(raw, ",") {
		normalized := strings.ToLower(strings.TrimSpace(fragment))
		if normalized == "" {
			continue
		}
		values[normalized] = struct{}{}
	}

	if len(values) == 0 {
		return nil
	}

	return values
}

func csvQueryFilterValues(raw string) []string {
	filter := parseCSVQueryFilter(raw)
	if len(filter) == 0 {
		return nil
	}
	values := make([]string, 0, len(filter))
	for value := range filter {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func mergeCSVFilters(filters ...[]string) []string {
	if len(filters) == 0 {
		return nil
	}

	merged := make(map[string]struct{})
	for _, values := range filters {
		for _, value := range values {
			normalized := strings.ToLower(strings.TrimSpace(value))
			if normalized == "" {
				continue
			}
			merged[normalized] = struct{}{}
		}
	}

	if len(merged) == 0 {
		return nil
	}

	values := make([]string, 0, len(merged))
	for value := range merged {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func (s *Server) handleGetRefComponents(w http.ResponseWriter, r *http.Request) {
	_, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}

	snapshot, ok := s.resolveSnapshotForRequestWithFallback(r, w, repo, s.queries.GetLatestSnapshotWithComponentsByRef)
	if !ok {
		return
	}
	if snapshot == nil {
		api.JSON(w, http.StatusOK, []componentWithVulnsResponse{})
		return
	}

	components, err := s.queries.ListComponentsBySnapshot(r.Context(), snapshot.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list components")
		return
	}
	vulnerabilities, err := s.queries.ListAllVulnerabilitiesBySnapshot(r.Context(), snapshot.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list vulnerability matches")
		return
	}

	responses, err := s.buildComponentResponses(r, components, vulnerabilities)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load advisories")
		return
	}

	api.JSON(w, http.StatusOK, responses)
}

func (s *Server) handleGetRefComponentGraph(w http.ResponseWriter, r *http.Request) {
	_, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}

	snapshot, ok := s.resolveSnapshotForRequestWithFallback(r, w, repo, s.queries.GetLatestSnapshotWithComponentsByRef)
	if !ok {
		return
	}
	if snapshot == nil {
		api.JSON(w, http.StatusOK, componentGraphResponse{RootRef: "", Nodes: []componentGraphNodeResponse{}, Edges: []componentGraphEdgeResponse{}})
		return
	}

	components, err := s.queries.ListComponentsBySnapshot(r.Context(), snapshot.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list components")
		return
	}
	vulnerabilities, err := s.queries.ListAllVulnerabilitiesBySnapshot(r.Context(), snapshot.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list vulnerability matches")
		return
	}
	edges, err := s.queries.ListComponentDependencyEdgesBySnapshot(r.Context(), snapshot.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list component dependencies")
		return
	}
	declaredRootRef, err := s.queries.GetSnapshotDependencyRoot(r.Context(), snapshot.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load component dependency root")
		return
	}

	response := buildComponentGraphResponse(components, vulnerabilities, edges, declaredRootRef)
	api.JSON(w, http.StatusOK, response)
}

func (s *Server) handleGetRefSummary(w http.ResponseWriter, r *http.Request) {
	_, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}

	snapshot, ok := s.resolveSnapshotForRequestWithFallback(r, w, repo,
		s.queries.GetLatestSnapshotWithComponentsByRef,
		s.queries.GetLatestSnapshotWithVulnerabilitiesByRef,
	)
	if !ok {
		return
	}
	if snapshot == nil {
		api.JSON(w, http.StatusOK, refSummaryResponse{})
		return
	}

	summary, err := s.buildRefSummary(r, snapshot)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load reference summary")
		return
	}

	api.JSON(w, http.StatusOK, summary)
}

func (s *Server) buildRefSummary(r *http.Request, snapshot *store.Snapshot) (refSummaryResponse, error) {
	vulnerabilities, err := s.queries.ListAllVulnerabilitiesBySnapshot(r.Context(), snapshot.ID)
	if err != nil {
		return refSummaryResponse{}, err
	}
	components, err := s.queries.ListComponentsBySnapshot(r.Context(), snapshot.ID)
	if err != nil {
		return refSummaryResponse{}, err
	}

	status := string(snapshot.Status)
	createdAt := snapshot.CreatedAt
	return refSummaryResponse{
		Vulnerabilities: countVulnerabilitySeverities(vulnerabilities),
		ComponentsTotal: len(components),
		SnapshotDate:    &createdAt,
		SnapshotStatus:  &status,
	}, nil
}

func (s *Server) handleGetOrgDashboard(w http.ResponseWriter, r *http.Request) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok {
		return
	}

	repos, coverage, err := s.listRepositoryInventory(r, org)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list repositories")
		return
	}

	response, err := s.buildOrgDashboardResponse(r, repos, coverage)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load dashboard data")
		return
	}

	sort.SliceStable(response.Repos, func(i, j int) bool {
		left := response.Repos[i]
		right := response.Repos[j]
		leftRisk := left.Vulnerabilities.Critical + left.Vulnerabilities.High
		rightRisk := right.Vulnerabilities.Critical + right.Vulnerabilities.High
		if leftRisk == rightRisk {
			return left.FullName < right.FullName
		}
		return leftRisk > rightRisk
	})

	api.JSON(w, http.StatusOK, response)
}

func (s *Server) buildOrgDashboardResponse(r *http.Request, repos []repositoryInventoryEntry, coverage repoInventorySummary) (orgDashboardResponse, error) {
	response := orgDashboardResponse{
		Repos:    make([]repoDashboardEntryResponse, 0, len(repos)),
		Coverage: coverage,
	}

	for _, repo := range repos {
		entry, err := s.buildRepoDashboardEntry(r, repo)
		if err != nil {
			return orgDashboardResponse{}, err
		}
		addSeverityCounts(&response.Totals.Vulnerabilities, entry.Vulnerabilities)
		response.Totals.ComponentsTotal += entry.ComponentsTotal
		response.Repos = append(response.Repos, entry)
	}

	return response, nil
}

func (s *Server) buildRepoDashboardEntry(r *http.Request, repo repositoryInventoryEntry) (repoDashboardEntryResponse, error) {
	entry := repoDashboardEntryResponse{
		RepoID:      repo.ID,
		RepoName:    repo.Name,
		RepoSlug:    repo.Slug,
		ProviderID:  repo.ProviderID,
		FullName:    repo.FullName,
		Provider:    repo.Provider,
		Enrolled:    repo.Enrolled,
		Status:      string(repo.Status),
		LastScanned: repo.LastScanned,
		Outdated:    repo.Outdated,
	}

	if !repo.Enrolled || repo.ID == nil {
		return entry, nil
	}

	repository, err := s.queries.GetRepositoryByID(r.Context(), *repo.ID)
	if err != nil || repository == nil {
		return entry, err
	}

	_, snapshot, err := s.resolveSnapshotForRepo(r, repository, repository.DefaultBranch)
	if err != nil || snapshot == nil {
		return entry, err
	}

	vulnerabilities, err := s.queries.ListAllVulnerabilitiesBySnapshot(r.Context(), snapshot.ID)
	if err != nil {
		return entry, err
	}
	components, err := s.queries.ListComponentsBySnapshot(r.Context(), snapshot.ID)
	if err != nil {
		return entry, err
	}

	entry.Vulnerabilities = countVulnerabilitySeverities(vulnerabilities)
	entry.ComponentsTotal = len(components)
	return entry, nil
}

func (s *Server) loadAuthorizedOrg(r *http.Request, w http.ResponseWriter) (*store.Organization, bool) {
	user := UserFromContext(r.Context())
	if user == nil {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return nil, false
	}

	org, err := s.resolveOrg(r)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load organization")
		return nil, false
	}
	if org == nil {
		api.JSONError(w, http.StatusNotFound, "organization not found")
		return nil, false
	}

	role, err := s.queries.GetOrgMemberRole(r.Context(), org.ID, user.ID)
	if err != nil || role == "" {
		api.JSONError(w, http.StatusNotFound, "organization not found")
		return nil, false
	}

	return org, true
}

func (s *Server) loadAuthorizedRepo(r *http.Request, w http.ResponseWriter) (*store.Organization, *store.Repository, bool) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok {
		return nil, nil, false
	}

	repo, err := s.queries.GetRepositoryBySlug(r.Context(), org.ID, chi.URLParam(r, "repoSlug"))
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load repository")
		return nil, nil, false
	}
	if repo == nil {
		api.JSONError(w, http.StatusNotFound, "repository not found")
		return nil, nil, false
	}

	return org, repo, true
}

func (s *Server) loadSnapshotForRepoByID(r *http.Request, repo *store.Repository, snapshotID string) (*store.Snapshot, int, string) {
	parsed, err := uuid.Parse(snapshotID)
	if err != nil {
		return nil, http.StatusBadRequest, "invalid snapshot"
	}

	snapshot, err := s.queries.GetSnapshotByID(r.Context(), parsed)
	if err != nil {
		return nil, http.StatusInternalServerError, "failed to load snapshot"
	}
	if snapshot == nil {
		return nil, http.StatusNotFound, "snapshot not found"
	}

	ref, err := s.queries.GetRefByID(r.Context(), snapshot.RefID)
	if err != nil {
		return nil, http.StatusInternalServerError, "failed to load snapshot reference"
	}
	if ref == nil || ref.RepoID != repo.ID {
		return nil, http.StatusForbidden, "snapshot does not belong to this repository"
	}

	return snapshot, 0, ""
}

func resolveRequestedRefName(r *http.Request, repo *store.Repository) string {
	refName := strings.TrimSpace(r.URL.Query().Get("ref"))
	if refName == "" {
		return repo.DefaultBranch
	}
	return refName
}

func (s *Server) resolveSnapshotForRequest(r *http.Request, w http.ResponseWriter, repo *store.Repository) (*store.Snapshot, bool) {
	return s.resolveSnapshotForRequestWithFallback(r, w, repo, s.queries.GetLatestNonPurgedSnapshotByRef)
}

func (s *Server) resolveSnapshotForRequestWithFallback(r *http.Request, w http.ResponseWriter, repo *store.Repository, fallbacks ...snapshotFallbackLookup) (*store.Snapshot, bool) {
	snapshotID := strings.TrimSpace(r.URL.Query().Get("snapshot"))
	if snapshotID != "" {
		snapshot, status, message := s.loadSnapshotForRepoByID(r, repo, snapshotID)
		if status != 0 {
			api.JSONError(w, status, message)
			return nil, false
		}
		return snapshot, true
	}

	refName := resolveRequestedRefName(r, repo)
	if refName == "" {
		api.JSONError(w, http.StatusBadRequest, "ref is required")
		return nil, false
	}

	var err error
	ref, snapshot, err := s.resolveSnapshotForRepoWithFallback(r, repo, refName, fallbacks...)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load repository reference")
		return nil, false
	}
	if ref == nil {
		api.JSONError(w, http.StatusNotFound, "ref not found")
		return nil, false
	}

	return snapshot, true
}

func (s *Server) resolveSnapshotForRepo(r *http.Request, repo *store.Repository, refName string) (*store.Ref, *store.Snapshot, error) {
	return s.resolveSnapshotForRepoWithFallback(r, repo, refName, s.queries.GetLatestNonPurgedSnapshotByRef)
}

func (s *Server) resolveSnapshotForRepoWithFallback(r *http.Request, repo *store.Repository, refName string, fallbacks ...snapshotFallbackLookup) (*store.Ref, *store.Snapshot, error) {
	ref, err := s.resolveRefForRepo(r, repo, refName)
	if err != nil || ref == nil {
		return ref, nil, err
	}

	snapshot, err := s.resolveDefaultSnapshotForDataView(r.Context(), ref.ID, fallbacks...)
	if err != nil {
		return ref, nil, err
	}

	return ref, snapshot, nil
}

func (s *Server) resolveDefaultSnapshotForDataView(ctx context.Context, refID uuid.UUID, fallbacks ...snapshotFallbackLookup) (*store.Snapshot, error) {
	snapshot, err := s.queries.GetLatestCompleteSnapshotByRef(ctx, refID)
	if err != nil {
		return nil, err
	}
	if snapshot != nil {
		return snapshot, nil
	}

	for _, fallback := range fallbacks {
		snapshot, err = fallback(ctx, refID)
		if err != nil {
			return nil, err
		}
		if snapshot != nil {
			return snapshot, nil
		}
	}

	snapshot, err = s.queries.GetLatestSnapshotWithAnalysisDataByRef(ctx, refID)
	if err != nil {
		return nil, err
	}
	if snapshot != nil {
		return snapshot, nil
	}

	return s.queries.GetLatestNonPurgedSnapshotByRef(ctx, refID)
}

func (s *Server) lookupRepoRef(r *http.Request, repo *store.Repository, name string, refType store.RefType) (*store.Ref, error) {
	if name == "" {
		return nil, nil
	}
	return s.queries.GetRefByRepoAndName(r.Context(), repo.ID, name, refType)
}

func (s *Server) resolveRefByCandidates(r *http.Request, repo *store.Repository, refType store.RefType, names ...string) (*store.Ref, error) {
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		ref, err := s.lookupRepoRef(r, repo, name, refType)
		if err != nil {
			return nil, err
		}
		if ref != nil {
			return ref, nil
		}
	}
	return nil, nil
}

func (s *Server) resolveGenericRefForRepo(r *http.Request, repo *store.Repository, requestedName, normalizedName string) (*store.Ref, error) {
	ref, err := s.resolveRefByCandidates(r, repo, store.RefTypeBranch, normalizedName, requestedName)
	if err != nil || ref != nil {
		return ref, err
	}
	ref, err = s.resolveRefByCandidates(r, repo, store.RefTypeTag, normalizedName, requestedName)
	if err != nil || ref != nil {
		return ref, err
	}
	return s.resolveRefByCandidates(r, repo, store.RefTypePullRequest, requestedName, normalizedName)
}

func (s *Server) resolveRefForRepo(r *http.Request, repo *store.Repository, refName string) (*store.Ref, error) {
	requestedName := strings.TrimSpace(refName)
	normalizedName := normalizeStoredRefName(requestedName)

	switch {
	case strings.HasPrefix(requestedName, "refs/heads/"):
		return s.resolveRefByCandidates(r, repo, store.RefTypeBranch, normalizedName, requestedName)
	case strings.HasPrefix(requestedName, "refs/tags/"):
		return s.resolveRefByCandidates(r, repo, store.RefTypeTag, normalizedName, requestedName)
	default:
		return s.resolveGenericRefForRepo(r, repo, requestedName, normalizedName)
	}
}

func (s *Server) buildComponentResponses(r *http.Request, components []dbgen.Component, vulnerabilities []store.Vulnerability) ([]componentWithVulnsResponse, error) {
	countedVulns, err := s.loadCountedVulns(r, vulnerabilities)
	if err != nil {
		return nil, err
	}

	vulnsByComponent := make(map[uuid.UUID][]countedVuln)
	for _, item := range countedVulns {
		vulnsByComponent[item.ComponentID] = append(vulnsByComponent[item.ComponentID], item)
	}

	responses := make([]componentWithVulnsResponse, 0, len(components))
	for _, component := range components {
		countedAdvisories := vulnsByComponent[component.ID]
		response := componentWithVulnsResponse{
			ID:        component.ID,
			Name:      component.Name,
			Version:   component.Version,
			Ecosystem: component.Ecosystem,
			Purl:      component.Purl,
		}
		if len(countedAdvisories) > 0 {
			response.Advisories = make([]advisoryResponse, 0, len(countedAdvisories))
			response.VulnCount = len(countedAdvisories)
			advisories := make([]dbgen.Advisory, 0, len(countedAdvisories))
			componentSources := make([]string, 0, len(countedAdvisories))
			componentFixedVersions := make([]string, 0, len(countedAdvisories))
			for _, countedAdvisory := range countedAdvisories {
				advisories = append(advisories, countedAdvisory.Advisory)
				response.Advisories = append(response.Advisories, advisoryToResponse(countedAdvisory.Advisory, countedAdvisory.Enrichment))
				componentSources = append(componentSources, countedAdvisory.Enrichment.Sources...)
				componentFixedVersions = append(componentFixedVersions, countedAdvisory.Enrichment.FixedVersions...)
			}
			response.Sources = sortedUniqueNonEmptyStrings(componentSources)
			response.FixedVersions = sortedUniqueNonEmptyStrings(componentFixedVersions)
			highest := highestAdvisorySeverity(advisories)
			if highest != "" {
				response.HighestSeverity = &highest
			}
		}
		responses = append(responses, response)
	}

	sort.SliceStable(responses, func(i, j int) bool {
		left := responses[i]
		right := responses[j]
		if left.VulnCount == right.VulnCount {
			return left.Name < right.Name
		}
		return left.VulnCount > right.VulnCount
	})

	return responses, nil
}

func buildComponentGraphResponse(components []dbgen.Component, vulnerabilities []store.Vulnerability, dependencyEdges []store.ListComponentDependencyEdgesBySnapshotRow, declaredRootRef *string) componentGraphResponse {
	vulnCounts := countCountedVulnerabilitiesByComponent(vulnerabilities)
	nodes := make([]componentGraphNodeResponse, 0, len(components))
	for _, component := range components {
		nodes = append(nodes, componentGraphNodeResponse{
			Ref:       component.Purl,
			Name:      component.Name,
			Version:   component.Version,
			Ecosystem: component.Ecosystem,
			VulnCount: vulnCounts[component.ID],
		})
	}
	sort.SliceStable(nodes, func(i, j int) bool {
		return nodes[i].Ref < nodes[j].Ref
	})

	dependsOnByRef := make(map[string][]string)
	inDegree := make(map[string]int)
	adjacency := make(map[string][]string)
	for _, edge := range dependencyEdges {
		dependsOnByRef[edge.Ref] = append(dependsOnByRef[edge.Ref], edge.DependsOn)
		adjacency[edge.Ref] = append(adjacency[edge.Ref], edge.DependsOn)
		inDegree[edge.DependsOn]++
		if _, ok := inDegree[edge.Ref]; !ok {
			inDegree[edge.Ref] = inDegree[edge.Ref]
		}
	}
	graphEdges := make([]componentGraphEdgeResponse, 0, len(dependsOnByRef))
	for ref, dependsOn := range dependsOnByRef {
		graphEdges = append(graphEdges, componentGraphEdgeResponse{Ref: ref, DependsOn: sortedUniqueNonEmptyStrings(dependsOn)})
	}
	sort.SliceStable(graphEdges, func(i, j int) bool {
		return graphEdges[i].Ref < graphEdges[j].Ref
	})
	rootRef := ""
	// Prefer the SBOM-declared root when persisted; fall back to a deterministic graph heuristic only when absent.
	if declaredRootRef != nil {
		rootRef = *declaredRootRef
	} else {
		rootRef = deriveComponentGraphRootRef(adjacency, inDegree)
	}

	return componentGraphResponse{
		RootRef: rootRef,
		Nodes:   nodes,
		Edges:   graphEdges,
	}
}

type countedVuln struct {
	ComponentID uuid.UUID
	Advisory    dbgen.Advisory
	Enrichment  advisoryEnrichment
}

type countedVulnerabilityPair struct {
	ComponentID uuid.UUID
	AdvisoryID  uuid.UUID
}

type advisoryEnrichment struct {
	FixedVersions []string
	References    []string
	Sources       []string
	Source        *string
}

func (s *Server) loadCountedVulns(r *http.Request, vulnerabilities []store.Vulnerability) ([]countedVuln, error) {
	advisoryIDs := collectCountedAdvisoryIDs(vulnerabilities)
	if len(advisoryIDs) == 0 {
		return nil, nil
	}

	advisoryByID, err := s.loadAdvisoryMapForCountedVulns(r, advisoryIDs)
	if err != nil {
		return nil, err
	}
	enrichmentByID, err := s.loadAdvisoryEnrichment(r.Context(), advisoryIDs, advisoryByID)
	if err != nil {
		return nil, err
	}

	pairs := collectCountedVulnerabilityPairs(vulnerabilities)
	counted := make([]countedVuln, 0, len(pairs))
	for _, pair := range pairs {
		advisory, ok := advisoryByID[pair.AdvisoryID]
		if !ok {
			continue
		}
		counted = append(counted, countedVuln{
			ComponentID: pair.ComponentID,
			Advisory:    advisory,
			Enrichment:  enrichmentByID[pair.AdvisoryID],
		})
	}

	return counted, nil
}

func collectCountedVulnerabilityPairs(vulnerabilities []store.Vulnerability) []countedVulnerabilityPair {
	pairs := make([]countedVulnerabilityPair, 0, len(vulnerabilities))
	seenPairs := make(map[string]struct{})
	for _, vulnerability := range vulnerabilities {
		if !shouldCountVulnerability(vulnerability) {
			continue
		}
		pair := countedVulnerabilityPair{
			ComponentID: *vulnerability.ComponentID,
			AdvisoryID:  *vulnerability.AdvisoryID,
		}
		key := countedVulnPairKey(pair.ComponentID, pair.AdvisoryID)
		if _, ok := seenPairs[key]; ok {
			continue
		}
		seenPairs[key] = struct{}{}
		pairs = append(pairs, pair)
	}
	return pairs
}

func countCountedVulnerabilitiesByComponent(vulnerabilities []store.Vulnerability) map[uuid.UUID]int {
	pairs := collectCountedVulnerabilityPairs(vulnerabilities)
	counts := make(map[uuid.UUID]int, len(pairs))
	for _, pair := range pairs {
		counts[pair.ComponentID]++
	}
	return counts
}

// When the SBOM root component bom-ref is not persisted, derive a stable root from the graph:
// choose an in-degree-zero node, prefer the one with the largest reachable descendant set,
// and tie-break lexicographically by purl. Flat graphs intentionally have no root_ref.
func deriveComponentGraphRootRef(adjacency map[string][]string, inDegree map[string]int) string {
	if len(adjacency) == 0 {
		return ""
	}
	candidates := make([]string, 0, len(adjacency))
	for ref := range adjacency {
		if len(adjacency[ref]) == 0 {
			continue
		}
		if inDegree[ref] == 0 {
			candidates = append(candidates, ref)
		}
	}
	if len(candidates) == 0 {
		return ""
	}
	sort.Strings(candidates)
	best := candidates[0]
	bestReachable := reachableDescendantCount(best, adjacency)
	for _, candidate := range candidates[1:] {
		reachable := reachableDescendantCount(candidate, adjacency)
		if reachable > bestReachable {
			best = candidate
			bestReachable = reachable
		}
	}
	return best
}

func reachableDescendantCount(root string, adjacency map[string][]string) int {
	seen := map[string]struct{}{root: {}}
	stack := append([]string(nil), adjacency[root]...)
	count := 0
	for len(stack) > 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if _, ok := seen[current]; ok {
			continue
		}
		seen[current] = struct{}{}
		count++
		stack = append(stack, adjacency[current]...)
	}
	return count
}

func (s *Server) loadAdvisoryEnrichment(ctx context.Context, advisoryIDs []uuid.UUID, advisoryByID map[uuid.UUID]dbgen.Advisory) (map[uuid.UUID]advisoryEnrichment, error) {
	affectedRanges, err := s.queries.ListAffectedRangesByAdvisoryIDs(ctx, advisoryIDs)
	if err != nil {
		return nil, err
	}
	sources, err := s.queries.ListSourcesByAdvisoryIDs(ctx, advisoryIDs)
	if err != nil {
		return nil, err
	}
	aliases, err := s.queries.ListAliasesByAdvisoryIDs(ctx, advisoryIDs)
	if err != nil {
		return nil, err
	}

	rangesByAdvisory := make(map[uuid.UUID][]dbgen.AffectedRange, len(advisoryIDs))
	for _, affectedRange := range affectedRanges {
		rangesByAdvisory[affectedRange.AdvisoryID] = append(rangesByAdvisory[affectedRange.AdvisoryID], affectedRange)
	}
	sourcesByAdvisory := make(map[uuid.UUID][]dbgen.AdvisorySource, len(advisoryIDs))
	for _, source := range sources {
		sourcesByAdvisory[source.AdvisoryID] = append(sourcesByAdvisory[source.AdvisoryID], source)
	}
	aliasesByAdvisory := make(map[uuid.UUID][]dbgen.AdvisoryAlias, len(advisoryIDs))
	for _, alias := range aliases {
		aliasesByAdvisory[alias.AdvisoryID] = append(aliasesByAdvisory[alias.AdvisoryID], alias)
	}

	enrichmentByID := make(map[uuid.UUID]advisoryEnrichment, len(advisoryIDs))
	for advisoryID, advisory := range advisoryByID {
		normalizedSources := collectNormalizedProviders(sourcesByAdvisory[advisoryID])
		enrichmentByID[advisoryID] = advisoryEnrichment{
			FixedVersions: collectAffectedRangeFixedVersions(rangesByAdvisory[advisoryID]),
			References:    collectAdvisoryReferences(advisory, aliasesByAdvisory[advisoryID], sourcesByAdvisory[advisoryID]),
			Sources:       normalizedSources,
			Source:        selectPrimaryProvider(normalizedSources),
		}
	}

	return enrichmentByID, nil
}

func collectCountedAdvisoryIDs(vulnerabilities []store.Vulnerability) []uuid.UUID {
	advisoryIDs := make([]uuid.UUID, 0, len(vulnerabilities))
	seenAdvisories := make(map[uuid.UUID]struct{})
	for _, vulnerability := range vulnerabilities {
		if !shouldCountVulnerability(vulnerability) {
			continue
		}
		if _, ok := seenAdvisories[*vulnerability.AdvisoryID]; ok {
			continue
		}
		seenAdvisories[*vulnerability.AdvisoryID] = struct{}{}
		advisoryIDs = append(advisoryIDs, *vulnerability.AdvisoryID)
	}
	return advisoryIDs
}

func (s *Server) loadAdvisoryMapForCountedVulns(r *http.Request, advisoryIDs []uuid.UUID) (map[uuid.UUID]dbgen.Advisory, error) {
	advisories, err := s.queries.GetAdvisoriesByIDs(r.Context(), advisoryIDs)
	if err != nil {
		return nil, err
	}
	advisoryByID := make(map[uuid.UUID]dbgen.Advisory, len(advisories))
	for _, advisory := range advisories {
		advisoryByID[advisory.ID] = advisory
	}
	return advisoryByID, nil
}

func shouldCountVulnerability(vulnerability store.Vulnerability) bool {
	// TODO(vex): Query vex_statements for effective vulnerability status.
	if vulnerability.Type != "dependency" && vulnerability.Type != "malware" {
		return false
	}
	if vulnerability.Status == "resolved" || vulnerability.Status == "dismissed" {
		return false
	}
	return vulnerability.ComponentID != nil && vulnerability.AdvisoryID != nil
}

func countedVulnPairKey(componentID, advisoryID uuid.UUID) string {
	return componentID.String() + ":" + advisoryID.String()
}

func (s *Server) listAllReposByOrg(r *http.Request, orgID uuid.UUID) ([]store.Repository, error) {
	page := 1
	all := make([]store.Repository, 0)
	for {
		repos, total, err := s.queries.ListRepositoriesByOrg(r.Context(), orgID, api.MaxPerPage, (page-1)*api.MaxPerPage)
		if err != nil {
			return nil, err
		}
		all = append(all, repos...)
		if len(all) >= total || len(repos) == 0 {
			break
		}
		page++
	}
	return all, nil
}

func advisoryToResponse(advisory dbgen.Advisory, enrichment advisoryEnrichment) advisoryResponse {
	var cvssScore *float64
	if advisory.CvssScore.Valid {
		if parsed, err := strconv.ParseFloat(advisory.CvssScore.String, 64); err == nil {
			cvssScore = &parsed
		}
	}
	var malwareType *string
	if advisory.MalwareType.Valid {
		value := string(advisory.MalwareType.MalwareType)
		malwareType = &value
	}
	var cwe *string
	for _, candidate := range advisory.CweIds {
		if value := strings.TrimSpace(candidate); value != "" {
			cwe = &value
			break
		}
	}
	var summary *string
	if value := strings.TrimSpace(advisory.Description); value != "" {
		summary = &value
	}
	return advisoryResponse{
		ID:            advisory.ID,
		CanonicalID:   advisory.CanonicalID,
		Title:         advisory.Title,
		Severity:      string(advisory.Severity),
		CvssScore:     cvssScore,
		IsMalware:     advisory.IsMalware,
		MalwareType:   malwareType,
		Cwe:           cwe,
		Summary:       summary,
		FixedVersions: enrichment.FixedVersions,
		References:    enrichment.References,
		Source:        enrichment.Source,
	}
}

func collectAffectedRangeFixedVersions(affectedRanges []dbgen.AffectedRange) []string {
	values := make([]string, 0, len(affectedRanges))
	for _, affectedRange := range affectedRanges {
		values = append(values, affectedRange.Fixed)
	}
	return sortedUniqueNonEmptyStrings(values)
}

func collectNormalizedProviders(sources []dbgen.AdvisorySource) []string {
	values := make([]string, 0, len(sources))
	for _, source := range sources {
		values = append(values, strings.ToLower(strings.TrimSpace(source.Provider)))
	}
	return sortedUniqueNonEmptyStrings(values)
}

func collectAdvisoryReferences(advisory dbgen.Advisory, aliases []dbgen.AdvisoryAlias, sources []dbgen.AdvisorySource) []string {
	values := make([]string, 0, len(sources))
	for _, source := range sources {
		values = append(values, extractReferenceURLsFromRawData(source.RawData)...)
	}
	values = sortedUniqueNonEmptyStrings(values)
	if len(values) > 0 {
		return values
	}
	if referenceURL, ok := deriveAdvisoryReferenceURL(advisory.CanonicalID); ok {
		values = append(values, referenceURL)
	}
	for _, alias := range aliases {
		if referenceURL, ok := deriveAdvisoryReferenceURL(alias.Alias); ok {
			values = append(values, referenceURL)
		}
	}
	return sortedUniqueNonEmptyStrings(values)
}

func extractReferenceURLsFromRawData(rawData json.RawMessage) []string {
	if len(rawData) == 0 {
		return nil
	}
	var payload struct {
		References []struct {
			URL string `json:"url"`
		} `json:"references"`
	}
	if err := json.Unmarshal(rawData, &payload); err != nil {
		return nil
	}
	values := make([]string, 0, len(payload.References))
	for _, reference := range payload.References {
		candidate := strings.TrimSpace(reference.URL)
		if candidate == "" || !isWellFormedURL(candidate) {
			continue
		}
		values = append(values, candidate)
	}
	return sortedUniqueNonEmptyStrings(values)
}

func deriveAdvisoryReferenceURL(identifier string) (string, bool) {
	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		return "", false
	}
	upperIdentifier := strings.ToUpper(identifier)
	switch {
	case strings.HasPrefix(upperIdentifier, "CVE-"):
		return "https://nvd.nist.gov/vuln/detail/" + upperIdentifier, true
	case strings.HasPrefix(upperIdentifier, "GHSA-"):
		return "https://github.com/advisories/" + upperIdentifier, true
	case strings.HasPrefix(upperIdentifier, "PYSEC-"), strings.HasPrefix(upperIdentifier, "GO-"), strings.HasPrefix(upperIdentifier, "RUSTSEC-"), strings.HasPrefix(upperIdentifier, "OSV-"), strings.HasPrefix(upperIdentifier, "GSD-"):
		return "https://osv.dev/vulnerability/" + upperIdentifier, true
	default:
		return "", false
	}
}

func selectPrimaryProvider(providers []string) *string {
	if len(providers) == 0 {
		return nil
	}
	priority := map[string]int{
		"ghsa": 0,
		"nvd":  1,
		"osv":  2,
	}
	sortedProviders := append([]string(nil), providers...)
	sort.SliceStable(sortedProviders, func(i, j int) bool {
		leftPriority, leftKnown := priority[sortedProviders[i]]
		rightPriority, rightKnown := priority[sortedProviders[j]]
		switch {
		case leftKnown && rightKnown && leftPriority != rightPriority:
			return leftPriority < rightPriority
		case leftKnown != rightKnown:
			return leftKnown
		default:
			return sortedProviders[i] < sortedProviders[j]
		}
	})
	return &sortedProviders[0]
}

func sortedUniqueNonEmptyStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	unique := make([]string, 0, len(values))
	for _, value := range values {
		normalized := strings.TrimSpace(value)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		unique = append(unique, normalized)
	}
	if len(unique) == 0 {
		return nil
	}
	sort.Strings(unique)
	return unique
}

func isWellFormedURL(candidate string) bool {
	parsed, err := url.ParseRequestURI(candidate)
	if err != nil {
		return false
	}
	return parsed.Scheme != "" && parsed.Host != ""
}

func paginateSlice[T any](items []T, offset, limit int) []T {
	if offset >= len(items) {
		return []T{}
	}
	end := offset + limit
	if end > len(items) {
		end = len(items)
	}
	return items[offset:end]
}

func countVulnerabilitySeverities(vulnerabilities []store.Vulnerability) severityCounts {
	counts := severityCounts{}
	for _, vulnerability := range vulnerabilities {
		incrementSeverity(&counts, string(vulnerability.Severity))
	}
	return counts
}

func addSeverityCounts(dst *severityCounts, src severityCounts) {
	dst.Critical += src.Critical
	dst.High += src.High
	dst.Medium += src.Medium
	dst.Low += src.Low
	dst.Info += src.Info
}

func highestAdvisorySeverity(advisories []dbgen.Advisory) string {
	highest := ""
	bestRank := -1
	for _, advisory := range advisories {
		rank := severityRank(string(advisory.Severity))
		if rank > bestRank {
			bestRank = rank
			highest = string(advisory.Severity)
		}
	}
	return highest
}

func incrementSeverity(counts *severityCounts, severity string) {
	switch strings.ToLower(severity) {
	case "critical":
		counts.Critical++
	case "high":
		counts.High++
	case "medium":
		counts.Medium++
	case "low":
		counts.Low++
	default:
		counts.Info++
	}
}

func severityRank(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
