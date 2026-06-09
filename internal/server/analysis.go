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
	"github.com/hibouhq/lehibou/internal/filterquery"
	"github.com/hibouhq/lehibou/internal/store"
	"github.com/hibouhq/lehibou/internal/store/dbgen"
)

type severityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

type advisoryResponse struct {
	ID          uuid.UUID `json:"id"`
	CanonicalID string    `json:"canonical_id"`
	Title       string    `json:"title"`
	Severity    string    `json:"severity"`
	CvssScore   *float64  `json:"cvss_score,omitempty"`
	IsMalware   bool      `json:"is_malware"`
	MalwareType *string   `json:"malware_type,omitempty"`
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
}

type refSummaryResponse struct {
	Vulnerabilities severityCounts `json:"vulnerabilities"`
	ComponentsTotal int            `json:"components_total"`
	SnapshotDate    *time.Time     `json:"snapshot_date,omitempty"`
	SnapshotStatus  *string        `json:"snapshot_status,omitempty"`
}

type repoDashboardEntryResponse struct {
	RepoID          uuid.UUID      `json:"repo_id"`
	RepoName        string         `json:"repo_name"`
	RepoSlug        string         `json:"repo_slug"`
	Provider        string         `json:"provider"`
	Vulnerabilities severityCounts `json:"vulnerabilities"`
	ComponentsTotal int            `json:"components_total"`
	LastScan        *time.Time     `json:"last_scan,omitempty"`
}

type orgDashboardTotalsResponse struct {
	Vulnerabilities severityCounts `json:"vulnerabilities"`
	ComponentsTotal int            `json:"components_total"`
}

type orgDashboardResponse struct {
	Repos  []repoDashboardEntryResponse `json:"repos"`
	Totals orgDashboardTotalsResponse   `json:"totals"`
}

func (s *Server) handleGetRefFindings(w http.ResponseWriter, r *http.Request) {
	_, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}

	snapshot, ok := s.resolveSnapshotForRequest(r, w, repo)
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

	snapshot, ok := s.resolveSnapshotForRequest(r, w, repo)
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

func (s *Server) handleGetRefSummary(w http.ResponseWriter, r *http.Request) {
	_, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}

	snapshot, ok := s.resolveSnapshotForRequest(r, w, repo)
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

	repos, err := s.listAllReposByOrg(r, org.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list repositories")
		return
	}

	response := orgDashboardResponse{
		Repos: make([]repoDashboardEntryResponse, 0, len(repos)),
	}

	for _, repo := range repos {
		entry := repoDashboardEntryResponse{
			RepoID:   repo.ID,
			RepoName: repo.Name,
			RepoSlug: repo.Slug,
			Provider: repo.Provider,
		}

		ref, snapshot, err := s.resolveSnapshotForRepo(r, &repo, repo.DefaultBranch)
		if err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to load dashboard data")
			return
		}
		if ref == nil || snapshot == nil {
			response.Repos = append(response.Repos, entry)
			continue
		}

		vulnerabilities, err := s.queries.ListAllVulnerabilitiesBySnapshot(r.Context(), snapshot.ID)
		if err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to load dashboard vulnerabilities")
			return
		}
		components, err := s.queries.ListComponentsBySnapshot(r.Context(), snapshot.ID)
		if err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to load dashboard components")
			return
		}

		entry.Vulnerabilities = countVulnerabilitySeverities(vulnerabilities)
		entry.ComponentsTotal = len(components)
		lastScan := snapshot.CreatedAt
		entry.LastScan = &lastScan

		addSeverityCounts(&response.Totals.Vulnerabilities, entry.Vulnerabilities)
		response.Totals.ComponentsTotal += entry.ComponentsTotal
		response.Repos = append(response.Repos, entry)
	}

	sort.SliceStable(response.Repos, func(i, j int) bool {
		left := response.Repos[i]
		right := response.Repos[j]
		leftRisk := left.Vulnerabilities.Critical + left.Vulnerabilities.High
		rightRisk := right.Vulnerabilities.Critical + right.Vulnerabilities.High
		if leftRisk == rightRisk {
			return left.RepoName < right.RepoName
		}
		return leftRisk > rightRisk
	})

	api.JSON(w, http.StatusOK, response)
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
	ref, snapshot, err := s.resolveSnapshotForRepo(r, repo, refName)
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
	ref, err := s.resolveRefForRepo(r, repo, refName)
	if err != nil || ref == nil {
		return ref, nil, err
	}

	snapshot, err := s.queries.GetLatestSnapshotByRef(r.Context(), ref.ID)
	if err != nil {
		return ref, nil, err
	}

	return ref, snapshot, nil
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

	vulnsByComponent := make(map[uuid.UUID][]dbgen.Advisory)
	for _, item := range countedVulns {
		vulnsByComponent[item.ComponentID] = append(vulnsByComponent[item.ComponentID], item.Advisory)
	}

	responses := make([]componentWithVulnsResponse, 0, len(components))
	for _, component := range components {
		advisories := vulnsByComponent[component.ID]
		response := componentWithVulnsResponse{
			ID:        component.ID,
			Name:      component.Name,
			Version:   component.Version,
			Ecosystem: component.Ecosystem,
			Purl:      component.Purl,
		}
		if len(advisories) > 0 {
			response.Advisories = make([]advisoryResponse, 0, len(advisories))
			response.VulnCount = len(advisories)
			for _, advisory := range advisories {
				response.Advisories = append(response.Advisories, advisoryToResponse(advisory))
			}
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

type countedVuln struct {
	ComponentID uuid.UUID
	Advisory    dbgen.Advisory
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

	counted := make([]countedVuln, 0, len(vulnerabilities))
	seenPairs := make(map[string]struct{})
	for _, vulnerability := range vulnerabilities {
		if !shouldCountVulnerability(vulnerability) {
			continue
		}
		advisory, ok := advisoryByID[*vulnerability.AdvisoryID]
		if !ok {
			continue
		}
		key := countedVulnPairKey(*vulnerability.ComponentID, *vulnerability.AdvisoryID)
		if _, ok := seenPairs[key]; ok {
			continue
		}
		seenPairs[key] = struct{}{}
		counted = append(counted, countedVuln{ComponentID: *vulnerability.ComponentID, Advisory: advisory})
	}

	return counted, nil
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

func advisoryToResponse(advisory dbgen.Advisory) advisoryResponse {
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
	return advisoryResponse{
		ID:          advisory.ID,
		CanonicalID: advisory.CanonicalID,
		Title:       advisory.Title,
		Severity:    string(advisory.Severity),
		CvssScore:   cvssScore,
		IsMalware:   advisory.IsMalware,
		MalwareType: malwareType,
	}
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
