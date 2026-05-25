package server

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/lehibou/internal/api"
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

type findingResponse struct {
	ID         uuid.UUID `json:"id"`
	SnapshotID uuid.UUID `json:"snapshot_id"`
	Tool       string    `json:"tool"`
	RuleID     string    `json:"rule_id"`
	Severity   string    `json:"severity"`
	Status     string    `json:"status"`
	FilePath   string    `json:"file_path"`
	StartLine  *int32    `json:"start_line,omitempty"`
	EndLine    *int32    `json:"end_line,omitempty"`
	Message    string    `json:"message"`
	Metadata   any       `json:"metadata,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
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
	Findings        severityCounts `json:"findings"`
	Vulns           severityCounts `json:"vulns"`
	ComponentsTotal int            `json:"components_total"`
	SnapshotDate    *time.Time     `json:"snapshot_date,omitempty"`
	SnapshotStatus  *string        `json:"snapshot_status,omitempty"`
}

type repoDashboardEntryResponse struct {
	RepoID          uuid.UUID      `json:"repo_id"`
	RepoName        string         `json:"repo_name"`
	RepoSlug        string         `json:"repo_slug"`
	Provider        string         `json:"provider"`
	Findings        severityCounts `json:"findings"`
	Vulns           severityCounts `json:"vulns"`
	ComponentsTotal int            `json:"components_total"`
	LastScan        *time.Time     `json:"last_scan,omitempty"`
}

type orgDashboardTotalsResponse struct {
	Findings        severityCounts `json:"findings"`
	Vulns           severityCounts `json:"vulns"`
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
		api.JSONList(w, []findingResponse{}, pagination.Page, pagination.PerPage, 0)
		return
	}

	severityFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("severity")))
	toolFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("tool")))
	statusFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status")))
	pagination := api.ParsePagination(r)

	rows, err := s.queries.ListAllFindingsBySnapshot(r.Context(), snapshot.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list findings")
		return
	}

	filtered := make([]findingResponse, 0, len(rows))
	for _, row := range rows {
		if severityFilter != "" && strings.ToLower(string(row.Severity)) != severityFilter {
			continue
		}
		if toolFilter != "" && strings.ToLower(row.Tool) != toolFilter {
			continue
		}
		if statusFilter != "" && strings.ToLower(row.Status) != statusFilter {
			continue
		}
		filtered = append(filtered, findingResponse{
			ID:         row.ID,
			SnapshotID: row.SnapshotID,
			Tool:       row.Tool,
			RuleID:     row.RuleID,
			Severity:   string(row.Severity),
			Status:     row.Status,
			FilePath:   row.FilePath,
			StartLine:  nullInt32Ptr(row.StartLine),
			EndLine:    nullInt32Ptr(row.EndLine),
			Message:    row.Message,
			Metadata:   jsonValueOrNil(row.Metadata),
			CreatedAt:  row.CreatedAt,
		})
	}

	paged := paginateSlice(filtered, pagination.Offset, pagination.PerPage)
	api.JSONList(w, paged, pagination.Page, pagination.PerPage, len(filtered))
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
	vulnMatches, err := s.queries.ListVulnMatchesBySnapshot(r.Context(), snapshot.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list vulnerability matches")
		return
	}

	responses, err := s.buildComponentResponses(r, components, vulnMatches)
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
	findings, err := s.queries.ListAllFindingsBySnapshot(r.Context(), snapshot.ID)
	if err != nil {
		return refSummaryResponse{}, err
	}
	vulnMatches, err := s.queries.ListVulnMatchesBySnapshot(r.Context(), snapshot.ID)
	if err != nil {
		return refSummaryResponse{}, err
	}
	components, err := s.queries.ListComponentsBySnapshot(r.Context(), snapshot.ID)
	if err != nil {
		return refSummaryResponse{}, err
	}
	vulns, err := s.loadCountedVulns(r, vulnMatches)
	if err != nil {
		return refSummaryResponse{}, err
	}

	status := string(snapshot.Status)
	createdAt := snapshot.CreatedAt
	return refSummaryResponse{
		Findings:        countFindingSeverities(findings),
		Vulns:           countAdvisorySeverities(vulns),
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

		findings, err := s.queries.ListAllFindingsBySnapshot(r.Context(), snapshot.ID)
		if err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to load dashboard findings")
			return
		}
		vulnMatches, err := s.queries.ListVulnMatchesBySnapshot(r.Context(), snapshot.ID)
		if err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to load dashboard vulnerability matches")
			return
		}
		components, err := s.queries.ListComponentsBySnapshot(r.Context(), snapshot.ID)
		if err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to load dashboard components")
			return
		}
		vulns, err := s.loadCountedVulns(r, vulnMatches)
		if err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to load dashboard advisories")
			return
		}

		entry.Findings = countFindingSeverities(findings)
		entry.Vulns = countAdvisorySeverities(vulns)
		entry.ComponentsTotal = len(components)
		lastScan := snapshot.CreatedAt
		entry.LastScan = &lastScan

		addSeverityCounts(&response.Totals.Findings, entry.Findings)
		addSeverityCounts(&response.Totals.Vulns, entry.Vulns)
		response.Totals.ComponentsTotal += entry.ComponentsTotal
		response.Repos = append(response.Repos, entry)
	}

	sort.SliceStable(response.Repos, func(i, j int) bool {
		left := response.Repos[i]
		right := response.Repos[j]
		leftRisk := left.Findings.Critical + left.Findings.High
		rightRisk := right.Findings.Critical + right.Findings.High
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

func (s *Server) resolveSnapshotForRequest(r *http.Request, w http.ResponseWriter, repo *store.Repository) (*store.Snapshot, bool) {
	snapshotID := strings.TrimSpace(r.URL.Query().Get("snapshot"))
	if snapshotID != "" {
		parsed, err := uuid.Parse(snapshotID)
		if err != nil {
			api.JSONError(w, http.StatusBadRequest, "invalid snapshot")
			return nil, false
		}
		snapshot, err := s.queries.GetSnapshotByID(r.Context(), parsed)
		if err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to load snapshot")
			return nil, false
		}
		if snapshot == nil {
			api.JSONError(w, http.StatusNotFound, "snapshot not found")
			return nil, false
		}
		ref, err := s.queries.GetRefByID(r.Context(), snapshot.RefID)
		if err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to load snapshot reference")
			return nil, false
		}
		if ref == nil || ref.RepoID != repo.ID {
			api.JSONError(w, http.StatusForbidden, "snapshot does not belong to this repository")
			return nil, false
		}
		return snapshot, true
	}

	refName := strings.TrimSpace(r.URL.Query().Get("ref"))
	if refName == "" {
		refName = repo.DefaultBranch
	}
	if refName == "" {
		api.JSONError(w, http.StatusBadRequest, "ref is required")
		return nil, false
	}

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

func (s *Server) resolveRefForRepo(r *http.Request, repo *store.Repository, refName string) (*store.Ref, error) {
	requestedName := strings.TrimSpace(refName)
	normalizedName := normalizeStoredRefName(requestedName)

	lookup := func(name string, refType store.RefType) (*store.Ref, error) {
		if name == "" {
			return nil, nil
		}
		return s.queries.GetRefByRepoAndName(r.Context(), repo.ID, name, refType)
	}

	tryNames := func(refType store.RefType, names ...string) (*store.Ref, error) {
		seen := make(map[string]struct{}, len(names))
		for _, name := range names {
			if name == "" {
				continue
			}
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			ref, err := lookup(name, refType)
			if err != nil {
				return nil, err
			}
			if ref != nil {
				return ref, nil
			}
		}
		return nil, nil
	}

	switch {
	case strings.HasPrefix(requestedName, "refs/heads/"):
		return tryNames(store.RefTypeBranch, normalizedName, requestedName)
	case strings.HasPrefix(requestedName, "refs/tags/"):
		return tryNames(store.RefTypeTag, normalizedName, requestedName)
	default:
		ref, err := tryNames(store.RefTypeBranch, normalizedName, requestedName)
		if err != nil || ref != nil {
			return ref, err
		}
		ref, err = tryNames(store.RefTypeTag, normalizedName, requestedName)
		if err != nil || ref != nil {
			return ref, err
		}
		return tryNames(store.RefTypePullRequest, requestedName, normalizedName)
	}
}

func (s *Server) buildComponentResponses(r *http.Request, components []dbgen.Component, vulnMatches []dbgen.VulnMatch) ([]componentWithVulnsResponse, error) {
	countedVulns, err := s.loadCountedVulns(r, vulnMatches)
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

func (s *Server) loadCountedVulns(r *http.Request, vulnMatches []dbgen.VulnMatch) ([]countedVuln, error) {
	advisoryIDs := make([]uuid.UUID, 0, len(vulnMatches))
	seenAdvisories := make(map[uuid.UUID]struct{})
	for _, match := range vulnMatches {
		if !match.IsAffected || match.Suppressed {
			continue
		}
		if _, ok := seenAdvisories[match.AdvisoryID]; ok {
			continue
		}
		seenAdvisories[match.AdvisoryID] = struct{}{}
		advisoryIDs = append(advisoryIDs, match.AdvisoryID)
	}
	if len(advisoryIDs) == 0 {
		return nil, nil
	}

	advisories, err := s.queries.GetAdvisoriesByIDs(r.Context(), advisoryIDs)
	if err != nil {
		return nil, err
	}
	advisoryByID := make(map[uuid.UUID]dbgen.Advisory, len(advisories))
	for _, advisory := range advisories {
		advisoryByID[advisory.ID] = advisory
	}

	counted := make([]countedVuln, 0, len(vulnMatches))
	seenPairs := make(map[string]struct{})
	for _, match := range vulnMatches {
		if !match.IsAffected || match.Suppressed {
			continue
		}
		advisory, ok := advisoryByID[match.AdvisoryID]
		if !ok {
			continue
		}
		key := match.ComponentID.String() + ":" + match.AdvisoryID.String()
		if _, ok := seenPairs[key]; ok {
			continue
		}
		seenPairs[key] = struct{}{}
		counted = append(counted, countedVuln{ComponentID: match.ComponentID, Advisory: advisory})
	}

	return counted, nil
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

func jsonValueOrNil(raw []byte) any {
	if len(raw) == 0 || string(raw) == "null" || string(raw) == "{}" {
		return nil
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil
	}
	return value
}

func nullInt32Ptr(value sql.NullInt32) *int32 {
	if !value.Valid {
		return nil
	}
	v := value.Int32
	return &v
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

func countFindingSeverities(findings []dbgen.Finding) severityCounts {
	counts := severityCounts{}
	for _, finding := range findings {
		incrementSeverity(&counts, string(finding.Severity))
	}
	return counts
}

func countAdvisorySeverities(vulns []countedVuln) severityCounts {
	counts := severityCounts{}
	for _, vuln := range vulns {
		incrementSeverity(&counts, string(vuln.Advisory.Severity))
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
