package mcp

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/rs/zerolog"

	"github.com/hibouhq/lehibou/internal/delta"
	"github.com/hibouhq/lehibou/internal/store"
	"github.com/hibouhq/lehibou/internal/store/dbgen"
)

const timeLayout = "2006-01-02T15:04:05Z07:00"

var (
	listVulnerabilitiesTool = mcp.NewTool("list_vulnerabilities",
		mcp.WithDescription("List vulnerability summaries for a repository ref."),
		mcp.WithString("org", mcp.Required()),
		mcp.WithString("repo", mcp.Required()),
		mcp.WithString("ref"),
		mcp.WithString("severity_filter"),
	)
	getDependencyTreeTool = mcp.NewTool("get_dependency_tree",
		mcp.WithDescription("List dependencies for a repository ref with vulnerability counts per component."),
		mcp.WithString("org", mcp.Required()),
		mcp.WithString("repo", mcp.Required()),
		mcp.WithString("ref"),
	)
	impactAnalysisTool = mcp.NewTool("impact_analysis",
		mcp.WithDescription("Look up advisory metadata for a CVE or alias within an organization."),
		mcp.WithString("org", mcp.Required()),
		mcp.WithString("cve_id", mcp.Required()),
	)
	compareRefsTool = mcp.NewTool("compare_refs",
		mcp.WithDescription("Compare ref2 against ref1 for a repository and return the vulnerability and finding delta."),
		mcp.WithString("org", mcp.Required()),
		mcp.WithString("repo", mcp.Required()),
		mcp.WithString("ref1", mcp.Required()),
		mcp.WithString("ref2", mcp.Required()),
	)
	searchComponentsTool = mcp.NewTool("search_components",
		mcp.WithDescription("Search components across an organization by package name, version, ecosystem, or PURL."),
		mcp.WithString("org", mcp.Required()),
		mcp.WithString("query", mcp.Required()),
	)
)

type service struct {
	store MCPStore
	delta *delta.Service
	log   zerolog.Logger
}

type vulnerabilitySummary struct {
	Severity string `json:"severity"`
	Count    int    `json:"count"`
}

type vulnerabilityItem struct {
	AdvisoryID    uuid.UUID `json:"advisory_id"`
	CanonicalID   string    `json:"canonical_id"`
	Title         string    `json:"title"`
	Description   string    `json:"description,omitempty"`
	Severity      string    `json:"severity"`
	CvssScore     *float64  `json:"cvss_score,omitempty"`
	CweIDs        []string  `json:"cwe_ids,omitempty"`
	IsMalware     bool      `json:"is_malware"`
	MalwareType   *string   `json:"malware_type,omitempty"`
	AffectedCount int       `json:"affected_count"`
	// TODO(vex): Populate from vex_statements once effective VEX state is wired in.
	Suppressed  int     `json:"suppressed_count"`
	PublishedAt *string `json:"published_at,omitempty"`
	WithdrawnAt *string `json:"withdrawn_at,omitempty"`
	UpdatedAt   string  `json:"updated_at"`
}

type componentItem struct {
	ID        uuid.UUID       `json:"id"`
	Purl      string          `json:"purl"`
	Name      string          `json:"name"`
	Version   string          `json:"version"`
	Ecosystem string          `json:"ecosystem"`
	Licenses  json.RawMessage `json:"licenses,omitempty"`
	VulnCount int64           `json:"vuln_count"`
}

func (s *service) handleListVulnerabilities(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	orgArg, ok := stringArg(request, "org")
	if !ok {
		return toolError("org is required")
	}
	repoSlug, ok := stringArg(request, "repo")
	if !ok {
		return toolError("repo is required")
	}
	severityFilter, err := normalizedSeverityArg(request, "severity_filter")
	if err != nil {
		return toolError(err.Error())
	}

	org, err := s.resolveOrgAndAuth(ctx, orgArg)
	if err != nil {
		return toolError(err.Error())
	}
	repo, ref, snapshot, err := s.resolveSnapshot(ctx, org, repoSlug, optionalStringArg(request, "ref"))
	if err != nil {
		return toolError(err.Error())
	}

	vulnerabilities, err := s.store.ListAllVulnerabilitiesBySnapshot(ctx, snapshot.ID)
	if err != nil {
		s.log.Error().Err(err).Str("snapshot_id", snapshot.ID.String()).Msg("failed to list vulnerabilities for MCP")
		return toolError("failed to load vulnerabilities")
	}
	activeVulnerabilities := filterActiveVulnerabilities(vulnerabilities)
	advisories, err := s.loadAdvisories(ctx, activeVulnerabilities)
	if err != nil {
		s.log.Error().Err(err).Str("snapshot_id", snapshot.ID.String()).Msg("failed to load advisories for MCP vulnerability list")
		return toolError("failed to load advisories")
	}

	items, summary := buildVulnerabilityResponse(activeVulnerabilities, advisories, severityFilter)
	response := map[string]any{
		"organization":        orgArg,
		"repository":          repo.Slug,
		"ref":                 ref.Name,
		"snapshot_id":         snapshot.ID,
		"snapshot_commit_sha": snapshot.CommitSHA,
		"severity_filter":     severityFilter,
		"summary":             summary,
		"vulnerabilities":     items,
	}

	return toolJSON(response)
}

func (s *service) handleGetDependencyTree(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	orgArg, ok := stringArg(request, "org")
	if !ok {
		return toolError("org is required")
	}
	repoSlug, ok := stringArg(request, "repo")
	if !ok {
		return toolError("repo is required")
	}

	org, err := s.resolveOrgAndAuth(ctx, orgArg)
	if err != nil {
		return toolError(err.Error())
	}
	repo, ref, snapshot, err := s.resolveSnapshot(ctx, org, repoSlug, optionalStringArg(request, "ref"))
	if err != nil {
		return toolError(err.Error())
	}

	components, err := s.store.ListComponentsBySnapshotWithVulns(ctx, snapshot.ID)
	if err != nil {
		s.log.Error().Err(err).Str("snapshot_id", snapshot.ID.String()).Msg("failed to list dependency tree for MCP")
		return toolError("failed to load dependency tree")
	}

	items := make([]componentItem, 0, len(components))
	for _, component := range components {
		items = append(items, componentItem{
			ID:        component.ID,
			Purl:      component.Purl,
			Name:      component.Name,
			Version:   component.Version,
			Ecosystem: component.Ecosystem,
			Licenses:  component.Licenses,
			VulnCount: component.VulnCount,
		})
	}

	response := map[string]any{
		"organization":        orgArg,
		"repository":          repo.Slug,
		"ref":                 ref.Name,
		"snapshot_id":         snapshot.ID,
		"snapshot_commit_sha": snapshot.CommitSHA,
		"components":          items,
	}

	return toolJSON(response)
}

func (s *service) handleImpactAnalysis(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	orgArg, ok := stringArg(request, "org")
	if !ok {
		return toolError("org is required")
	}
	cveID, ok := stringArg(request, "cve_id")
	if !ok {
		return toolError("cve_id is required")
	}

	org, err := s.resolveOrgAndAuth(ctx, orgArg)
	if err != nil {
		return toolError(err.Error())
	}
	advisory, err := s.store.GetAdvisoryByAlias(ctx, cveID)
	if err != nil {
		s.log.Error().Err(err).Str("org_id", org.ID.String()).Str("alias", cveID).Msg("failed to resolve advisory alias for MCP impact analysis")
		return toolError("advisory not found for alias " + cveID)
	}

	response := map[string]any{
		"organization": orgArg,
		"advisory": map[string]any{
			"id":           advisory.ID,
			"canonical_id": advisory.CanonicalID,
			"title":        advisory.Title,
			"description":  advisory.Description,
			"severity":     strings.ToLower(string(advisory.Severity)),
			"cvss_score":   parseNullFloat(advisory.CvssScore.String, advisory.CvssScore.Valid),
			"cwe_ids":      advisory.CweIds,
			"is_malware":   advisory.IsMalware,
			"malware_type": nullEnumString(string(advisory.MalwareType.MalwareType), advisory.MalwareType.Valid),
			"published_at": nullTimeString(advisory.PublishedAt),
			"withdrawn_at": nullTimeString(advisory.WithdrawnAt),
			"updated_at":   advisory.UpdatedAt.UTC().Format(timeLayout),
		},
		"note": "Cross-repository impact enumeration is not implemented yet. This tool currently returns advisory metadata after authentication and organization authorization.",
	}

	return toolJSON(response)
}

func (s *service) handleCompareRefs(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if s.delta == nil {
		return toolError("delta service is not configured")
	}
	orgArg, ok := stringArg(request, "org")
	if !ok {
		return toolError("org is required")
	}
	repoSlug, ok := stringArg(request, "repo")
	if !ok {
		return toolError("repo is required")
	}
	ref1, ok := stringArg(request, "ref1")
	if !ok {
		return toolError("ref1 is required")
	}
	ref2, ok := stringArg(request, "ref2")
	if !ok {
		return toolError("ref2 is required")
	}

	org, err := s.resolveOrgAndAuth(ctx, orgArg)
	if err != nil {
		return toolError(err.Error())
	}
	repo, baseRef, baseSnapshot, err := s.resolveSnapshot(ctx, org, repoSlug, ref1)
	if err != nil {
		return toolError(err.Error())
	}
	_, headRef, headSnapshot, err := s.resolveSnapshot(ctx, org, repoSlug, ref2)
	if err != nil {
		return toolError(err.Error())
	}

	deltaResult, err := s.delta.ComputeDelta(ctx, headSnapshot.ID, baseSnapshot.ID)
	if err != nil {
		s.log.Error().Err(err).Str("base_snapshot_id", baseSnapshot.ID.String()).Str("head_snapshot_id", headSnapshot.ID.String()).Msg("failed to compare refs for MCP")
		return toolError("failed to compute ref comparison")
	}

	response := map[string]any{
		"organization": orgArg,
		"repository":   repo.Slug,
		"base": map[string]any{
			"ref":         baseRef.Name,
			"snapshot_id": baseSnapshot.ID,
			"commit_sha":  baseSnapshot.CommitSHA,
		},
		"head": map[string]any{
			"ref":         headRef.Name,
			"snapshot_id": headSnapshot.ID,
			"commit_sha":  headSnapshot.CommitSHA,
		},
		"delta": deltaResult,
	}

	return toolJSON(response)
}

func (s *service) handleSearchComponents(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	orgArg, ok := stringArg(request, "org")
	if !ok {
		return toolError("org is required")
	}
	query, ok := stringArg(request, "query")
	if !ok {
		return toolError("query is required")
	}

	org, err := s.resolveOrgAndAuth(ctx, orgArg)
	if err != nil {
		return toolError(err.Error())
	}
	components, total, err := s.store.SearchComponents(ctx, org.ID, query, 50, 0)
	if err != nil {
		s.log.Error().Err(err).Str("org_id", org.ID.String()).Str("query", query).Msg("failed to search components for MCP")
		return toolError("failed to search components")
	}

	response := map[string]any{
		"organization": orgArg,
		"query":        query,
		"total":        total,
		"components":   components,
	}

	return toolJSON(response)
}

func (s *service) resolveOrgAndAuth(ctx context.Context, orgArg string) (*store.Organization, error) {
	user := UserFromContext(ctx)
	if user == nil {
		return nil, errors.New("authentication required; provide a Bearer API key")
	}
	parts := strings.SplitN(strings.TrimSpace(orgArg), "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, errors.New("org must be in provider/slug format")
	}

	org, err := s.store.GetOrganizationByProviderAndSlug(ctx, parts[0], parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to load organization %s", orgArg)
	}
	if org == nil {
		return nil, fmt.Errorf("organization not found: %s", orgArg)
	}

	role, err := s.store.GetOrgMemberRole(ctx, org.ID, user.ID)
	if err != nil || role == "" {
		return nil, fmt.Errorf("you do not have access to organization %s", orgArg)
	}

	return org, nil
}

func (s *service) resolveSnapshot(ctx context.Context, org *store.Organization, repoSlug, refName string) (*store.Repository, *store.Ref, *store.Snapshot, error) {
	repo, err := s.store.GetRepositoryBySlug(ctx, org.ID, repoSlug)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to load repository %s", repoSlug)
	}
	if repo == nil {
		return nil, nil, nil, fmt.Errorf("repository not found: %s", repoSlug)
	}
	if strings.TrimSpace(refName) == "" {
		refName = repo.DefaultBranch
	}
	if strings.TrimSpace(refName) == "" {
		return nil, nil, nil, fmt.Errorf("repository %s has no default branch configured", repoSlug)
	}

	ref, err := s.resolveRef(ctx, repo.ID, refName)
	if err != nil {
		return nil, nil, nil, err
	}
	snapshot, err := s.store.GetLatestSnapshotByRef(ctx, ref.ID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to load latest snapshot for ref %s", refName)
	}
	if snapshot == nil {
		return nil, nil, nil, fmt.Errorf("no snapshot available for ref %s", refName)
	}

	return repo, ref, snapshot, nil
}

func (s *service) resolveRef(ctx context.Context, repoID uuid.UUID, refName string) (*store.Ref, error) {
	for _, refType := range []store.RefType{store.RefTypeBranch, store.RefTypeTag, store.RefTypePullRequest} {
		ref, err := s.store.GetRefByRepoAndName(ctx, repoID, refName, refType)
		if err != nil {
			return nil, fmt.Errorf("failed to load ref %s", refName)
		}
		if ref != nil {
			return ref, nil
		}
	}

	return nil, fmt.Errorf("ref not found: %s", refName)
}

func (s *service) loadAdvisories(ctx context.Context, vulnerabilities []store.Vulnerability) (map[uuid.UUID]dbgen.Advisory, error) {
	ids := make([]uuid.UUID, 0, len(vulnerabilities))
	seen := make(map[uuid.UUID]struct{}, len(vulnerabilities))
	for _, vulnerability := range vulnerabilities {
		if vulnerability.AdvisoryID == nil {
			continue
		}
		if _, ok := seen[*vulnerability.AdvisoryID]; ok {
			continue
		}
		seen[*vulnerability.AdvisoryID] = struct{}{}
		ids = append(ids, *vulnerability.AdvisoryID)
	}
	if len(ids) == 0 {
		return map[uuid.UUID]dbgen.Advisory{}, nil
	}
	rows, err := s.store.GetAdvisoriesByIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	result := make(map[uuid.UUID]dbgen.Advisory, len(rows))
	for _, advisory := range rows {
		result[advisory.ID] = advisory
	}
	return result, nil
}

func buildVulnerabilityResponse(vulnerabilities []store.Vulnerability, advisories map[uuid.UUID]dbgen.Advisory, severityFilter string) ([]vulnerabilityItem, []vulnerabilitySummary) {
	type counts struct {
		affected int
	}

	byAdvisory := make(map[uuid.UUID]counts, len(vulnerabilities))
	for _, vulnerability := range vulnerabilities {
		if vulnerability.AdvisoryID == nil {
			continue
		}
		entry := byAdvisory[*vulnerability.AdvisoryID]
		entry.affected++
		byAdvisory[*vulnerability.AdvisoryID] = entry
	}

	items := make([]vulnerabilityItem, 0, len(byAdvisory))
	summaryCounts := map[string]int{}
	for advisoryID, count := range byAdvisory {
		advisory, ok := advisories[advisoryID]
		if !ok {
			continue
		}
		severity := strings.ToLower(string(advisory.Severity))
		if severityFilter != "" && severity != severityFilter {
			continue
		}
		summaryCounts[severity]++
		items = append(items, vulnerabilityItem{
			AdvisoryID:    advisory.ID,
			CanonicalID:   advisory.CanonicalID,
			Title:         advisory.Title,
			Description:   advisory.Description,
			Severity:      severity,
			CvssScore:     parseNullFloat(advisory.CvssScore.String, advisory.CvssScore.Valid),
			CweIDs:        advisory.CweIds,
			IsMalware:     advisory.IsMalware,
			MalwareType:   nullEnumString(string(advisory.MalwareType.MalwareType), advisory.MalwareType.Valid),
			AffectedCount: count.affected,
			Suppressed:    0,
			PublishedAt:   nullTimeString(advisory.PublishedAt),
			WithdrawnAt:   nullTimeString(advisory.WithdrawnAt),
			UpdatedAt:     advisory.UpdatedAt.UTC().Format(timeLayout),
		})
	}

	summaries := make([]vulnerabilitySummary, 0, len(summaryCounts))
	for _, severity := range []string{"critical", "high", "medium", "low", "info"} {
		if count := summaryCounts[severity]; count > 0 {
			summaries = append(summaries, vulnerabilitySummary{Severity: severity, Count: count})
		}
	}

	return items, summaries
}

func filterActiveVulnerabilities(vulnerabilities []store.Vulnerability) []store.Vulnerability {
	filtered := make([]store.Vulnerability, 0, len(vulnerabilities))
	for _, vulnerability := range vulnerabilities {
		if vulnerability.Type != "dependency" && vulnerability.Type != "malware" {
			continue
		}
		if vulnerability.Status == "resolved" || vulnerability.Status == "dismissed" {
			continue
		}
		if vulnerability.AdvisoryID == nil {
			continue
		}
		filtered = append(filtered, vulnerability)
	}
	return filtered
}

func stringArg(request mcp.CallToolRequest, name string) (string, bool) {
	value := optionalStringArg(request, name)
	if value == "" {
		return "", false
	}
	return value, true
}

func optionalStringArg(request mcp.CallToolRequest, name string) string {
	value, ok := request.GetArguments()[name]
	if !ok || value == nil {
		return ""
	}
	text, ok := value.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(text)
}

func normalizedSeverityArg(request mcp.CallToolRequest, name string) (string, error) {
	value := optionalStringArg(request, name)
	if value == "" {
		return "", nil
	}
	for _, allowed := range []string{"critical", "high", "medium", "low", "info"} {
		if value == allowed {
			return value, nil
		}
	}
	return "", errors.New("severity_filter must be one of critical, high, medium, low, info")
}

func toolJSON(value any) (*mcp.CallToolResult, error) {
	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return toolError("failed to encode tool response")
	}
	return mcp.NewToolResultText(string(payload)), nil
}

func toolError(msg string) (*mcp.CallToolResult, error) {
	result := mcp.NewToolResultText(msg)
	result.IsError = true
	return result, nil
}

func parseNullFloat(raw string, valid bool) *float64 {
	if !valid || strings.TrimSpace(raw) == "" {
		return nil
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return nil
	}
	return &value
}

func nullEnumString(raw string, valid bool) *string {
	if !valid || strings.TrimSpace(raw) == "" {
		return nil
	}
	value := strings.TrimSpace(raw)
	return &value
}

func nullTimeString(value sql.NullTime) *string {
	if !value.Valid {
		return nil
	}
	formatted := value.Time.UTC().Format(timeLayout)
	return &formatted
}
