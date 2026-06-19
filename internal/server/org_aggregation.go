package server

import (
	"net/http"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/store"
)

// orgRepoSnapshot pairs an enrolled repo with its current (default-branch) snapshot.
type orgRepoSnapshot struct {
	repo     *store.Repository
	snapshot *store.Snapshot
}

// currentRepoSnapshots resolves the current snapshot for every enrolled repo in
// the org, reusing the same resolution the per-repo data views use.
func (s *Server) currentRepoSnapshots(r *http.Request, org *store.Organization) ([]orgRepoSnapshot, error) {
	repos, _, err := s.listRepositoryInventory(r, org)
	if err != nil {
		return nil, err
	}

	pairs := make([]orgRepoSnapshot, 0, len(repos))
	for _, entry := range repos {
		if !entry.Enrolled || entry.ID == nil {
			continue
		}
		repo, err := s.queries.GetRepositoryByID(r.Context(), *entry.ID)
		if err != nil || repo == nil {
			continue
		}
		_, snapshot, err := s.resolveSnapshotForRepo(r, repo, repo.DefaultBranch)
		if err != nil || snapshot == nil {
			continue
		}
		pairs = append(pairs, orgRepoSnapshot{repo: repo, snapshot: snapshot})
	}

	return pairs, nil
}

type orgVulnerabilityResponse struct {
	store.Vulnerability
	RepoSlug string `json:"repo_slug"`
	RepoName string `json:"repo_name"`
}

func (s *Server) handleListOrgVulnerabilities(w http.ResponseWriter, r *http.Request) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok {
		return
	}

	pairs, err := s.currentRepoSnapshots(r, org)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to resolve repository snapshots")
		return
	}

	pagination := api.ParsePagination(r)
	if len(pairs) == 0 {
		api.JSONList(w, []orgVulnerabilityResponse{}, pagination.Page, pagination.PerPage, 0)
		return
	}

	snapshotIDs := make([]uuid.UUID, 0, len(pairs))
	repoBySnapshot := make(map[uuid.UUID]orgRepoSnapshot, len(pairs))
	for _, pair := range pairs {
		snapshotIDs = append(snapshotIDs, pair.snapshot.ID)
		repoBySnapshot[pair.snapshot.ID] = pair
	}

	vulnerabilities, total, err := s.queries.ListVulnerabilitiesBySnapshots(r.Context(), snapshotIDs, store.VulnerabilityListOptions{
		Types:      csvQueryFilterValues(r.URL.Query().Get("type")),
		Severities: csvQueryFilterValues(r.URL.Query().Get("severity")),
		Statuses:   csvQueryFilterValues(r.URL.Query().Get("status")),
		Scanners:   mergeCSVFilters(csvQueryFilterValues(r.URL.Query().Get("scanner")), csvQueryFilterValues(r.URL.Query().Get("tool"))),
		Search:     strings.TrimSpace(r.URL.Query().Get("search")),
		Sort:       strings.TrimSpace(r.URL.Query().Get("sort")),
		Limit:      pagination.PerPage,
		Offset:     pagination.Offset,
	})
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list vulnerabilities")
		return
	}

	responses := make([]orgVulnerabilityResponse, len(vulnerabilities))
	for i := range vulnerabilities {
		vuln := vulnerabilities[i]
		entry := orgVulnerabilityResponse{Vulnerability: vuln}
		if meta, ok := repoBySnapshot[vuln.SnapshotID]; ok {
			entry.RepoSlug = meta.repo.Slug
			entry.RepoName = meta.repo.Name
		}
		responses[i] = entry
	}

	api.JSONList(w, responses, pagination.Page, pagination.PerPage, total)
}

type orgComponentResponse struct {
	componentWithVulnsResponse
	Repos []string `json:"repos"`
}

func (s *Server) handleListOrgComponents(w http.ResponseWriter, r *http.Request) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok {
		return
	}

	pairs, err := s.currentRepoSnapshots(r, org)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to resolve repository snapshots")
		return
	}

	type aggregate struct {
		response componentWithVulnsResponse
		repos    map[string]struct{}
	}
	byKey := make(map[string]*aggregate)

	for _, pair := range pairs {
		components, err := s.queries.ListComponentsBySnapshot(r.Context(), pair.snapshot.ID)
		if err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to list components")
			return
		}
		vulnerabilities, err := s.queries.ListAllVulnerabilitiesBySnapshot(r.Context(), pair.snapshot.ID)
		if err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to list vulnerability matches")
			return
		}
		responses, err := s.buildComponentResponses(r, components, vulnerabilities)
		if err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to load advisories")
			return
		}

		for _, cr := range responses {
			key := cr.Purl + "@" + cr.Version
			agg, ok := byKey[key]
			if !ok {
				agg = &aggregate{response: cr, repos: make(map[string]struct{})}
				byKey[key] = agg
			} else {
				// Same component@version across repos shares advisories; keep the
				// richest view (highest vuln count, union of advisories).
				if cr.VulnCount > agg.response.VulnCount {
					agg.response.VulnCount = cr.VulnCount
					agg.response.HighestSeverity = cr.HighestSeverity
				}
				agg.response.Advisories = unionAdvisories(agg.response.Advisories, cr.Advisories)
				agg.response.Sources = sortedUniqueNonEmptyStrings(append(agg.response.Sources, cr.Sources...))
				agg.response.FixedVersions = sortedUniqueNonEmptyStrings(append(agg.response.FixedVersions, cr.FixedVersions...))
			}
			agg.repos[pair.repo.Slug] = struct{}{}
		}
	}

	out := make([]orgComponentResponse, 0, len(byKey))
	for _, agg := range byKey {
		repos := make([]string, 0, len(agg.repos))
		for slug := range agg.repos {
			repos = append(repos, slug)
		}
		sort.Strings(repos)
		out = append(out, orgComponentResponse{componentWithVulnsResponse: agg.response, Repos: repos})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].VulnCount != out[j].VulnCount {
			return out[i].VulnCount > out[j].VulnCount
		}
		return out[i].Name < out[j].Name
	})

	api.JSON(w, http.StatusOK, out)
}

func unionAdvisories(existing, incoming []advisoryResponse) []advisoryResponse {
	seen := make(map[uuid.UUID]struct{}, len(existing))
	for _, advisory := range existing {
		seen[advisory.ID] = struct{}{}
	}
	for _, advisory := range incoming {
		if _, ok := seen[advisory.ID]; ok {
			continue
		}
		seen[advisory.ID] = struct{}{}
		existing = append(existing, advisory)
	}
	return existing
}
