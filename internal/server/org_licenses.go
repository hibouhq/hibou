package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/delta"
	"github.com/hibouhq/hibou/internal/license"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// The org license overview answers one question across a whole organization:
// "what license obligations are we under, and where?". It deliberately reports
// EXPOSURE, not enforcement — a component appearing under `copyleft` here says
// nothing about whether any repo's quality gate denies that category. Conflating
// the two would let a reader conclude they are protected when no gate is
// configured, so the coverage block below always ships alongside the totals and
// the response states the population it measured.

type orgLicenseCoverage struct {
	// ReposEnrolled is the denominator that matters: every other count in this
	// response is drawn only from repos that got as far as a usable snapshot.
	ReposEnrolled       int `json:"repos_enrolled"`
	ReposWithSnapshot   int `json:"repos_with_snapshot"`
	ReposWithComponents int `json:"repos_with_components"`
	ComponentsTotal     int `json:"components_total"`
	// Undeclared: the SBOM carried no license at all — a generator problem.
	Undeclared int `json:"undeclared"`
	// Unrecognized: a license string we could not map to a category — a catalog
	// problem. Both are CategoryUnknown, but they have different owners.
	Unrecognized int `json:"unrecognized"`
}

type orgLicenseCategoryStat struct {
	Category   string `json:"category"`
	Components int    `json:"components"`
	Repos      int    `json:"repos"`
}

type orgLicenseStat struct {
	License    string `json:"license"`
	Category   string `json:"category"`
	Components int    `json:"components"`
	Repos      int    `json:"repos"`
	// HasAnd marks a conjunctive expression: every operand's obligations apply
	// at once. HasOr marks an elective one, where the reported category is the
	// alternative a consumer would pick. Surfacing both stops the table looking
	// like it disagrees with the gate.
	HasAnd bool `json:"has_and"`
	HasOr  bool `json:"has_or"`
}

type orgLicenseRepoStat struct {
	Slug           string         `json:"slug"`
	Name           string         `json:"name"`
	Components     int            `json:"components"`
	Undeclared     int            `json:"undeclared"`
	ByCategory     map[string]int `json:"by_category"`
	SnapshotAt     *time.Time     `json:"snapshot_at,omitempty"`
	SnapshotStatus string         `json:"snapshot_status,omitempty"`
}

type orgLicenseOverviewResponse struct {
	Coverage   orgLicenseCoverage       `json:"coverage"`
	Categories []orgLicenseCategoryStat `json:"categories"`
	Licenses   []orgLicenseStat         `json:"licenses"`
	Repos      []orgLicenseRepoStat     `json:"repos"`
}

// componentLicenseFacts is the per-component reduction every aggregate reads,
// computed once so the category taxonomy is applied in exactly one place.
type componentLicenseFacts struct {
	category   license.Category
	entries    []string
	declared   bool
	recognized bool
}

func summarizeComponentLicenses(raw []string) componentLicenseFacts {
	entries := license.NormalizeIDs(raw)
	declared := len(entries) > 0
	category := license.CategorizeAll(entries)
	return componentLicenseFacts{
		category:   category,
		entries:    entries,
		declared:   declared,
		recognized: declared && category != license.CategoryUnknown,
	}
}

// @Summary      Organization license overview
// @Description  License exposure across the current default-branch snapshot of every enrolled repository: category partition, license expressions in use, per-repo posture, and the coverage denominators behind those numbers. Reports exposure, not gate enforcement.
// @Tags         organizations
// @Produce      json
// @Param        provider  path  string  true  "Forge provider"
// @Param        slug      path  string  true  "Organization slug"
// @Success      200  {object}  orgLicenseOverviewResponse
// @Router       /orgs/{provider}/{slug}/licenses [get]
func (s *Server) handleGetOrgLicenses(w http.ResponseWriter, r *http.Request) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok {
		return
	}
	// Reuses CapComponents rather than introducing a license capability:
	// component licenses are component data, and a new scope would 403 every
	// token already issued.
	if !s.enforceOrgWideCapability(w, r, apitoken.CapComponents, apitoken.AccessRead, org.Slug) {
		return
	}

	// One inventory walk, not two: it is a forge-backed listing, and the
	// enrolled count is the coverage denominator this response reports.
	pairs, enrolled, err := s.currentRepoSnapshotsWithEnrolledCount(r, org)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to resolve repository snapshots")
		return
	}

	snapshotIDs := make([]uuid.UUID, 0, len(pairs))
	repoBySnapshot := make(map[uuid.UUID]orgRepoSnapshot, len(pairs))
	for _, pair := range pairs {
		snapshotIDs = append(snapshotIDs, pair.snapshot.ID)
		repoBySnapshot[pair.repo.ID] = pair
	}

	// No resolvable snapshot anywhere in the org: skip the query, but still
	// return the full envelope so the page renders "nothing measured" rather
	// than "no exposure found".
	if len(snapshotIDs) == 0 {
		api.JSON(w, http.StatusOK, buildOrgLicenseOverview(nil, repoBySnapshot, enrolled))
		return
	}

	rows, err := s.queries.ListComponentLicensesBySnapshots(r.Context(), snapshotIDs)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list component licenses")
		return
	}

	api.JSON(w, http.StatusOK, buildOrgLicenseOverview(rows, repoBySnapshot, enrolled))
}

// buildOrgLicenseOverview reduces the flat (repo, component, licenses[]) rows
// into the three aggregates the page renders. Kept pure so the counting rules —
// which are the part that goes subtly wrong — are testable without a forge, a
// snapshot resolver, or a database.
func buildOrgLicenseOverview(
	rows []dbgen.ListComponentLicensesBySnapshotsRow,
	repos map[uuid.UUID]orgRepoSnapshot,
	enrolled int,
) orgLicenseOverviewResponse {
	response := orgLicenseOverviewResponse{
		Coverage: orgLicenseCoverage{
			ReposEnrolled:     enrolled,
			ReposWithSnapshot: len(repos),
		},
		Categories: []orgLicenseCategoryStat{},
		Licenses:   []orgLicenseStat{},
		Repos:      []orgLicenseRepoStat{},
	}

	// Aggregation is keyed on purl@version so a dependency shared by ten repos
	// counts once in the org totals while still contributing to each repo's row.
	type componentAgg struct {
		facts componentLicenseFacts
		repos map[uuid.UUID]struct{}
	}
	components := make(map[string]*componentAgg)
	type licenseAgg struct {
		category   license.Category
		hasAnd     bool
		hasOr      bool
		components map[string]struct{}
		repos      map[uuid.UUID]struct{}
	}
	licenses := make(map[string]*licenseAgg)
	repoStats := make(map[uuid.UUID]*orgLicenseRepoStat)
	reposWithComponents := make(map[uuid.UUID]struct{})

	for _, row := range rows {
		pair, known := repos[row.RepoID]
		if !known {
			continue
		}
		reposWithComponents[row.RepoID] = struct{}{}
		facts := summarizeComponentLicenses(row.Licenses)

		key := row.Purl + "@" + row.Version
		component, seen := components[key]
		if !seen {
			component = &componentAgg{facts: facts, repos: make(map[uuid.UUID]struct{})}
			components[key] = component
		}
		component.repos[row.RepoID] = struct{}{}

		stat, seen := repoStats[row.RepoID]
		if !seen {
			stat = &orgLicenseRepoStat{
				ByCategory: make(map[string]int),
			}
			if pair.repo != nil {
				stat.Slug = pair.repo.Slug
				stat.Name = pair.repo.Name
			}
			if pair.snapshot != nil {
				stat.SnapshotStatus = string(pair.snapshot.Status)
				createdAt := pair.snapshot.CreatedAt
				stat.SnapshotAt = &createdAt
			}
			repoStats[row.RepoID] = stat
		}
		stat.Components++
		stat.ByCategory[string(facts.category)]++
		if !facts.declared {
			stat.Undeclared++
		}

		for _, entry := range facts.entries {
			agg, seen := licenses[entry]
			if !seen {
				upper := strings.ToUpper(entry)
				agg = &licenseAgg{
					category:   license.CategorizeExpression(entry),
					hasAnd:     strings.Contains(upper, " AND "),
					hasOr:      strings.Contains(upper, " OR "),
					components: make(map[string]struct{}),
					repos:      make(map[uuid.UUID]struct{}),
				}
				licenses[entry] = agg
			}
			agg.components[key] = struct{}{}
			agg.repos[row.RepoID] = struct{}{}
		}
	}

	categoryComponents := make(map[license.Category]int)
	categoryRepos := make(map[license.Category]map[uuid.UUID]struct{})
	for _, component := range components {
		response.Coverage.ComponentsTotal++
		if !component.facts.declared {
			response.Coverage.Undeclared++
		} else if !component.facts.recognized {
			response.Coverage.Unrecognized++
		}
		categoryComponents[component.facts.category]++
		repoSet, seen := categoryRepos[component.facts.category]
		if !seen {
			repoSet = make(map[uuid.UUID]struct{})
			categoryRepos[component.facts.category] = repoSet
		}
		for repoID := range component.repos {
			repoSet[repoID] = struct{}{}
		}
	}
	response.Coverage.ReposWithComponents = len(reposWithComponents)

	// Every category is emitted, including empty ones: a partition with holes
	// reads as missing data rather than as an absence of exposure.
	for _, category := range license.Categories() {
		response.Categories = append(response.Categories, orgLicenseCategoryStat{
			Category:   string(category),
			Components: categoryComponents[category],
			Repos:      len(categoryRepos[category]),
		})
	}

	for expression, agg := range licenses {
		response.Licenses = append(response.Licenses, orgLicenseStat{
			License:    expression,
			Category:   string(agg.category),
			Components: len(agg.components),
			Repos:      len(agg.repos),
			HasAnd:     agg.hasAnd,
			HasOr:      agg.hasOr,
		})
	}
	sort.SliceStable(response.Licenses, func(i, j int) bool {
		if response.Licenses[i].Components != response.Licenses[j].Components {
			return response.Licenses[i].Components > response.Licenses[j].Components
		}
		return response.Licenses[i].License < response.Licenses[j].License
	})

	for _, stat := range repoStats {
		response.Repos = append(response.Repos, *stat)
	}
	// Most restrictive exposure first, so the repos that need a decision are at
	// the top rather than the ones that merely have the most dependencies.
	sort.SliceStable(response.Repos, func(i, j int) bool {
		left, right := riskWeight(response.Repos[i]), riskWeight(response.Repos[j])
		if left != right {
			return left > right
		}
		return response.Repos[i].Slug < response.Repos[j].Slug
	})

	return response
}

// riskWeight ranks a REPOSITORY by its worst exposure. Unknown is weighted low
// on purpose — see categoryRank, which ranks a single component and orders it
// higher — because a repo's unknown count is usually one misbehaving SBOM
// generator, and letting it dominate would bury the repo with one real AGPL
// dependency underneath it.
func riskWeight(stat orgLicenseRepoStat) int {
	weights := map[string]int{
		string(license.CategoryUnknown):         1,
		string(license.CategorySourceAvailable): 100,
		string(license.CategoryNetworkCopyleft): 50,
		string(license.CategoryCopyleft):        10,
		string(license.CategoryWeakCopyleft):    2,
	}
	total := 0
	for category, count := range stat.ByCategory {
		total += weights[category] * count
	}
	return total
}

// orgLicenseComponentResponse is one row of the drilldown: which component, in
// which repos, under which license and category.
type orgLicenseComponentResponse struct {
	Purl      string   `json:"purl"`
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Ecosystem string   `json:"ecosystem"`
	Licenses  []string `json:"licenses"`
	Category  string   `json:"category"`
	Repos     []string `json:"repos"`
	// Declared is false when the component carried no license metadata at all,
	// which is a different problem from an identifier we failed to recognize
	// even though both land in the unknown category.
	Declared bool `json:"declared"`
}

// orgLicenseComponentFilter is the parsed query string. Zero value means "no
// filter" for every field.
type orgLicenseComponentFilter struct {
	license    string
	category   string
	repo       string
	undeclared bool
}

func parseOrgLicenseComponentFilter(r *http.Request) orgLicenseComponentFilter {
	query := r.URL.Query()
	return orgLicenseComponentFilter{
		// Normalized so a link built from a license table row matches the stored
		// value regardless of parens or casing.
		license:    license.NormalizeID(query.Get("license")),
		category:   strings.ToLower(strings.TrimSpace(query.Get("category"))),
		repo:       strings.TrimSpace(query.Get("repo")),
		undeclared: query.Get("undeclared") == "true",
	}
}

func (f orgLicenseComponentFilter) matches(row orgLicenseComponentResponse) bool {
	if f.undeclared && row.Declared {
		return false
	}
	if f.category != "" && !strings.EqualFold(f.category, row.Category) {
		return false
	}
	if f.license != "" {
		found := false
		for _, entry := range row.Licenses {
			if strings.EqualFold(entry, f.license) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if f.repo != "" {
		found := false
		for _, slug := range row.Repos {
			if strings.EqualFold(slug, f.repo) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// @Summary      Organization license drilldown
// @Description  Paginated components behind the org license overview, filterable by license expression, category, repository, or missing metadata. A rollup without a drilldown is only half actionable.
// @Tags         organizations
// @Produce      json
// @Param        provider    path   string  true   "Forge provider"
// @Param        slug        path   string  true   "Organization slug"
// @Param        license     query  string  false  "License expression to filter by"
// @Param        category    query  string  false  "License category to filter by"
// @Param        repo        query  string  false  "Repository slug to filter by"
// @Param        undeclared  query  bool    false  "Only components with no license metadata"
// @Success      200  {object}  api.ListResponse
// @Router       /orgs/{provider}/{slug}/licenses/components [get]
func (s *Server) handleListOrgLicenseComponents(w http.ResponseWriter, r *http.Request) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok {
		return
	}
	if !s.enforceOrgWideCapability(w, r, apitoken.CapComponents, apitoken.AccessRead, org.Slug) {
		return
	}

	pagination := api.ParsePagination(r)

	pairs, err := s.currentRepoSnapshots(r, org)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to resolve repository snapshots")
		return
	}
	snapshotIDs := make([]uuid.UUID, 0, len(pairs))
	repoBySnapshot := make(map[uuid.UUID]orgRepoSnapshot, len(pairs))
	for _, pair := range pairs {
		snapshotIDs = append(snapshotIDs, pair.snapshot.ID)
		repoBySnapshot[pair.repo.ID] = pair
	}
	if len(snapshotIDs) == 0 {
		api.JSONList(w, []orgLicenseComponentResponse{}, pagination.Page, pagination.PerPage, 0)
		return
	}

	rows, err := s.queries.ListComponentLicensesBySnapshots(r.Context(), snapshotIDs)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list component licenses")
		return
	}

	filtered := buildOrgLicenseComponents(rows, repoBySnapshot, parseOrgLicenseComponentFilter(r))
	page := paginateLicenseComponents(filtered, pagination.Offset, pagination.PerPage)
	api.JSONList(w, page, pagination.Page, pagination.PerPage, len(filtered))
}

// paginateLicenseComponents slices one page, tolerating an offset past the end.
// Pagination happens in Go rather than SQL because the rows are grouped by
// purl@version across repos first, and paginating before that grouping would cut
// a component's repo list across two pages.
func paginateLicenseComponents(rows []orgLicenseComponentResponse, offset, perPage int) []orgLicenseComponentResponse {
	if offset < 0 || offset >= len(rows) || perPage <= 0 {
		// Never nil: a null list renders as an error client-side, while an empty
		// page past the end is a legitimate answer.
		return []orgLicenseComponentResponse{}
	}
	end := offset + perPage
	if end > len(rows) {
		end = len(rows)
	}
	return rows[offset:end]
}

// buildOrgLicenseComponents groups the flat rows by purl@version, applies the
// filter, and orders most restrictive first so the first page is the one worth
// reading. Pure, for the same reason buildOrgLicenseOverview is.
func buildOrgLicenseComponents(
	rows []dbgen.ListComponentLicensesBySnapshotsRow,
	repos map[uuid.UUID]orgRepoSnapshot,
	filter orgLicenseComponentFilter,
) []orgLicenseComponentResponse {
	type aggregate struct {
		row   orgLicenseComponentResponse
		repos map[string]struct{}
	}
	byKey := make(map[string]*aggregate)

	for _, row := range rows {
		pair, known := repos[row.RepoID]
		if !known || pair.repo == nil {
			continue
		}
		key := row.Purl + "@" + row.Version
		entry, seen := byKey[key]
		if !seen {
			facts := summarizeComponentLicenses(row.Licenses)
			entry = &aggregate{
				row: orgLicenseComponentResponse{
					Purl:      row.Purl,
					Name:      row.Name,
					Version:   row.Version,
					Ecosystem: row.Ecosystem,
					Licenses:  facts.entries,
					Category:  string(facts.category),
					Declared:  facts.declared,
				},
				repos: make(map[string]struct{}),
			}
			byKey[key] = entry
		}
		entry.repos[pair.repo.Slug] = struct{}{}
	}

	out := make([]orgLicenseComponentResponse, 0, len(byKey))
	for _, entry := range byKey {
		slugs := make([]string, 0, len(entry.repos))
		for slug := range entry.repos {
			slugs = append(slugs, slug)
		}
		sort.Strings(slugs)
		entry.row.Repos = slugs
		if !filter.matches(entry.row) {
			continue
		}
		out = append(out, entry.row)
	}

	sort.SliceStable(out, func(i, j int) bool {
		left, right := categoryRank(out[i].Category), categoryRank(out[j].Category)
		if left != right {
			return left > right
		}
		if len(out[i].Repos) != len(out[j].Repos) {
			return len(out[i].Repos) > len(out[j].Repos)
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		// Purl before version, and purl is what makes this comparator TOTAL:
		// two components can share a name and a version (the same package in two
		// ecosystems), and the rows arrive in Go map order. A stable sort over a
		// randomized input with ties is not deterministic, which for a paginated
		// endpoint means a component can appear on two pages or on none.
		if out[i].Purl != out[j].Purl {
			return out[i].Purl < out[j].Purl
		}
		return out[i].Version < out[j].Version
	})
	return out
}

// categoryRank orders categories by how much attention a single component
// deserves. It is close to riskWeight but NOT identical — see the unknown case.
func categoryRank(category string) int {
	switch category {
	case string(license.CategorySourceAvailable):
		return 5
	case string(license.CategoryNetworkCopyleft):
		return 4
	case string(license.CategoryCopyleft):
		return 3
	// Unknown above weak-copyleft here, and BELOW it in riskWeight — deliberately.
	// This ranks one component, where an unreviewed licence is the worse of the
	// two (internal/license.rank agrees). riskWeight ranks a whole repository,
	// where hundreds of undeclared components are usually one broken SBOM
	// generator and would otherwise swamp a repo carrying a single real AGPL
	// obligation.
	case string(license.CategoryUnknown):
		return 2
	case string(license.CategoryWeakCopyleft):
		return 1
	default:
		return 0
	}
}

// Org policy + per-repository override status. Compliance needs the org-wide
// answer to "what do we enforce, and who has departed from it", and the only way
// to know a repository's declared policy is to read its `.hibou.yaml` from the
// forge — one fetch per repository.
//
// That fan-out is why this is a SEPARATE endpoint rather than part of the license
// overview: a dashboard must not make N forge calls on load, but a compliance
// check a human explicitly asks for legitimately can.

type orgLicensePolicyRepo struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
	// Source is "organization" when the repo inherits, "repository" when it
	// declares its own, "none" when no policy applies at all.
	Source string `json:"source"`
	// Relation is set only for a repository that declares its own policy:
	// equivalent / stricter / looser / mixed against the org's.
	Relation    string           `json:"relation,omitempty"`
	Differences []orgLicenseDiff `json:"differences,omitempty"`
	// Unreadable marks a repository whose config could not be fetched. Reported
	// rather than assumed compliant — an unknown is not a pass.
	Unreadable bool `json:"unreadable"`
}

type orgLicenseDiff struct {
	Field     string `json:"field"`
	Direction string `json:"direction"`
	Base      string `json:"base"`
	Override  string `json:"override"`
	// Added/Removed are the delta for set-valued axes. The full Base/Override
	// lists are unreadable on a real policy, so the UI renders these.
	Added   []string `json:"added,omitempty"`
	Removed []string `json:"removed,omitempty"`
}

type orgLicensePolicySpec struct {
	DenyCategories []string `json:"deny_categories"`
	Deny           []string `json:"deny"`
	Allow          []string `json:"allow"`
	ExemptPurls    []string `json:"exempt_purls"`
	DenyUnknown    bool     `json:"deny_unknown"`
	Evaluate       string   `json:"evaluate"`
}

type orgLicensePolicyResponse struct {
	Configured bool                   `json:"configured"`
	Policy     *orgLicensePolicySpec  `json:"policy,omitempty"`
	Repos      []orgLicensePolicyRepo `json:"repos"`
	// ReposScanned distinguishes "no repository overrides" from "repositories
	// were not checked". Without it an empty list reads as an all-clear.
	ReposScanned bool `json:"repos_scanned"`
	// Counts for the compliance headline. Departures is what someone is actually
	// looking for; the rest is denominator.
	Total      int `json:"total"`
	Inheriting int `json:"inheriting"`
	Overriding int `json:"overriding"`
	Departures int `json:"departures"`
	Unreadable int `json:"unreadable"`
}

// @Summary      Organization license policy and repository overrides
// @Description  The org's license policy. With include_repos=true it also reports, for every enrolled repository, whether it inherits or overrides the policy and in which direction — which costs one forge request per repository, so it is opt-in.
// @Tags         organizations
// @Produce      json
// @Param        provider  path  string  true  "Forge provider"
// @Param        slug           path   string  true   "Organization slug"
// @Param        include_repos  query  bool    false  "Also check each repository's .hibou.yaml for an override (one forge request per repository)"
// @Success      200  {object}  orgLicensePolicyResponse
// @Router       /orgs/{provider}/{slug}/licenses/policy [get]
func (s *Server) handleGetOrgLicensePolicy(w http.ResponseWriter, r *http.Request) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok {
		return
	}
	if !s.enforceOrgWideCapability(w, r, apitoken.CapComponents, apitoken.AccessRead, org.Slug) {
		return
	}

	orgSpec, err := s.queries.GetOrgLicensePolicy(r.Context(), org.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load the organization license policy")
		return
	}

	response := orgLicensePolicyResponse{
		Configured: orgSpec != nil && !orgSpec.Empty(),
		Repos:      []orgLicensePolicyRepo{},
	}
	if orgSpec != nil {
		response.Policy = policySpecResponse(*orgSpec)
	}

	// Reading the policy is one query; discovering which repositories override it
	// costs a forge request each. Keeping them behind one call forced every
	// caller to pay for the fan-out — including the settings form, which only
	// ever wanted the policy. So the scan is opt-in.
	if !queryFlag(r, "include_repos") {
		response.ReposScanned = false
		api.JSON(w, http.StatusOK, response)
		return
	}
	response.ReposScanned = true

	repos, _, err := s.listRepositoryInventory(r, org)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to resolve repository inventory")
		return
	}

	for _, entry := range repos {
		if !entry.Enrolled || entry.ID == nil {
			continue
		}
		repo, repoErr := s.queries.GetRepositoryByID(r.Context(), *entry.ID)
		if repoErr != nil || repo == nil {
			continue
		}
		response.Repos = append(response.Repos, s.repoLicensePolicyStatus(r, repo, orgSpec))
	}

	response.Total = len(response.Repos)
	for _, repo := range response.Repos {
		switch {
		case repo.Unreadable:
			response.Unreadable++
		case repo.Source == delta.LicenseSourceRepository:
			response.Overriding++
			// Only a loosening or a mixed change needs chasing; a repository
			// tightening its own policy is not a compliance exception.
			if repo.Relation == string(license.RelationLooser) || repo.Relation == string(license.RelationMixed) {
				response.Departures++
			}
		case repo.Source == delta.LicenseSourceOrganization:
			response.Inheriting++
		}
	}

	// Departures first, then unreadable, then everything else: the list is read
	// top-down by someone looking for exceptions.
	sort.SliceStable(response.Repos, func(i, j int) bool {
		left, right := policyAttentionRank(response.Repos[i]), policyAttentionRank(response.Repos[j])
		if left != right {
			return left > right
		}
		return response.Repos[i].Slug < response.Repos[j].Slug
	})

	api.JSON(w, http.StatusOK, response)
}

func policyAttentionRank(repo orgLicensePolicyRepo) int {
	switch {
	case repo.Relation == string(license.RelationMixed):
		return 4
	case repo.Relation == string(license.RelationLooser):
		return 3
	case repo.Unreadable:
		return 2
	case repo.Source == delta.LicenseSourceRepository:
		return 1
	default:
		return 0
	}
}

// repoLicensePolicyStatus resolves one repository's policy the same way the gate
// does, so the compliance answer and the gate outcome cannot disagree.
func (s *Server) repoLicensePolicyStatus(r *http.Request, repo *store.Repository, orgSpec *license.Spec) orgLicensePolicyRepo {
	status := orgLicensePolicyRepo{Slug: repo.Slug, Name: repo.Name, Source: "none"}

	if s.repoConfigLoader == nil {
		status.Unreadable = true
		return status
	}
	owner, name, resolved := repoCoordinates(repo.ProviderID, repo.Name, repo.Slug)
	if !resolved {
		status.Unreadable = true
		return status
	}
	cfg, err := s.repoConfigLoader.Load(r.Context(), repo.Provider, owner, name, repo.DefaultBranch)
	if err != nil {
		// One unreachable repository must not fail the whole report, but it must
		// not be counted as compliant either.
		s.log.Warn().Err(err).Str("repo_id", repo.ID.String()).Msg("load repo config for license policy compliance")
		status.Unreadable = true
		return status
	}

	matched := cfg.MatchGate(repo.DefaultBranch)
	if matched == nil || matched.Licenses == nil {
		if orgSpec != nil && !orgSpec.Empty() {
			status.Source = delta.LicenseSourceOrganization
		}
		return status
	}

	status.Source = delta.LicenseSourceRepository
	repoSpec := license.Spec{
		DenyCategories: matched.Licenses.DenyCategories,
		Deny:           matched.Licenses.Deny,
		Allow:          matched.Licenses.Allow,
		ExemptPurls:    matched.Licenses.ExemptPurls,
		DenyUnknown:    matched.Licenses.DenyUnknownValue(),
		Evaluate:       matched.Licenses.EvaluateValue(),
	}
	if orgSpec == nil || orgSpec.Empty() {
		// Nothing to compare against: the repository's policy is the only one.
		return status
	}

	relation, differences := license.Compare(*orgSpec, repoSpec)
	status.Relation = string(relation)
	for _, difference := range differences {
		status.Differences = append(status.Differences, orgLicenseDiff{
			Field:     difference.Field,
			Direction: string(difference.Direction),
			Base:      difference.Base,
			Override:  difference.Override,
			Added:     difference.Added,
			Removed:   difference.Removed,
		})
	}
	return status
}

func policySpecResponse(spec license.Spec) *orgLicensePolicySpec {
	return &orgLicensePolicySpec{
		DenyCategories: nonNilStringSlice(spec.DenyCategories),
		Deny:           nonNilStringSlice(spec.Deny),
		Allow:          nonNilStringSlice(spec.Allow),
		ExemptPurls:    nonNilStringSlice(spec.ExemptPurls),
		DenyUnknown:    spec.DenyUnknown,
		Evaluate:       spec.EvaluateValue(),
	}
}

func nonNilStringSlice(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

type updateOrgLicensePolicyRequest struct {
	DenyCategories []string `json:"deny_categories"`
	Deny           []string `json:"deny"`
	Allow          []string `json:"allow"`
	ExemptPurls    []string `json:"exempt_purls"`
	// Pointer so "not sent" is distinguishable from "sent as false"; absent
	// means the fail-closed default.
	DenyUnknown *bool  `json:"deny_unknown"`
	Evaluate    string `json:"evaluate"`
	// Enabled false retires the policy without deleting it.
	Enabled *bool `json:"enabled"`
}

// @Summary      Set the organization license policy
// @Description  Writes the org's single active license policy. Repositories inherit it and may override it in their .hibou.yaml; overrides are reported by the policy compliance endpoint.
// @Tags         organizations
// @Accept       json
// @Produce      json
// @Param        provider  path  string  true  "Forge provider"
// @Param        slug      path  string  true  "Organization slug"
// @Success      200  {object}  orgLicensePolicyResponse
// @Router       /orgs/{provider}/{slug}/licenses/policy [put]
func (s *Server) handleUpdateOrgLicensePolicy(w http.ResponseWriter, r *http.Request) {
	// Writing the policy is an admin act: it changes what every repository in
	// the org is held to.
	org, user, ok := s.loadOrgAdminUser(r, w)
	if !ok {
		return
	}
	if !s.enforceOrgWideCapability(w, r, apitoken.CapAdmin, apitoken.AccessWrite, org.Slug) {
		return
	}

	var request updateOrgLicensePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var actor *uuid.UUID
	if user != nil {
		actorID := user.ID
		actor = &actorID
	}

	if request.Enabled != nil && !*request.Enabled {
		if err := s.queries.DisableOrgLicensePolicy(r.Context(), org.ID, actor); err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to disable the license policy")
			return
		}
		s.writeAuditLog(r, user, orgAuditID(org.ID), auditEntry{
			Action:       audit.ActionSettingUpdate,
			ResourceType: "license_policy",
			ResourceID:   org.ID.String(),
			Context:      map[string]any{"enabled": false},
		})
		api.JSON(w, http.StatusOK, orgLicensePolicyResponse{Configured: false, Repos: []orgLicensePolicyRepo{}})
		return
	}

	// Reject unknown categories here rather than letting them sit in the
	// database silently matching nothing.
	for _, category := range request.DenyCategories {
		if !validLicenseCategory(category) {
			api.JSONError(w, http.StatusBadRequest, fmt.Sprintf("unknown license category %q", category))
			return
		}
	}
	evaluate := strings.ToLower(strings.TrimSpace(request.Evaluate))
	if evaluate != "" && evaluate != license.EvaluateNew && evaluate != license.EvaluateAll {
		api.JSONError(w, http.StatusBadRequest, fmt.Sprintf("evaluate must be %q or %q", license.EvaluateNew, license.EvaluateAll))
		return
	}

	denyUnknown := true
	if request.DenyUnknown != nil {
		denyUnknown = *request.DenyUnknown
	}
	spec := license.Spec{
		DenyCategories: request.DenyCategories,
		Deny:           request.Deny,
		Allow:          request.Allow,
		ExemptPurls:    request.ExemptPurls,
		DenyUnknown:    denyUnknown,
		Evaluate:       evaluate,
	}

	written, err := s.queries.UpsertOrgLicensePolicy(r.Context(), org.ID, "default", spec, actor)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to save the license policy")
		return
	}
	// The policy is a compliance artefact, so the whole of it is recorded, not
	// just the fields that changed.
	s.writeAuditLog(r, user, orgAuditID(org.ID), auditEntry{
		Action:       audit.ActionSettingUpdate,
		ResourceType: "license_policy",
		ResourceID:   org.ID.String(),
		Context: map[string]any{
			"deny_categories": written.DenyCategories,
			"deny":            written.Deny,
			"allow":           written.Allow,
			"exempt_purls":    written.ExemptPurls,
			"deny_unknown":    written.DenyUnknown,
			"evaluate":        written.EvaluateValue(),
		},
	})

	api.JSON(w, http.StatusOK, orgLicensePolicyResponse{
		Configured: !written.Empty(),
		Policy:     policySpecResponse(*written),
		Repos:      []orgLicensePolicyRepo{},
	})
}

// queryFlag reads a boolean query parameter, treating only explicit truthy
// values as set so a bare `?include_repos` typo cannot silently trigger a
// per-repository forge fan-out.
func queryFlag(r *http.Request, name string) bool {
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get(name))) {
	case "true", "1", "yes":
		return true
	default:
		return false
	}
}

func validLicenseCategory(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	for _, category := range license.Categories() {
		if normalized == string(category) {
			return true
		}
	}
	return false
}

// Policy simulation: what would this policy flag, before anyone adopts it.
//
// Evaluated with license.Policy.Evaluate rather than by summing category
// counts, because Evaluate and CategorizeAll deliberately disagree on OR
// expressions (see ADR-029) — `MIT OR GPL-3.0-only` displays as permissive but a
// tile-summing simulator would still have to guess. Only the real evaluator
// gives the number the gate would actually produce.
//
// Costs no forge requests: it reads components already in the database.

type orgLicenseSimulationRepo struct {
	Slug  string `json:"slug"`
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type orgLicenseSimulationResponse struct {
	// ComponentsTotal is the denominator: an unqualified "12 would be flagged"
	// means nothing without it.
	ComponentsTotal   int `json:"components_total"`
	ComponentsFlagged int `json:"components_flagged"`
	// Exempted counts components a rule would have flagged but exempt_purls
	// clears, so the effect of that list is visible rather than inferred.
	Exempted   int `json:"exempted"`
	ReposTotal int `json:"repos_total"`
	// Repos lists only those with at least one flagged component, worst first.
	Repos []orgLicenseSimulationRepo `json:"repos"`
	// Licenses that would trip the policy, most components first.
	Licenses []orgLicenseStat `json:"licenses"`
}

// @Summary      Simulate a license policy
// @Description  Reports how many components across the organization a candidate policy would flag, without saving it. Reads stored components only — no forge requests.
// @Tags         organizations
// @Accept       json
// @Produce      json
// @Param        provider  path  string  true  "Forge provider"
// @Param        slug      path  string  true  "Organization slug"
// @Success      200  {object}  orgLicenseSimulationResponse
// @Router       /orgs/{provider}/{slug}/licenses/simulate [post]
func (s *Server) handleSimulateOrgLicensePolicy(w http.ResponseWriter, r *http.Request) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok {
		return
	}
	if !s.enforceOrgWideCapability(w, r, apitoken.CapComponents, apitoken.AccessRead, org.Slug) {
		return
	}

	var request updateOrgLicensePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	for _, category := range request.DenyCategories {
		if !validLicenseCategory(category) {
			api.JSONError(w, http.StatusBadRequest, fmt.Sprintf("unknown license category %q", category))
			return
		}
	}

	denyUnknown := true
	if request.DenyUnknown != nil {
		denyUnknown = *request.DenyUnknown
	}
	spec := license.Spec{
		DenyCategories: request.DenyCategories,
		Deny:           request.Deny,
		Allow:          request.Allow,
		ExemptPurls:    request.ExemptPurls,
		DenyUnknown:    denyUnknown,
		Evaluate:       request.Evaluate,
	}

	pairs, err := s.currentRepoSnapshots(r, org)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to resolve repository snapshots")
		return
	}
	snapshotIDs := make([]uuid.UUID, 0, len(pairs))
	repoBySnapshot := make(map[uuid.UUID]orgRepoSnapshot, len(pairs))
	for _, pair := range pairs {
		snapshotIDs = append(snapshotIDs, pair.snapshot.ID)
		repoBySnapshot[pair.repo.ID] = pair
	}
	if len(snapshotIDs) == 0 {
		api.JSON(w, http.StatusOK, orgLicenseSimulationResponse{
			Repos:    []orgLicenseSimulationRepo{},
			Licenses: []orgLicenseStat{},
		})
		return
	}

	rows, err := s.queries.ListComponentLicensesBySnapshots(r.Context(), snapshotIDs)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list component licenses")
		return
	}

	api.JSON(w, http.StatusOK, simulateLicensePolicy(rows, repoBySnapshot, spec))
}

// simulateLicensePolicy is pure so the counting can be tested without a database,
// and so it cannot drift from the gate's own arithmetic unnoticed.
func simulateLicensePolicy(
	rows []dbgen.ListComponentLicensesBySnapshotsRow,
	repos map[uuid.UUID]orgRepoSnapshot,
	spec license.Spec,
) orgLicenseSimulationResponse {
	response := orgLicenseSimulationResponse{
		Repos:    []orgLicenseSimulationRepo{},
		Licenses: []orgLicenseStat{},
	}
	policy := spec.Policy()

	// Components are deduped by purl@version so the total matches the overview's,
	// while per-repo counts stay per-repo.
	type componentVerdict struct {
		flagged  bool
		exempted bool
		license  string
		category license.Category
	}
	verdicts := make(map[string]componentVerdict)
	flaggedByRepo := make(map[uuid.UUID]map[string]struct{})
	seenRepos := make(map[uuid.UUID]struct{})

	for _, row := range rows {
		if _, known := repos[row.RepoID]; !known {
			continue
		}
		seenRepos[row.RepoID] = struct{}{}
		key := row.Purl + "@" + row.Version

		verdict, evaluated := verdicts[key]
		if !evaluated {
			verdict = componentVerdict{}
			if !policy.Empty() {
				if violation := policy.Evaluate(license.NormalizeIDs(row.Licenses)); violation != nil {
					// Exemption is checked after evaluation so the count reflects
					// what the list actually suppresses.
					if license.MatchesPurlGlob(row.Purl, spec.ExemptPurls) {
						verdict.exempted = true
					} else {
						verdict.flagged = true
						verdict.license = violation.License
						if verdict.license == "" {
							verdict.license = "no license metadata"
						}
						verdict.category = violation.Category
					}
				}
			}
			verdicts[key] = verdict
		}
		if verdict.flagged {
			if flaggedByRepo[row.RepoID] == nil {
				flaggedByRepo[row.RepoID] = make(map[string]struct{})
			}
			flaggedByRepo[row.RepoID][key] = struct{}{}
		}
	}

	byLicense := make(map[string]*orgLicenseStat)
	for _, verdict := range verdicts {
		response.ComponentsTotal++
		if verdict.exempted {
			response.Exempted++
		}
		if !verdict.flagged {
			continue
		}
		response.ComponentsFlagged++
		stat, ok := byLicense[verdict.license]
		if !ok {
			stat = &orgLicenseStat{License: verdict.license, Category: string(verdict.category)}
			byLicense[verdict.license] = stat
		}
		stat.Components++
	}
	response.ReposTotal = len(seenRepos)

	for repoID, flagged := range flaggedByRepo {
		pair := repos[repoID]
		if pair.repo == nil || len(flagged) == 0 {
			continue
		}
		response.Repos = append(response.Repos, orgLicenseSimulationRepo{
			Slug: pair.repo.Slug, Name: pair.repo.Name, Count: len(flagged),
		})
	}
	sort.SliceStable(response.Repos, func(i, j int) bool {
		if response.Repos[i].Count != response.Repos[j].Count {
			return response.Repos[i].Count > response.Repos[j].Count
		}
		return response.Repos[i].Slug < response.Repos[j].Slug
	})

	for _, stat := range byLicense {
		response.Licenses = append(response.Licenses, *stat)
	}
	sort.SliceStable(response.Licenses, func(i, j int) bool {
		if response.Licenses[i].Components != response.Licenses[j].Components {
			return response.Licenses[i].Components > response.Licenses[j].Components
		}
		return response.Licenses[i].License < response.Licenses[j].License
	})
	return response
}
