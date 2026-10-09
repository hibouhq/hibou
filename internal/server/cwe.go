package server

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/cwe"
	"github.com/hibouhq/hibou/internal/filterquery"
	"github.com/hibouhq/hibou/internal/store"
)

// cweCatalogEntryResponse is one catalog entry as the filter bar's
// completion and hover cards show it (ADR-037 §6).
type cweCatalogEntryResponse struct {
	ID          int          `json:"id"`
	Name        string       `json:"name"`
	Abstraction string       `json:"abstraction"`
	Deprecated  bool         `json:"deprecated,omitempty"`
	Category    *cwe.SetRef  `json:"category,omitempty"`
	Sets        []cwe.SetRef `json:"sets,omitempty"`
	// Descendants counts the View 1000 entries under this one, so a
	// cwe-tree: suggestion can say how much it covers.
	Descendants int `json:"descendants"`
	// Ancestors are the View 1000 parents, nearest first: what a cwe-tree:
	// query would have to name to include this CWE.
	Ancestors []int `json:"ancestors,omitempty"`
}

type cweCatalogResponse struct {
	Version string                    `json:"version"`
	Entries []cweCatalogEntryResponse `json:"entries"`
}

type cweSetResponse struct {
	Slug        string `json:"slug"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	MemberCount int    `json:"member_count"`
}

type cweSetsResponse struct {
	Version    string           `json:"version"`
	Sets       []cweSetResponse `json:"sets"`
	Categories []cweSetResponse `json:"categories"`
}

const maxCWECatalogResults = 100

// @Summary      Search the CWE catalog
// @Description  Embedded MITRE CWE catalog lookup for completion and hover: ids=79,89 resolves titles in one call; q=sql matches ids and titles. Reference data only — no tenant data — so any authenticated caller may use it. The response is stable for a catalog version and cacheable.
// @Tags         cwe
// @Produce      json
// @Param        q      query  string  false  "Id (79, CWE-79) or title fragment"
// @Param        ids    query  string  false  "Comma-separated ids to resolve"
// @Param        limit  query  int     false  "Maximum results for q (default 20, max 100)"
// @Param        abstraction  query  string  false  "Without q/ids: list entries of these abstractions (pillar,class)"
// @Success      200  {object}  api.Response{data=server.cweCatalogResponse}
// @Security     BearerAuth
// @Router       /cwe [get]
func (s *Server) handleSearchCWECatalog(w http.ResponseWriter, r *http.Request) {
	catalog := cwe.Default()
	response := cweCatalogResponse{Version: catalog.Version, Entries: []cweCatalogEntryResponse{}}

	if raw := strings.TrimSpace(r.URL.Query().Get("ids")); raw != "" {
		ids := cwe.ParseAll(strings.Split(raw, ","))
		if len(ids) > maxCWECatalogResults {
			ids = ids[:maxCWECatalogResults]
		}
		for _, id := range ids {
			entry, ok := catalog.Lookup(id)
			if !ok {
				// Unknown to the catalog but still a real producer claim: the
				// client shows it without a title rather than dropping it.
				response.Entries = append(response.Entries, cweCatalogEntryResponse{ID: id})
				continue
			}
			response.Entries = append(response.Entries, catalogEntryResponse(catalog, entry))
		}
	} else if query := strings.TrimSpace(r.URL.Query().Get("q")); query != "" {
		limit := 20
		if parsed, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && parsed > 0 {
			limit = min(parsed, maxCWECatalogResults)
		}
		for _, entry := range catalog.Search(query, limit) {
			response.Entries = append(response.Entries, catalogEntryResponse(catalog, entry))
		}
	} else if raw := strings.TrimSpace(r.URL.Query().Get("abstraction")); raw != "" {
		// The roots a cwe-tree: query starts from when nothing is typed.
		entries := catalog.ByAbstraction(strings.Split(raw, ",")...)
		if len(entries) > maxCWECatalogResults {
			entries = entries[:maxCWECatalogResults]
		}
		for _, entry := range entries {
			response.Entries = append(response.Entries, catalogEntryResponse(catalog, entry))
		}
	}

	w.Header().Set("Cache-Control", "private, max-age=3600")
	api.JSON(w, http.StatusOK, response)
}

func catalogEntryResponse(catalog *cwe.Catalog, entry cwe.Entry) cweCatalogEntryResponse {
	return cweCatalogEntryResponse{
		ID:          entry.ID,
		Name:        entry.Name,
		Abstraction: entry.Abstraction,
		Deprecated:  entry.Deprecated(),
		Category:    catalog.CategoryRef(entry.ID),
		Sets:        catalog.SetRefs(entry.ID),
		Descendants: len(catalog.Descendants(entry.ID)) - 1,
		Ancestors:   catalog.Ancestors(entry.ID),
	}
}

// @Summary      CWE named sets and categories
// @Description  The named sets cwe-set: accepts (CWE Top 25, OWASP Top 10 and its categories) and the MITRE View 1400 categories cwe-category: accepts, with the catalog edition in each name.
// @Tags         cwe
// @Produce      json
// @Success      200  {object}  api.Response{data=server.cweSetsResponse}
// @Security     BearerAuth
// @Router       /cwe/sets [get]
func (s *Server) handleListCWESets(w http.ResponseWriter, _ *http.Request) {
	catalog := cwe.Default()
	response := cweSetsResponse{Version: catalog.Version, Sets: []cweSetResponse{}, Categories: []cweSetResponse{}}
	for _, set := range catalog.Sets {
		entry := cweSetResponse{Slug: set.Slug, Name: set.Name, Kind: set.Kind, MemberCount: len(set.Members)}
		if set.Kind == cwe.SetKindCategory {
			response.Categories = append(response.Categories, entry)
			continue
		}
		response.Sets = append(response.Sets, entry)
	}
	w.Header().Set("Cache-Control", "private, max-age=3600")
	api.JSON(w, http.StatusOK, response)
}

// parseOptionalFilter compiles the bar's q once to validate it; nil when
// absent. It writes the 400 itself.
func parseOptionalFilter(w http.ResponseWriter, r *http.Request) (filterquery.Node, bool) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		return nil, true
	}
	node, err := filterquery.Parse(q)
	if err == nil {
		_, err = filterquery.ToSQL(node, 2)
	}
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid filter query")
		return nil, false
	}
	return node, true
}

// @Summary      CWEs in a repository
// @Description  Every CWE carried by the ref's findings, with per-type counts, plus how many findings carry none. q scopes it exactly like the findings list; without q, open findings are counted.
// @Tags         cwe
// @Produce      json
// @Param        provider  path   string  true   "Forge provider"
// @Param        slug      path   string  true   "Organization slug"
// @Param        repoSlug  path   string  true   "Repository slug"
// @Param        q         query  string  false  "Filter query (same grammar as the findings list)"
// @Success      200  {object}  api.Response{data=store.CWEUsageReport}
// @Failure      400  {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/cwes [get]
func (s *Server) handleGetRefCWEs(w http.ResponseWriter, r *http.Request) {
	_, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}
	filter, ok := parseOptionalFilter(w, r)
	if !ok {
		return
	}
	snapshot, ok := s.resolveSnapshotForRequestWithFallback(r, w, repo, s.queries.GetLatestSnapshotWithVulnerabilitiesByRef)
	if !ok {
		return
	}
	if snapshot == nil {
		api.JSON(w, http.StatusOK, &store.CWEUsageReport{CWEs: []store.CWEUsage{}})
		return
	}
	report, err := s.queries.ListCWEUsage(r.Context(), []uuid.UUID{snapshot.ID}, filter)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list cwes")
		return
	}
	api.JSON(w, http.StatusOK, report)
}

// @Summary      CWEs across an organization
// @Description  The CWE list over every repository's current snapshot. q scopes it like the org findings list; without q, open findings are counted.
// @Tags         cwe
// @Produce      json
// @Param        provider  path   string  true   "Forge provider"
// @Param        slug      path   string  true   "Organization slug"
// @Param        q         query  string  false  "Filter query (same grammar as the findings list)"
// @Success      200  {object}  api.Response{data=store.CWEUsageReport}
// @Failure      400  {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/cwes [get]
func (s *Server) handleListOrgCWEs(w http.ResponseWriter, r *http.Request) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok {
		return
	}
	if !s.enforceOrgWideCapability(w, r, apitoken.CapVulnerabilities, apitoken.AccessRead, org.Slug) {
		return
	}
	filter, ok := parseOptionalFilter(w, r)
	if !ok {
		return
	}
	pairs, err := s.currentRepoSnapshots(r, org)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to resolve repository snapshots")
		return
	}
	snapshotIDs := make([]uuid.UUID, 0, len(pairs))
	for _, pair := range pairs {
		snapshotIDs = append(snapshotIDs, pair.snapshot.ID)
	}
	report, err := s.queries.ListCWEUsage(r.Context(), snapshotIDs, filter)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list cwes")
		return
	}
	api.JSON(w, http.StatusOK, report)
}
