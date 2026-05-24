package server

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/hibouhq/lehibou/internal/api"
)

type searchResultResponse struct {
	Type     string         `json:"type"`
	ID       string         `json:"id"`
	Title    string         `json:"title"`
	Subtitle string         `json:"subtitle"`
	Severity *string        `json:"severity,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

type searchResponse struct {
	Results    []searchResultResponse `json:"results"`
	Pagination api.Pagination         `json:"pagination"`
}

// @Summary      Global search
// @Description  Search vulnerabilities, components, findings, or clients within an organization
// @Tags         search
// @Produce      json
// @Param        provider  path      string  true   "Forge provider"
// @Param        slug      path      string  true   "Organization slug"
// @Param        q         query     string  false  "Search query"
// @Param        type      query     string  false  "Result type: vuln, component, finding, client"
// @Param        severity  query     string  false  "Severity filter for vulnerabilities or findings"
// @Param        page      query     int     false  "Page number"
// @Param        per_page  query     int     false  "Items per page"
// @Success      200       {object}  api.Response{data=server.searchResponse}
// @Failure      401       {object}  api.Response
// @Failure      404       {object}  api.Response
// @Failure      500       {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/search [get]
func (s *Server) handleGlobalSearch(w http.ResponseWriter, r *http.Request) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok {
		return
	}

	pagination := api.ParsePagination(r)
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	resultType := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("type")))
	severity := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("severity")))

	var (
		results []searchResultResponse
		total   int
		err     error
	)

	switch resultType {
	case "", "all":
		results, total, err = s.searchAllTypes(r, org.ID, query, pagination)
	case "vuln", "vulnerability", "vulnerabilities":
		results, total, err = s.searchAdvisories(r, org.ID, query, severity, pagination.PerPage, pagination.Offset)
	case "component", "components":
		results, total, err = s.searchComponents(r, org.ID, query, pagination.PerPage, pagination.Offset)
	case "finding", "findings":
		results, total, err = s.searchFindings(r, org.ID, query, severity, pagination.PerPage, pagination.Offset)
	case "client", "clients":
		results, total, err = s.searchClients(r, org.ID, query, pagination.PerPage, pagination.Offset)
	default:
		api.JSONError(w, http.StatusBadRequest, "invalid search type")
		return
	}
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to search organization")
		return
	}

	api.JSON(w, http.StatusOK, searchResponse{
		Results: results,
		Pagination: api.Pagination{
			Page:    pagination.Page,
			PerPage: pagination.PerPage,
			Total:   total,
		},
	})
}

func (s *Server) searchAllTypes(r *http.Request, orgID uuid.UUID, query string, pagination api.PaginationParams) ([]searchResultResponse, int, error) {
	fetchLimit := pagination.Page * pagination.PerPage
	advisories, advisoryTotal, err := s.searchAdvisories(r, orgID, query, "", fetchLimit, 0)
	if err != nil {
		return nil, 0, err
	}
	components, componentTotal, err := s.searchComponents(r, orgID, query, fetchLimit, 0)
	if err != nil {
		return nil, 0, err
	}
	findings, findingTotal, err := s.searchFindings(r, orgID, query, "", fetchLimit, 0)
	if err != nil {
		return nil, 0, err
	}
	clients, clientTotal, err := s.searchClients(r, orgID, query, fetchLimit, 0)
	if err != nil {
		return nil, 0, err
	}

	results := append(advisories, components...)
	results = append(results, findings...)
	results = append(results, clients...)
	sort.SliceStable(results, func(i, j int) bool {
		left := results[i]
		right := results[j]
		if left.Type == right.Type {
			return left.Title < right.Title
		}
		return left.Type < right.Type
	})

	return paginateSlice(results, pagination.Offset, pagination.PerPage), advisoryTotal + componentTotal + findingTotal + clientTotal, nil
}

func (s *Server) searchAdvisories(r *http.Request, orgID uuid.UUID, query, severity string, limit, offset int) ([]searchResultResponse, int, error) {
	rows, total, err := s.queries.SearchAdvisories(r.Context(), orgID, query, severity, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	results := make([]searchResultResponse, 0, len(rows))
	for _, advisory := range rows {
		severityValue := string(advisory.Severity)
		title := strings.TrimSpace(advisory.Title)
		if title == "" {
			title = advisory.CanonicalID
		}
		results = append(results, searchResultResponse{
			Type:     "vulnerability",
			ID:       advisory.ID.String(),
			Title:    title,
			Subtitle: advisory.CanonicalID,
			Severity: &severityValue,
			Metadata: map[string]any{"canonical_id": advisory.CanonicalID, "is_malware": advisory.IsMalware},
		})
	}
	return results, total, nil
}

func stringValueFromJSONMap(raw json.RawMessage, key string) string {
	if len(raw) == 0 {
		return ""
	}

	values := map[string]string{}
	if err := json.Unmarshal(raw, &values); err != nil {
		return ""
	}

	return values[key]
}

func (s *Server) searchComponents(r *http.Request, orgID uuid.UUID, query string, limit, offset int) ([]searchResultResponse, int, error) {
	rows, total, err := s.queries.SearchComponents(r.Context(), orgID, query, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	results := make([]searchResultResponse, 0, len(rows))
	for _, component := range rows {
		results = append(results, searchResultResponse{
			Type:     "component",
			ID:       component.ID.String(),
			Title:    component.Name + "@" + component.Version,
			Subtitle: component.Purl,
			Metadata: map[string]any{"ecosystem": component.Ecosystem, "purl": component.Purl},
		})
	}
	return results, total, nil
}

func (s *Server) searchFindings(r *http.Request, orgID uuid.UUID, query, severity string, limit, offset int) ([]searchResultResponse, int, error) {
	rows, total, err := s.queries.SearchFindings(r.Context(), orgID, query, severity, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	results := make([]searchResultResponse, 0, len(rows))
	for _, finding := range rows {
		severityValue := string(finding.Severity)
		results = append(results, searchResultResponse{
			Type:     "finding",
			ID:       finding.ID.String(),
			Title:    finding.RuleID,
			Subtitle: finding.Tool + " • " + finding.Message,
			Severity: &severityValue,
			Metadata: map[string]any{"snapshot_id": finding.SnapshotID.String(), "file_path": finding.FilePath, "tool": finding.Tool},
		})
	}
	return results, total, nil
}

func (s *Server) searchClients(r *http.Request, orgID uuid.UUID, query string, limit, offset int) ([]searchResultResponse, int, error) {
	rows, total, err := s.queries.SearchClients(r.Context(), orgID, query, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	results := make([]searchResultResponse, 0, len(rows))
	for _, client := range rows {
		subtitle := client.Slug
		metadata := map[string]any{"slug": client.Slug}
		if environment := strings.TrimSpace(stringValueFromJSONMap(client.Labels, "environment")); environment != "" {
			subtitle = environment
			metadata["environment"] = environment
		}
		results = append(results, searchResultResponse{
			Type:     "client",
			ID:       client.ID.String(),
			Title:    client.Name,
			Subtitle: subtitle,
			Metadata: metadata,
		})
	}
	return results, total, nil
}
