package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/hibouhq/lehibou/internal/api"
)

// @Summary      List repositories
// @Description  List repositories in an organization visible to organization members
// @Tags         repositories
// @Produce      json
// @Param        slug      path      string  true   "Organization slug"
// @Param        page      query     int     false  "Page number"
// @Param        per_page  query     int     false  "Items per page"
// @Success      200       {object}  api.ListResponse{data=[]store.Repository}
// @Failure      401       {object}  api.Response
// @Failure      404       {object}  api.Response
// @Failure      500       {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{slug}/repos [get]
func (s *Server) handleListRepos(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	org, err := s.queries.GetOrganizationBySlug(r.Context(), chi.URLParam(r, "slug"))
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
// @Param        slug      path      string  true  "Organization slug"
// @Param        repoSlug  path      string  true  "Repository slug"
// @Success      200       {object}  api.Response{data=store.Repository}
// @Failure      401       {object}  api.Response
// @Failure      404       {object}  api.Response
// @Failure      500       {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{slug}/repos/{repoSlug} [get]
func (s *Server) handleGetRepo(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	org, err := s.queries.GetOrganizationBySlug(r.Context(), chi.URLParam(r, "slug"))
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