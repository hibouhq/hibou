package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/hibouhq/lehibou/internal/api"
)

type createTeamRequest struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

type updateTeamRequest struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

// @Summary      Create team
// @Description  Create a team within an organization when the caller is an admin
// @Tags         teams
// @Accept       json
// @Produce      json
// @Param        provider  path      string             true  "Forge provider"
// @Param        slug  path      string             true  "Organization slug"
// @Param        payload  body      createTeamRequest  true  "Team details"
// @Success      201   {object}  api.Response{data=store.Team}
// @Failure      400   {object}  api.Response
// @Failure      401   {object}  api.Response
// @Failure      403   {object}  api.Response
// @Failure      404   {object}  api.Response
// @Failure      500   {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/teams [post]
func (s *Server) handleCreateTeam(w http.ResponseWriter, r *http.Request) {
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
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load organization")
		return
	}
	if role != "admin" {
		api.JSONError(w, http.StatusForbidden, "admin access required")
		return
	}

	var input createTeamRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	input.Name = strings.TrimSpace(input.Name)
	input.Slug = strings.TrimSpace(input.Slug)

	if input.Name == "" {
		api.JSONError(w, http.StatusBadRequest, "name is required")
		return
	}
	if input.Slug == "" {
		api.JSONError(w, http.StatusBadRequest, "slug is required")
		return
	}
	if !api.IsValidSlug(input.Slug) {
		api.JSONError(w, http.StatusBadRequest, "slug must be 2-63 characters of lowercase letters, numbers, or hyphens")
		return
	}

	team, err := s.queries.CreateTeam(r.Context(), org.ID, input.Name, input.Slug)
	if err != nil {
		if isUniqueViolation(err) {
			api.JSONError(w, http.StatusBadRequest, "team slug already exists in this organization")
			return
		}
		api.JSONError(w, http.StatusInternalServerError, "failed to create team")
		return
	}

	api.JSON(w, http.StatusCreated, team)
}

// @Summary      List teams
// @Description  List teams in an organization visible to organization members
// @Tags         teams
// @Produce      json
// @Param        provider  path      string  true   "Forge provider"
// @Param        slug      path      string  true   "Organization slug"
// @Param        page      query     int     false  "Page number"
// @Param        per_page  query     int     false  "Items per page"
// @Success      200       {object}  api.ListResponse{data=[]store.Team}
// @Failure      401       {object}  api.Response
// @Failure      404       {object}  api.Response
// @Failure      500       {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/teams [get]
func (s *Server) handleListTeams(w http.ResponseWriter, r *http.Request) {
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
	teams, total, err := s.queries.ListTeamsByOrg(r.Context(), org.ID, pagination.PerPage, pagination.Offset)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list teams")
		return
	}

	api.JSONList(w, teams, pagination.Page, pagination.PerPage, total)
}

// @Summary      Get team
// @Description  Get a team by slug when the caller belongs to the organization
// @Tags         teams
// @Produce      json
// @Param        provider  path      string  true  "Forge provider"
// @Param        slug      path      string  true  "Organization slug"
// @Param        teamSlug  path      string  true  "Team slug"
// @Success      200       {object}  api.Response{data=store.Team}
// @Failure      401       {object}  api.Response
// @Failure      404       {object}  api.Response
// @Failure      500       {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/teams/{teamSlug} [get]
func (s *Server) handleGetTeam(w http.ResponseWriter, r *http.Request) {
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

	team, err := s.queries.GetTeamBySlug(r.Context(), org.ID, chi.URLParam(r, "teamSlug"))
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load team")
		return
	}
	if team == nil {
		api.JSONError(w, http.StatusNotFound, "team not found")
		return
	}

	api.JSON(w, http.StatusOK, team)
}

// @Summary      Update team
// @Description  Update a team when the caller is an organization admin
// @Tags         teams
// @Accept       json
// @Produce      json
// @Param        provider  path      string             true  "Forge provider"
// @Param        slug      path      string             true  "Organization slug"
// @Param        teamSlug  path      string             true  "Team slug"
// @Param        payload   body      updateTeamRequest  true  "Team updates"
// @Success      200       {object}  api.Response{data=store.Team}
// @Failure      400       {object}  api.Response
// @Failure      401       {object}  api.Response
// @Failure      403       {object}  api.Response
// @Failure      404       {object}  api.Response
// @Failure      500       {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/teams/{teamSlug} [put]
func (s *Server) handleUpdateTeam(w http.ResponseWriter, r *http.Request) {
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
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load organization")
		return
	}
	if role != "admin" {
		api.JSONError(w, http.StatusForbidden, "admin access required")
		return
	}

	team, err := s.queries.GetTeamBySlug(r.Context(), org.ID, chi.URLParam(r, "teamSlug"))
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load team")
		return
	}
	if team == nil {
		api.JSONError(w, http.StatusNotFound, "team not found")
		return
	}

	var input updateTeamRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	input.Name = strings.TrimSpace(input.Name)
	input.Slug = strings.TrimSpace(input.Slug)

	if input.Name == "" {
		api.JSONError(w, http.StatusBadRequest, "name is required")
		return
	}
	if input.Slug == "" {
		api.JSONError(w, http.StatusBadRequest, "slug is required")
		return
	}
	if !api.IsValidSlug(input.Slug) {
		api.JSONError(w, http.StatusBadRequest, "slug must be 2-63 characters of lowercase letters, numbers, or hyphens")
		return
	}

	updated, err := s.queries.UpdateTeam(r.Context(), team.ID, input.Name, input.Slug)
	if err != nil {
		if isUniqueViolation(err) {
			api.JSONError(w, http.StatusBadRequest, "team slug already exists in this organization")
			return
		}
		api.JSONError(w, http.StatusInternalServerError, "failed to update team")
		return
	}
	if updated == nil {
		api.JSONError(w, http.StatusNotFound, "team not found")
		return
	}

	api.JSON(w, http.StatusOK, updated)
}

// @Summary      Delete team
// @Description  Delete a team when the caller is an organization admin
// @Tags         teams
// @Produce      json
// @Param        provider  path  string  true  "Forge provider"
// @Param        slug      path  string  true  "Organization slug"
// @Param        teamSlug  path  string  true  "Team slug"
// @Success      204       "No Content"
// @Failure      401       {object}  api.Response
// @Failure      403       {object}  api.Response
// @Failure      404       {object}  api.Response
// @Failure      500       {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/teams/{teamSlug} [delete]
func (s *Server) handleDeleteTeam(w http.ResponseWriter, r *http.Request) {
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
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load organization")
		return
	}
	if role != "admin" {
		api.JSONError(w, http.StatusForbidden, "admin access required")
		return
	}

	team, err := s.queries.GetTeamBySlug(r.Context(), org.ID, chi.URLParam(r, "teamSlug"))
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load team")
		return
	}
	if team == nil {
		api.JSONError(w, http.StatusNotFound, "team not found")
		return
	}

	if err := s.queries.DeleteTeam(r.Context(), team.ID); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to delete team")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
