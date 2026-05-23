package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/lib/pq"

	"github.com/hibouhq/lehibou/internal/api"
)

type createOrgRequest struct {
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
}

type updateOrgRequest struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
}

// @Summary      Create organization
// @Description  Create a new organization and assign the caller as admin
// @Tags         organizations
// @Accept       json
// @Produce      json
// @Param        body  body      createOrgRequest  true  "Organization details"
// @Success      201   {object}  api.Response{data=store.Organization}
// @Failure      400   {object}  api.Response
// @Failure      401   {object}  api.Response
// @Failure      500   {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs [post]
func (s *Server) handleCreateOrg(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var input createOrgRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	input.Name = strings.TrimSpace(input.Name)
	input.Slug = strings.TrimSpace(input.Slug)
	input.DisplayName = strings.TrimSpace(input.DisplayName)

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
	if input.DisplayName == "" {
		api.JSONError(w, http.StatusBadRequest, "display_name is required")
		return
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to create organization")
		return
	}
	defer func() {
		_ = tx.Rollback()
	}()

	queries := s.queries.WithTx(tx)
	org, err := queries.CreateOrganization(r.Context(), input.Name, input.Slug, input.DisplayName)
	if err != nil {
		if isUniqueViolation(err) {
			api.JSONError(w, http.StatusBadRequest, "organization slug already exists")
			return
		}
		api.JSONError(w, http.StatusInternalServerError, "failed to create organization")
		return
	}

	if err := queries.AddOrgMember(r.Context(), org.ID, user.ID, "admin"); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to add organization member")
		return
	}
	if err := tx.Commit(); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to create organization")
		return
	}

	if s.enforcer != nil {
		if err := s.enforcer.SeedOrgPolicies(org.ID); err != nil {
			s.log.Error().Err(err).Str("org_id", org.ID.String()).Msg("failed to seed org RBAC policies")
		}
		if err := s.enforcer.AddRoleForUserInOrg(user.ID, "admin", org.ID); err != nil {
			s.log.Error().Err(err).Str("org_id", org.ID.String()).Str("user_id", user.ID.String()).Msg("failed to assign admin role")
		}
	}

	api.JSON(w, http.StatusCreated, org)
}

// @Summary      List organizations
// @Description  List organizations visible to the authenticated user
// @Tags         organizations
// @Produce      json
// @Param        page      query     int  false  "Page number"
// @Param        per_page  query     int  false  "Items per page"
// @Success      200       {object}  api.ListResponse{data=[]store.Organization}
// @Failure      401       {object}  api.Response
// @Failure      500       {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs [get]
func (s *Server) handleListOrgs(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	pagination := api.ParsePagination(r)
	orgs, total, err := s.queries.ListOrganizationsByUser(r.Context(), user.ID, pagination.PerPage, pagination.Offset)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list organizations")
		return
	}

	api.JSONList(w, orgs, pagination.Page, pagination.PerPage, total)
}

// @Summary      Get organization
// @Description  Get an organization by slug when the caller is a member
// @Tags         organizations
// @Produce      json
// @Param        slug  path      string  true  "Organization slug"
// @Success      200   {object}  api.Response{data=store.Organization}
// @Failure      401   {object}  api.Response
// @Failure      404   {object}  api.Response
// @Failure      500   {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{slug} [get]
func (s *Server) handleGetOrg(w http.ResponseWriter, r *http.Request) {
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
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load organization")
		return
	}
	if role == "" {
		api.JSONError(w, http.StatusNotFound, "organization not found")
		return
	}

	api.JSON(w, http.StatusOK, org)
}

// @Summary      Update organization
// @Description  Update an existing organization when the caller is an admin
// @Tags         organizations
// @Accept       json
// @Produce      json
// @Param        slug  path      string            true  "Organization slug"
// @Param        body  body      updateOrgRequest  true  "Organization updates"
// @Success      200   {object}  api.Response{data=store.Organization}
// @Failure      400   {object}  api.Response
// @Failure      401   {object}  api.Response
// @Failure      404   {object}  api.Response
// @Failure      500   {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{slug} [put]
func (s *Server) handleUpdateOrg(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	slug := chi.URLParam(r, "slug")
	if !api.IsValidSlug(slug) {
		api.JSONError(w, http.StatusBadRequest, "slug must be 2-63 characters of lowercase letters, numbers, or hyphens")
		return
	}

	org, err := s.queries.GetOrganizationBySlug(r.Context(), slug)
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
		api.JSONError(w, http.StatusNotFound, "organization not found")
		return
	}

	var input updateOrgRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	input.Name = strings.TrimSpace(input.Name)
	input.DisplayName = strings.TrimSpace(input.DisplayName)

	if input.Name == "" {
		api.JSONError(w, http.StatusBadRequest, "name is required")
		return
	}
	if input.DisplayName == "" {
		api.JSONError(w, http.StatusBadRequest, "display_name is required")
		return
	}

	updated, err := s.queries.UpdateOrganization(r.Context(), org.ID, input.Name, input.DisplayName)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to update organization")
		return
	}
	if updated == nil {
		api.JSONError(w, http.StatusNotFound, "organization not found")
		return
	}

	api.JSON(w, http.StatusOK, updated)
}

// @Summary      Delete organization
// @Description  Delete an organization when the caller is an admin
// @Tags         organizations
// @Produce      json
// @Param        slug  path  string  true  "Organization slug"
// @Success      204   "No Content"
// @Failure      401   {object}  api.Response
// @Failure      404   {object}  api.Response
// @Failure      500   {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{slug} [delete]
func (s *Server) handleDeleteOrg(w http.ResponseWriter, r *http.Request) {
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
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load organization")
		return
	}
	if role != "admin" {
		api.JSONError(w, http.StatusNotFound, "organization not found")
		return
	}

	if err := s.queries.DeleteOrganization(r.Context(), org.ID); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to delete organization")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func isUniqueViolation(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && pqErr.Code == "23505"
}
