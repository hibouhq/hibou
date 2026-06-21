package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/orgprovision"
	"github.com/hibouhq/hibou/internal/store"
)

type orgResponse struct {
	*store.Organization
	ForgeURL string `json:"forge_url,omitempty"`
	Role     string `json:"role,omitempty"`
}

type createOrgRequest struct {
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
	Provider    string `json:"provider"`
}

type updateOrgRequest struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
}

// @Summary      List onboardable organizations
// @Description  List forge accounts the authenticated user can onboard into Hibou
// @Tags         organizations
// @Produce      json
// @Success      200   {object}  api.Response{data=[]orgprovision.OnboardableAccount}
// @Failure      401   {object}  api.Response
// @Failure      500   {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/onboardable [get]
func (s *Server) handleListOnboardableOrgs(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if s.orgProvisionSvc == nil {
		api.JSON(w, http.StatusOK, []orgprovision.OnboardableAccount{})
		return
	}

	accounts, err := s.orgProvisionSvc.ListOnboardableAccounts(r.Context(), user)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list onboardable organizations")
		return
	}

	api.JSON(w, http.StatusOK, accounts)
}

// @Summary      Create organization
// @Description  Create a new organization and assign the caller as admin
// @Tags         organizations
// @Accept       json
// @Produce      json
// @Param        payload  body      createOrgRequest  true  "Organization details"
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

	input, ok := decodeCreateOrgInput(w, r)
	if !ok {
		return
	}
	if s.forges[input.Provider] != nil && s.orgProvisionSvc != nil {
		err := s.orgProvisionSvc.AuthorizeForgeOrgCreation(r.Context(), user, input.Provider, input.Slug)
		if errors.Is(err, orgprovision.ErrForgeOrgUnauthorized) {
			api.JSONError(w, http.StatusForbidden, "forge organization creation requires a verified forge admin of an installed account")
			return
		}
		if err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to authorize forge organization creation")
			return
		}
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to create organization")
		return
	}
	defer func() {
		_ = tx.Rollback()
	}()

	org, ok := s.createOrganizationWithDefaults(w, r, tx, user.ID, input)
	if !ok {
		return
	}

	if err := tx.Commit(); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to create organization")
		return
	}

	s.seedCreatedOrg(org.ID, user.ID)
	s.syncCreatedOrg(org)

	api.JSON(w, http.StatusCreated, org)
}

func decodeCreateOrgInput(w http.ResponseWriter, r *http.Request) (createOrgRequest, bool) {
	var input createOrgRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return createOrgRequest{}, false
	}
	input.Name = strings.TrimSpace(input.Name)
	input.Slug = strings.TrimSpace(input.Slug)
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	input.Provider = strings.TrimSpace(input.Provider)
	if input.Name == "" {
		api.JSONError(w, http.StatusBadRequest, "name is required")
		return createOrgRequest{}, false
	}
	if input.Slug == "" {
		api.JSONError(w, http.StatusBadRequest, "slug is required")
		return createOrgRequest{}, false
	}
	if !api.IsValidSlug(input.Slug) {
		api.JSONError(w, http.StatusBadRequest, "slug must be 2-63 characters of lowercase letters, numbers, or hyphens")
		return createOrgRequest{}, false
	}
	if input.DisplayName == "" {
		api.JSONError(w, http.StatusBadRequest, "display_name is required")
		return createOrgRequest{}, false
	}
	if input.Provider == "" {
		input.Provider = "github"
	}
	if !isValidOrgProvider(input.Provider) {
		api.JSONError(w, http.StatusBadRequest, "provider must be one of github, gitlab, or forgejo")
		return createOrgRequest{}, false
	}
	return input, true
}

func (s *Server) createOrganizationWithDefaults(w http.ResponseWriter, r *http.Request, tx *sql.Tx, userID uuid.UUID, input createOrgRequest) (*store.Organization, bool) {
	queries := s.queries.WithTx(tx)
	org, err := queries.CreateOrganization(r.Context(), input.Name, input.Slug, input.DisplayName, input.Provider)
	if err != nil {
		if isUniqueViolation(err) {
			api.JSONError(w, http.StatusBadRequest, "organization slug already exists")
		} else {
			api.JSONError(w, http.StatusInternalServerError, "failed to create organization")
		}
		return nil, false
	}
	if err := queries.AddOrgMember(r.Context(), org.ID, userID, "admin"); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to add organization member")
		return nil, false
	}
	if _, err := queries.CreateClient(r.Context(), org.ID, "Internal", "internal", nil, "internal", nil, nil, nil, nil); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to create default client")
		return nil, false
	}
	return org, true
}

func (s *Server) seedCreatedOrg(orgID, userID uuid.UUID) {
	if s.enforcer == nil {
		return
	}
	if err := s.enforcer.SeedOrgPolicies(orgID); err != nil {
		s.log.Error().Err(err).Str("org_id", orgID.String()).Msg("failed to seed org RBAC policies")
	}
	if err := s.enforcer.AddRoleForUserInOrg(userID, "admin", orgID); err != nil {
		s.log.Error().Err(err).Str("org_id", orgID.String()).Str("user_id", userID.String()).Msg("failed to assign admin role")
	}
}

func (s *Server) syncCreatedOrg(org *store.Organization) {
	if org == nil || s.inventorySvc == nil {
		return
	}
	ctx := s.lifecycleCtx
	if ctx == nil {
		ctx = context.Background()
	}
	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				s.log.Error().Interface("panic", recovered).Str("provider", org.Provider).Str("account", org.Slug).Msg("background repository inventory sync panicked")
			}
		}()
		if err := s.inventorySvc.Sync(ctx, org.Provider, org.Slug); err != nil {
			s.log.Error().Err(err).Str("provider", org.Provider).Str("account", org.Slug).Msg("background repository inventory sync failed")
		}
	}()
}

func isValidOrgProvider(provider string) bool {
	switch provider {
	case "github", "gitlab", "forgejo":
		return true
	default:
		return false
	}
}

func (s *Server) forgeWebURL(provider string) string {
	for _, fc := range s.cfg.Forges {
		if fc.ID == provider {
			if fc.URL != "" {
				return fc.URL
			}
			if fc.Type == "github" {
				return "https://github.com"
			}
			return ""
		}
	}
	return ""
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

	enriched := make([]orgResponse, len(orgs))
	for i := range orgs {
		role, roleErr := s.queries.GetOrgMemberRole(r.Context(), orgs[i].ID, user.ID)
		if roleErr != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to list organizations")
			return
		}
		enriched[i] = orgResponse{Organization: &orgs[i], ForgeURL: s.forgeWebURL(orgs[i].Provider), Role: role}
	}

	api.JSONList(w, enriched, pagination.Page, pagination.PerPage, total)
}

// @Summary      Get organization
// @Description  Get an organization by provider and slug when the caller is a member
// @Tags         organizations
// @Produce      json
// @Param        provider  path      string  true  "Forge provider"
// @Param        slug  path      string  true  "Organization slug"
// @Success      200   {object}  api.Response{data=orgResponse}
// @Failure      401   {object}  api.Response
// @Failure      404   {object}  api.Response
// @Failure      500   {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug} [get]
func (s *Server) handleGetOrg(w http.ResponseWriter, r *http.Request) {
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
	if role == "" {
		api.JSONError(w, http.StatusNotFound, "organization not found")
		return
	}

	api.JSON(w, http.StatusOK, orgResponse{Organization: org, ForgeURL: s.forgeWebURL(org.Provider), Role: role})
}

// @Summary      Update organization
// @Description  Update an existing organization when the caller is an admin
// @Tags         organizations
// @Accept       json
// @Produce      json
// @Param        provider  path      string            true  "Forge provider"
// @Param        slug  path      string            true  "Organization slug"
// @Param        payload  body      updateOrgRequest  true  "Organization updates"
// @Success      200   {object}  api.Response{data=store.Organization}
// @Failure      400   {object}  api.Response
// @Failure      401   {object}  api.Response
// @Failure      404   {object}  api.Response
// @Failure      500   {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug} [put]
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

	org, err := s.queries.GetOrganizationByProviderAndSlug(r.Context(), chi.URLParam(r, "provider"), slug)
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
// @Param        provider  path  string  true  "Forge provider"
// @Param        slug  path  string  true  "Organization slug"
// @Success      204   "No Content"
// @Failure      401   {object}  api.Response
// @Failure      404   {object}  api.Response
// @Failure      500   {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug} [delete]
func (s *Server) handleDeleteOrg(w http.ResponseWriter, r *http.Request) {
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
		api.JSONError(w, http.StatusNotFound, "organization not found")
		return
	}

	// Purge object-store bytes for every snapshot under the org before the hard
	// delete cascades the snapshot_artifacts rows away, or they orphan forever.
	objectKeys, err := s.queries.ListSnapshotArtifactObjectKeysByOrg(r.Context(), org.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to enumerate organization artifacts")
		return
	}
	s.purgeObjectStoreKeys(r.Context(), objectKeys)

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

func isForeignKeyViolation(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && pqErr.Code == "23503"
}

func constraintName(err error) string {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return pqErr.Constraint
	}
	return ""
}
