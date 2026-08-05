package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/store"
)

// Org-owned tokens (ADR-020): created by an org admin but owned by the org, so
// they survive any member's departure and any current admin can list, edit,
// rotate, or revoke them. The acting admin is recorded in the audit trail; the
// managing authority is the org role.
//
// Caveat, documented deliberately: the token still RESOLVES to its creating
// user at request time (`api_keys.user_id` drives RBAC intersection), so if the
// creator is deprovisioned the token stops authorizing until an admin rotates
// ownership by re-creating it. Managing outlives the creator; acting does not
// yet.

type createOrgAPIKeyRequest struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Scopes      json.RawMessage `json:"scopes"`
	ExpiresAt   *time.Time      `json:"expires_at,omitempty"`
}

// loadOrgAdminForTokens is the shared gate for org-token management: browser
// session only (no token can mint or reshape tokens — same invariant as the
// user-owned endpoints) and an org admin role.
func (s *Server) loadOrgAdminForTokens(w http.ResponseWriter, r *http.Request) (*store.Organization, *store.User, bool) {
	if auth.TokenAuthFromContext(r.Context()) != nil {
		api.JSONError(w, http.StatusForbidden, "API keys can only be managed from a browser session")
		return nil, nil, false
	}
	return s.loadOrgAdminUser(r, w)
}

// @Summary      List organization API keys
// @Description  List org-owned API keys. Requires org admin.
// @Tags         api-keys
// @Produce      json
// @Param        provider  path  string  true  "Forge provider"
// @Param        slug      path  string  true  "Organization slug"
// @Success      200  {object}  api.Response{data=[]store.APIKey}
// @Failure      401  {object}  api.Response
// @Failure      403  {object}  api.Response
// @Failure      404  {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/api-keys [get]
func (s *Server) handleListOrgAPIKeys(w http.ResponseWriter, r *http.Request) {
	org, _, ok := s.loadOrgAdminForTokens(w, r)
	if !ok {
		return
	}

	keys, err := s.queries.ListAPIKeysByOrg(r.Context(), org.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list API keys")
		return
	}

	api.JSON(w, http.StatusOK, keys)
}

// @Summary      List unscoped-token exposure
// @Description  Lists legacy full-access (unscoped) tokens owned by members of this organization. Any of them can act on the org with its owner's full role, which makes this the org's real token risk surface until they are restricted or expire. Visibility only — personal tokens stay managed by their owners. Requires org admin.
// @Tags         api-keys
// @Produce      json
// @Param        provider  path  string  true  "Forge provider"
// @Param        slug      path  string  true  "Organization slug"
// @Success      200  {object}  api.Response{data=[]store.UnscopedKeyExposure}
// @Failure      401  {object}  api.Response
// @Failure      403  {object}  api.Response
// @Failure      404  {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/api-keys/exposure [get]
func (s *Server) handleListOrgTokenExposure(w http.ResponseWriter, r *http.Request) {
	org, _, ok := s.loadOrgAdminForTokens(w, r)
	if !ok {
		return
	}

	exposures, err := s.queries.ListUnscopedAPIKeysByOrgMembers(r.Context(), org.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list unscoped tokens")
		return
	}

	api.JSON(w, http.StatusOK, exposures)
}

// @Summary      Create organization API key
// @Description  Create an org-owned API key and return the raw key once. Org-owned keys are always scoped to this organization and carry a mandatory expiry. Requires org admin.
// @Tags         api-keys
// @Accept       json
// @Produce      json
// @Param        provider  path  string                       true  "Forge provider"
// @Param        slug      path  string                       true  "Organization slug"
// @Param        payload   body  server.createOrgAPIKeyRequest  true  "API key details"
// @Success      201  {object}  api.Response{data=server.createAPIKeyResponse}
// @Failure      400  {object}  api.Response
// @Failure      401  {object}  api.Response
// @Failure      403  {object}  api.Response
// @Failure      404  {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/api-keys [post]
func (s *Server) handleCreateOrgAPIKey(w http.ResponseWriter, r *http.Request) {
	org, user, ok := s.loadOrgAdminForTokens(w, r)
	if !ok {
		return
	}

	var input createOrgAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" {
		api.JSONError(w, http.StatusBadRequest, "name is required")
		return
	}

	scopes, err := normalizeOrgScope(input.Scopes, org)
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateScopedExpiry(true, input.ExpiresAt); err != nil {
		api.JSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	rawKey, err := apitoken.Generate()
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to generate API key")
		return
	}

	apiKey, err := s.queries.CreateAPIKey(r.Context(), user.ID, input.Name, store.HashAPIKey(rawKey), scopes, input.ExpiresAt, "org", &org.ID, input.Description)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to create API key")
		return
	}

	s.writeTokenAuditLog(r, user, orgAuditID(org.ID), apiKey, audit.ActionTokenCreate, nil)

	api.JSON(w, http.StatusCreated, createAPIKeyResponse{Key: rawKey, APIKey: apiKey})
}

// normalizeOrgScope validates an org-owned token's scope. Unlike user keys
// there is no legacy-unscoped escape hatch: an org token is always scoped, its
// org is always the org it was minted under, and its owner block is rewritten
// to that org — a request body cannot point either anywhere else.
func normalizeOrgScope(raw json.RawMessage, org *store.Organization) (json.RawMessage, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil, errors.New("org-owned tokens require a scope")
	}

	scope, err := apitoken.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid token scope: %w", err)
	}
	if scope.Org != "" && scope.Org != org.Slug {
		return nil, fmt.Errorf("token scope must target this organization (%s)", org.Slug)
	}
	if scope.Repos.Mode == apitoken.RepoList && len(scope.Repos.Slugs) == 0 {
		return nil, errors.New("token scope requires at least one repository, or repos.mode=all")
	}
	if !scope.HasPermissions() {
		return nil, errors.New("token scope requires at least one permission")
	}

	scope.Org = org.Slug
	scope.Owner = apitoken.Owner{Type: apitoken.OwnerOrg, ID: org.ID.String()}
	normalized, err := json.Marshal(scope)
	if err != nil {
		return nil, errors.New("invalid token scope")
	}
	return normalized, nil
}

// @Summary      Update organization API key
// @Description  Update an org-owned API key's name, description, scope, or expiry. Requires org admin.
// @Tags         api-keys
// @Accept       json
// @Produce      json
// @Param        provider  path  string                      true  "Forge provider"
// @Param        slug      path  string                      true  "Organization slug"
// @Param        keyID     path  string                      true  "API key ID"
// @Param        payload   body  server.updateAPIKeyRequest  true  "Fields to update"
// @Success      200  {object}  api.Response{data=store.APIKey}
// @Failure      400  {object}  api.Response
// @Failure      401  {object}  api.Response
// @Failure      403  {object}  api.Response
// @Failure      404  {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/api-keys/{keyID} [patch]
func (s *Server) handleUpdateOrgAPIKey(w http.ResponseWriter, r *http.Request) {
	org, user, existing, ok := s.loadOrgOwnedAPIKey(w, r)
	if !ok {
		return
	}

	var input updateAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	name := existing.Name
	if input.Name != nil {
		name = strings.TrimSpace(*input.Name)
		if name == "" {
			api.JSONError(w, http.StatusBadRequest, "name is required")
			return
		}
	}
	description := existing.Description
	if input.Description != nil {
		description = *input.Description
	}
	scopes := existing.Scopes
	if len(input.Scopes) > 0 {
		normalized, err := normalizeOrgScope(input.Scopes, org)
		if err != nil {
			api.JSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		scopes = normalized
	}
	expiresAt := existing.ExpiresAt
	if input.ExpiresAt != nil {
		expiresAt = input.ExpiresAt
	}
	if err := validateScopedExpiry(true, expiresAt); err != nil {
		api.JSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	updated, err := s.queries.UpdateAPIKeyMetaByOrg(r.Context(), existing.ID, org.ID, name, description, scopes, expiresAt)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to update API key")
		return
	}
	if updated == nil {
		api.JSONError(w, http.StatusNotFound, "API key not found")
		return
	}

	s.writeTokenAuditLog(r, user, orgAuditID(org.ID), updated, audit.ActionTokenUpdate, map[string]any{
		"previous_name":  existing.Name,
		"previous_scope": scopeAuditSummary(existing),
	})

	api.JSON(w, http.StatusOK, updated)
}

// @Summary      Rotate organization API key
// @Description  Issues a new secret for an org-owned API key, keeping its id, scope, and audit history. Requires org admin.
// @Tags         api-keys
// @Produce      json
// @Param        provider  path  string  true  "Forge provider"
// @Param        slug      path  string  true  "Organization slug"
// @Param        keyID     path  string  true  "API key ID"
// @Success      200  {object}  api.Response{data=server.createAPIKeyResponse}
// @Failure      400  {object}  api.Response
// @Failure      401  {object}  api.Response
// @Failure      403  {object}  api.Response
// @Failure      404  {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/api-keys/{keyID}/rotate [post]
func (s *Server) handleRotateOrgAPIKey(w http.ResponseWriter, r *http.Request) {
	org, user, existing, ok := s.loadOrgOwnedAPIKey(w, r)
	if !ok {
		return
	}

	rawKey, err := apitoken.Generate()
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to generate API key")
		return
	}

	rotated, err := s.queries.RotateAPIKeyByOrg(r.Context(), existing.ID, org.ID, store.HashAPIKey(rawKey))
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to rotate API key")
		return
	}
	if rotated == nil {
		api.JSONError(w, http.StatusNotFound, "API key not found")
		return
	}

	s.writeTokenAuditLog(r, user, orgAuditID(org.ID), rotated, audit.ActionTokenRotate, nil)

	api.JSON(w, http.StatusOK, createAPIKeyResponse{Key: rawKey, APIKey: rotated})
}

// @Summary      Revoke organization API key
// @Description  Revoke an org-owned API key. Requires org admin.
// @Tags         api-keys
// @Produce      json
// @Param        provider  path  string  true  "Forge provider"
// @Param        slug      path  string  true  "Organization slug"
// @Param        keyID     path  string  true  "API key ID"
// @Success      204  "No Content"
// @Failure      400  {object}  api.Response
// @Failure      401  {object}  api.Response
// @Failure      403  {object}  api.Response
// @Failure      404  {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/api-keys/{keyID} [delete]
func (s *Server) handleDeleteOrgAPIKey(w http.ResponseWriter, r *http.Request) {
	org, user, existing, ok := s.loadOrgOwnedAPIKey(w, r)
	if !ok {
		return
	}

	deleted, err := s.queries.DeleteAPIKeyByOrg(r.Context(), existing.ID, org.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to delete API key")
		return
	}
	if !deleted {
		api.JSONError(w, http.StatusNotFound, "API key not found")
		return
	}

	s.writeTokenAuditLog(r, user, orgAuditID(org.ID), existing, audit.ActionTokenRevoke, nil)

	w.WriteHeader(http.StatusNoContent)
}

// loadOrgOwnedAPIKey resolves the path key strictly within the org's ownership
// (`owner_type='org' AND owner_id=<org>`), so a user-owned key or another
// org's key is a 404 regardless of who asks.
func (s *Server) loadOrgOwnedAPIKey(w http.ResponseWriter, r *http.Request) (*store.Organization, *store.User, *store.APIKey, bool) {
	org, user, ok := s.loadOrgAdminForTokens(w, r)
	if !ok {
		return nil, nil, nil, false
	}

	id, err := uuid.Parse(chi.URLParam(r, "keyID"))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid API key ID")
		return nil, nil, nil, false
	}

	apiKey, err := s.queries.GetAPIKeyByOrg(r.Context(), id, org.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load API key")
		return nil, nil, nil, false
	}
	if apiKey == nil {
		api.JSONError(w, http.StatusNotFound, "API key not found")
		return nil, nil, nil, false
	}

	return org, user, apiKey, true
}
