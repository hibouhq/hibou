package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
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

type createAPIKeyRequest struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Scopes      json.RawMessage `json:"scopes"`
	ExpiresAt   *time.Time      `json:"expires_at,omitempty"`
}

type createAPIKeyResponse struct {
	Key    string        `json:"key"`
	APIKey *store.APIKey `json:"api_key"`
}

// @Summary      Create API key
// @Description  Create a new API key for the authenticated user and return the raw key once
// @Tags         api-keys
// @Accept       json
// @Produce      json
// @Param        payload  body      createAPIKeyRequest  true  "API key details"
// @Success      201   {object}  api.Response{data=server.createAPIKeyResponse}
// @Failure      400   {object}  api.Response
// @Failure      401   {object}  api.Response
// @Failure      500   {object}  api.Response
// @Security     BearerAuth
// @Router       /users/me/api-keys [post]
func (s *Server) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if auth.TokenAuthFromContext(r.Context()) != nil {
		api.JSONError(w, http.StatusForbidden, "API keys can only be managed from a browser session")
		return
	}

	var input createAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" {
		api.JSONError(w, http.StatusBadRequest, "name is required")
		return
	}

	scopes, err := normalizeCreateScope(input.Scopes, user.ID)
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateScopedExpiry(true, input.ExpiresAt); err != nil {
		api.JSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !s.checkAPIKeyQuota(w, r, user.ID) {
		return
	}

	rawKey, err := apitoken.Generate()
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to generate API key")
		return
	}
	keyHash := store.HashAPIKey(rawKey)

	apiKey, err := s.queries.CreateAPIKey(r.Context(), user.ID, input.Name, keyHash, scopes, input.ExpiresAt, "user", &user.ID, input.Description)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to create API key")
		return
	}

	s.writeTokenAuditLog(r, user, uuid.NullUUID{}, apiKey, audit.ActionTokenCreate, nil)

	api.JSON(w, http.StatusCreated, createAPIKeyResponse{
		Key:    rawKey,
		APIKey: apiKey,
	})
}

// normalizeCreateScope validates a requested token scope at mint time. A scope
// is REQUIRED — unscoped full-RBAC tokens can no longer be minted anywhere;
// rows without one are legacy and keep working until they expire or are
// restricted. The scope must parse and be usable: an unparseable or
// resource-less document would mint a token that silently denies everything,
// so it is a 400 rather than a working-looking key. The owner block is always
// rewritten to the creating user; org-owned tokens are an org-admin action
// (ADR-020), not something a request body can ask for here.
// maxAPIKeysPerUser caps the keys one account can mint, personal and
// org-requested together.
const maxAPIKeysPerUser = 50

// checkAPIKeyQuota answers 422 and returns false once the user holds
// maxAPIKeysPerUser keys.
func (s *Server) checkAPIKeyQuota(w http.ResponseWriter, r *http.Request, userID uuid.UUID) bool {
	count, err := s.queries.CountAPIKeysCreatedByUser(r.Context(), userID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to create API key")
		return false
	}
	if count >= maxAPIKeysPerUser {
		api.JSONError(w, http.StatusUnprocessableEntity, "API key limit reached: delete an unused key before creating another")
		return false
	}
	return true
}

func normalizeCreateScope(raw json.RawMessage, userID uuid.UUID) (json.RawMessage, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil, errors.New("a token scope is required")
	}

	scope, err := apitoken.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid token scope: %w", err)
	}
	if strings.TrimSpace(scope.Org) == "" {
		return nil, errors.New("token scope requires an organization")
	}
	if scope.Repos.Mode == apitoken.RepoList && len(scope.Repos.Slugs) == 0 {
		return nil, errors.New("token scope requires at least one repository, or repos.mode=all")
	}
	if !scope.HasPermissions() {
		return nil, errors.New("token scope requires at least one permission")
	}

	scope.Owner = apitoken.Owner{Type: apitoken.OwnerUser, ID: userID.String()}
	normalized, err := json.Marshal(scope)
	if err != nil {
		return nil, errors.New("invalid token scope")
	}
	return normalized, nil
}

const maxTokenLifetime = 366 * 24 * time.Hour

// validateScopedExpiry enforces the ADR's lifecycle rule for scoped tokens:
// expiry is mandatory and bounded (≤ 1 year), no non-expiring tokens. Legacy
// unscoped keys are exempt — they predate the rule and changing them here
// would break existing CLI and CI credentials.
func validateScopedExpiry(scoped bool, expiresAt *time.Time) error {
	if !scoped {
		return nil
	}
	if expiresAt == nil {
		return errors.New("scoped tokens require an expiry of at most one year")
	}
	if !expiresAt.After(time.Now()) {
		return errors.New("token expiry must be in the future")
	}
	if time.Until(*expiresAt) > maxTokenLifetime {
		return errors.New("token expiry must be at most one year from now")
	}
	return nil
}

// @Summary      List API keys
// @Description  List API keys owned by the authenticated user
// @Tags         api-keys
// @Produce      json
// @Success      200  {object}  api.Response{data=[]store.APIKey}
// @Failure      401  {object}  api.Response
// @Failure      500  {object}  api.Response
// @Security     BearerAuth
// @Router       /users/me/api-keys [get]
func (s *Server) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	keys, err := s.queries.ListAPIKeysByUser(r.Context(), user.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list API keys")
		return
	}

	api.JSON(w, http.StatusOK, keys)
}

// @Summary      Delete API key
// @Description  Delete an API key owned by the authenticated user
// @Tags         api-keys
// @Produce      json
// @Param        keyID  path  string  true  "API key ID"
// @Success      204    "No Content"
// @Failure      400    {object}  api.Response
// @Failure      401    {object}  api.Response
// @Failure      500    {object}  api.Response
// @Security     BearerAuth
// @Router       /users/me/api-keys/{keyID} [delete]
func (s *Server) handleDeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if auth.TokenAuthFromContext(r.Context()) != nil {
		api.JSONError(w, http.StatusForbidden, "API keys can only be managed from a browser session")
		return
	}

	id, err := uuid.Parse(chi.URLParam(r, "keyID"))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid API key ID")
		return
	}

	existing, err := s.queries.GetAPIKeyByID(r.Context(), id, user.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load API key")
		return
	}
	if existing == nil {
		api.JSONError(w, http.StatusNotFound, "API key not found")
		return
	}

	if err := s.queries.DeleteAPIKey(r.Context(), id, user.ID); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to delete API key")
		return
	}

	s.writeTokenAuditLog(r, user, uuid.NullUUID{}, existing, audit.ActionTokenRevoke, nil)

	w.WriteHeader(http.StatusNoContent)
}

type updateAPIKeyRequest struct {
	Name        *string         `json:"name,omitempty"`
	Description *string         `json:"description,omitempty"`
	Scopes      json.RawMessage `json:"scopes,omitempty"`
	ExpiresAt   *time.Time      `json:"expires_at,omitempty"`
}

// @Summary      Update API key
// @Description  Update an API key's name, description, scope, or expiry without re-issuing the secret
// @Tags         api-keys
// @Accept       json
// @Produce      json
// @Param        keyID    path  string                      true  "API key ID"
// @Param        payload  body  server.updateAPIKeyRequest  true  "Fields to update"
// @Success      200  {object}  api.Response{data=store.APIKey}
// @Failure      400  {object}  api.Response
// @Failure      401  {object}  api.Response
// @Failure      403  {object}  api.Response
// @Failure      404  {object}  api.Response
// @Security     BearerAuth
// @Router       /users/me/api-keys/{keyID} [patch]
func (s *Server) handleUpdateAPIKey(w http.ResponseWriter, r *http.Request) {
	user, existing, ok := s.loadOwnAPIKey(w, r)
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
		normalized, err := normalizeCreateScope(input.Scopes, user.ID)
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
	if err := validateScopedExpiry((&store.APIKey{Scopes: scopes}).HasScope(), expiresAt); err != nil {
		api.JSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	updated, err := s.queries.UpdateAPIKeyMeta(r.Context(), existing.ID, user.ID, name, description, scopes, expiresAt)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to update API key")
		return
	}
	if updated == nil {
		api.JSONError(w, http.StatusNotFound, "API key not found")
		return
	}

	s.writeTokenAuditLog(r, user, uuid.NullUUID{}, updated, audit.ActionTokenUpdate, map[string]any{
		"previous_name":       existing.Name,
		"previous_scope":      scopeAuditSummary(existing),
		"scope_changed":       !bytes.Equal(bytes.TrimSpace(existing.Scopes), bytes.TrimSpace(updated.Scopes)),
		"description_changed": existing.Description != updated.Description,
	})

	api.JSON(w, http.StatusOK, updated)
}

// @Summary      Rotate API key
// @Description  Issues a new secret for an existing API key, keeping its id, scope, and audit history. The old secret stops working immediately.
// @Tags         api-keys
// @Produce      json
// @Param        keyID  path  string  true  "API key ID"
// @Success      200  {object}  api.Response{data=server.createAPIKeyResponse}
// @Failure      400  {object}  api.Response
// @Failure      401  {object}  api.Response
// @Failure      403  {object}  api.Response
// @Failure      404  {object}  api.Response
// @Security     BearerAuth
// @Router       /users/me/api-keys/{keyID}/rotate [post]
func (s *Server) handleRotateAPIKey(w http.ResponseWriter, r *http.Request) {
	user, existing, ok := s.loadOwnAPIKey(w, r)
	if !ok {
		return
	}

	rawKey, err := apitoken.Generate()
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to generate API key")
		return
	}

	rotated, err := s.queries.RotateAPIKey(r.Context(), existing.ID, user.ID, store.HashAPIKey(rawKey))
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to rotate API key")
		return
	}
	if rotated == nil {
		api.JSONError(w, http.StatusNotFound, "API key not found")
		return
	}

	s.writeTokenAuditLog(r, user, uuid.NullUUID{}, rotated, audit.ActionTokenRotate, nil)

	api.JSON(w, http.StatusOK, createAPIKeyResponse{Key: rawKey, APIKey: rotated})
}

// loadOwnAPIKey resolves the path key for the session user. Like create and
// delete, editing and rotating are session-only: no token may reshape or
// re-issue a token, including itself.
func (s *Server) loadOwnAPIKey(w http.ResponseWriter, r *http.Request) (*store.User, *store.APIKey, bool) {
	user := UserFromContext(r.Context())
	if user == nil {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return nil, nil, false
	}
	if auth.TokenAuthFromContext(r.Context()) != nil {
		api.JSONError(w, http.StatusForbidden, "API keys can only be managed from a browser session")
		return nil, nil, false
	}

	id, err := uuid.Parse(chi.URLParam(r, "keyID"))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid API key ID")
		return nil, nil, false
	}

	apiKey, err := s.queries.GetAPIKeyByID(r.Context(), id, user.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load API key")
		return nil, nil, false
	}
	if apiKey == nil {
		api.JSONError(w, http.StatusNotFound, "API key not found")
		return nil, nil, false
	}

	return user, apiKey, true
}

// writeTokenAuditLog records a token lifecycle event. User-owned keys hang off
// the user, so their orgID is null and the scope's org travels in the context;
// org-owned keys attribute to the owning org so the events surface in that
// org's audit view.
func (s *Server) writeTokenAuditLog(r *http.Request, user *store.User, orgID uuid.NullUUID, apiKey *store.APIKey, action string, extra map[string]any) {
	entryContext := map[string]any{
		"token_name": apiKey.Name,
		"owner_type": apiKey.OwnerType,
		"scope":      scopeAuditSummary(apiKey),
		"has_expiry": apiKey.ExpiresAt != nil,
	}
	for key, value := range extra {
		entryContext[key] = value
	}

	s.writeAuditLog(r, user, orgID, auditEntry{
		Action:       action,
		ResourceType: "api_key",
		ResourceID:   apiKey.ID.String(),
		Context:      entryContext,
	})
}

// scopeAuditSummary renders the scope compactly for the audit trail — what was
// granted, not the raw document.
func scopeAuditSummary(apiKey *store.APIKey) string {
	if !apiKey.HasScope() {
		return "unscoped"
	}
	scope, err := apiKey.Scope()
	if err != nil {
		return "malformed"
	}

	repos := string(scope.Repos.Mode)
	if scope.Repos.Mode == apitoken.RepoList {
		repos = fmt.Sprintf("%d repo(s)", len(scope.Repos.Slugs))
	}
	grants := make([]string, 0, len(scope.Permissions))
	for capability, level := range scope.Permissions {
		if level != apitoken.AccessNone {
			grants = append(grants, string(capability)+":"+string(level))
		}
	}
	sort.Strings(grants)
	return fmt.Sprintf("org=%s repos=%s %s", scope.Org, repos, strings.Join(grants, ","))
}
