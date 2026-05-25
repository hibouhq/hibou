package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/lehibou/internal/api"
	"github.com/hibouhq/lehibou/internal/store"
)

type createAPIKeyRequest struct {
	Name      string          `json:"name"`
	Scopes    json.RawMessage `json:"scopes"`
	ExpiresAt *time.Time      `json:"expires_at,omitempty"`
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
	if input.Scopes == nil {
		input.Scopes = json.RawMessage(`[]`)
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to generate API key")
		return
	}
	rawKey := "hibou_" + hex.EncodeToString(raw)
	keyHash := store.HashAPIKey(rawKey)

	apiKey, err := s.queries.CreateAPIKey(r.Context(), user.ID, input.Name, keyHash, input.Scopes, input.ExpiresAt)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to create API key")
		return
	}

	api.JSON(w, http.StatusCreated, createAPIKeyResponse{
		Key:    rawKey,
		APIKey: apiKey,
	})
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

	id, err := uuid.Parse(chi.URLParam(r, "keyID"))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid API key ID")
		return
	}

	if err := s.queries.DeleteAPIKey(r.Context(), id, user.ID); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to delete API key")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
