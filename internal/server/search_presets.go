package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/filterquery"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// Saved filter-bar queries. Personal only for now: the schema reserves a scope
// so org- or repo-shared presets can follow, but who may curate a shared list
// is a policy question this endpoint does not answer.

const (
	maxSearchPresetsPerSurface = 100
	maxSearchPresetNameLength  = 80
	maxSearchPresetQueryLength = 2000
)

type searchPreset struct {
	ID        uuid.UUID `json:"id"`
	ScopeType string    `json:"scope_type"`
	Surface   string    `json:"surface"`
	Name      string    `json:"name"`
	Query     string    `json:"query"`
	CreatedAt string    `json:"created_at"`
	UpdatedAt string    `json:"updated_at"`
}

type createSearchPresetRequest struct {
	Surface string `json:"surface"`
	Name    string `json:"name"`
	Query   string `json:"query"`
}

type updateSearchPresetRequest struct {
	Name  string `json:"name"`
	Query string `json:"query"`
}

func toSearchPreset(row dbgen.SearchPreset) searchPreset {
	return searchPreset{
		ID:        row.ID,
		ScopeType: row.ScopeType,
		Surface:   row.Surface,
		Name:      row.Name,
		Query:     row.Query,
		CreatedAt: row.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt: row.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

func validSearchPresetSurface(surface string) bool {
	return surface == store.SearchPresetSurfaceFindings
}

// validateSearchPreset normalizes a name and query and rejects a query the
// list endpoints would refuse, so a saved preset can never be a broken one.
func validateSearchPreset(name, query string) (string, string, error) {
	name = strings.TrimSpace(name)
	query = strings.TrimSpace(query)
	if name == "" {
		return "", "", errors.New("a name is required")
	}
	if utf8.RuneCountInString(name) > maxSearchPresetNameLength {
		return "", "", errors.New("name must be at most 80 characters")
	}
	if query == "" {
		return "", "", errors.New("a query is required")
	}
	if utf8.RuneCountInString(query) > maxSearchPresetQueryLength {
		return "", "", errors.New("query must be at most 2000 characters")
	}
	node, err := filterquery.Parse(query)
	if err != nil {
		return "", "", errors.New("invalid query: " + err.Error())
	}
	if _, err := filterquery.ToSQL(node, 1); err != nil {
		return "", "", errors.New("invalid query: " + err.Error())
	}
	return name, query, nil
}

// @Summary      List search presets
// @Description  List the authenticated user's saved filter-bar queries for one surface
// @Tags         search-presets
// @Produce      json
// @Param        surface  query     string  true  "Filter bar surface"  Enums(findings)
// @Success      200      {object}  api.Response{data=[]server.searchPreset}
// @Failure      400      {object}  api.Response
// @Failure      401      {object}  api.Response
// @Failure      500      {object}  api.Response
// @Security     BearerAuth
// @Router       /users/me/search-presets [get]
func (s *Server) handleListSearchPresets(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	surface := r.URL.Query().Get("surface")
	if !validSearchPresetSurface(surface) {
		api.JSONError(w, http.StatusBadRequest, "unknown surface")
		return
	}
	rows, err := s.queries.ListUserSearchPresets(r.Context(), user.ID, surface)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list search presets")
		return
	}
	out := make([]searchPreset, 0, len(rows))
	for _, row := range rows {
		out = append(out, toSearchPreset(row))
	}
	api.JSON(w, http.StatusOK, out)
}

// @Summary      Create search preset
// @Description  Save a filter-bar query under a name unique (case-insensitively) per user and surface
// @Tags         search-presets
// @Accept       json
// @Produce      json
// @Param        payload  body      createSearchPresetRequest  true  "Preset"
// @Success      201      {object}  api.Response{data=server.searchPreset}
// @Failure      400      {object}  api.Response
// @Failure      401      {object}  api.Response
// @Failure      409      {object}  api.Response
// @Failure      500      {object}  api.Response
// @Security     BearerAuth
// @Router       /users/me/search-presets [post]
func (s *Server) handleCreateSearchPreset(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var input createSearchPresetRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if !validSearchPresetSurface(input.Surface) {
		api.JSONError(w, http.StatusBadRequest, "unknown surface")
		return
	}
	name, query, err := validateSearchPreset(input.Name, input.Query)
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	count, err := s.queries.CountUserSearchPresets(r.Context(), user.ID, input.Surface)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to save the search preset")
		return
	}
	if count >= maxSearchPresetsPerSurface {
		api.JSONError(w, http.StatusBadRequest, "preset limit reached: delete one before saving another")
		return
	}
	created, err := s.queries.CreateUserSearchPreset(r.Context(), user.ID, input.Surface, name, query)
	if err != nil {
		if isUniqueViolation(err) {
			api.JSONError(w, http.StatusConflict, "a preset with this name already exists")
			return
		}
		api.JSONError(w, http.StatusInternalServerError, "failed to save the search preset")
		return
	}
	api.JSON(w, http.StatusCreated, toSearchPreset(created))
}

// @Summary      Update search preset
// @Description  Rename or replace the query of one of the authenticated user's presets
// @Tags         search-presets
// @Accept       json
// @Produce      json
// @Param        presetID  path      string                     true  "Preset ID"
// @Param        payload   body      updateSearchPresetRequest  true  "Preset"
// @Success      200       {object}  api.Response{data=server.searchPreset}
// @Failure      400       {object}  api.Response
// @Failure      401       {object}  api.Response
// @Failure      404       {object}  api.Response
// @Failure      409       {object}  api.Response
// @Failure      500       {object}  api.Response
// @Security     BearerAuth
// @Router       /users/me/search-presets/{presetID} [put]
func (s *Server) handleUpdateSearchPreset(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "presetID"))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid preset ID")
		return
	}
	var input updateSearchPresetRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	name, query, err := validateSearchPreset(input.Name, input.Query)
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	updated, err := s.queries.UpdateUserSearchPreset(r.Context(), id, user.ID, name, query)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			api.JSONError(w, http.StatusNotFound, "search preset not found")
		case isUniqueViolation(err):
			api.JSONError(w, http.StatusConflict, "a preset with this name already exists")
		default:
			api.JSONError(w, http.StatusInternalServerError, "failed to update the search preset")
		}
		return
	}
	api.JSON(w, http.StatusOK, toSearchPreset(updated))
}

// @Summary      Delete search preset
// @Description  Delete one of the authenticated user's presets
// @Tags         search-presets
// @Param        presetID  path  string  true  "Preset ID"
// @Success      204       "No Content"
// @Failure      400       {object}  api.Response
// @Failure      401       {object}  api.Response
// @Failure      404       {object}  api.Response
// @Failure      500       {object}  api.Response
// @Security     BearerAuth
// @Router       /users/me/search-presets/{presetID} [delete]
func (s *Server) handleDeleteSearchPreset(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "presetID"))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid preset ID")
		return
	}
	deleted, err := s.queries.DeleteUserSearchPreset(r.Context(), id, user.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to delete the search preset")
		return
	}
	if !deleted {
		api.JSONError(w, http.StatusNotFound, "search preset not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
