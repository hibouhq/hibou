package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/hibouhq/lehibou/internal/api"
	"github.com/hibouhq/lehibou/internal/store"
)

type createQualityGateRequest struct {
	RepoID            *string         `json:"repo_id"`
	Name              string          `json:"name"`
	Description       string          `json:"description"`
	MaxCritical       int32           `json:"max_critical"`
	MaxHigh           int32           `json:"max_high"`
	MaxMedium         *int32          `json:"max_medium"`
	MaxNewFindings    *int32          `json:"max_new_findings"`
	FindingSeverities json.RawMessage `json:"finding_severities"`
	Enabled           bool            `json:"enabled"`
}

type updateQualityGateRequest struct {
	Name              string          `json:"name"`
	Description       string          `json:"description"`
	MaxCritical       int32           `json:"max_critical"`
	MaxHigh           int32           `json:"max_high"`
	MaxMedium         *int32          `json:"max_medium"`
	MaxNewFindings    *int32          `json:"max_new_findings"`
	FindingSeverities json.RawMessage `json:"finding_severities"`
	Enabled           bool            `json:"enabled"`
}

type qualityGateFields struct {
	Name              string
	Description       string
	MaxCritical       int32
	MaxHigh           int32
	MaxMedium         *int32
	MaxNewFindings    *int32
	FindingSeverities json.RawMessage
	Enabled           bool
}

// @Summary      Create quality gate
// @Description  Create a quality gate within an organization when the caller is an admin
// @Tags         quality-gates
// @Accept       json
// @Produce      json
// @Param        provider  path      string                    true  "Forge provider"
// @Param        slug      path      string                    true  "Organization slug"
// @Param        payload   body      createQualityGateRequest  true  "Quality gate details"
// @Success      201       {object}  api.Response{data=store.QualityGate}
// @Failure      400       {object}  api.Response
// @Failure      401       {object}  api.Response
// @Failure      403       {object}  api.Response
// @Failure      404       {object}  api.Response
// @Failure      500       {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/quality-gates [post]
func (s *Server) handleCreateQualityGate(w http.ResponseWriter, r *http.Request) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok {
		return
	}
	if !s.requireOrgAdmin(r, w, org.ID) {
		return
	}

	var input createQualityGateRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	qualityGate, err := s.createOrUpdateQualityGate(r, org, input.RepoID, qualityGateFields{
		Name:              input.Name,
		Description:       input.Description,
		MaxCritical:       input.MaxCritical,
		MaxHigh:           input.MaxHigh,
		MaxMedium:         input.MaxMedium,
		MaxNewFindings:    input.MaxNewFindings,
		FindingSeverities: input.FindingSeverities,
		Enabled:           input.Enabled,
	}, uuid.Nil)
	if err != nil {
		s.handleQualityGateError(w, err, true)
		return
	}

	api.JSON(w, http.StatusCreated, qualityGate)
}

// @Summary      List quality gates
// @Description  List quality gates in an organization visible to organization members
// @Tags         quality-gates
// @Produce      json
// @Param        provider  path      string  true   "Forge provider"
// @Param        slug      path      string  true   "Organization slug"
// @Param        page      query     int     false  "Page number"
// @Param        per_page  query     int     false  "Items per page"
// @Success      200       {object}  api.ListResponse{data=[]store.QualityGate}
// @Failure      401       {object}  api.Response
// @Failure      404       {object}  api.Response
// @Failure      500       {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/quality-gates [get]
func (s *Server) handleListQualityGates(w http.ResponseWriter, r *http.Request) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok {
		return
	}

	gates, err := s.queries.ListQualityGatesByOrg(r.Context(), org.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list quality gates")
		return
	}

	pagination := api.ParsePagination(r)
	api.JSONList(w, paginateItems(gates, pagination), pagination.Page, pagination.PerPage, len(gates))
}

// @Summary      Get quality gate
// @Description  Get a quality gate by ID when the caller belongs to the organization
// @Tags         quality-gates
// @Produce      json
// @Param        provider  path      string  true  "Forge provider"
// @Param        slug      path      string  true  "Organization slug"
// @Param        gateID    path      string  true  "Quality gate ID"
// @Success      200       {object}  api.Response{data=store.QualityGate}
// @Failure      400       {object}  api.Response
// @Failure      401       {object}  api.Response
// @Failure      404       {object}  api.Response
// @Failure      500       {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/quality-gates/{gateID} [get]
func (s *Server) handleGetQualityGate(w http.ResponseWriter, r *http.Request) {
	_, gate, ok := s.loadAuthorizedQualityGate(r, w)
	if !ok {
		return
	}

	api.JSON(w, http.StatusOK, gate)
}

// @Summary      Update quality gate
// @Description  Update a quality gate when the caller is an organization admin
// @Tags         quality-gates
// @Accept       json
// @Produce      json
// @Param        provider  path      string                    true  "Forge provider"
// @Param        slug      path      string                    true  "Organization slug"
// @Param        gateID    path      string                    true  "Quality gate ID"
// @Param        payload   body      updateQualityGateRequest  true  "Quality gate updates"
// @Success      200       {object}  api.Response{data=store.QualityGate}
// @Failure      400       {object}  api.Response
// @Failure      401       {object}  api.Response
// @Failure      403       {object}  api.Response
// @Failure      404       {object}  api.Response
// @Failure      500       {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/quality-gates/{gateID} [put]
func (s *Server) handleUpdateQualityGate(w http.ResponseWriter, r *http.Request) {
	org, gate, ok := s.loadAuthorizedQualityGate(r, w)
	if !ok {
		return
	}
	if !s.requireOrgAdmin(r, w, org.ID) {
		return
	}

	var input updateQualityGateRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	updated, err := s.createOrUpdateQualityGate(r, org, nil, qualityGateFields(input), gate.ID)
	if err != nil {
		s.handleQualityGateError(w, err, false)
		return
	}

	api.JSON(w, http.StatusOK, updated)
}

// @Summary      Delete quality gate
// @Description  Delete a quality gate when the caller is an organization admin
// @Tags         quality-gates
// @Produce      json
// @Param        provider  path      string  true  "Forge provider"
// @Param        slug      path      string  true  "Organization slug"
// @Param        gateID    path      string  true  "Quality gate ID"
// @Success      204       "No Content"
// @Failure      400       {object}  api.Response
// @Failure      401       {object}  api.Response
// @Failure      403       {object}  api.Response
// @Failure      404       {object}  api.Response
// @Failure      500       {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/quality-gates/{gateID} [delete]
func (s *Server) handleDeleteQualityGate(w http.ResponseWriter, r *http.Request) {
	org, gate, ok := s.loadAuthorizedQualityGate(r, w)
	if !ok {
		return
	}
	if !s.requireOrgAdmin(r, w, org.ID) {
		return
	}

	if err := s.queries.DeleteQualityGate(r.Context(), gate.ID); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to delete quality gate")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) loadAuthorizedQualityGate(r *http.Request, w http.ResponseWriter) (*store.Organization, *store.QualityGate, bool) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok {
		return nil, nil, false
	}

	gateID, err := parseUUIDParam(r, "gateID")
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid quality gate ID")
		return nil, nil, false
	}

	gate, err := s.queries.GetQualityGateByID(r.Context(), gateID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load quality gate")
		return nil, nil, false
	}
	if gate == nil || gate.OrgID != org.ID {
		api.JSONError(w, http.StatusNotFound, "quality gate not found")
		return nil, nil, false
	}

	return org, gate, true
}

func (s *Server) createOrUpdateQualityGate(r *http.Request, org *store.Organization, repoIDInput *string, fields qualityGateFields, gateID uuid.UUID) (*store.QualityGate, error) {
	fields.Name = strings.TrimSpace(fields.Name)
	fields.Description = strings.TrimSpace(fields.Description)
	if fields.Name == "" {
		return nil, errQualityGateNameRequired
	}

	repoID, err := parseOptionalUUID(repoIDInput)
	if err != nil {
		return nil, errInvalidQualityGateRepoID
	}
	if repoID != nil {
		repo, err := s.queries.GetRepositoryByID(r.Context(), *repoID)
		if err != nil {
			return nil, err
		}
		if repo == nil {
			return nil, errQualityGateRepoNotFound
		}
		if repo.OrgID != org.ID {
			return nil, errQualityGateRepoOrgMismatch
		}
	}

	findingSeverities, err := parseFindingSeverities(fields.FindingSeverities)
	if err != nil {
		return nil, err
	}

	if gateID == uuid.Nil {
		return s.queries.CreateQualityGate(r.Context(), org.ID, repoID, fields.Name, fields.Description, fields.MaxCritical, fields.MaxHigh, fields.MaxMedium, fields.MaxNewFindings, findingSeverities, fields.Enabled)
	}

	return s.queries.UpdateQualityGate(r.Context(), gateID, fields.Name, fields.Description, fields.MaxCritical, fields.MaxHigh, fields.MaxMedium, fields.MaxNewFindings, findingSeverities, fields.Enabled)
}

var (
	errQualityGateNameRequired    = &qualityGateValidationError{message: "name is required"}
	errInvalidQualityGateRepoID   = &qualityGateValidationError{message: "repo_id must be a valid UUID"}
	errQualityGateRepoNotFound    = &qualityGateValidationError{message: "repository not found"}
	errInvalidFindingSeverities   = &qualityGateValidationError{message: "finding_severities must be an array of strings"}
	errQualityGateRepoOrgMismatch = &qualityGateAuthorizationError{message: "repository does not belong to this organization"}
)

type qualityGateValidationError struct {
	message string
}

func (e *qualityGateValidationError) Error() string {
	return e.message
}

type qualityGateAuthorizationError struct {
	message string
}

func (e *qualityGateAuthorizationError) Error() string {
	return e.message
}

func (s *Server) handleQualityGateError(w http.ResponseWriter, err error, creating bool) {
	var validationErr *qualityGateValidationError
	if errors.As(err, &validationErr) {
		api.JSONError(w, http.StatusBadRequest, validationErr.message)
		return
	}
	var authzErr *qualityGateAuthorizationError
	if errors.As(err, &authzErr) {
		api.JSONError(w, http.StatusForbidden, authzErr.message)
		return
	}
	if isUniqueViolation(err) {
		api.JSONError(w, http.StatusBadRequest, "quality gate name already exists in this organization")
		return
	}
	if creating {
		api.JSONError(w, http.StatusInternalServerError, "failed to create quality gate")
		return
	}
	api.JSONError(w, http.StatusInternalServerError, "failed to update quality gate")
}

func parseOptionalUUID(value *string) (*uuid.UUID, error) {
	if value == nil {
		return nil, nil
	}
	trimmed := strings.TrimSpace(*value)
	if trimmed == "" {
		return nil, nil
	}
	parsed, err := uuid.Parse(trimmed)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

func parseFindingSeverities(value json.RawMessage) ([]string, error) {
	if len(value) == 0 {
		return []string{}, nil
	}

	var severities []string
	if err := json.Unmarshal(value, &severities); err != nil {
		return nil, errInvalidFindingSeverities
	}
	for index := range severities {
		severities[index] = strings.TrimSpace(severities[index])
	}
	return severities, nil
}
