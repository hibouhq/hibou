package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/notify"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type createIntegrationRequest struct {
	Name            string          `json:"name"`
	IntegrationType string          `json:"integration_type"`
	Config          json.RawMessage `json:"config"`
	Enabled         bool            `json:"enabled"`
}

type updateIntegrationRequest struct {
	Name    string          `json:"name"`
	Config  json.RawMessage `json:"config"`
	Enabled bool            `json:"enabled"`
}

type integrationReplayResponse struct {
	IntegrationID string   `json:"integration_id"`
	Requested     int      `json:"requested"`
	Replayed      int      `json:"replayed"`
	Skipped       int      `json:"skipped"`
	AuditLogIDs   []string `json:"audit_log_ids"`
}

// @Summary      Create integration
// @Description  Create an integration within an organization when the caller is an admin
// @Tags         integrations
// @Accept       json
// @Produce      json
// @Param        provider  path      string                    true  "Forge provider"
// @Param        slug      path      string                    true  "Organization slug"
// @Param        payload   body      createIntegrationRequest  true  "Integration details"
// @Success      201       {object}  api.Response{data=store.Integration}
// @Failure      400       {object}  api.Response
// @Failure      401       {object}  api.Response
// @Failure      403       {object}  api.Response
// @Failure      404       {object}  api.Response
// @Failure      500       {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/integrations [post]
func (s *Server) handleCreateIntegration(w http.ResponseWriter, r *http.Request) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok {
		return
	}
	if !s.requireOrgAdmin(r, w, org.ID) {
		return
	}

	var input createIntegrationRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	input.Name = strings.TrimSpace(input.Name)
	input.IntegrationType = strings.TrimSpace(input.IntegrationType)
	if input.Name == "" {
		api.JSONError(w, http.StatusBadRequest, "name is required")
		return
	}
	if input.IntegrationType == "" {
		api.JSONError(w, http.StatusBadRequest, "integration_type is required")
		return
	}
	integrationType, ok := normalizeIntegrationType(input.IntegrationType)
	if !ok {
		api.JSONError(w, http.StatusBadRequest, "invalid integration_type")
		return
	}

	integration, err := s.queries.CreateIntegration(r.Context(), org.ID, input.Name, string(integrationType), defaultRawJSON(input.Config, "{}"), input.Enabled)
	if err != nil {
		if isUniqueViolation(err) {
			api.JSONError(w, http.StatusBadRequest, "integration name already exists in this organization")
			return
		}
		api.JSONError(w, http.StatusInternalServerError, "failed to create integration")
		return
	}

	api.JSON(w, http.StatusCreated, integration)
}

// @Summary      List integrations
// @Description  List integrations in an organization visible to organization members
// @Tags         integrations
// @Produce      json
// @Param        provider  path      string  true   "Forge provider"
// @Param        slug      path      string  true   "Organization slug"
// @Param        page      query     int     false  "Page number"
// @Param        per_page  query     int     false  "Items per page"
// @Success      200       {object}  api.ListResponse{data=[]store.Integration}
// @Failure      401       {object}  api.Response
// @Failure      404       {object}  api.Response
// @Failure      500       {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/integrations [get]
func (s *Server) handleListIntegrations(w http.ResponseWriter, r *http.Request) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok {
		return
	}

	isAdmin, err := s.isOrgAdminMember(r, org.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load organization")
		return
	}

	integrations, err := s.queries.ListIntegrationsByOrg(r.Context(), org.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list integrations")
		return
	}

	pagination := api.ParsePagination(r)
	visible := make([]dbgen.Integration, 0, len(integrations))
	for _, integration := range integrations {
		visible = append(visible, redactIntegrationConfig(integration, isAdmin))
	}
	api.JSONList(w, paginateItems(visible, pagination), pagination.Page, pagination.PerPage, len(visible))
}

// @Summary      Get integration
// @Description  Get an integration by ID when the caller belongs to the organization
// @Tags         integrations
// @Produce      json
// @Param        provider       path      string  true  "Forge provider"
// @Param        slug           path      string  true  "Organization slug"
// @Param        integrationID  path      string  true  "Integration ID"
// @Success      200            {object}  api.Response{data=store.Integration}
// @Failure      400            {object}  api.Response
// @Failure      401            {object}  api.Response
// @Failure      404            {object}  api.Response
// @Failure      500            {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/integrations/{integrationID} [get]
func (s *Server) handleGetIntegration(w http.ResponseWriter, r *http.Request) {
	org, integration, ok := s.loadAuthorizedIntegration(r, w)
	if !ok {
		return
	}

	isAdmin, err := s.isOrgAdminMember(r, org.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load organization")
		return
	}

	api.JSON(w, http.StatusOK, redactIntegrationConfig(*integration, isAdmin))
}

func (s *Server) handleGetIntegrationHealth(w http.ResponseWriter, r *http.Request) {
	_, integration, ok := s.loadAuthorizedIntegration(r, w)
	if !ok {
		return
	}

	api.JSON(w, http.StatusOK, notify.IntegrationHealthFor(*integration))
}

func (s *Server) handleReplayIntegration(w http.ResponseWriter, r *http.Request) {
	org, integration, ok := s.loadAuthorizedIntegration(r, w)
	if !ok {
		return
	}
	if !s.requireOrgAdmin(r, w, org.ID) {
		return
	}
	if s.dispatcher == nil {
		api.JSONError(w, http.StatusServiceUnavailable, "notification dispatcher unavailable")
		return
	}

	limit, ok := parseReplayLimit(w, r)
	if !ok {
		return
	}

	auditLogs, err := s.queries.ListAuditLogsByResource(r.Context(), "integration", integration.ID.String(), int32(limit), 0) //nolint:gosec // G115: limit is bounded to [1,10] by parseReplayLimit.
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load audit logs")
		return
	}

	response := integrationReplayResponse{
		IntegrationID: integration.ID.String(),
		Requested:     limit,
		AuditLogIDs:   make([]string, 0, len(auditLogs)),
	}
	processed := replayIntegrationAuditLogs(r.Context(), s.dispatcher, *integration, auditLogs, &response)
	response.Skipped += processed - response.Replayed - response.Skipped
	if response.Skipped < 0 {
		response.Skipped = 0
	}

	api.JSON(w, http.StatusOK, response)
}

func parseReplayLimit(w http.ResponseWriter, r *http.Request) (int, bool) {
	limit := 5
	if rawLimit := strings.TrimSpace(r.URL.Query().Get("limit")); rawLimit != "" {
		parsed, err := strconv.Atoi(rawLimit)
		if err != nil || parsed <= 0 {
			api.JSONError(w, http.StatusBadRequest, "invalid limit")
			return 0, false
		}
		if parsed > 10 {
			parsed = 10
		}
		limit = parsed
	}
	return limit, true
}

func replayIntegrationAuditLogs(ctx context.Context, dispatcher *notify.Dispatcher, integration store.Integration, auditLogs []dbgen.AuditLog, response *integrationReplayResponse) int {
	processed := 0
	for _, entry := range auditLogs {
		if entry.Action != "integration.delivery" {
			continue
		}
		processed++
		if replayIntegrationAuditLog(ctx, dispatcher, integration, entry, response) {
			response.Replayed++
		}
	}
	return processed
}

func replayIntegrationAuditLog(ctx context.Context, dispatcher *notify.Dispatcher, integration store.Integration, entry dbgen.AuditLog, response *integrationReplayResponse) bool {
	payload, err := notify.ReplayPayloadFromAuditLog(entry)
	if err != nil {
		response.Skipped++
		return false
	}
	payload.Metadata = cloneMap(payload.Metadata)
	payload.Metadata["replay_source_audit_log_id"] = entry.ID.String()
	if err := dispatcher.Replay(ctx, integration, payload); err != nil {
		response.Skipped++
		return false
	}
	response.AuditLogIDs = append(response.AuditLogIDs, entry.ID.String())
	return true
}

// @Summary      Update integration
// @Description  Update an integration when the caller is an organization admin
// @Tags         integrations
// @Accept       json
// @Produce      json
// @Param        provider       path      string                    true  "Forge provider"
// @Param        slug           path      string                    true  "Organization slug"
// @Param        integrationID  path      string                    true  "Integration ID"
// @Param        payload        body      updateIntegrationRequest  true  "Integration updates"
// @Success      200            {object}  api.Response{data=store.Integration}
// @Failure      400            {object}  api.Response
// @Failure      401            {object}  api.Response
// @Failure      403            {object}  api.Response
// @Failure      404            {object}  api.Response
// @Failure      500            {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/integrations/{integrationID} [put]
func (s *Server) handleUpdateIntegration(w http.ResponseWriter, r *http.Request) {
	org, integration, ok := s.loadAuthorizedIntegration(r, w)
	if !ok {
		return
	}
	if !s.requireOrgAdmin(r, w, org.ID) {
		return
	}

	var input updateIntegrationRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" {
		api.JSONError(w, http.StatusBadRequest, "name is required")
		return
	}

	updated, err := s.queries.UpdateIntegration(r.Context(), integration.ID, input.Name, defaultRawJSON(input.Config, "{}"), input.Enabled)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to update integration")
		return
	}
	if updated == nil {
		api.JSONError(w, http.StatusNotFound, "integration not found")
		return
	}

	api.JSON(w, http.StatusOK, updated)
}

// @Summary      Delete integration
// @Description  Delete an integration when the caller is an organization admin
// @Tags         integrations
// @Produce      json
// @Param        provider       path      string  true  "Forge provider"
// @Param        slug           path      string  true  "Organization slug"
// @Param        integrationID  path      string  true  "Integration ID"
// @Success      204            "No Content"
// @Failure      400            {object}  api.Response
// @Failure      401            {object}  api.Response
// @Failure      403            {object}  api.Response
// @Failure      404            {object}  api.Response
// @Failure      500            {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/integrations/{integrationID} [delete]
func (s *Server) handleDeleteIntegration(w http.ResponseWriter, r *http.Request) {
	org, integration, ok := s.loadAuthorizedIntegration(r, w)
	if !ok {
		return
	}
	if !s.requireOrgAdmin(r, w, org.ID) {
		return
	}

	if err := s.queries.DeleteIntegration(r.Context(), integration.ID); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to delete integration")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) loadAuthorizedIntegration(r *http.Request, w http.ResponseWriter) (*store.Organization, *store.Integration, bool) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok {
		return nil, nil, false
	}

	integrationID, err := parseUUIDParam(r, "integrationID")
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid integration ID")
		return nil, nil, false
	}

	integration, err := s.queries.GetIntegrationByID(r.Context(), integrationID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load integration")
		return nil, nil, false
	}
	if integration == nil || integration.OrgID != org.ID {
		api.JSONError(w, http.StatusNotFound, "integration not found")
		return nil, nil, false
	}

	return org, integration, true
}

func normalizeIntegrationType(value string) (dbgen.IntegrationType, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(dbgen.IntegrationTypeWebhook):
		return dbgen.IntegrationTypeWebhook, true
	case string(dbgen.IntegrationTypeSlack):
		return dbgen.IntegrationTypeSlack, true
	case string(dbgen.IntegrationTypeTeams):
		return dbgen.IntegrationTypeTeams, true
	case string(dbgen.IntegrationTypeEmail):
		return dbgen.IntegrationTypeEmail, true
	case string(dbgen.IntegrationTypeDiscord):
		return dbgen.IntegrationTypeDiscord, true
	default:
		return "", false
	}
}

func cloneMap(input map[string]any) map[string]any {
	if len(input) == 0 {
		return map[string]any{}
	}
	cloned := make(map[string]any, len(input))
	for key, value := range input {
		cloned[key] = value
	}
	return cloned
}

func (s *Server) isOrgAdminMember(r *http.Request, orgID uuid.UUID) (bool, error) {
	role, err := s.principalOrgRole(r, orgID)
	if err != nil {
		return false, err
	}
	return role == "admin", nil
}

func redactIntegrationConfig(integration dbgen.Integration, includeConfig bool) dbgen.Integration {
	if includeConfig {
		return integration
	}
	integration.Config = json.RawMessage("{}")
	return integration
}
