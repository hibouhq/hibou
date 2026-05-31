package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/hibouhq/lehibou/internal/api"
	"github.com/hibouhq/lehibou/internal/events"
	"github.com/hibouhq/lehibou/internal/notify"
	"github.com/hibouhq/lehibou/internal/store"
)

type createNotificationRuleRequest struct {
	Name              string          `json:"name"`
	EventType         string          `json:"event_type"`
	Conditions        json.RawMessage `json:"conditions"`
	DestinationType   string          `json:"destination_type"`
	DestinationConfig json.RawMessage `json:"destination_config"`
	Enabled           bool            `json:"enabled"`
}

type updateNotificationRuleRequest struct {
	Name              string          `json:"name"`
	EventType         string          `json:"event_type"`
	Conditions        json.RawMessage `json:"conditions"`
	DestinationType   string          `json:"destination_type"`
	DestinationConfig json.RawMessage `json:"destination_config"`
	Enabled           bool            `json:"enabled"`
}

type dryRunNotificationRuleResponse struct {
	Matches []dryRunNotificationRuleMatch `json:"matches"`
}

type dryRunNotificationRuleMatch struct {
	EventType    string                     `json:"event_type"`
	Title        string                     `json:"title"`
	RepoName     string                     `json:"repo_name"`
	CreatedAt    time.Time                  `json:"created_at"`
	Integrations []dryRunNotificationTarget `json:"integrations"`
}

type dryRunNotificationTarget struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

// @Summary      Create notification rule
// @Description  Create a notification rule within an organization when the caller is an admin
// @Tags         notification-rules
// @Accept       json
// @Produce      json
// @Param        provider  path      string                          true  "Forge provider"
// @Param        slug      path      string                          true  "Organization slug"
// @Param        payload   body      createNotificationRuleRequest   true  "Notification rule details"
// @Success      201       {object}  api.Response{data=store.NotificationRule}
// @Failure      400       {object}  api.Response
// @Failure      401       {object}  api.Response
// @Failure      403       {object}  api.Response
// @Failure      404       {object}  api.Response
// @Failure      500       {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/notification-rules [post]
func (s *Server) handleCreateNotificationRule(w http.ResponseWriter, r *http.Request) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok {
		return
	}
	if !s.requireOrgAdmin(r, w, org.ID) {
		return
	}

	var input createNotificationRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	input.Name = strings.TrimSpace(input.Name)
	input.EventType = strings.TrimSpace(input.EventType)
	destinationType, ok := normalizeDestinationType(input.DestinationType)
	if !ok {
		api.JSONError(w, http.StatusBadRequest, "destination_type must be one of 'webhook', 'slack', 'teams', 'discord', or 'email'")
		return
	}
	if input.Name == "" {
		api.JSONError(w, http.StatusBadRequest, "name is required")
		return
	}
	if input.EventType == "" {
		api.JSONError(w, http.StatusBadRequest, "event_type is required")
		return
	}
	if !isValidNotificationEventType(input.EventType) {
		api.JSONError(w, http.StatusBadRequest, "invalid event_type")
		return
	}

	rule, err := s.queries.CreateNotificationRule(r.Context(), org.ID, input.Name, input.EventType, defaultRawJSON(input.Conditions, "{}"), destinationType, defaultRawJSON(input.DestinationConfig, "{}"), input.Enabled)
	if err != nil {
		if isUniqueViolation(err) {
			api.JSONError(w, http.StatusBadRequest, "notification rule name already exists in this organization")
			return
		}
		api.JSONError(w, http.StatusInternalServerError, "failed to create notification rule")
		return
	}

	api.JSON(w, http.StatusCreated, rule)
}

// @Summary      List notification rules
// @Description  List notification rules in an organization visible to organization members
// @Tags         notification-rules
// @Produce      json
// @Param        provider  path      string  true   "Forge provider"
// @Param        slug      path      string  true   "Organization slug"
// @Param        page      query     int     false  "Page number"
// @Param        per_page  query     int     false  "Items per page"
// @Success      200       {object}  api.ListResponse{data=[]store.NotificationRule}
// @Failure      401       {object}  api.Response
// @Failure      404       {object}  api.Response
// @Failure      500       {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/notification-rules [get]
func (s *Server) handleListNotificationRules(w http.ResponseWriter, r *http.Request) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok {
		return
	}

	rules, err := s.queries.ListNotificationRulesByOrg(r.Context(), org.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list notification rules")
		return
	}

	pagination := api.ParsePagination(r)
	api.JSONList(w, paginateItems(rules, pagination), pagination.Page, pagination.PerPage, len(rules))
}

func (s *Server) handleDryRunNotificationRule(w http.ResponseWriter, r *http.Request) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok {
		return
	}
	if !s.requireOrgAdmin(r, w, org.ID) {
		return
	}

	var input createNotificationRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	input.Name = strings.TrimSpace(input.Name)
	input.EventType = strings.TrimSpace(input.EventType)
	destinationType, valid := normalizeDestinationType(input.DestinationType)
	if !valid {
		api.JSONError(w, http.StatusBadRequest, "destination_type must be one of 'webhook', 'slack', 'teams', 'discord', or 'email'")
		return
	}
	if input.EventType == "" {
		api.JSONError(w, http.StatusBadRequest, "event_type is required")
		return
	}
	if !isValidNotificationEventType(input.EventType) {
		api.JSONError(w, http.StatusBadRequest, "invalid event_type")
		return
	}

	integrations, err := s.queries.ListIntegrationsByOrg(r.Context(), org.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load integrations")
		return
	}
	auditLogs, err := s.queries.ListRecentAuditLogsByOrg(r.Context(), org.ID, time.Now().UTC().Add(-24*time.Hour), 200)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load recent events")
		return
	}

	rule := store.NotificationRule{
		OrgID:             org.ID,
		Name:              input.Name,
		EventType:         input.EventType,
		Conditions:        defaultRawJSON(input.Conditions, "{}"),
		DestinationType:   destinationType,
		DestinationConfig: defaultRawJSON(input.DestinationConfig, "{}"),
		Enabled:           true,
	}
	response := dryRunNotificationRuleResponse{Matches: make([]dryRunNotificationRuleMatch, 0)}
	seen := make(map[string]struct{})
	for _, entry := range auditLogs {
		if entry.Action != "integration.delivery" {
			continue
		}
		key := string(entry.Context)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		payload, err := notify.ReplayPayloadFromAuditLog(entry)
		if err != nil || payload.EventType != input.EventType {
			continue
		}
		targets := notify.PreviewIntegrationsForRule(payload, integrations, rule)
		if len(targets) == 0 {
			continue
		}
		match := dryRunNotificationRuleMatch{
			EventType:    payload.EventType,
			Title:        payload.Title,
			RepoName:     payload.RepoName,
			CreatedAt:    entry.CreatedAt.UTC(),
			Integrations: make([]dryRunNotificationTarget, 0, len(targets)),
		}
		for _, integration := range targets {
			match.Integrations = append(match.Integrations, dryRunNotificationTarget{
				ID:   integration.ID.String(),
				Name: integration.Name,
				Type: integration.IntegrationType,
			})
		}
		response.Matches = append(response.Matches, match)
	}

	api.JSON(w, http.StatusOK, response)
}

// @Summary      Get notification rule
// @Description  Get a notification rule by ID when the caller belongs to the organization
// @Tags         notification-rules
// @Produce      json
// @Param        provider  path      string  true  "Forge provider"
// @Param        slug      path      string  true  "Organization slug"
// @Param        ruleID    path      string  true  "Notification rule ID"
// @Success      200       {object}  api.Response{data=store.NotificationRule}
// @Failure      400       {object}  api.Response
// @Failure      401       {object}  api.Response
// @Failure      404       {object}  api.Response
// @Failure      500       {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/notification-rules/{ruleID} [get]
func (s *Server) handleGetNotificationRule(w http.ResponseWriter, r *http.Request) {
	_, rule, ok := s.loadAuthorizedNotificationRule(r, w)
	if !ok {
		return
	}

	api.JSON(w, http.StatusOK, rule)
}

// @Summary      Update notification rule
// @Description  Update a notification rule when the caller is an organization admin
// @Tags         notification-rules
// @Accept       json
// @Produce      json
// @Param        provider  path      string                          true  "Forge provider"
// @Param        slug      path      string                          true  "Organization slug"
// @Param        ruleID    path      string                          true  "Notification rule ID"
// @Param        payload   body      updateNotificationRuleRequest   true  "Notification rule updates"
// @Success      200       {object}  api.Response{data=store.NotificationRule}
// @Failure      400       {object}  api.Response
// @Failure      401       {object}  api.Response
// @Failure      403       {object}  api.Response
// @Failure      404       {object}  api.Response
// @Failure      500       {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/notification-rules/{ruleID} [put]
func (s *Server) handleUpdateNotificationRule(w http.ResponseWriter, r *http.Request) {
	org, rule, ok := s.loadAuthorizedNotificationRule(r, w)
	if !ok {
		return
	}
	if !s.requireOrgAdmin(r, w, org.ID) {
		return
	}

	var input updateNotificationRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	input.Name = strings.TrimSpace(input.Name)
	input.EventType = strings.TrimSpace(input.EventType)
	destinationType, valid := normalizeDestinationType(input.DestinationType)
	if !valid {
		api.JSONError(w, http.StatusBadRequest, "destination_type must be one of 'webhook', 'slack', 'teams', 'discord', or 'email'")
		return
	}
	if input.Name == "" {
		api.JSONError(w, http.StatusBadRequest, "name is required")
		return
	}
	if input.EventType == "" {
		api.JSONError(w, http.StatusBadRequest, "event_type is required")
		return
	}
	if !isValidNotificationEventType(input.EventType) {
		api.JSONError(w, http.StatusBadRequest, "invalid event_type")
		return
	}

	updated, err := s.queries.UpdateNotificationRule(r.Context(), rule.ID, input.Name, input.EventType, defaultRawJSON(input.Conditions, "{}"), destinationType, defaultRawJSON(input.DestinationConfig, "{}"), input.Enabled)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to update notification rule")
		return
	}
	if updated == nil {
		api.JSONError(w, http.StatusNotFound, "notification rule not found")
		return
	}

	api.JSON(w, http.StatusOK, updated)
}

// @Summary      Delete notification rule
// @Description  Delete a notification rule when the caller is an organization admin
// @Tags         notification-rules
// @Produce      json
// @Param        provider  path      string  true  "Forge provider"
// @Param        slug      path      string  true  "Organization slug"
// @Param        ruleID    path      string  true  "Notification rule ID"
// @Success      204       "No Content"
// @Failure      400       {object}  api.Response
// @Failure      401       {object}  api.Response
// @Failure      403       {object}  api.Response
// @Failure      404       {object}  api.Response
// @Failure      500       {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/notification-rules/{ruleID} [delete]
func (s *Server) handleDeleteNotificationRule(w http.ResponseWriter, r *http.Request) {
	org, rule, ok := s.loadAuthorizedNotificationRule(r, w)
	if !ok {
		return
	}
	if !s.requireOrgAdmin(r, w, org.ID) {
		return
	}

	if err := s.queries.DeleteNotificationRule(r.Context(), rule.ID); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to delete notification rule")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) loadAuthorizedNotificationRule(r *http.Request, w http.ResponseWriter) (*store.Organization, *store.NotificationRule, bool) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok {
		return nil, nil, false
	}

	ruleID, err := parseUUIDParam(r, "ruleID")
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid notification rule ID")
		return nil, nil, false
	}

	rule, err := s.queries.GetNotificationRuleByID(r.Context(), ruleID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load notification rule")
		return nil, nil, false
	}
	if rule == nil || rule.OrgID != org.ID {
		api.JSONError(w, http.StatusNotFound, "notification rule not found")
		return nil, nil, false
	}

	return org, rule, true
}

func normalizeDestinationType(value string) (store.NotificationDestinationType, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(store.NotificationDestinationTypeWebhook):
		return store.NotificationDestinationTypeWebhook, true
	case string(store.NotificationDestinationTypeSlack):
		return store.NotificationDestinationTypeSlack, true
	case string(store.NotificationDestinationTypeTeams):
		return store.NotificationDestinationTypeTeams, true
	case string(store.NotificationDestinationTypeDiscord):
		return store.NotificationDestinationTypeDiscord, true
	case string(store.NotificationDestinationTypeEmail):
		return store.NotificationDestinationTypeEmail, true
	default:
		return "", false
	}
}

func isValidNotificationEventType(value string) bool {
	switch strings.TrimSpace(value) {
	case string(events.ScanRequested),
		string(events.ScanCompleted),
		string(events.ScanFailed),
		string(events.ScanStale),
		string(events.VulnDiscovered),
		string(events.FindingCreated),
		string(events.GatePassed),
		string(events.GateFailed),
		string(events.NotificationNew):
		return true
	default:
		return false
	}
}
