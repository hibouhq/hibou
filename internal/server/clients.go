package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/store"
)

type createClientRequest struct {
	Name              string            `json:"name"`
	Slug              string            `json:"slug"`
	Labels            map[string]string `json:"labels"`
	ClientType        string            `json:"client_type"`
	ContactEmail      *string           `json:"contact_email"`
	ContactName       *string           `json:"contact_name"`
	NotificationPrefs json.RawMessage   `json:"notification_prefs"`
	Metadata          json.RawMessage   `json:"metadata"`
}

type updateClientRequest struct {
	Name              string            `json:"name"`
	Labels            map[string]string `json:"labels"`
	ClientType        string            `json:"client_type"`
	ContactEmail      *string           `json:"contact_email"`
	ContactName       *string           `json:"contact_name"`
	NotificationPrefs json.RawMessage   `json:"notification_prefs"`
	Metadata          json.RawMessage   `json:"metadata"`
}

type createDeploymentRequest struct {
	ReleaseID        string     `json:"release_id"`
	Environment      string     `json:"environment"`
	Status           string     `json:"status"`
	DeployedAt       *time.Time `json:"deployed_at"`
	DeployedBy       *string    `json:"deployed_by"`
	RollbackTargetID *string    `json:"rollback_target_id"`
	Notes            *string    `json:"notes"`
}

type clientListItemResponse struct {
	store.Client
	DeploymentsCount int        `json:"deployments_count"`
	LastDeploymentAt *time.Time `json:"last_deployment_at,omitempty"`
	ActiveVersion    *string    `json:"active_version,omitempty"`
}

type deploymentResponse struct {
	store.Deployment
	ReleaseVersion *string `json:"release_version,omitempty"`
}

type clientImpactResponse struct {
	Vulnerabilities []clientImpactVulnerabilityResponse `json:"vulnerabilities"`
}

type clientImpactVulnerabilityResponse struct {
	CanonicalID    string `json:"canonical_id"`
	Severity       string `json:"severity"`
	ComponentName  string `json:"component_name"`
	ReleaseVersion string `json:"release_version"`
}

// @Summary      Create client
// @Description  Create a client within an organization when the caller is an admin
// @Tags         clients
// @Accept       json
// @Produce      json
// @Param        provider  path      string               true  "Forge provider"
// @Param        slug      path      string               true  "Organization slug"
// @Param        payload   body      createClientRequest  true  "Client details"
// @Success      201       {object}  api.Response{data=store.Client}
// @Failure      400       {object}  api.Response
// @Failure      401       {object}  api.Response
// @Failure      403       {object}  api.Response
// @Failure      404       {object}  api.Response
// @Failure      500       {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/clients [post]
func (s *Server) handleCreateClient(w http.ResponseWriter, r *http.Request) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok {
		return
	}
	if !s.requireOrgAdmin(r, w, org.ID) {
		return
	}

	var input createClientRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	input.Name = strings.TrimSpace(input.Name)
	input.Slug = strings.TrimSpace(input.Slug)
	trimStringPtr(input.ContactEmail)
	trimStringPtr(input.ContactName)
	clientType, ok := normalizeClientType(input.ClientType, "external")
	if !ok {
		api.JSONError(w, http.StatusBadRequest, "client_type must be either 'external' or 'internal'")
		return
	}

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

	labelsJSON, err := marshalClientLabels(input.Labels)
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "labels must be a valid object")
		return
	}

	client, err := s.queries.CreateClient(r.Context(), org.ID, input.Name, input.Slug, labelsJSON, clientType, input.ContactEmail, input.ContactName, input.NotificationPrefs, input.Metadata)
	if err != nil {
		if isUniqueViolation(err) {
			api.JSONError(w, http.StatusBadRequest, "client slug already exists in this organization")
			return
		}
		api.JSONError(w, http.StatusInternalServerError, "failed to create client")
		return
	}

	s.auditOrgConfig(r, org.ID, audit.ActionClientCreate, "client", client.ID.String(), map[string]any{
		"name":        client.Name,
		"slug":        client.Slug,
		"client_type": client.ClientType,
	})
	api.JSON(w, http.StatusCreated, client)
}

// @Summary      List clients
// @Description  List clients in an organization visible to organization members
// @Tags         clients
// @Produce      json
// @Param        provider  path      string  true   "Forge provider"
// @Param        slug      path      string  true   "Organization slug"
// @Param        page      query     int     false  "Page number"
// @Param        per_page  query     int     false  "Items per page"
// @Success      200       {object}  api.ListResponse{data=[]server.clientListItemResponse}
// @Failure      401       {object}  api.Response
// @Failure      404       {object}  api.Response
// @Failure      500       {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/clients [get]
func (s *Server) handleListClients(w http.ResponseWriter, r *http.Request) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok {
		return
	}

	pagination := api.ParsePagination(r)
	clients, total, err := s.queries.ListClientsWithStatsByOrg(r.Context(), org.ID, pagination.PerPage, pagination.Offset)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list clients")
		return
	}

	response := make([]clientListItemResponse, 0, len(clients))
	for _, client := range clients {
		response = append(response, clientListItemResponse{
			Client:           client.Client,
			DeploymentsCount: client.DeploymentsCount,
			LastDeploymentAt: client.LastDeploymentAt,
			ActiveVersion:    client.ActiveVersion,
		})
	}

	api.JSONList(w, response, pagination.Page, pagination.PerPage, total)
}

func (s *Server) handleListClientLabelKeys(w http.ResponseWriter, r *http.Request) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok {
		return
	}

	keys, err := s.queries.ListClientLabelKeys(r.Context(), org.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list label keys")
		return
	}

	api.JSON(w, http.StatusOK, keys)
}

// @Summary      Get client
// @Description  Get a client by slug when the caller belongs to the organization
// @Tags         clients
// @Produce      json
// @Param        provider    path      string  true  "Forge provider"
// @Param        slug        path      string  true  "Organization slug"
// @Param        clientSlug  path      string  true  "Client slug"
// @Success      200         {object}  api.Response{data=store.Client}
// @Failure      401         {object}  api.Response
// @Failure      404         {object}  api.Response
// @Failure      500         {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/clients/{clientSlug} [get]
func (s *Server) handleGetClient(w http.ResponseWriter, r *http.Request) {
	_, client, ok := s.loadAuthorizedClient(r, w)
	if !ok {
		return
	}

	api.JSON(w, http.StatusOK, client)
}

// @Summary      Update client
// @Description  Update a client when the caller is an organization admin
// @Tags         clients
// @Accept       json
// @Produce      json
// @Param        provider    path      string               true  "Forge provider"
// @Param        slug        path      string               true  "Organization slug"
// @Param        clientSlug  path      string               true  "Client slug"
// @Param        payload     body      updateClientRequest  true  "Client updates"
// @Success      200         {object}  api.Response{data=store.Client}
// @Failure      400         {object}  api.Response
// @Failure      401         {object}  api.Response
// @Failure      403         {object}  api.Response
// @Failure      404         {object}  api.Response
// @Failure      500         {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/clients/{clientSlug} [put]
func (s *Server) handleUpdateClient(w http.ResponseWriter, r *http.Request) {
	org, client, ok := s.loadAuthorizedClient(r, w)
	if !ok {
		return
	}
	if !s.requireOrgAdmin(r, w, org.ID) {
		return
	}

	var input updateClientRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	input.Name = strings.TrimSpace(input.Name)
	trimStringPtr(input.ContactEmail)
	trimStringPtr(input.ContactName)
	clientType, valid := normalizeClientType(input.ClientType, client.ClientType)
	if !valid {
		api.JSONError(w, http.StatusBadRequest, "client_type must be either 'external' or 'internal'")
		return
	}

	if input.Name == "" {
		api.JSONError(w, http.StatusBadRequest, "name is required")
		return
	}

	labelsJSON, err := marshalClientLabels(input.Labels)
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "labels must be a valid object")
		return
	}

	updated, err := s.queries.UpdateClient(r.Context(), client.ID, input.Name, labelsJSON, clientType, input.ContactEmail, input.ContactName, input.NotificationPrefs, input.Metadata)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to update client")
		return
	}
	if updated == nil {
		api.JSONError(w, http.StatusNotFound, "client not found")
		return
	}

	// Field names only: contact details are personal data.
	s.auditOrgConfig(r, org.ID, audit.ActionClientUpdate, "client", updated.ID.String(), map[string]any{
		"name":           updated.Name,
		"changed_fields": audit.ChangedFields(client, updated, "updated_at", "created_at"),
	})
	api.JSON(w, http.StatusOK, updated)
}

// @Summary      Delete client
// @Description  Delete a client when the caller is an organization admin
// @Tags         clients
// @Produce      json
// @Param        provider    path  string  true  "Forge provider"
// @Param        slug        path  string  true  "Organization slug"
// @Param        clientSlug  path  string  true  "Client slug"
// @Success      204         "No Content"
// @Failure      401         {object}  api.Response
// @Failure      403         {object}  api.Response
// @Failure      404         {object}  api.Response
// @Failure      500         {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/clients/{clientSlug} [delete]
func (s *Server) handleDeleteClient(w http.ResponseWriter, r *http.Request) {
	org, client, ok := s.loadAuthorizedClient(r, w)
	if !ok {
		return
	}
	if !s.requireOrgAdmin(r, w, org.ID) {
		return
	}

	if err := s.queries.DeleteClient(r.Context(), client.ID); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to delete client")
		return
	}
	s.auditOrgConfig(r, org.ID, audit.ActionClientDelete, "client", client.ID.String(), map[string]any{
		"name": client.Name,
		"slug": client.Slug,
	})

	w.WriteHeader(http.StatusNoContent)
}

// @Summary      List client deployments
// @Description  List deployments for a client visible to organization members
// @Tags         clients
// @Produce      json
// @Param        provider    path      string  true   "Forge provider"
// @Param        slug        path      string  true   "Organization slug"
// @Param        clientSlug  path      string  true   "Client slug"
// @Param        page        query     int     false  "Page number"
// @Param        per_page    query     int     false  "Items per page"
// @Success      200         {object}  api.ListResponse{data=[]server.deploymentResponse}
// @Failure      401         {object}  api.Response
// @Failure      404         {object}  api.Response
// @Failure      500         {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/clients/{clientSlug}/deployments [get]
func (s *Server) handleListClientDeployments(w http.ResponseWriter, r *http.Request) {
	_, client, ok := s.loadAuthorizedClient(r, w)
	if !ok {
		return
	}

	pagination := api.ParsePagination(r)
	deployments, total, err := s.queries.ListDeploymentsWithReleaseByClient(r.Context(), client.ID, pagination.PerPage, pagination.Offset)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list deployments")
		return
	}

	response := make([]deploymentResponse, 0, len(deployments))
	for _, deployment := range deployments {
		response = append(response, deploymentResponse{Deployment: deployment.Deployment, ReleaseVersion: deployment.ReleaseVersion})
	}

	api.JSONList(w, response, pagination.Page, pagination.PerPage, total)
}

// @Summary      Create deployment
// @Description  Create a deployment for a client when the caller is an organization admin
// @Tags         clients
// @Accept       json
// @Produce      json
// @Param        provider    path      string                   true  "Forge provider"
// @Param        slug        path      string                   true  "Organization slug"
// @Param        clientSlug  path      string                   true  "Client slug"
// @Param        payload     body      createDeploymentRequest  true  "Deployment details"
// @Success      201         {object}  api.Response{data=server.deploymentResponse}
// @Failure      400         {object}  api.Response
// @Failure      401         {object}  api.Response
// @Failure      403         {object}  api.Response
// @Failure      404         {object}  api.Response
// @Failure      500         {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/clients/{clientSlug}/deployments [post]
func (s *Server) handleCreateDeployment(w http.ResponseWriter, r *http.Request) {
	org, client, ok := s.loadAuthorizedClient(r, w)
	if !ok {
		return
	}
	if !s.requireOrgAdmin(r, w, org.ID) {
		return
	}

	var input createDeploymentRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	release, ok := s.loadDeploymentRelease(w, r, org.ID, input.ReleaseID)
	if !ok {
		return
	}
	status, ok := parseDeploymentStatus(input.Status)
	if !ok {
		api.JSONError(w, http.StatusBadRequest, "invalid deployment status")
		return
	}
	environment := strings.TrimSpace(input.Environment)
	if environment == "" {
		api.JSONError(w, http.StatusBadRequest, "environment is required")
		return
	}
	trimStringPtr(input.DeployedBy)
	trimStringPtr(input.Notes)

	rollbackTargetID, err := parseRollbackTargetID(input.RollbackTargetID)
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid rollback_target_id")
		return
	}
	deployedAt := deploymentTime(input.DeployedAt)

	if err := s.supersedeActiveDeployments(r, client.ID, environment, status); err != nil {
		s.log.Error().Err(err).Str("client_id", client.ID.String()).Msg("supersede active deployments")
		api.JSONError(w, http.StatusInternalServerError, "failed to supersede active deployments")
		return
	}

	deployment, err := s.queries.CreateDeployment(r.Context(), client.ID, release.ID, environment, status, deployedAt, input.DeployedBy, rollbackTargetID, input.Notes)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to create deployment")
		return
	}

	response := deploymentResponse{Deployment: *deployment, ReleaseVersion: &release.Version}
	api.JSON(w, http.StatusCreated, response)
}

func (s *Server) loadDeploymentRelease(w http.ResponseWriter, r *http.Request, orgID uuid.UUID, rawReleaseID string) (*store.Release, bool) {
	releaseID, err := uuid.Parse(strings.TrimSpace(rawReleaseID))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid release_id")
		return nil, false
	}
	release, err := s.queries.GetReleaseByID(r.Context(), releaseID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load release")
		return nil, false
	}
	if release == nil {
		api.JSONError(w, http.StatusNotFound, "release not found")
		return nil, false
	}
	belongsToOrg, err := s.releaseBelongsToOrg(r, release, orgID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to validate release")
		return nil, false
	}
	if !belongsToOrg {
		api.JSONError(w, http.StatusNotFound, "release not found")
		return nil, false
	}
	return release, true
}

func parseDeploymentStatus(raw string) (store.DeploymentStatus, bool) {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	if normalized == "" {
		return store.DeploymentStatusActive, true
	}
	switch normalized {
	case string(store.DeploymentStatusActive):
		return store.DeploymentStatusActive, true
	case string(store.DeploymentStatusRolledBack):
		return store.DeploymentStatusRolledBack, true
	case string(store.DeploymentStatusSuperseded):
		return store.DeploymentStatusSuperseded, true
	default:
		return "", false
	}
}

func parseRollbackTargetID(raw *string) (*uuid.UUID, error) {
	if raw == nil || strings.TrimSpace(*raw) == "" {
		return nil, nil
	}
	parsed, err := uuid.Parse(strings.TrimSpace(*raw))
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

func deploymentTime(raw *time.Time) time.Time {
	if raw == nil {
		return time.Now().UTC()
	}
	return raw.UTC()
}

func (s *Server) supersedeActiveDeployments(r *http.Request, clientID uuid.UUID, environment string, status store.DeploymentStatus) error {
	if status != store.DeploymentStatusActive {
		return nil
	}
	activeDeployments, err := s.queries.ListActiveDeploymentsByClient(r.Context(), clientID)
	if err != nil {
		return errors.New("failed to load active deployments")
	}
	for _, activeDeployment := range activeDeployments {
		if activeDeployment.Environment != environment {
			continue
		}
		if _, err := s.queries.UpdateDeploymentStatus(r.Context(), activeDeployment.ID, store.DeploymentStatusSuperseded); err != nil {
			return errors.New("failed to update active deployments")
		}
	}
	return nil
}

// @Summary      Get client impact
// @Description  List vulnerabilities affecting active deployments for a client
// @Tags         clients
// @Produce      json
// @Param        provider    path      string  true  "Forge provider"
// @Param        slug        path      string  true  "Organization slug"
// @Param        clientSlug  path      string  true  "Client slug"
// @Success      200         {object}  api.Response{data=server.clientImpactResponse}
// @Failure      401         {object}  api.Response
// @Failure      404         {object}  api.Response
// @Failure      500         {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/clients/{clientSlug}/impact [get]
func (s *Server) handleGetClientImpact(w http.ResponseWriter, r *http.Request) {
	_, client, ok := s.loadAuthorizedClient(r, w)
	if !ok {
		return
	}

	vulns, err := s.queries.ListClientImpactVulns(r.Context(), client.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load client impact")
		return
	}

	results := make([]clientImpactVulnerabilityResponse, len(vulns))
	for i, vuln := range vulns {
		results[i] = clientImpactVulnerabilityResponse{
			CanonicalID:    vuln.CanonicalID,
			Severity:       vuln.Severity,
			ComponentName:  vuln.ComponentName,
			ReleaseVersion: vuln.ReleaseVersion,
		}
	}

	// Keep API ordering stable even if the backing query plan changes.
	sort.SliceStable(results, func(i, j int) bool {
		left := results[i]
		right := results[j]
		if severityRank(left.Severity) == severityRank(right.Severity) {
			if left.ReleaseVersion == right.ReleaseVersion {
				if left.ComponentName == right.ComponentName {
					return left.CanonicalID < right.CanonicalID
				}
				return left.ComponentName < right.ComponentName
			}
			return left.ReleaseVersion < right.ReleaseVersion
		}
		return severityRank(left.Severity) > severityRank(right.Severity)
	})

	api.JSON(w, http.StatusOK, clientImpactResponse{Vulnerabilities: results})
}

func (s *Server) loadAuthorizedClient(r *http.Request, w http.ResponseWriter) (*store.Organization, *store.Client, bool) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok {
		return nil, nil, false
	}

	client, err := s.queries.GetClientBySlug(r.Context(), org.ID, chi.URLParam(r, "clientSlug"))
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load client")
		return nil, nil, false
	}
	if client == nil {
		api.JSONError(w, http.StatusNotFound, "client not found")
		return nil, nil, false
	}

	return org, client, true
}

func marshalClientLabels(labels map[string]string) (json.RawMessage, error) {
	if labels == nil {
		return json.RawMessage("{}"), nil
	}

	encoded, err := json.Marshal(labels)
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

func (s *Server) requireOrgAdmin(r *http.Request, w http.ResponseWriter, orgID uuid.UUID) bool {
	if !s.hasPrincipal(r) {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return false
	}
	role, err := s.principalOrgRole(r, orgID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load organization")
		return false
	}
	if role != "admin" {
		api.JSONError(w, http.StatusForbidden, "admin access required")
		return false
	}
	return true
}

func trimStringPtr(value *string) {
	if value == nil {
		return
	}
	trimmed := strings.TrimSpace(*value)
	*value = trimmed
}

func normalizeClientType(value string, fallback string) (string, bool) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		normalized = strings.ToLower(strings.TrimSpace(fallback))
	}
	if normalized == "" {
		normalized = "external"
	}
	if normalized != "external" && normalized != "internal" {
		return "", false
	}
	return normalized, true
}

func (s *Server) releaseBelongsToOrg(r *http.Request, release *store.Release, orgID uuid.UUID) (bool, error) {
	const query = `SELECT EXISTS (SELECT 1 FROM repositories WHERE id = $1 AND org_id = $2)`
	var exists bool
	err := s.db.QueryRowContext(r.Context(), query, release.RepoID, orgID).Scan(&exists)
	return exists, err
}
