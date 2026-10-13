package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/applicability"
	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/scanpolicy"
	"github.com/hibouhq/hibou/internal/store"
)

// maxExceptionDays bounds an exception: it must expire (ADR-035 §5).
const maxExceptionDays = 365

type repoScannerSettingsResponse struct {
	Decisions    []scanpolicy.Decision      `json:"decisions"`
	Requirements []store.ScannerRequirement `json:"requirements"`
	Exceptions   []store.CoverageException  `json:"exceptions"`
}

// repoScannerDecisions resolves which scanners run on the repository from
// trusted org state only (D10): its latest detection, its settings, the org
// requirements and its exceptions. Nothing here is read from the repository.
func (s *Server) repoScannerDecisions(ctx context.Context, repo *store.Repository, detected *applicability.Result) ([]scanpolicy.Decision, []store.ScannerRequirement, []store.CoverageException, error) {
	result := applicability.Result{Status: applicability.StatusUnknown, Languages: map[string]int{}}
	if detected != nil {
		result = *detected
	} else if latest, err := s.queries.GetLatestRepoApplicability(ctx, repo.ID); err != nil {
		return nil, nil, nil, err
	} else if latest != nil {
		if err := json.Unmarshal(latest.Result, &result); err != nil {
			return nil, nil, nil, err
		}
	}
	settings, err := s.queries.ListRepoScannerSettings(ctx, repo.ID)
	if err != nil {
		return nil, nil, nil, err
	}
	requirements, err := s.queries.ListScannerRequirements(ctx, repo.OrgID)
	if err != nil {
		return nil, nil, nil, err
	}
	exceptions, err := s.queries.ListCoverageExceptionsByRepo(ctx, repo.ID)
	if err != nil {
		return nil, nil, nil, err
	}
	input := scanpolicy.Input{Catalog: s.scanCatalog, Applicability: result, Settings: map[string]string{}, Now: time.Now()}
	for _, setting := range settings {
		input.Settings[setting.ScannerID] = setting.Mode
	}
	for _, requirement := range requirements {
		input.Requirements = append(input.Requirements, scanpolicy.Requirement{
			ID: requirement.ID, Language: requirement.Language, Capability: requirement.Capability,
			ScannerIDs: requirement.ScannerIDs, FreshnessDays: requirement.FreshnessDays, Enforcement: requirement.Enforcement,
		})
	}
	for _, exception := range exceptions {
		input.Exceptions = append(input.Exceptions, scanpolicy.Exception{
			ID: exception.ID, RequirementID: exception.RequirementID, Scope: exception.Scope, Status: exception.Status, ExpiresAt: exception.ExpiresAt,
		})
	}
	return scanpolicy.Resolve(input), requirements, exceptions, nil
}

// @Summary      Effective scanner settings of a repository
// @Description  One decision per scanner — required (org), enabled or disabled (repo), recommended (org default), off (pre-release) — with its source, the requirements behind it and any approved exception (ADR-035 §5). The same resolution feeds the scan plan.
// @Tags         scanners
// @Produce      json
// @Param        provider  path  string  true  "Forge provider"
// @Param        slug      path  string  true  "Organization slug"
// @Param        repoSlug  path  string  true  "Repository slug"
// @Success      200  {object}  api.Response{data=server.repoScannerSettingsResponse}
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/scanner-settings [get]
func (s *Server) handleGetRepoScannerSettings(w http.ResponseWriter, r *http.Request) {
	_, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}
	if s.scanCatalog == nil {
		api.JSONError(w, http.StatusServiceUnavailable, "scanner catalog unavailable")
		return
	}
	decisions, requirements, exceptions, err := s.repoScannerDecisions(r.Context(), repo, nil)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to resolve scanner settings")
		return
	}
	api.JSON(w, http.StatusOK, repoScannerSettingsResponse{Decisions: decisions, Requirements: requirements, Exceptions: exceptions})
}

type setRepoScannerRequest struct {
	ScannerID string `json:"scanner_id"`
	Mode      string `json:"mode"`
}

// @Summary      Enable, disable or inherit a scanner on a repository
// @Description  Repository admins. "disabled" does not remove a scanner the organization requires; that needs an approved exception.
// @Tags         scanners
// @Accept       json
// @Produce      json
// @Param        provider  path  string                         true  "Forge provider"
// @Param        slug      path  string                         true  "Organization slug"
// @Param        repoSlug  path  string                         true  "Repository slug"
// @Param        payload   body  server.setRepoScannerRequest  true  "Setting"
// @Success      200  {object}  api.Response{data=server.repoScannerSettingsResponse}
// @Failure      400  {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/scanner-settings [put]
func (s *Server) handleSetRepoScannerSetting(w http.ResponseWriter, r *http.Request) {
	org, repo, user, ok := s.loadAuthorizedRepoWithUser(w, r, true)
	if !ok {
		return
	}
	if !s.enforceTokenCapability(w, r, apitoken.CapAdmin, apitoken.AccessWrite, org.Slug, repo.Slug) {
		return
	}
	var request setRepoScannerRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if _, ok := s.scanCatalog.Scanner(request.ScannerID); !ok {
		api.JSONError(w, http.StatusBadRequest, "unknown scanner")
		return
	}
	switch request.Mode {
	case scanpolicy.ModeInherit, scanpolicy.ModeEnabled, scanpolicy.ModeDisabled:
	default:
		api.JSONError(w, http.StatusBadRequest, "mode must be inherit, enabled or disabled")
		return
	}
	var actor *uuid.UUID
	if user != nil {
		actor = &user.ID
	}
	if err := s.queries.UpsertRepoScannerSetting(r.Context(), repo.ID, request.ScannerID, request.Mode, actor); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to save scanner setting")
		return
	}
	s.writeRepositoryAuditLog(r, user, org.ID, repo.ID, audit.ActionConfigChange, map[string]any{
		"scanner_id": request.ScannerID, "mode": request.Mode, "setting": "scanner",
	})
	s.refreshScanCoverageAsync(repo)
	s.handleGetRepoScannerSettings(w, r)
}

type requestCoverageExceptionRequest struct {
	RequirementID uuid.UUID `json:"requirement_id"`
	Scope         string    `json:"scope"`
	Reason        string    `json:"reason"`
	ExpiresInDays int       `json:"expires_in_days"`
}

// @Summary      Request an exception to an org scanner requirement
// @Description  Asks org admins to waive a requirement for this repository. Needs a reason and an expiry (at most 365 days); it takes effect only once approved.
// @Tags         scanners
// @Accept       json
// @Produce      json
// @Param        provider  path  string                                  true  "Forge provider"
// @Param        slug      path  string                                  true  "Organization slug"
// @Param        repoSlug  path  string                                  true  "Repository slug"
// @Param        payload   body  server.requestCoverageExceptionRequest  true  "Exception request"
// @Success      201  {object}  api.Response{data=store.CoverageException}
// @Failure      400  {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/coverage-exceptions [post]
func (s *Server) handleRequestCoverageException(w http.ResponseWriter, r *http.Request) {
	org, repo, user, ok := s.loadAuthorizedRepoWithUser(w, r, false)
	if !ok {
		return
	}
	if !s.enforceTokenCapability(w, r, apitoken.CapTriage, apitoken.AccessWrite, org.Slug, repo.Slug) {
		return
	}
	var request requestCoverageExceptionRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	request.Reason = strings.TrimSpace(request.Reason)
	request.Scope = strings.TrimSpace(request.Scope)
	if request.Scope == "" {
		request.Scope = "."
	}
	if request.Reason == "" || len(request.Reason) > 2000 {
		api.JSONError(w, http.StatusBadRequest, "a reason is required (at most 2000 characters)")
		return
	}
	if request.ExpiresInDays < 1 || request.ExpiresInDays > maxExceptionDays {
		api.JSONError(w, http.StatusBadRequest, "expires_in_days must be between 1 and 365: an exception must expire")
		return
	}
	requirements, err := s.queries.ListScannerRequirements(r.Context(), org.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load requirements")
		return
	}
	known := false
	for _, requirement := range requirements {
		known = known || requirement.ID == request.RequirementID
	}
	if !known {
		api.JSONError(w, http.StatusBadRequest, "unknown requirement")
		return
	}
	var actor *uuid.UUID
	if user != nil {
		actor = &user.ID
	}
	exception, err := s.queries.CreateCoverageException(r.Context(), store.CoverageException{
		RepoID: repo.ID, RequirementID: request.RequirementID, Scope: request.Scope, Reason: request.Reason,
		RequestedBy: actor, ExpiresAt: time.Now().Add(time.Duration(request.ExpiresInDays) * 24 * time.Hour),
	})
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to request the exception")
		return
	}
	s.writeRepositoryAuditLog(r, user, org.ID, repo.ID, audit.ActionConfigChange, map[string]any{
		"setting": "coverage_exception", "status": "requested", "requirement_id": request.RequirementID.String(), "reason": request.Reason,
	})
	api.JSON(w, http.StatusCreated, exception)
}

type orgScannerPolicyResponse struct {
	Requirements      []store.ScannerRequirement `json:"requirements"`
	PendingExceptions []store.CoverageException  `json:"pending_exceptions"`
}

// @Summary      Org scanner requirements and pending exceptions
// @Tags         scanners
// @Produce      json
// @Param        provider  path  string  true  "Forge provider"
// @Param        slug      path  string  true  "Organization slug"
// @Success      200  {object}  api.Response{data=server.orgScannerPolicyResponse}
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/scanner-requirements [get]
func (s *Server) handleGetScannerRequirements(w http.ResponseWriter, r *http.Request) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok {
		return
	}
	requirements, err := s.queries.ListScannerRequirements(r.Context(), org.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load requirements")
		return
	}
	pending, err := s.queries.ListPendingCoverageExceptionsByOrg(r.Context(), org.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load exceptions")
		return
	}
	api.JSON(w, http.StatusOK, orgScannerPolicyResponse{Requirements: requirements, PendingExceptions: pending})
}

// @Summary      Require a scanner capability for a language
// @Description  Org admins. Requires, on every repository with code in the language, a catalog scanner providing the capability (restricted to scanner_ids when set; pre-releases only when named). blocking fails the coverage check; advisory warns.
// @Tags         scanners
// @Accept       json
// @Produce      json
// @Param        provider  path  string                    true  "Forge provider"
// @Param        slug      path  string                    true  "Organization slug"
// @Param        payload   body  store.ScannerRequirement  true  "Requirement"
// @Success      200  {object}  api.Response{data=store.ScannerRequirement}
// @Failure      400  {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/scanner-requirements [put]
func (s *Server) handleSetScannerRequirement(w http.ResponseWriter, r *http.Request) {
	org, user, ok := s.loadOrgAdminUser(r, w)
	if !ok {
		return
	}
	if !s.enforceOrgWideCapability(w, r, apitoken.CapAdmin, apitoken.AccessWrite, org.Slug) {
		return
	}
	var request store.ScannerRequirement
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	request.Language = strings.ToLower(strings.TrimSpace(request.Language))
	request.Capability = strings.TrimSpace(request.Capability)
	if request.Enforcement == "" {
		request.Enforcement = "advisory"
	}
	if request.Enforcement != "advisory" && request.Enforcement != "blocking" {
		api.JSONError(w, http.StatusBadRequest, "enforcement must be advisory or blocking")
		return
	}
	if request.FreshnessDays < 0 || request.FreshnessDays > 3650 {
		api.JSONError(w, http.StatusBadRequest, "freshness_days must be between 0 and 3650")
		return
	}
	provided := false
	for i := range s.scanCatalog.Scanners {
		for _, capability := range s.scanCatalog.Scanners[i].Capabilities {
			provided = provided || (capability.Language == request.Language && capability.Capability == request.Capability)
		}
	}
	if !provided {
		api.JSONError(w, http.StatusBadRequest, "no catalog scanner provides "+request.Capability+" for "+request.Language)
		return
	}
	for _, id := range request.ScannerIDs {
		if _, ok := s.scanCatalog.Scanner(id); !ok {
			api.JSONError(w, http.StatusBadRequest, "unknown scanner "+id)
			return
		}
	}
	var actor *uuid.UUID
	if user != nil {
		actor = &user.ID
	}
	saved, err := s.queries.UpsertScannerRequirement(r.Context(), org.ID, request, actor)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to save requirement")
		return
	}
	s.writeAuditLog(r, user, orgAuditID(org.ID), auditEntry{
		Action: audit.ActionSettingUpdate, ResourceType: "scanner_requirement", ResourceID: saved.ID.String(),
		Context: map[string]any{"language": saved.Language, "capability": saved.Capability, "enforcement": saved.Enforcement},
	})
	s.refreshOrgScanCoverageAsync(org.ID)
	api.JSON(w, http.StatusOK, saved)
}

// @Summary      Remove a scanner requirement
// @Tags         scanners
// @Param        provider  path   string  true  "Forge provider"
// @Param        slug      path   string  true  "Organization slug"
// @Param        id        query  string  true  "Requirement ID"
// @Success      204
// @Failure      404  {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/scanner-requirements [delete]
func (s *Server) handleDeleteScannerRequirement(w http.ResponseWriter, r *http.Request) {
	org, user, ok := s.loadOrgAdminUser(r, w)
	if !ok {
		return
	}
	if !s.enforceOrgWideCapability(w, r, apitoken.CapAdmin, apitoken.AccessWrite, org.Slug) {
		return
	}
	id, err := uuid.Parse(r.URL.Query().Get("id"))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	deleted, err := s.queries.DeleteScannerRequirement(r.Context(), org.ID, id)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to delete requirement")
		return
	}
	if !deleted {
		api.JSONError(w, http.StatusNotFound, "requirement not found")
		return
	}
	s.writeAuditLog(r, user, orgAuditID(org.ID), auditEntry{Action: audit.ActionSettingUpdate, ResourceType: "scanner_requirement", ResourceID: id.String(), Context: map[string]any{"deleted": true}})
	s.refreshOrgScanCoverageAsync(org.ID)
	w.WriteHeader(http.StatusNoContent)
}

type decideExceptionRequest struct {
	Approve bool `json:"approve"`
}

// @Summary      Approve or reject a coverage exception
// @Tags         scanners
// @Accept       json
// @Produce      json
// @Param        provider     path  string                         true  "Forge provider"
// @Param        slug         path  string                         true  "Organization slug"
// @Param        exceptionID  path  string                         true  "Exception ID"
// @Param        payload      body  server.decideExceptionRequest  true  "Decision"
// @Success      200  {object}  api.Response{data=store.CoverageException}
// @Failure      404  {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/coverage-exceptions/{exceptionID}/decision [post]
func (s *Server) handleDecideCoverageException(w http.ResponseWriter, r *http.Request) {
	org, user, ok := s.loadOrgAdminUser(r, w)
	if !ok {
		return
	}
	if !s.enforceOrgWideCapability(w, r, apitoken.CapAdmin, apitoken.AccessWrite, org.Slug) {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "exceptionID"))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid exception id")
		return
	}
	var request decideExceptionRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	status := "rejected"
	if request.Approve {
		status = "approved"
	}
	var actor *uuid.UUID
	if user != nil {
		actor = &user.ID
	}
	decided, err := s.queries.DecideCoverageException(r.Context(), org.ID, id, status, actor)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to record the decision")
		return
	}
	if decided == nil {
		api.JSONError(w, http.StatusNotFound, "no pending exception with that id")
		return
	}
	s.writeAuditLog(r, user, orgAuditID(org.ID), auditEntry{
		Action: audit.ActionSettingUpdate, ResourceType: "coverage_exception", ResourceID: id.String(),
		Context: map[string]any{"status": status, "repo_id": decided.RepoID.String()},
	})
	if repo, err := s.queries.GetRepositoryByID(r.Context(), decided.RepoID); err == nil && repo != nil {
		s.refreshScanCoverageAsync(repo)
	}
	api.JSON(w, http.StatusOK, decided)
}

type bulkScannerSettingRequest struct {
	ScannerID string `json:"scanner_id"`
	Mode      string `json:"mode"`
	// DryRun returns the repositories that would change without changing them.
	DryRun bool `json:"dry_run"`
}

type bulkScannerChange struct {
	RepoID   uuid.UUID `json:"repo_id"`
	RepoSlug string    `json:"repo_slug"`
	From     string    `json:"from"`
}

type bulkScannerSettingResponse struct {
	Changes []bulkScannerChange `json:"changes"`
	// Kept are repositories left alone: disabling a scanner the org
	// requires needs an exception, not a bulk action.
	Kept    []bulkScannerChange `json:"kept"`
	Applied bool                `json:"applied"`
}

// @Summary      Enable or disable a scanner on many repositories
// @Description  Org admins. Applies to every repository where the scanner applies (from the coverage inventory) and its effective state would change. dry_run previews. Disabling never touches repositories where the org requires the scanner.
// @Tags         scanners
// @Accept       json
// @Produce      json
// @Param        provider  path  string                            true  "Forge provider"
// @Param        slug      path  string                            true  "Organization slug"
// @Param        payload   body  server.bulkScannerSettingRequest  true  "Bulk setting"
// @Success      200  {object}  api.Response{data=server.bulkScannerSettingResponse}
// @Failure      400  {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/scanner-settings/bulk [post]
func (s *Server) handleBulkScannerSetting(w http.ResponseWriter, r *http.Request) {
	org, user, ok := s.loadOrgAdminUser(r, w)
	if !ok {
		return
	}
	if !s.enforceOrgWideCapability(w, r, apitoken.CapAdmin, apitoken.AccessWrite, org.Slug) {
		return
	}
	var request bulkScannerSettingRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if _, ok := s.scanCatalog.Scanner(request.ScannerID); !ok {
		api.JSONError(w, http.StatusBadRequest, "unknown scanner")
		return
	}
	if request.Mode != scanpolicy.ModeEnabled && request.Mode != scanpolicy.ModeDisabled {
		api.JSONError(w, http.StatusBadRequest, "mode must be enabled or disabled")
		return
	}
	cells, err := s.queries.ListOrgScanCoverage(r.Context(), org.ID, store.OrgScanCoverageFilter{ScannerID: request.ScannerID, Limit: 10000})
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load the coverage inventory")
		return
	}
	response := bulkScannerSettingResponse{Changes: []bulkScannerChange{}, Kept: []bulkScannerChange{}}
	for _, cell := range cells {
		change := bulkScannerChange{RepoID: cell.RepoID, RepoSlug: cell.RepoSlug, From: cell.Configured}
		runs := cell.Configured == scanpolicy.StateRequired || cell.Configured == scanpolicy.StateEnabled || cell.Configured == scanpolicy.StateRecommended
		switch {
		case request.Mode == scanpolicy.ModeDisabled && cell.Configured == scanpolicy.StateRequired:
			response.Kept = append(response.Kept, change)
		case request.Mode == scanpolicy.ModeEnabled && !runs, request.Mode == scanpolicy.ModeDisabled && runs:
			response.Changes = append(response.Changes, change)
		}
	}
	if request.DryRun || len(response.Changes) == 0 {
		api.JSON(w, http.StatusOK, response)
		return
	}
	var actor *uuid.UUID
	if user != nil {
		actor = &user.ID
	}
	for _, change := range response.Changes {
		if err := s.queries.UpsertRepoScannerSetting(r.Context(), change.RepoID, request.ScannerID, request.Mode, actor); err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to save scanner settings")
			return
		}
	}
	response.Applied = true
	s.writeAuditLog(r, user, orgAuditID(org.ID), auditEntry{
		Action: audit.ActionSettingUpdate, ResourceType: "scanner_setting", ResourceID: request.ScannerID,
		Context: map[string]any{"bulk": true, "mode": request.Mode, "repositories": len(response.Changes)},
	})
	s.refreshOrgScanCoverageAsync(org.ID)
	api.JSON(w, http.StatusOK, response)
}

type scopeOverrideRequest struct {
	Kind   string `json:"kind"`
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// @Summary      Owner scope refinements of a repository
// @Description  Excluded paths and declared module roots (ADR-035 §3). Whether each exclusion applied, and why not, is in the latest applicability result.
// @Tags         scanners
// @Produce      json
// @Param        provider  path  string  true  "Forge provider"
// @Param        slug      path  string  true  "Organization slug"
// @Param        repoSlug  path  string  true  "Repository slug"
// @Success      200  {object}  api.Response{data=[]store.RepoScopeOverride}
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/scope-overrides [get]
func (s *Server) handleListScopeOverrides(w http.ResponseWriter, r *http.Request) {
	_, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}
	overrides, err := s.queries.ListRepoScopeOverrides(r.Context(), repo.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load scope overrides")
		return
	}
	api.JSON(w, http.StatusOK, overrides)
}

// @Summary      Add an owner scope refinement
// @Description  Repository admins. kind "exclude" leaves a path out of analysis (applied only if it hides no code the org requires scanned, unless an exception for that path is approved); kind "module_root" declares a module the recipes miss. A reason is required; detection re-runs.
// @Tags         scanners
// @Accept       json
// @Produce      json
// @Param        provider  path  string                       true  "Forge provider"
// @Param        slug      path  string                       true  "Organization slug"
// @Param        repoSlug  path  string                       true  "Repository slug"
// @Param        payload   body  server.scopeOverrideRequest  true  "Override"
// @Success      201  {object}  api.Response{data=store.RepoScopeOverride}
// @Failure      400  {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/scope-overrides [post]
func (s *Server) handleCreateScopeOverride(w http.ResponseWriter, r *http.Request) {
	org, repo, user, ok := s.loadAuthorizedRepoWithUser(w, r, true)
	if !ok {
		return
	}
	if !s.enforceTokenCapability(w, r, apitoken.CapAdmin, apitoken.AccessWrite, org.Slug, repo.Slug) {
		return
	}
	var request scopeOverrideRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	request.Path = strings.Trim(strings.TrimSpace(request.Path), "/")
	request.Path = strings.TrimPrefix(request.Path, "./")
	request.Reason = strings.TrimSpace(request.Reason)
	if request.Kind != "exclude" && request.Kind != "module_root" {
		api.JSONError(w, http.StatusBadRequest, "kind must be exclude or module_root")
		return
	}
	if !validScopeOverridePath(request.Path) {
		api.JSONError(w, http.StatusBadRequest, "path must be a repository-relative path below the root")
		return
	}
	if request.Reason == "" || len(request.Reason) > 2000 {
		api.JSONError(w, http.StatusBadRequest, "a reason is required (at most 2000 characters)")
		return
	}
	var actor *uuid.UUID
	if user != nil {
		actor = &user.ID
	}
	saved, err := s.queries.CreateRepoScopeOverride(r.Context(), repo.ID, store.RepoScopeOverride{Kind: request.Kind, Path: request.Path, Reason: request.Reason, CreatedBy: actor})
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to save the override")
		return
	}
	s.writeRepositoryAuditLog(r, user, org.ID, repo.ID, audit.ActionConfigChange, map[string]any{
		"setting": "scope_override", "kind": request.Kind, "path": request.Path, "reason": request.Reason,
	})
	s.refreshApplicabilityAsync(repo, repo.DefaultBranch)
	api.JSON(w, http.StatusCreated, saved)
}

// validScopeOverridePath accepts a repository-relative path below the root.
// Override paths become scanner targets and exclusions on the CLI, so a
// leading "-" (read as an option, Q14) and ".." are refused.
func validScopeOverridePath(p string) bool {
	return p != "" && p != "." && !strings.Contains(p, "..") && !strings.HasPrefix(p, "-") && len(p) <= 512
}

// @Summary      Remove an owner scope refinement
// @Tags         scanners
// @Param        provider  path   string  true  "Forge provider"
// @Param        slug      path   string  true  "Organization slug"
// @Param        repoSlug  path   string  true  "Repository slug"
// @Param        id        query  string  true  "Override ID"
// @Success      204
// @Failure      404  {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/scope-overrides [delete]
func (s *Server) handleDeleteScopeOverride(w http.ResponseWriter, r *http.Request) {
	org, repo, user, ok := s.loadAuthorizedRepoWithUser(w, r, true)
	if !ok {
		return
	}
	if !s.enforceTokenCapability(w, r, apitoken.CapAdmin, apitoken.AccessWrite, org.Slug, repo.Slug) {
		return
	}
	id, err := uuid.Parse(r.URL.Query().Get("id"))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	deleted, err := s.queries.DeleteRepoScopeOverride(r.Context(), repo.ID, id)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to delete the override")
		return
	}
	if !deleted {
		api.JSONError(w, http.StatusNotFound, "override not found")
		return
	}
	s.writeRepositoryAuditLog(r, user, org.ID, repo.ID, audit.ActionConfigChange, map[string]any{"setting": "scope_override", "deleted": id.String()})
	s.refreshApplicabilityAsync(repo, repo.DefaultBranch)
	w.WriteHeader(http.StatusNoContent)
}
