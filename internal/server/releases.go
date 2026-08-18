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
	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type addReleaseClientRequest struct {
	ClientSlug  string  `json:"client_slug"`
	Environment string  `json:"environment"`
	Notes       *string `json:"notes"`
}

// requireReleaseManager gates the release lifecycle: org admins and release
// managers (SPEC roles). The UI hides the affordances on top of this, never
// instead of it.
func (s *Server) requireReleaseManager(r *http.Request, w http.ResponseWriter, orgID uuid.UUID) bool {
	if !s.hasPrincipal(r) {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return false
	}
	role, err := s.principalOrgRole(r, orgID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load organization")
		return false
	}
	if role != "admin" && role != "release_manager" {
		api.JSONError(w, http.StatusForbidden, "release manager access required")
		return false
	}
	return true
}

// pinReleaseSnapshot marks a released snapshot as pinned so the retention
// worker never prunes shipped state (ADR-024 §2). retention_hold is preserved.
func (s *Server) pinReleaseSnapshot(ctx context.Context, snapshotID uuid.UUID) error {
	snapshot, err := s.queries.GetSnapshotByID(ctx, snapshotID)
	if err != nil || snapshot == nil || snapshot.Pinned {
		return err
	}
	_, err = s.queries.UpdateSnapshotRetentionFlags(ctx, snapshotID, true, snapshot.RetentionHold)
	return err
}

// @Summary      List releases
// @Description  List releases with the open-risk posture of their pinned snapshot and the clients currently on them (active deployments)
// @Tags         releases
// @Produce      json
// @Param        provider    path      string  true   "Forge provider"
// @Param        slug        path      string  true   "Organization slug"
// @Param        repoSlug    path      string  true   "Repository slug"
// @Param        q           query     string  false  "Version substring filter"
// @Param        client      query     string  false  "Only releases an org client (by slug) has an active deployment of"
// @Param        vulnerable  query     bool    false  "Only releases with at least one open finding"
// @Param        page        query     int     false  "Page number"
// @Param        per_page    query     int     false  "Items per page"
// @Success      200         {object}  api.ListResponse{data=[]store.ReleaseWithRisk}
// @Failure      401         {object}  api.Response
// @Failure      404         {object}  api.Response
// @Failure      500         {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/releases [get]
func (s *Server) handleListReleases(w http.ResponseWriter, r *http.Request) {
	_, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}

	filters := store.ReleaseListFilters{
		VersionQuery:   strings.TrimSpace(r.URL.Query().Get("q")),
		ClientSlug:     strings.TrimSpace(r.URL.Query().Get("client")),
		VulnerableOnly: r.URL.Query().Get("vulnerable") == "true",
	}

	pagination := api.ParsePagination(r)
	releases, total, err := s.queries.ListReleasesWithRiskByRepo(r.Context(), repo.ID, filters, pagination.PerPage, pagination.Offset)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list releases")
		return
	}

	api.JSONList(w, releases, pagination.Page, pagination.PerPage, total)
}

// removeDerivedRelease deletes a release in reaction to its source
// disappearing (tag deleted, forge release deleted) — the only removal path
// (ADR-024 §5b). Shipped history wins: any deployment row, whatever its
// status, blocks removal (the FK RESTRICTs as the last line of defense).
// Removal is audited with the webhook actor.
func (s *Server) removeDerivedRelease(ctx context.Context, repo *store.Repository, release *store.Release, reason string) {
	deployments, err := s.queries.CountDeploymentsByRelease(ctx, release.ID)
	if err != nil {
		s.log.Warn().Err(err).Str("version", release.Version).Msg("release removal: failed to count deployments")
		return
	}
	if deployments > 0 {
		s.log.Info().Str("version", release.Version).Str("repo", repo.Slug).Int64("deployments", deployments).Str("reason", reason).Msg("release source deleted but rollout history exists; keeping the release")
		return
	}

	if err := s.queries.DeleteRelease(ctx, release.ID); err != nil {
		s.log.Warn().Err(err).Str("version", release.Version).Msg("release removal failed")
		return
	}
	if release.SnapshotID != nil {
		s.unpinSnapshotIfUnreferenced(ctx, *release.SnapshotID, release.ID)
	}

	orgID := uuid.NullUUID{UUID: repo.OrgID, Valid: true}
	context := map[string]any{
		"repo_id": repo.ID.String(),
		"repo":    repo.Slug,
		"version": release.Version,
		"reason":  reason,
		"source":  release.Source,
	}
	encoded, err := json.Marshal(context)
	if err != nil {
		encoded = []byte(`{"status":"marshal_error"}`)
	}
	if _, err := s.queries.CreateAuditLog(ctx, dbgen.CreateAuditLogParams{
		ActorType:    audit.ActorWebhook,
		ActorDisplay: "forge: " + reason,
		Action:       "release.removed",
		ResourceType: "release",
		ResourceID:   release.ID.String(),
		OrgID:        orgID,
		Context:      encoded,
	}); err != nil {
		s.log.Warn().Err(err).Str("version", release.Version).Msg("audit log write failed; the release removal itself succeeded")
	}
	s.log.Info().Str("version", release.Version).Str("repo", repo.Slug).Str("reason", reason).Msg("release removed: source deleted and nothing ever shipped")
}

func (s *Server) unpinSnapshotIfUnreferenced(ctx context.Context, snapshotID, excludedReleaseID uuid.UUID) {
	remaining, err := s.queries.CountReleasesBySnapshotExcluding(ctx, snapshotID, excludedReleaseID)
	if err != nil || remaining > 0 {
		return
	}
	snapshot, err := s.queries.GetSnapshotByID(ctx, snapshotID)
	if err != nil || snapshot == nil || !snapshot.Pinned {
		return
	}
	if _, err := s.queries.UpdateSnapshotRetentionFlags(ctx, snapshotID, false, snapshot.RetentionHold); err != nil {
		s.log.Warn().Err(err).Str("snapshot_id", snapshotID.String()).Msg("failed to unpin snapshot no release references")
	}
}

// @Summary      Add client to release
// @Description  Record that an org client runs this release: creates an active deployment and supersedes the client's active deployment of any other release of this repository in the same environment. Requires the admin or release_manager org role.
// @Tags         releases
// @Accept       json
// @Produce      json
// @Param        provider   path      string                   true  "Forge provider"
// @Param        slug       path      string                   true  "Organization slug"
// @Param        repoSlug   path      string                   true  "Repository slug"
// @Param        releaseID  path      string                   true  "Release ID"
// @Param        payload    body      addReleaseClientRequest  true  "Client assignment"
// @Success      201        {object}  api.Response{data=store.Deployment}
// @Failure      400        {object}  api.Response
// @Failure      401        {object}  api.Response
// @Failure      403        {object}  api.Response
// @Failure      404        {object}  api.Response
// @Failure      500        {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/releases/{releaseID}/clients [post]
func (s *Server) handleAddReleaseClient(w http.ResponseWriter, r *http.Request) {
	org, repo, user, release, ok := s.loadReleaseForManager(w, r)
	if !ok {
		return
	}

	var input addReleaseClientRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	input.ClientSlug = strings.TrimSpace(input.ClientSlug)
	if input.ClientSlug == "" {
		api.JSONError(w, http.StatusBadRequest, "client_slug is required")
		return
	}
	environment := strings.TrimSpace(input.Environment)
	if environment == "" {
		environment = "production"
	}
	trimStringPtr(input.Notes)

	client, err := s.queries.GetClientBySlug(r.Context(), org.ID, input.ClientSlug)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load client")
		return
	}
	if client == nil {
		api.JSONError(w, http.StatusNotFound, "client not found")
		return
	}

	if _, err := s.queries.SupersedeActiveDeployments(r.Context(), repo.ID, client.ID, environment, release.ID); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to supersede previous deployments")
		return
	}

	actor := requestAuditActor(r, user)
	deployedBy := actor.Display
	deployment, err := s.queries.CreateDeployment(r.Context(), client.ID, release.ID, environment, store.DeploymentStatusActive, time.Now().UTC(), &deployedBy, nil, input.Notes)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to create deployment")
		return
	}

	s.writeAuditLog(r, user, uuid.NullUUID{UUID: org.ID, Valid: true}, auditEntry{
		Action:       "release.client_added",
		ResourceType: "release",
		ResourceID:   release.ID.String(),
		Context: map[string]any{
			"repo_id":       repo.ID.String(),
			"repo":          repo.Slug,
			"version":       release.Version,
			"client":        client.Slug,
			"environment":   environment,
			"deployment_id": deployment.ID.String(),
		},
	})

	api.JSON(w, http.StatusCreated, deployment)
}

// @Summary      Remove client from release
// @Description  Mark a release's deployment as rolled back. Requires the admin or release_manager org role.
// @Tags         releases
// @Produce      json
// @Param        provider      path      string  true  "Forge provider"
// @Param        slug          path      string  true  "Organization slug"
// @Param        repoSlug      path      string  true  "Repository slug"
// @Param        releaseID     path      string  true  "Release ID"
// @Param        deploymentID  path      string  true  "Deployment ID"
// @Success      200           {object}  api.Response{data=store.Deployment}
// @Failure      400           {object}  api.Response
// @Failure      401           {object}  api.Response
// @Failure      403           {object}  api.Response
// @Failure      404           {object}  api.Response
// @Failure      500           {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/releases/{releaseID}/clients/{deploymentID} [delete]
func (s *Server) handleRemoveReleaseClient(w http.ResponseWriter, r *http.Request) {
	org, repo, user, release, ok := s.loadReleaseForManager(w, r)
	if !ok {
		return
	}

	deploymentID, err := uuid.Parse(chi.URLParam(r, "deploymentID"))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid deployment ID")
		return
	}
	deployment, err := s.queries.GetDeploymentByReleaseAndID(r.Context(), release.ID, deploymentID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load deployment")
		return
	}
	if deployment == nil {
		api.JSONError(w, http.StatusNotFound, "deployment not found")
		return
	}

	updated, err := s.queries.UpdateDeploymentStatus(r.Context(), deployment.ID, store.DeploymentStatusRolledBack)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to update deployment")
		return
	}

	s.writeAuditLog(r, user, uuid.NullUUID{UUID: org.ID, Valid: true}, auditEntry{
		Action:       "release.client_removed",
		ResourceType: "release",
		ResourceID:   release.ID.String(),
		Context: map[string]any{
			"repo_id":       repo.ID.String(),
			"repo":          repo.Slug,
			"version":       release.Version,
			"deployment_id": deployment.ID.String(),
			"client_id":     deployment.ClientID.String(),
		},
	})

	api.JSON(w, http.StatusOK, updated)
}

// loadReleaseForManager loads the org/repo/release chain for a release
// lifecycle mutation and enforces the release-manager gate.
func (s *Server) loadReleaseForManager(w http.ResponseWriter, r *http.Request) (*store.Organization, *store.Repository, *store.User, *store.Release, bool) {
	org, repo, user, ok := s.loadAuthorizedRepoWithUser(w, r, false)
	if !ok {
		return nil, nil, nil, nil, false
	}
	if !s.requireReleaseManager(r, w, org.ID) {
		return nil, nil, nil, nil, false
	}

	releaseID, err := uuid.Parse(chi.URLParam(r, "releaseID"))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid release ID")
		return nil, nil, nil, nil, false
	}
	release, err := s.queries.GetReleaseByRepoAndID(r.Context(), repo.ID, releaseID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load release")
		return nil, nil, nil, nil, false
	}
	if release == nil {
		api.JSONError(w, http.StatusNotFound, "release not found")
		return nil, nil, nil, nil, false
	}
	return org, repo, user, release, true
}

type resolveReleaseDivergenceRequest struct {
	Action string `json:"action"`
}

// @Summary      Resolve release divergence
// @Description  A released tag was recreated on another commit (ADR-024 §5). "adopt" repoints the release to the new build; "keep" keeps the shipped build and stops flagging that commit. Requires the admin or release_manager org role.
// @Tags         releases
// @Accept       json
// @Produce      json
// @Param        provider   path      string                            true  "Forge provider"
// @Param        slug       path      string                            true  "Organization slug"
// @Param        repoSlug   path      string                            true  "Repository slug"
// @Param        releaseID  path      string                            true  "Release ID"
// @Param        payload    body      resolveReleaseDivergenceRequest  true  "adopt or keep"
// @Success      200        {object}  api.Response{data=store.Release}
// @Failure      400        {object}  api.Response
// @Failure      401        {object}  api.Response
// @Failure      403        {object}  api.Response
// @Failure      404        {object}  api.Response
// @Failure      409        {object}  api.Response
// @Failure      500        {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/releases/{releaseID}/divergence [post]
func (s *Server) handleResolveReleaseDivergence(w http.ResponseWriter, r *http.Request) {
	org, repo, user, release, ok := s.loadReleaseForManager(w, r)
	if !ok {
		return
	}

	var input resolveReleaseDivergenceRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if release.PendingSnapshotID == nil {
		api.JSONError(w, http.StatusConflict, "release has no pending divergence")
		return
	}
	pendingID := *release.PendingSnapshotID

	var (
		updated *store.Release
		err     error
		action  string
	)
	switch strings.ToLower(strings.TrimSpace(input.Action)) {
	case "adopt":
		action = "release.retag_adopted"
		previousSnapshotID := release.SnapshotID
		updated, err = s.queries.SetReleaseSnapshot(r.Context(), release.ID, pendingID)
		if err == nil {
			if pinErr := s.pinReleaseSnapshot(r.Context(), pendingID); pinErr != nil {
				s.log.Warn().Err(pinErr).Str("snapshot_id", pendingID.String()).Msg("failed to pin adopted release snapshot")
			}
			if previousSnapshotID != nil {
				s.unpinSnapshotIfUnreferenced(r.Context(), *previousSnapshotID, release.ID)
			}
		}
	case "keep":
		action = "release.retag_dismissed"
		pending, pendingErr := s.queries.GetSnapshotByID(r.Context(), pendingID)
		if pendingErr != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to load pending snapshot")
			return
		}
		dismissedSHA := ""
		if pending != nil {
			dismissedSHA = pending.CommitSHA
		}
		updated, err = s.queries.DismissReleaseDivergence(r.Context(), release.ID, dismissedSHA)
	default:
		api.JSONError(w, http.StatusBadRequest, "action must be \"adopt\" or \"keep\"")
		return
	}
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to resolve divergence")
		return
	}

	s.writeAuditLog(r, user, uuid.NullUUID{UUID: org.ID, Valid: true}, auditEntry{
		Action:       action,
		ResourceType: "release",
		ResourceID:   release.ID.String(),
		Context: map[string]any{
			"repo_id":             repo.ID.String(),
			"repo":                repo.Slug,
			"version":             release.Version,
			"pending_snapshot_id": pendingID.String(),
		},
	})

	api.JSON(w, http.StatusOK, updated)
}
