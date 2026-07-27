package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/store"
)

type findingAcceptanceRequest struct {
	// Status: "accepted" | "false_positive" to suppress, "open" to unaccept.
	Status    string     `json:"status"`
	Reason    string     `json:"reason"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// @Summary      Accept or reopen a finding
// @Description  Accepts a finding (with a required reason) or reopens it. Decisions are fingerprint-scoped so they survive new snapshots, and the PR gate re-evaluates immediately.
// @Tags         vulnerabilities
// @Accept       json
// @Produce      json
// @Param        provider  path  string  true  "Forge provider"
// @Param        slug      path  string  true  "Organization slug"
// @Param        repoSlug  path  string  true  "Repository slug"
// @Param        vulnID    path  string  true  "Vulnerability ID"
// @Param        payload   body  server.findingAcceptanceRequest  true  "Acceptance"
// @Success      200  {object}  api.Response{data=store.FindingAcceptance}
// @Failure      400  {object}  api.Response
// @Failure      401  {object}  api.Response
// @Failure      403  {object}  api.Response
// @Failure      404  {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/vulnerabilities/{vulnID}/acceptance [put]
func (s *Server) handleSetFindingAcceptance(w http.ResponseWriter, r *http.Request) {
	org, repo, user, ok := s.loadAuthorizedRepoWithUser(w, r, true)
	if !ok {
		return
	}

	vulnID, err := uuid.Parse(chi.URLParam(r, "vulnID"))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid vulnerability id")
		return
	}
	vulnerability, err := s.queries.GetVulnerabilityByID(r.Context(), vulnID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load finding")
		return
	}
	if vulnerability == nil || !s.vulnerabilityBelongsToRepo(r, repo, vulnerability) {
		api.JSONError(w, http.StatusNotFound, "finding not found")
		return
	}
	fingerprint := strings.TrimSpace(vulnerability.Fingerprint)
	if fingerprint == "" {
		api.JSONError(w, http.StatusUnprocessableEntity, "finding has no fingerprint to key an acceptance on")
		return
	}

	var input findingAcceptanceRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	status := strings.ToLower(strings.TrimSpace(input.Status))

	switch status {
	case "open":
		if _, err := s.queries.DeleteFindingAcceptance(r.Context(), repo.ID, fingerprint); err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to reopen finding")
			return
		}
		s.writeAcceptanceAuditLog(r, user, org.ID, repo.ID, fingerprint, "open", "")
		s.publishGateRecompute(r.Context(), repo.ID)
		api.JSON(w, http.StatusOK, map[string]string{"status": "open"})
		return
	case "accepted", "false_positive":
	default:
		api.JSONError(w, http.StatusBadRequest, "status must be accepted, false_positive, or open")
		return
	}

	reason := strings.TrimSpace(input.Reason)
	if reason == "" {
		api.JSONError(w, http.StatusBadRequest, "a reason is required to accept a finding")
		return
	}
	if input.ExpiresAt != nil && input.ExpiresAt.Before(time.Now()) {
		api.JSONError(w, http.StatusBadRequest, "expires_at must be in the future")
		return
	}

	userID := user.ID
	acceptance, err := s.queries.UpsertFindingAcceptance(r.Context(), repo.ID, fingerprint, status, reason, &userID, input.ExpiresAt)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to store acceptance")
		return
	}

	s.writeAcceptanceAuditLog(r, user, org.ID, repo.ID, fingerprint, status, reason)
	// The gate must reflect the decision immediately, without a CI re-run.
	s.publishGateRecompute(r.Context(), repo.ID)
	api.JSON(w, http.StatusOK, acceptance)
}

// @Summary      List active finding acceptances
// @Tags         vulnerabilities
// @Produce      json
// @Param        provider  path  string  true  "Forge provider"
// @Param        slug      path  string  true  "Organization slug"
// @Param        repoSlug  path  string  true  "Repository slug"
// @Success      200  {object}  api.Response{data=[]store.FindingAcceptance}
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/finding-acceptances [get]
func (s *Server) handleListFindingAcceptances(w http.ResponseWriter, r *http.Request) {
	_, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}
	acceptances, err := s.queries.ListActiveFindingAcceptancesByRepo(r.Context(), repo.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list acceptances")
		return
	}
	if acceptances == nil {
		acceptances = []store.FindingAcceptance{}
	}
	api.JSON(w, http.StatusOK, acceptances)
}

// vulnerabilityBelongsToRepo walks snapshot → ref → repo to stop cross-repo
// acceptance writes.
func (s *Server) vulnerabilityBelongsToRepo(r *http.Request, repo *store.Repository, vulnerability *store.Vulnerability) bool {
	snapshot, err := s.queries.GetSnapshotByID(r.Context(), vulnerability.SnapshotID)
	if err != nil || snapshot == nil {
		return false
	}
	ref, err := s.queries.GetRefByID(r.Context(), snapshot.RefID)
	if err != nil || ref == nil {
		return false
	}
	return ref.RepoID == repo.ID
}

func (s *Server) writeAcceptanceAuditLog(r *http.Request, user *store.User, orgID, repoID uuid.UUID, fingerprint, status, reason string) {
	s.writeRepositoryAuditLog(r, user, orgID, repoID, audit.ActionFindingAcceptance, map[string]any{
		"fingerprint": fingerprint,
		"status":      status,
		"reason":      reason,
	})
}
