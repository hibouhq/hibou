package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/store"
)

// A dispute is the recourse ADR-026 leaves open against an in-source
// suppression: the scanner will keep reporting the finding as suppressed for
// as long as the directive is in the code, so the UI cannot "reopen" it — but
// a human can contest the call. A disputed suppression stays visible and
// gating until the directive is removed or the dispute withdrawn.

type findingDisputeRequest struct {
	// Reason is required: a dispute is a disagreement with a written
	// justification, so it owes one back.
	Reason string `json:"reason"`
}

// @Summary      Dispute an in-source suppression
// @Description  Contests a scanner-suppressed finding (ADR-026). The finding stays visible and counts against the quality gate despite the in-source directive, until the directive is removed or the dispute withdrawn. Only findings whose current status is suppressed can be disputed.
// @Tags         vulnerabilities
// @Accept       json
// @Produce      json
// @Param        provider  path  string  true  "Forge provider"
// @Param        slug      path  string  true  "Organization slug"
// @Param        repoSlug  path  string  true  "Repository slug"
// @Param        vulnID    path  string  true  "Vulnerability ID"
// @Param        payload   body  server.findingDisputeRequest  true  "Dispute"
// @Success      200  {object}  api.Response{data=store.FindingDispute}
// @Failure      400  {object}  api.Response
// @Failure      401  {object}  api.Response
// @Failure      403  {object}  api.Response
// @Failure      404  {object}  api.Response
// @Failure      422  {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/vulnerabilities/{vulnID}/dispute [put]
func (s *Server) handleSetFindingDispute(w http.ResponseWriter, r *http.Request) {
	org, repo, user, vulnerability, fingerprint, ok := s.loadDisputeTarget(w, r)
	if !ok {
		return
	}

	// Disputing anything else is a category error: open findings are already
	// gating, and resolved ones have nothing to contest.
	if vulnerability.Status != "suppressed" {
		api.JSONError(w, http.StatusUnprocessableEntity, "only scanner-suppressed findings can be disputed")
		return
	}

	var input findingDisputeRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	reason := strings.TrimSpace(input.Reason)
	if reason == "" {
		api.JSONError(w, http.StatusBadRequest, "reason is required to dispute a suppression")
		return
	}

	var disputedBy *uuid.UUID
	if user != nil {
		disputedBy = &user.ID
	}
	dispute, err := s.queries.UpsertFindingDispute(r.Context(), repo.ID, fingerprint, reason, disputedBy)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to store dispute")
		return
	}

	s.writeRepositoryAuditLog(r, user, org.ID, repo.ID, audit.ActionFindingDispute, map[string]any{
		"fingerprint": fingerprint,
		"status":      "disputed",
		"reason":      reason,
	})
	// The gate must reflect the dispute immediately, without a CI re-run.
	s.publishGateRecompute(r.Context(), repo.ID)
	api.JSON(w, http.StatusOK, dispute)
}

// @Summary      Withdraw a suppression dispute
// @Description  Withdraws the dispute on a scanner-suppressed finding; the in-source suppression applies again (visible but never open, never gating).
// @Tags         vulnerabilities
// @Produce      json
// @Param        provider  path  string  true  "Forge provider"
// @Param        slug      path  string  true  "Organization slug"
// @Param        repoSlug  path  string  true  "Repository slug"
// @Param        vulnID    path  string  true  "Vulnerability ID"
// @Success      200  {object}  api.Response
// @Failure      401  {object}  api.Response
// @Failure      403  {object}  api.Response
// @Failure      404  {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/vulnerabilities/{vulnID}/dispute [delete]
func (s *Server) handleDeleteFindingDispute(w http.ResponseWriter, r *http.Request) {
	org, repo, user, _, fingerprint, ok := s.loadDisputeTarget(w, r)
	if !ok {
		return
	}

	deleted, err := s.queries.DeleteFindingDispute(r.Context(), repo.ID, fingerprint)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to withdraw dispute")
		return
	}
	if deleted {
		s.writeRepositoryAuditLog(r, user, org.ID, repo.ID, audit.ActionFindingDispute, map[string]any{
			"fingerprint": fingerprint,
			"status":      "undisputed",
		})
		s.publishGateRecompute(r.Context(), repo.ID)
	}
	api.JSON(w, http.StatusOK, map[string]string{"status": "undisputed"})
}

// loadDisputeTarget shares the auth + lookup prologue of both dispute verbs:
// triage-write capability, the finding must belong to the repo, and it must
// carry a fingerprint to key the dispute on.
func (s *Server) loadDisputeTarget(w http.ResponseWriter, r *http.Request) (*store.Organization, *store.Repository, *store.User, *store.Vulnerability, string, bool) {
	org, repo, user, ok := s.loadAuthorizedRepoWithUser(w, r, true)
	if !ok {
		return nil, nil, nil, nil, "", false
	}
	if !s.enforceTokenCapability(w, r, apitoken.CapTriage, apitoken.AccessWrite, org.Slug, repo.Slug) {
		return nil, nil, nil, nil, "", false
	}

	vulnID, err := uuid.Parse(chi.URLParam(r, "vulnID"))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid vulnerability id")
		return nil, nil, nil, nil, "", false
	}
	vulnerability, err := s.queries.GetVulnerabilityByID(r.Context(), vulnID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load finding")
		return nil, nil, nil, nil, "", false
	}
	if vulnerability == nil || !s.vulnerabilityBelongsToRepo(r, repo, vulnerability) {
		api.JSONError(w, http.StatusNotFound, "finding not found")
		return nil, nil, nil, nil, "", false
	}
	fingerprint := strings.TrimSpace(vulnerability.Fingerprint)
	if fingerprint == "" {
		api.JSONError(w, http.StatusUnprocessableEntity, "finding has no fingerprint to key a dispute on")
		return nil, nil, nil, nil, "", false
	}
	return org, repo, user, vulnerability, fingerprint, true
}
