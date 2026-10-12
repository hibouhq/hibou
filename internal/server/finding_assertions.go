package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/presence"
	"github.com/hibouhq/hibou/internal/store"
)

// Manual and agent-filed findings ("assertions", ADR-034 §4) are carried to
// every new snapshot of their branch. Nothing re-runs them, so they end only
// by an explicit decision: resolve (the problem is gone) or retract (the
// assertion was wrong). Re-assert confirms one is still there.

type assertionDecisionRequest struct {
	Reason string `json:"reason"`
}

type assertionResponse struct {
	Fingerprint string                  `json:"fingerprint"`
	Assertion   *store.FindingAssertion `json:"assertion"`
}

// maxAssertionReasonLength bounds the decision text kept on the row.
const maxAssertionReasonLength = 2000

// loadAssertion resolves the finding behind {fingerprint} and checks it is an
// assertion: a scanner finding is re-checked by its scanner, not by a person.
func (s *Server) loadAssertion(w http.ResponseWriter, r *http.Request, repo *store.Repository) (*store.Vulnerability, bool) {
	fingerprint := pathFingerprint(r)
	if fingerprint == "" {
		api.JSONError(w, http.StatusBadRequest, "fingerprint is required")
		return nil, false
	}
	finding, err := s.queries.GetLatestVulnerabilityByFingerprint(r.Context(), repo.ID, fingerprint)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load finding")
		return nil, false
	}
	if finding == nil {
		api.JSONError(w, http.StatusNotFound, "finding not found")
		return nil, false
	}
	if finding.Origin != string(store.FindingOriginHuman) && finding.Origin != string(store.FindingOriginAgent) {
		api.JSONError(w, http.StatusConflict, "only manual and agent-filed findings are re-asserted, resolved or retracted here: a scanner finding is resolved when its scanner re-checks the code")
		return nil, false
	}
	return finding, true
}

// principalIDs splits the caller into the user and the API key that acted.
func principalIDs(r *http.Request, user *store.User) (*uuid.UUID, *uuid.UUID) {
	var userID, apiKeyID *uuid.UUID
	if user != nil {
		id := user.ID
		userID = &id
	}
	if tokenAuth := auth.TokenAuthFromContext(r.Context()); tokenAuth != nil {
		id := tokenAuth.KeyID
		apiKeyID = &id
	}
	return userID, apiKeyID
}

func decodeAssertionReason(w http.ResponseWriter, r *http.Request, required bool) (string, bool) {
	var input assertionDecisionRequest
	if r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
			return "", false
		}
	}
	reason := strings.TrimSpace(input.Reason)
	if required && reason == "" {
		api.JSONError(w, http.StatusBadRequest, "reason is required")
		return "", false
	}
	if len(reason) > maxAssertionReasonLength {
		api.JSONError(w, http.StatusBadRequest, "reason is too long")
		return "", false
	}
	return reason, true
}

// @Summary      Re-assert a manual or agent finding
// @Description  Confirms the finding is still there (ADR-034 §4): updates "last confirmed" without creating a duplicate, and reopens it if it had been resolved or retracted.
// @Tags         findings
// @Produce      json
// @Param        provider     path  string  true  "Forge provider"
// @Param        slug         path  string  true  "Organization slug"
// @Param        repoSlug     path  string  true  "Repository slug"
// @Param        fingerprint  path  string  true  "Finding fingerprint"
// @Success      200  {object}  api.Response{data=server.assertionResponse}
// @Failure      404  {object}  api.Response
// @Failure      409  {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/findings/{fingerprint}/reassert [post]
func (s *Server) handleReassertFinding(w http.ResponseWriter, r *http.Request) {
	org, repo, user, ok := s.loadAuthorizedRepoWithUser(w, r, false)
	if !ok {
		return
	}
	if !s.enforceTokenCapability(w, r, apitoken.CapVulnerabilities, apitoken.AccessWrite, org.Slug, repo.Slug) {
		return
	}
	finding, ok := s.loadAssertion(w, r, repo)
	if !ok {
		return
	}
	userID, apiKeyID := principalIDs(r, user)
	previous, err := s.queries.GetFindingAssertion(r.Context(), repo.ID, finding.Fingerprint)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load assertion")
		return
	}
	assertion, err := s.queries.ConfirmFindingAssertion(r.Context(), repo.ID, finding.Fingerprint, userID, apiKeyID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to re-assert finding")
		return
	}
	reopened := previous != nil && previous.ClosedKind != ""
	if reopened {
		if err := s.reopenAssertion(r, finding); err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to reopen finding")
			return
		}
	}
	s.writeRepositoryAuditLog(r, user, org.ID, repo.ID, audit.ActionFindingReassert, map[string]any{
		"fingerprint": finding.Fingerprint,
		"reopened":    reopened,
	})
	api.JSON(w, http.StatusOK, assertionResponse{Fingerprint: finding.Fingerprint, Assertion: &assertion})
}

// @Summary      Resolve a manual or agent finding
// @Description  Records that the problem is gone (ADR-034 §4). Requires a reason. The finding stops counting now and is no longer carried to new snapshots.
// @Tags         findings
// @Accept       json
// @Produce      json
// @Param        provider     path  string                           true  "Forge provider"
// @Param        slug         path  string                           true  "Organization slug"
// @Param        repoSlug     path  string                           true  "Repository slug"
// @Param        fingerprint  path  string                           true  "Finding fingerprint"
// @Param        payload      body  server.assertionDecisionRequest  true  "Reason"
// @Success      200  {object}  api.Response{data=server.assertionResponse}
// @Failure      400  {object}  api.Response
// @Failure      404  {object}  api.Response
// @Failure      409  {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/findings/{fingerprint}/resolve [post]
func (s *Server) handleResolveFinding(w http.ResponseWriter, r *http.Request) {
	// Resolving is a triage decision, held to the same bar as accepting.
	org, repo, user, ok := s.loadAuthorizedRepoWithUser(w, r, true)
	if !ok {
		return
	}
	if !s.enforceTokenCapability(w, r, apitoken.CapTriage, apitoken.AccessWrite, org.Slug, repo.Slug) {
		return
	}
	s.closeAssertion(w, r, org, repo, user, store.AssertionResolved, audit.ActionFindingResolve)
}

// @Summary      Retract a manual or agent finding
// @Description  Withdraws an assertion that was wrong (ADR-034 §4). Allowed to the person who filed it, the filing token or its owner, and org admins.
// @Tags         findings
// @Accept       json
// @Produce      json
// @Param        provider     path  string                           true   "Forge provider"
// @Param        slug         path  string                           true   "Organization slug"
// @Param        repoSlug     path  string                           true   "Repository slug"
// @Param        fingerprint  path  string                           true   "Finding fingerprint"
// @Param        payload      body  server.assertionDecisionRequest  false  "Reason"
// @Success      200  {object}  api.Response{data=server.assertionResponse}
// @Failure      403  {object}  api.Response
// @Failure      404  {object}  api.Response
// @Failure      409  {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/findings/{fingerprint}/retract [post]
func (s *Server) handleRetractFinding(w http.ResponseWriter, r *http.Request) {
	org, repo, user, ok := s.loadAuthorizedRepoWithUser(w, r, false)
	if !ok {
		return
	}
	if !s.enforceTokenCapability(w, r, apitoken.CapVulnerabilities, apitoken.AccessWrite, org.Slug, repo.Slug) {
		return
	}
	s.closeAssertion(w, r, org, repo, user, store.AssertionRetracted, audit.ActionFindingRetract)
}

func (s *Server) closeAssertion(w http.ResponseWriter, r *http.Request, org *store.Organization, repo *store.Repository, user *store.User, kind, action string) {
	finding, ok := s.loadAssertion(w, r, repo)
	if !ok {
		return
	}
	if kind == store.AssertionRetracted && !s.mayRetract(r, org, user, finding) {
		api.JSONError(w, http.StatusForbidden, "only whoever filed this finding (or its token's owner, or an org admin) can retract it")
		return
	}
	reason, ok := decodeAssertionReason(w, r, kind == store.AssertionResolved)
	if !ok {
		return
	}
	userID, apiKeyID := principalIDs(r, user)
	assertion, err := s.queries.CloseFindingAssertion(r.Context(), repo.ID, finding.Fingerprint, kind, reason, userID, apiKeyID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to record the decision")
		return
	}
	// Stops counting now, not at the next commit.
	if _, err := s.queries.SetAssertionRowsStatus(r.Context(), repo.ID, finding.Fingerprint, "resolved", userID); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to close the finding")
		return
	}
	s.writeRepositoryAuditLog(r, user, org.ID, repo.ID, action, map[string]any{
		"fingerprint": finding.Fingerprint,
		"reason":      reason,
		"origin":      finding.Origin,
	})
	api.JSON(w, http.StatusOK, assertionResponse{Fingerprint: finding.Fingerprint, Assertion: &assertion})
}

// mayRetract: the filing person, the filing token, the token's owner, or an
// org admin. An assertion is its author's claim to withdraw.
func (s *Server) mayRetract(r *http.Request, org *store.Organization, user *store.User, finding *store.Vulnerability) bool {
	if tokenAuth := auth.TokenAuthFromContext(r.Context()); tokenAuth != nil && finding.OriginAPIKeyID != nil && *finding.OriginAPIKeyID == tokenAuth.KeyID {
		return true
	}
	if user != nil {
		if finding.CreatedBy != nil && *finding.CreatedBy == user.ID {
			return true
		}
		if finding.OriginOwnerType == "user" && finding.OriginOwnerID != nil && *finding.OriginOwnerID == user.ID {
			return true
		}
	}
	admin, err := s.isOrgAdminMember(r, org.ID)
	return err == nil && admin
}

// reopenAssertion brings a closed assertion back into the latest snapshot of
// its branch. Once closed it was no longer carried, so the newest snapshot
// may not hold it: copy its last row there, then mark the latest rows open.
func (s *Server) reopenAssertion(r *http.Request, finding *store.Vulnerability) error {
	ctx := r.Context()
	snapshot, err := s.queries.GetSnapshotByID(ctx, finding.SnapshotID)
	if err != nil || snapshot == nil {
		return err
	}
	latest, err := s.queries.GetLatestSnapshotByRef(ctx, snapshot.RefID)
	if err != nil {
		return err
	}
	if latest != nil && latest.ID != snapshot.ID {
		lastSeen := snapshot.ID
		if _, err := s.queries.CarryVulnerabilitiesForward(ctx, latest.ID, []store.CarryInput{{
			SourceID:           finding.ID,
			Presence:           store.PresenceNotRechecked,
			Reason:             presence.ReasonAssertion,
			LastSeenSnapshotID: &lastSeen,
			LastSeenCommit:     snapshot.CommitSHA,
		}}); err != nil {
			return err
		}
	}
	repoID := uuid.Nil
	if ref, err := s.queries.GetRefByID(ctx, snapshot.RefID); err == nil && ref != nil {
		repoID = ref.RepoID
	}
	_, err = s.queries.SetAssertionRowsStatus(ctx, repoID, finding.Fingerprint, "detected", nil)
	return err
}
