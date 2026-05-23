package server

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/lehibou/internal/api"
	"github.com/hibouhq/lehibou/internal/delta"
)

type deltaResponse struct {
	Delta *delta.DeltaResult `json:"delta"`
	Gate  *delta.GateResult  `json:"gate"`
}

func (s *Server) handleGetDelta(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if s.deltaSvc == nil {
		api.JSONError(w, http.StatusServiceUnavailable, "delta service unavailable")
		return
	}

	org, err := s.queries.GetOrganizationBySlug(r.Context(), chi.URLParam(r, "slug"))
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load organization")
		return
	}
	if org == nil {
		api.JSONError(w, http.StatusNotFound, "organization not found")
		return
	}
	role, err := s.queries.GetOrgMemberRole(r.Context(), org.ID, user.ID)
	if err != nil || role == "" {
		api.JSONError(w, http.StatusNotFound, "organization not found")
		return
	}

	repo, err := s.queries.GetRepositoryBySlug(r.Context(), org.ID, chi.URLParam(r, "repoSlug"))
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load repository")
		return
	}
	if repo == nil {
		api.JSONError(w, http.StatusNotFound, "repository not found")
		return
	}

	prSnapshotID, err := uuid.Parse(r.URL.Query().Get("pr_snapshot_id"))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid pr_snapshot_id")
		return
	}
	targetSnapshotID, err := uuid.Parse(r.URL.Query().Get("target_snapshot_id"))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid target_snapshot_id")
		return
	}
	if !s.validateDeltaSnapshotOwnership(r.Context(), w, repo.ID, prSnapshotID) {
		return
	}
	if !s.validateDeltaSnapshotOwnership(r.Context(), w, repo.ID, targetSnapshotID) {
		return
	}

	result, err := s.deltaSvc.ComputeDelta(r.Context(), prSnapshotID, targetSnapshotID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to compute delta")
		return
	}
	weaknessGate := s.resolveRepoWeaknessGate(r.Context(), repo.Provider, repo.DefaultBranch, repo.ProviderID, repo.Name, repo.Slug, targetSnapshotID)
	gate, err := s.deltaSvc.EvaluateGatesWithConfig(r.Context(), repo.ID, org.ID, result, weaknessGate)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to evaluate quality gates")
		return
	}

	api.JSON(w, http.StatusOK, deltaResponse{Delta: result, Gate: gate})
}

func (s *Server) validateDeltaSnapshotOwnership(ctx context.Context, w http.ResponseWriter, repoID, snapshotID uuid.UUID) bool {
	snapshot, err := s.queries.GetSnapshotByID(ctx, snapshotID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load snapshot")
		return false
	}
	if snapshot == nil {
		api.JSONError(w, http.StatusNotFound, "snapshot not found")
		return false
	}

	ref, err := s.queries.GetRefByID(ctx, snapshot.RefID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load snapshot reference")
		return false
	}
	if ref == nil {
		api.JSONError(w, http.StatusNotFound, "snapshot reference not found")
		return false
	}
	if ref.RepoID != repoID {
		api.JSONError(w, http.StatusForbidden, "snapshot does not belong to this repository")
		return false
	}

	return true
}
