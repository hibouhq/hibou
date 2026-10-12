package server

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/delta"
	"github.com/hibouhq/hibou/internal/store"
)

type deltaResponse struct {
	Delta *delta.DeltaResult `json:"delta"`
	Gate  *delta.GateResult  `json:"gate"`
	// GateSource says where the verdict came from: "persisted" is the exact
	// check the forge shows (single source of truth for a PR head);
	// "computed" is a live evaluation for comparisons no check was published
	// for. Divergence between page and forge was dogfood bug #5.
	GateSource string `json:"gate_source"`
	// GateCommit is the commit the persisted verdict was evaluated for.
	GateCommit string `json:"gate_commit,omitempty"`
}

func (s *Server) handleGetDelta(w http.ResponseWriter, r *http.Request) {
	if !s.hasPrincipal(r) {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if s.deltaSvc == nil {
		api.JSONError(w, http.StatusServiceUnavailable, "delta service unavailable")
		return
	}

	org, err := s.resolveOrg(r)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load organization")
		return
	}
	if org == nil {
		api.JSONError(w, http.StatusNotFound, "organization not found")
		return
	}
	role, err := s.principalOrgRole(r, org.ID)
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
	if !s.authorizeRepoRequest(w, r, org.ID, role, repo) {
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

	// Prefer the persisted verdict — the one the forge shows — whenever this
	// comparison IS the published PR gate (head snapshot on a PR ref, target
	// on its merge target). The two surfaces can then never disagree.
	if gate, commit := s.persistedGateForComparison(r.Context(), repo.ID, prSnapshotID, targetSnapshotID); gate != nil {
		api.JSON(w, http.StatusOK, deltaResponse{Delta: result, Gate: gate, GateSource: "persisted", GateCommit: commit})
		return
	}

	gateConfig := s.resolveRepoGateConfig(r.Context(), repo.Provider, repo.DefaultBranch, repo.ProviderID, repo.Name, repo.Slug, targetSnapshotID)
	if gateConfig == nil {
		gateConfig = &delta.GateConfig{}
	}
	gateConfig.HeadSnapshotID = prSnapshotID
	gateConfig.BaseSnapshotID = targetSnapshotID
	gate, err := s.deltaSvc.EvaluateGatesWithConfig(r.Context(), repo.ID, org.ID, result, gateConfig)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to evaluate quality gates")
		return
	}

	api.JSON(w, http.StatusOK, deltaResponse{Delta: result, Gate: gate, GateSource: "computed"})
}

// persistedGateForComparison returns the stored pr_checks verdict when the
// requested comparison matches the published PR gate exactly; nil otherwise
// (arbitrary comparisons fall back to a live evaluation).
func (s *Server) persistedGateForComparison(ctx context.Context, repoID, prSnapshotID, targetSnapshotID uuid.UUID) (*delta.GateResult, string) {
	snapshot, err := s.queries.GetSnapshotByID(ctx, prSnapshotID)
	if err != nil || snapshot == nil || snapshot.CommitSHA == "" {
		return nil, ""
	}
	ref, err := s.queries.GetRefByID(ctx, snapshot.RefID)
	if err != nil || ref == nil || ref.RefType != store.RefTypePullRequest || ref.MergeTargetRefID == nil {
		return nil, ""
	}
	targetSnapshot, err := s.queries.GetSnapshotByID(ctx, targetSnapshotID)
	if err != nil || targetSnapshot == nil || targetSnapshot.RefID != *ref.MergeTargetRefID {
		return nil, ""
	}
	check, err := s.queries.GetPRCheck(ctx, repoID, snapshot.CommitSHA, gateStatusContext)
	if err != nil || check == nil || check.State == "pending" {
		return nil, ""
	}
	reasons := []string{}
	if len(check.Reasons) > 0 {
		_ = json.Unmarshal(check.Reasons, &reasons)
	}
	return &delta.GateResult{Passed: check.Passed, Configured: true, Reasons: reasons}, check.HeadSha
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
