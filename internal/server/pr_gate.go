package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/delta"
	"github.com/hibouhq/hibou/internal/events"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/ws"
)

const gateStatusContext = "hibou/security"

type prGateResponse struct {
	PRNumber    int        `json:"pr_number"`
	HeadSHA     string     `json:"head_sha"`
	Context     string     `json:"context"`
	State       string     `json:"state"`
	Conclusion  string     `json:"conclusion,omitempty"`
	Enforcement string     `json:"enforcement"`
	Passed      bool       `json:"passed"`
	Reasons     []string   `json:"reasons"`
	TargetURL   string     `json:"target_url,omitempty"`
	Source      string     `json:"source"` // persisted | computed | pending
	UpdatedAt   *time.Time `json:"updated_at,omitempty"`
}

// handleGetPRGate returns the quality-gate outcome for a pull request. It prefers
// the persisted pr_checks row (what was last published to the forge) and falls
// back to an on-demand computation when no check has been posted yet. Read-only;
// never affects any build. Consumed by the UI and the opt-in `hibou gate` CLI.
func (s *Server) handleGetPRGate(w http.ResponseWriter, r *http.Request) {
	org, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}
	prNumber, err := strconv.Atoi(strings.TrimSpace(chi.URLParam(r, "pr")))
	if err != nil || prNumber <= 0 {
		api.JSONError(w, http.StatusBadRequest, "invalid pull request number")
		return
	}

	ref, err := s.queries.GetRefByRepoAndName(r.Context(), repo.ID, pullRequestRefName(repo.Provider, prNumber), store.RefTypePullRequest)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load pull request")
		return
	}
	if ref == nil {
		api.JSONError(w, http.StatusNotFound, "pull request not found")
		return
	}

	prSnapshot, _ := s.queries.GetLatestSnapshotByRef(r.Context(), ref.ID)
	headSHA := prHeadSHA(ref, prSnapshot)

	// Prefer the persisted, forge-published outcome; fall back to on-demand compute.
	if headSHA != "" {
		if check, err := s.queries.GetPRCheck(r.Context(), repo.ID, headSHA, gateStatusContext); err == nil && check != nil {
			api.JSON(w, http.StatusOK, persistedGateResponse(prNumber, check))
			return
		}
	}
	api.JSON(w, http.StatusOK, s.computePRGate(r.Context(), org.ID, repo, ref, prSnapshot, prNumber, headSHA))
}

func prHeadSHA(ref *store.Ref, prSnapshot *store.Snapshot) string {
	if prSnapshot != nil && prSnapshot.CommitSHA != "" {
		return prSnapshot.CommitSHA
	}
	if ref.LatestCommitSHA != nil {
		return *ref.LatestCommitSHA
	}
	return ""
}

// computePRGate evaluates the gate on demand when no check has been posted yet.
// Returns a "pending" response when the PR has no scanned head/target snapshot.
func (s *Server) computePRGate(ctx context.Context, orgID uuid.UUID, repo *store.Repository, ref *store.Ref, prSnapshot *store.Snapshot, prNumber int, headSHA string) prGateResponse {
	pending := prGateResponse{
		PRNumber: prNumber, HeadSHA: headSHA, Context: gateStatusContext,
		State: "pending", Enforcement: "advisory", Reasons: []string{}, Source: "pending",
	}
	if prSnapshot == nil || ref.MergeTargetRefID == nil {
		return pending
	}
	targetSnapshot, err := s.queries.GetLatestSnapshotByRef(ctx, *ref.MergeTargetRefID)
	if err != nil || targetSnapshot == nil {
		return pending
	}
	deltaResult, err := s.deltaSvc.ComputeDelta(ctx, prSnapshot.ID, targetSnapshot.ID)
	if err != nil {
		s.log.Error().Err(err).Str("repo_id", repo.ID.String()).Msg("compute PR gate delta")
		return pending
	}
	gateConfig := s.resolveRepoGateConfig(ctx, repo.Provider, repo.DefaultBranch, repo.ProviderID, repo.Name, repo.Slug, targetSnapshot.ID)
	if gateConfig == nil {
		gateConfig = &delta.GateConfig{}
	}
	gateConfig.HeadSnapshotID = prSnapshot.ID
	gate, err := s.deltaSvc.EvaluateGatesWithConfig(ctx, repo.ID, orgID, deltaResult, gateConfig)
	if err != nil {
		s.log.Error().Err(err).Str("repo_id", repo.ID.String()).Msg("evaluate PR gate")
		return pending
	}

	passed := gate != nil && gate.Passed
	reasons := []string{}
	if gate != nil && len(gate.Reasons) > 0 {
		reasons = gate.Reasons
	}
	state := "failure"
	if passed {
		state = "success"
	}
	return prGateResponse{
		PRNumber: prNumber, HeadSHA: headSHA, Context: gateStatusContext,
		State: state, Enforcement: "advisory", Passed: passed, Reasons: reasons, Source: "computed",
	}
}

func persistedGateResponse(prNumber int, check *store.PrCheck) prGateResponse {
	reasons := []string{}
	if len(check.Reasons) > 0 {
		_ = json.Unmarshal(check.Reasons, &reasons)
	}
	resp := prGateResponse{
		PRNumber:    prNumber,
		HeadSHA:     check.HeadSha,
		Context:     check.Context,
		State:       check.State,
		Conclusion:  check.Conclusion,
		Enforcement: check.Enforcement,
		Passed:      check.Passed,
		Reasons:     reasons,
		TargetURL:   check.TargetUrl,
		Source:      "persisted",
	}
	updated := check.UpdatedAt
	resp.UpdatedAt = &updated
	return resp
}

// wsGateNotifier adapts the WS fanout to forge.LiveGateNotifier so the gate
// publisher can broadcast live PR-gate refreshes without importing the ws package
// (which would form an import cycle). Cross-replica delivery is handled by the
// fanout's Postgres LISTEN/NOTIFY bridge (ADR-015).
type wsGateNotifier struct {
	live ws.LiveDelivery
}

func (n wsGateNotifier) PublishGateUpdate(ctx context.Context, topic string, payload []byte) {
	if n.live == nil {
		return
	}
	n.live.PublishBroadcast(ctx, ws.Message{Type: topic, Payload: payload})
}

// publishGateRecompute asks the gate publisher to re-evaluate and re-post the PR
// gate check(s) for a repository without a CI re-run — used after a gate-affecting
// change such as a VEX/false-positive dismissal. Best-effort and asynchronous.
func (s *Server) publishGateRecompute(ctx context.Context, repoID uuid.UUID) {
	if s.bus == nil || repoID == uuid.Nil {
		return
	}
	s.bus.Publish(ctx, events.Event{
		Type:    events.GateRecomputeRequested,
		Payload: map[string]any{"repo_id": repoID.String()},
	})
}
