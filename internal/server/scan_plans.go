package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/applicability"
	"github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/scanplan"
	"github.com/hibouhq/hibou/internal/scanpolicy"
	"github.com/hibouhq/hibou/internal/store"
)

type createScanPlanRequest struct {
	Ref           string `json:"ref"`
	CommitSHA     string `json:"commit_sha"`
	BaseCommitSHA string `json:"base_commit_sha"`
	// Mode "" lets hibou choose (baseline or full); "sweep" asks for one.
	Mode   string          `json:"mode"`
	Runner scanplan.Runner `json:"runner"`
	// Scanners selects catalog scanners explicitly, including pre-releases;
	// empty means every applicable, non-preview scanner. Repo and org
	// policy (ADR-035 §5) will narrow this.
	Scanners []string `json:"scanners"`
	// DryRun returns the plan without storing it (UI preview).
	DryRun bool `json:"dry_run"`
}

type scanPlanResponse struct {
	ID   *uuid.UUID    `json:"id,omitempty"`
	Plan scanplan.Plan `json:"plan"`
}

// @Summary      Create a scan plan
// @Description  Builds the reproducible plan CI executes (ADR-035 §4, ADR-036 §3): one job per applicable scanner with its scope, verified artifact location, ruleset, prerequisites and budget, or the exact blocker. Upload each job's report with plan_id and plan_job_id to bind it to the plan.
// @Tags         scanners
// @Accept       json
// @Produce      json
// @Param        provider  path  string                        true  "Forge provider"
// @Param        slug      path  string                        true  "Organization slug"
// @Param        repoSlug  path  string                        true  "Repository slug"
// @Param        payload   body  server.createScanPlanRequest  true  "Plan request"
// @Success      201  {object}  api.Response{data=server.scanPlanResponse}
// @Success      200  {object}  api.Response{data=server.scanPlanResponse}  "dry run"
// @Failure      400  {object}  api.Response
// @Failure      502  {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/scan-plans [post]
func (s *Server) handleCreateScanPlan(w http.ResponseWriter, r *http.Request) {
	org, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}
	if !s.enforceTokenCapability(w, r, apitoken.CapUploads, apitoken.AccessWrite, org.Slug, repo.Slug) {
		return
	}
	if s.scanCatalog == nil {
		api.JSONError(w, http.StatusServiceUnavailable, "scanner catalog unavailable")
		return
	}
	var request createScanPlanRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	request.Mode = strings.TrimSpace(request.Mode)
	if request.Mode != "" && request.Mode != scanplan.ModeSweep {
		api.JSONError(w, http.StatusBadRequest, "mode must be empty or \"sweep\"")
		return
	}
	request.Runner.OS = strings.ToLower(strings.TrimSpace(request.Runner.OS))
	request.Runner.Arch = strings.ToLower(strings.TrimSpace(request.Runner.Arch))
	if request.Runner.OS == "" || request.Runner.Arch == "" {
		api.JSONError(w, http.StatusBadRequest, "runner.os and runner.arch are required (the platform the scanners must run on)")
		return
	}
	for _, id := range request.Scanners {
		if _, ok := s.scanCatalog.Scanner(id); !ok {
			api.JSONError(w, http.StatusBadRequest, "unknown scanner "+id)
			return
		}
	}
	ref := strings.TrimPrefix(strings.TrimSpace(request.Ref), "refs/heads/")
	if ref == "" {
		ref = repo.DefaultBranch
	}

	ctx, cancel := context.WithTimeout(r.Context(), applicabilityTimeout)
	defer cancel()
	detected, err := s.applicabilityForCommit(ctx, repo, ref, strings.TrimSpace(request.CommitSHA))
	if err != nil {
		s.log.Warn().Err(err).Str("repo", repo.Slug).Msg("scan plan: applicability detection failed")
		api.JSONError(w, http.StatusBadGateway, "could not list the repository through the forge")
		return
	}
	var result applicability.Result
	if err := json.Unmarshal(detected.Result, &result); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "stored applicability is unreadable")
		return
	}
	input := scanplan.Input{
		CommitSHA:         detected.CommitSHA,
		BaseCommitSHA:     strings.TrimSpace(request.BaseCommitSHA),
		RequestedMode:     request.Mode,
		Runner:            request.Runner,
		Applicability:     result,
		DetectionRevision: detected.DetectionRevision,
		CatalogRevision:   detected.CatalogRevision,
	}
	// ADR-035 §5: the plan runs what the policy decides. A CI request may
	// add scanners; it can never drop one the org requires.
	decisions, _, _, err := s.repoScannerDecisions(r.Context(), repo, &result)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to resolve scanner policy")
		return
	}
	input.Enabled = scanpolicy.Enabled(decisions)
	if len(request.Scanners) > 0 {
		selected := map[string]bool{}
		for _, id := range request.Scanners {
			selected[id] = true
		}
		for _, decision := range decisions {
			if decision.State == scanpolicy.StateRequired {
				selected[decision.ScannerID] = true
			}
		}
		input.Enabled = make([]string, 0, len(selected))
		for id := range selected {
			input.Enabled = append(input.Enabled, id)
		}
	}
	if previous, err := s.queries.GetLatestScanPlan(r.Context(), repo.ID); err == nil && previous != nil {
		var plan scanplan.Plan
		if json.Unmarshal(previous.Plan, &plan) == nil {
			input.Previous = &plan
		}
	}
	plan := scanplan.Build(input, s.scanCatalog, s.cfg.ScannerDistribution)
	if request.DryRun {
		api.JSON(w, http.StatusOK, scanPlanResponse{Plan: plan})
		return
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to encode plan")
		return
	}
	var apiKeyID *uuid.UUID
	if tokenAuth := auth.TokenAuthFromContext(r.Context()); tokenAuth != nil {
		id := tokenAuth.KeyID
		apiKeyID = &id
	}
	var base *string
	if plan.BaseCommitSHA != "" {
		base = &plan.BaseCommitSHA
	}
	stored, err := s.queries.CreateScanPlan(r.Context(), store.ScanPlan{
		RepoID: repo.ID, RefName: ref, CommitSHA: plan.CommitSHA, BaseCommitSHA: base, Mode: plan.Mode,
		Digest: plan.Digest, DetectionRevision: plan.DetectionRevision, CatalogRevision: plan.CatalogRevision, Plan: encoded,
	}, apiKeyID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to store plan")
		return
	}
	s.refreshScanCoverageAsync(repo)
	api.JSON(w, http.StatusCreated, scanPlanResponse{ID: &stored.ID, Plan: plan})
}

// applicabilityForCommit reuses the latest detection when it is for this
// commit and the current recipes and catalog, else detects at the commit.
func (s *Server) applicabilityForCommit(ctx context.Context, repo *store.Repository, ref, commit string) (*store.RepoApplicability, error) {
	if latest, err := s.queries.GetLatestRepoApplicability(ctx, repo.ID); err == nil && latest != nil &&
		(commit == "" || latest.CommitSHA == commit) &&
		latest.DetectionRevision == applicability.Revision && latest.CatalogRevision == s.scanCatalog.Revision &&
		(commit != "" || latest.RefName == ref) {
		return latest, nil
	}
	return s.detectRepoApplicability(ctx, repo, ref, commit)
}

// @Summary      Get a scan plan
// @Tags         scanners
// @Produce      json
// @Param        provider  path  string  true  "Forge provider"
// @Param        slug      path  string  true  "Organization slug"
// @Param        repoSlug  path  string  true  "Repository slug"
// @Param        planID    path  string  true  "Plan ID"
// @Success      200  {object}  api.Response{data=server.scanPlanResponse}
// @Failure      404  {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/scan-plans/{planID} [get]
func (s *Server) handleGetScanPlan(w http.ResponseWriter, r *http.Request) {
	_, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}
	planID, err := uuid.Parse(chi.URLParam(r, "planID"))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid plan id")
		return
	}
	stored, err := s.queries.GetScanPlan(r.Context(), repo.ID, planID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load plan")
		return
	}
	if stored == nil {
		api.JSONError(w, http.StatusNotFound, "plan not found")
		return
	}
	var plan scanplan.Plan
	if err := json.Unmarshal(stored.Plan, &plan); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "stored plan is unreadable")
		return
	}
	api.JSON(w, http.StatusOK, scanPlanResponse{ID: &stored.ID, Plan: plan})
}

var (
	errPlanJobUnknown  = errors.New("plan_job_id is not a job of that plan")
	errPlanCommitDiffs = errors.New("the plan was made for another commit")
)

// planJobDeclaration resolves an upload's plan binding (ADR-036 §3): the
// job's planned scope becomes the run's declared scope. A report bound to a
// plan for another commit is refused, not silently treated as evidence.
func (s *Server) planJobDeclaration(ctx context.Context, repo *store.Repository, planID uuid.UUID, jobID, commit string) (store.ArtifactRunDeclaration, error) {
	var declaration store.ArtifactRunDeclaration
	stored, err := s.queries.GetScanPlan(ctx, repo.ID, planID)
	if err != nil {
		return declaration, err
	}
	if stored == nil {
		return declaration, errPlanJobUnknown
	}
	var plan scanplan.Plan
	if err := json.Unmarshal(stored.Plan, &plan); err != nil {
		return declaration, err
	}
	if commit != "" && plan.CommitSHA != commit {
		return declaration, errPlanCommitDiffs
	}
	for _, job := range plan.Jobs {
		if job.ID != jobID {
			continue
		}
		scope := job.Scope
		declaration.Scope = &scope
		if scope == store.ProducerScopePartial {
			declaration.ScopePaths = append([]string(nil), job.Targets...)
		}
		return declaration, nil
	}
	return declaration, errPlanJobUnknown
}
