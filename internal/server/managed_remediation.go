package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/config"
	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/remediation"
	"github.com/hibouhq/hibou/internal/store"
)

func (s *Server) managedRoutes(r chi.Router) {
	r.Get("/{repoSlug}/remediation/capabilities", s.handleRemediationCapabilities)
	s.managedMaintenanceRoutes(r)
	r.Post("/{repoSlug}/remediation/prepare", s.handleRemediationPrepare)
	r.Get("/{repoSlug}/remediation/{jobID}", s.handleRemediationJob)
	r.Post("/{repoSlug}/remediation/{jobID}/generate", s.handleRemediationGenerate)
	r.Post("/{repoSlug}/remediation/{jobID}/cancel", s.handleRemediationCancel)
	r.Get("/{repoSlug}/remediation/{jobID}/patch", s.handleRemediationPatch)
	r.Post("/{repoSlug}/remediation/{jobID}/publish", s.handleRemediationPublish)
	r.Put("/{repoSlug}/remediation/consent", s.handleRemediationConsent)
}

func (s *Server) managedAuthorized(w http.ResponseWriter, r *http.Request, mutation bool) (*store.Organization, *store.Repository, *store.User, bool) {
	org, repo, user, ok := s.loadAuthorizedRepoWithUser(w, r, false)
	if !ok {
		return nil, nil, nil, false
	}
	access := apitoken.AccessRead
	if mutation {
		access = apitoken.AccessWrite
	}
	if !s.enforceTokenCapability(w, r, apitoken.CapVulnerabilities, access, org.Slug, repo.Slug) {
		return nil, nil, nil, false
	}
	return org, repo, user, true
}

// handleRemediationCapabilities reports managed execution and mutation readiness.
// @Summary      Get managed remediation capabilities
// @Description  Reports opt-in Kubernetes execution readiness for the exact configured image/toolchain/mirror profile and caller permissions. Historical runtime-controller heartbeats cannot enable it. No dependency tools run in the API process.
// @Tags         remediation
// @Produce      json
// @Security     BearerAuth
// @Param        provider path string true "Forge provider"
// @Param        slug path string true "Organization slug"
// @Param        repoSlug path string true "Repository slug"
// @Success      200 {object} api.Response{data=ManagedRemediationCapabilitiesResponse}
// @Failure      401,403,404,500 {object} api.Response
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/remediation/capabilities [get]
func (s *Server) handleRemediationCapabilities(w http.ResponseWriter, r *http.Request) {
	org, repo, _, ok := s.managedAuthorized(w, r, false)
	if !ok {
		return
	}
	available, reason := s.managedExecutionReady(r.Context())
	binding, bindErr := s.queries.VerifiedForgeRepositoryTarget(r.Context(), repo.ID)
	if bindErr != nil || binding == nil {
		available = false
		if reason != "" {
			reason += "; "
		}
		reason += "repository has no current immutable forge enrollment"
	}
	role, roleErr := s.principalOrgRole(r, org.ID)
	access, accessErr := s.principalRepoAccess(r, org.ID, role)
	mayGenerate, canPublish, canConsent := managedPermissions(r, org.Slug, repo.Slug, repo.ID, role, access)
	if roleErr != nil || accessErr != nil {
		mayGenerate, canPublish, canConsent = false, false, false
	}
	publicationReason := "Requires organization consent, GitHub App propose tier and installation write permissions, and repository admin authorization."
	publisher, atomic := s.forges[repo.Provider].(forge.RemediationPublicationCapability)
	publicationAvailable := false
	if atomic && canPublish && managedOrgConsent(org) && binding != nil && bindErr == nil {
		ctx := forge.WithRepositoryIdentity(forge.WithInstallationOwner(r.Context(), binding.Owner), binding.AccountID, binding.RepositoryID)
		if err := publisher.CheckRemediationPublication(ctx, binding.Owner, binding.Name); err == nil {
			publicationAvailable = true
			publicationReason = ""
		} else {
			publicationReason = err.Error()
		}
	}
	generationReason := reason
	if !mayGenerate {
		generationReason = "Repository write authorization and vulnerabilities:write capability are required for managed generation."
	}
	maintenanceSettings, maintenanceErr := parseManagedMaintenanceSettings(org)
	maintenanceReason := "Organization maintenance mappings are invalid."
	if maintenanceErr == nil {
		maintenanceReason = s.managedMaintenanceCreationReason(r, org, repo, maintenanceSettings)
	}
	api.JSON(w, http.StatusOK, map[string]any{
		"available": available, "reason": reason, "profile": "npm package-lock v3 via approved internal mirror",
		"can_generate": mayGenerate && available, "generation_reason": generationReason, "can_consent": canConsent,
		"publication_available": publicationAvailable, "publication_reason": publicationReason,
		"maintenance_creation_available": maintenanceReason == "", "maintenance_creation_reason": maintenanceReason,
		"target_suggestions_url":    "maintenance-targets?release_id=<release UUID>",
		"target_suggestions_reason": "Suggestions require explicit organization release-tag mappings and live tag/ancestry evidence; inventory branch patterns are not maintenance mappings.",
		"limits":                    []string{"Independent package-lock v3 modules only", "Approved internal npm mirror and preprovisioned Node/npm profile; no public fallback or executable bootstrap", "Private namespaces, aliases, workspaces, repository registry/runtime controls and zero-network execution are unsupported", "Builds/application tests are not run; graph/policy checks and independent native lockfile verification are mandatory"},
	})
}

func managedPermissions(r *http.Request, org, repo string, repoID uuid.UUID, role string, access repoAccess) (generate, publish, consent bool) {
	effectiveRole := access.repoRole(role, repoID)
	generate = roleCanWrite(effectiveRole) && auth.RequireCapability(r.Context(), apitoken.CapVulnerabilities, apitoken.AccessWrite, org, repo) == nil
	publish = effectiveRole == "admin" && generate
	consent = role == "admin" && !access.scoped && auth.RequireOrgWideCapability(r.Context(), apitoken.CapAdmin, apitoken.AccessWrite, org) == nil
	return
}

func decodeManaged(w http.ResponseWriter, r *http.Request, value any) bool {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid remediation request")
		return false
	}
	if d.Decode(&struct{}{}) != io.EOF {
		api.JSONError(w, http.StatusBadRequest, "exactly one JSON request is required")
		return false
	}
	return true
}

func (s *Server) managedLiveTarget(ctx context.Context, repo *store.Repository) (context.Context, forge.Provider, *forge.Repository, error) {
	binding, err := s.queries.VerifiedForgeRepositoryTarget(ctx, repo.ID)
	if err != nil {
		return ctx, nil, nil, err
	}
	provider := s.forges[repo.Provider]
	if provider == nil {
		return ctx, nil, nil, errors.New("forge unavailable")
	}
	ctx = forge.WithInstallationOwner(ctx, binding.Owner)
	ctx = forge.WithRepositoryIdentity(ctx, binding.AccountID, binding.RepositoryID)
	live, err := provider.GetRepository(ctx, binding.Owner, binding.Name)
	if err != nil {
		return ctx, nil, nil, err
	}
	if live == nil || live.Archived || live.OwnerID != binding.AccountID || live.ProviderRepoID != binding.RepositoryID {
		return ctx, nil, nil, errors.New("live repository identity differs from enrollment")
	}
	return ctx, provider, live, nil
}

// handleRemediationPrepare creates an immutable, durable discovery draft.
// @Summary      Prepare a managed dependency remediation draft
// @Description  Requires an enabled matching Kubernetes controller, repository write authorization and vulnerabilities:write. Returns 503 without enqueue when execution is unavailable. Pins the workload profile and target branch or exact shipped snapshot. maintenance_target=true requires an explicit existing branch. Optional expected_head_sha must be a full 40- or 64-character hexadecimal branch-source SHA; it is not supported for exact shipped-release sources. No local patch/artifact upload is supported.
// @Tags         remediation
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        provider path string true "Forge provider"
// @Param        slug path string true "Organization slug"
// @Param        repoSlug path string true "Repository slug"
// @Param        payload body ManagedRemediationPrepareRequest true "Immutable source and optional advisory selection"
// @Success      202 {object} api.Response{data=ManagedRemediationJobResponse}
// @Failure      400,401,403,404,409,500,503 {object} api.Response
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/remediation/prepare [post]
func (s *Server) handleRemediationPrepare(w http.ResponseWriter, r *http.Request) {
	_, repo, user, ok := s.managedAuthorized(w, r, true)
	if !ok {
		return
	}
	if !s.requireManagedExecution(w, r) {
		return
	}
	s.prepareManagedDraft(w, r, repo, user)
}

// prepareManagedDraft runs only after execution readiness and authorization.
func (s *Server) prepareManagedDraft(w http.ResponseWriter, r *http.Request, repo *store.Repository, user *store.User) {
	var req ManagedRemediationPrepareRequest
	if !decodeManaged(w, r, &req) {
		return
	}
	if req.MaintenanceTarget && strings.TrimSpace(req.TargetBranch) == "" {
		api.JSONError(w, http.StatusBadRequest, "an explicit existing maintenance branch is required")
		return
	}
	if req.ExpectedHeadSHA != "" {
		if !managedFullCommitSHA.MatchString(req.ExpectedHeadSHA) {
			api.JSONError(w, http.StatusBadRequest, "expected_head_sha must be a full 40- or 64-character hexadecimal commit SHA")
			return
		}
		if req.ReleaseID != "" && !req.MaintenanceTarget {
			api.JSONError(w, http.StatusBadRequest, "expected_head_sha applies to branch-source drafts, not exact shipped release sources")
			return
		}
	}
	if len(req.Vulns) > 5000 {
		api.JSONError(w, 400, "too many selected advisories")
		return
	}
	ctx, provider, live, err := s.managedLiveTarget(r.Context(), repo)
	if err != nil {
		api.JSONError(w, 409, "repository binding is unavailable")
		return
	}
	target := strings.TrimSpace(req.TargetBranch)
	if target == "" {
		target = live.DefaultBranch
	}
	head, err := provider.GetBranch(ctx, live.Owner, live.Name, target)
	if err != nil || head == nil {
		api.JSONError(w, 409, "select an existing target branch")
		return
	}
	if !checkManagedExpectedHead(w, req.ExpectedHeadSHA, head.SHA) {
		return
	}
	base, source := head.SHA, target
	if req.ReleaseID != "" && !req.MaintenanceTarget {
		id, err := uuid.Parse(req.ReleaseID)
		if err != nil {
			api.JSONError(w, 400, "invalid release")
			return
		}
		release, err := s.queries.GetReleaseByID(ctx, id)
		if err != nil || release == nil || release.RepoID != repo.ID || release.SnapshotID == nil {
			api.JSONError(w, 409, "release has no exact shipped source snapshot")
			return
		}
		snapshot, err := s.queries.GetSnapshotByID(ctx, *release.SnapshotID)
		if err != nil || snapshot == nil {
			api.JSONError(w, 409, "shipped source unavailable")
			return
		}
		ref, err := s.queries.GetRefByID(ctx, release.RefID)
		if err != nil || ref == nil || ref.RepoID != repo.ID || snapshot.RefID != release.RefID {
			api.JSONError(w, 409, "release source mismatch")
			return
		}
		base, source = snapshot.CommitSHA, "refs/tags/"+strings.TrimPrefix(ref.Name, "refs/tags/")
		// Exact shipped source is deliberately not silently rebased onto a
		// maintenance/default head. Download is valid; PR requires same base.
	}
	if !regexp.MustCompile(`^[a-f0-9]{40}([a-f0-9]{24})?$`).MatchString(base) {
		api.JSONError(w, 409, "forge did not provide a full immutable commit")
		return
	}
	profile, err := config.ManagedExecutionFromEnv()
	if err != nil || !profile.Enabled {
		api.JSONError(w, 503, "managed Kubernetes workload profile is unavailable")
		return
	}
	input := remediation.ManagedInput{Operation: "prepare", Profile: profile.Profile(), BaseSHA: base, Vulns: req.Vulns}
	data, _ := json.Marshal(input)
	var creator *uuid.UUID
	if user != nil {
		creator = &user.ID
	}
	job, err := s.queries.CreateRemediationJob(ctx, store.RemediationJob{ID: uuid.New(), RepoID: repo.ID, BaseSHA: base, SourceRef: source, TargetBranch: target, Request: data, ExpiresAt: time.Now().Add(24 * time.Hour)}, creator)
	if err != nil {
		api.JSONError(w, 500, "unable to persist remediation draft")
		return
	}
	_ = s.queries.RecordRemediationEvent(ctx, job.ID, "prepare_requested", map[string]any{"creator": creator, "base_sha": base, "target": target, "expected_head_sha": req.ExpectedHeadSHA})
	api.JSON(w, http.StatusAccepted, job)
}

func (s *Server) managedLoadJob(w http.ResponseWriter, r *http.Request, mutation bool) (*store.Organization, *store.Repository, *store.RemediationJob, bool) {
	org, repo, _, ok := s.managedAuthorized(w, r, mutation)
	if !ok {
		return nil, nil, nil, false
	}
	id, err := uuid.Parse(chi.URLParam(r, "jobID"))
	if err != nil {
		api.JSONError(w, 404, "draft not found")
		return nil, nil, nil, false
	}
	job, err := s.queries.GetRemediationJob(r.Context(), repo.ID, id)
	if err != nil || job == nil {
		api.JSONError(w, 404, "draft not found")
		return nil, nil, nil, false
	}
	if !job.ExpiresAt.After(time.Now()) || job.State == "expired" {
		api.JSONError(w, http.StatusGone, "draft expired; prepare again")
		return nil, nil, nil, false
	}
	return org, repo, job, true
}

// handleRemediationJob returns repository-authorized durable job state.
// @Summary      Get a managed remediation draft
// @Description  Poll for preparation/generation phases, normalized modules, unavailable reasons and verified artifact summaries. Only state=ready permits download/publication; artifact presence alone is insufficient. Patch bytes, complete publication files, storage keys and leases are not exposed. Expired drafts return 410.
// @Tags         remediation
// @Produce      json
// @Security     BearerAuth
// @Param        provider path string true "Forge provider"
// @Param        slug path string true "Organization slug"
// @Param        repoSlug path string true "Repository slug"
// @Param        jobID path string true "Managed draft UUID"
// @Success      200 {object} api.Response{data=ManagedRemediationJobResponse}
// @Failure      401,403,404,410,500 {object} api.Response
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/remediation/{jobID} [get]
func (s *Server) handleRemediationJob(w http.ResponseWriter, r *http.Request) {
	_, _, job, ok := s.managedLoadJob(w, r, false)
	if !ok {
		return
	}
	api.JSON(w, 200, job)
}

type managedSelection struct {
	ID             string                      `json:"id"`
	UpgradeLevel   string                      `json:"upgrade_level"`
	VersionTargets []remediation.VersionTarget `json:"version_targets,omitempty"`
}

func selectManagedUnits(result remediation.ManagedResult, selections []managedSelection) ([]remediation.Unit, error) {
	if len(selections) == 0 || len(selections) > remediation.MaxUnits {
		return nil, errors.New("select at least one supported module")
	}
	units := map[string]remediation.Unit{}
	for _, module := range result.Modules {
		if module.Unit != nil {
			units[module.Unit.ID] = *module.Unit
		}
	}
	var selected []remediation.Unit
	seen := map[string]bool{}
	for _, selection := range selections {
		unit, ok := units[selection.ID]
		if !ok || seen[selection.ID] {
			return nil, errors.New("unknown or duplicate selected module")
		}
		if !slices.Contains([]string{"patch", "minor", "major"}, selection.UpgradeLevel) {
			return nil, errors.New("invalid upgrade policy")
		}
		unit.UpgradeLevel, unit.VersionTargets = selection.UpgradeLevel, selection.VersionTargets
		selected = append(selected, unit)
		seen[unit.ID] = true
	}
	return selected, nil
}

// handleRemediationGenerate enqueues an explicitly selected draft revision.
// @Summary      Generate and verify selected remediation units
// @Description  Requires an enabled matching Kubernetes controller, write authorization and vulnerabilities:write. Returns 503 without enqueue when execution is unavailable. Select server-discovered unit IDs, patch/minor/major ceilings and optional exact/cached-Gossip targets. Paths, hashes, source identity and profile remain server-owned; changed profiles require new preparation. Verification/relock failure never produces a ready artifact.
// @Tags         remediation
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        provider path string true "Forge provider"
// @Param        slug path string true "Organization slug"
// @Param        repoSlug path string true "Repository slug"
// @Param        jobID path string true "Prepared managed draft UUID"
// @Param        payload body ManagedRemediationGenerateRequest true "Current revision and selected normalized units"
// @Success      202 {object} api.Response{data=ManagedRemediationJobResponse}
// @Failure      400,401,403,404,409,410,500,503 {object} api.Response
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/remediation/{jobID}/generate [post]
func (s *Server) handleRemediationGenerate(w http.ResponseWriter, r *http.Request) {
	_, repo, job, ok := s.managedLoadJob(w, r, true)
	if !ok {
		return
	}
	if !s.requireManagedExecution(w, r) {
		return
	}
	s.generateManagedDraft(w, r, repo, job)
}

// generateManagedDraft keeps source, units and profile server-owned.
func (s *Server) generateManagedDraft(w http.ResponseWriter, r *http.Request, repo *store.Repository, job *store.RemediationJob) {
	var req ManagedRemediationGenerateRequest
	if !decodeManaged(w, r, &req) {
		return
	}
	var result remediation.ManagedResult
	if json.Unmarshal(job.Result, &result) != nil {
		api.JSONError(w, 409, "draft has no normalized modules")
		return
	}
	units, err := selectManagedUnits(result, req.Units)
	if err != nil {
		api.JSONError(w, 400, err.Error())
		return
	}
	// Refuse a stale maintenance/default target before costly execution.
	if job.SourceRef == job.TargetBranch {
		ctx, provider, live, err := s.managedLiveTarget(r.Context(), repo)
		if err != nil {
			api.JSONError(w, 409, "repository identity unavailable")
			return
		}
		head, err := provider.GetBranch(ctx, live.Owner, live.Name, job.TargetBranch)
		if err != nil || head == nil || head.SHA != job.BaseSHA {
			api.JSONError(w, 409, "target head moved; prepare a new draft")
			return
		}
	}
	profile, err := config.ManagedExecutionFromEnv()
	if err != nil || !profile.Enabled {
		api.JSONError(w, 503, "managed Kubernetes workload profile is unavailable")
		return
	}
	var prepared remediation.ManagedInput
	if json.Unmarshal(job.Request, &prepared) != nil || prepared.Profile != profile.Profile() {
		api.JSONError(w, 409, "managed workload profile changed; prepare a new draft")
		return
	}
	input := remediation.ManagedInput{Operation: "generate", Profile: prepared.Profile, BaseSHA: job.BaseSHA, Units: units}
	data, _ := json.Marshal(input)
	updated, err := s.queries.SelectRemediationUnits(r.Context(), repo.ID, job.ID, req.Revision, data)
	if errors.Is(err, store.ErrRemediationConflict) {
		api.JSONError(w, 409, "draft revision or phase changed; refresh")
		return
	}
	if err != nil {
		api.JSONError(w, 500, "unable to enqueue generation")
		return
	}
	_ = s.queries.RecordRemediationEvent(r.Context(), job.ID, "generate_requested", map[string]any{"revision": updated.Revision, "selected_units": len(units), "total_units": len(result.Modules)})
	api.JSON(w, 202, updated)
}

// handleRemediationCancel revokes a draft's claim and schedules private cleanup.
// @Summary      Cancel a managed remediation draft
// @Description  Requires write authorization and vulnerabilities:write. Revokes the job lease, fences active workloads and schedules private cleanup. The Kubernetes controller reconciles cleanup/expiry. Serialized publication finishes before cancellation takes effect; previously published branches/PRs are not deleted. No request body is required.
// @Tags         remediation
// @Produce      json
// @Security     BearerAuth
// @Param        provider path string true "Forge provider"
// @Param        slug path string true "Organization slug"
// @Param        repoSlug path string true "Repository slug"
// @Param        jobID path string true "Managed draft UUID"
// @Success      200 {object} api.Response{data=ManagedRemediationCancelResponse}
// @Failure      401,403,404,410,500 {object} api.Response
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/remediation/{jobID}/cancel [post]
func (s *Server) handleRemediationCancel(w http.ResponseWriter, r *http.Request) {
	_, repo, job, ok := s.managedLoadJob(w, r, true)
	if !ok {
		return
	}
	if _, err := s.queries.CancelRemediationJob(r.Context(), repo.ID, job.ID); err != nil {
		api.JSONError(w, 500, "unable to cancel draft")
		return
	}
	if job.ArtifactKey != "" {
		_ = s.queries.ScheduleRemediationArtifactCleanup(r.Context(), job.ArtifactKey)
		_ = s.objStore.Delete(r.Context(), job.ArtifactKey)
	}
	_ = s.queries.RecordRemediationEvent(r.Context(), job.ID, "cancelled", nil)
	api.JSON(w, 200, map[string]string{"state": "cancelled"})
}

func (s *Server) managedArtifact(ctx context.Context, job *store.RemediationJob) (*remediation.ManagedResult, error) {
	if job.State != "ready" || job.ArtifactKey == "" || !job.ExpiresAt.After(time.Now()) {
		return nil, errors.New("verified artifact is not ready")
	}
	reader, err := s.objStore.Get(ctx, job.ArtifactKey)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, remediation.MaxInputBytes+1))
	if err != nil || len(data) > remediation.MaxInputBytes {
		return nil, errors.New("invalid artifact size")
	}
	var result remediation.ManagedResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	var input remediation.ManagedInput
	if err := json.Unmarshal(job.Request, &input); err != nil {
		return nil, err
	}
	if err := remediation.ValidateManagedArtifact(input, result.Artifact); err != nil {
		return nil, err
	}
	if err := remediation.ValidateManagedFiles(result.Artifact, result.Files); err != nil {
		return nil, err
	}
	return &result, nil
}

// handleRemediationPatch downloads the verified patch without a JSON envelope.
// @Summary      Download a verified dependency patch
// @Description  Returns raw UTF-8 unified diff bytes as an attachment, not a JSON/base64 envelope. Requires current repository read authorization and vulnerabilities:read, ready state, unexpired storage and complete verification/digest checks. Errors use the standard JSON error envelope.
// @Tags         remediation
// @Produce      text/x-diff,json
// @Security     BearerAuth
// @Param        provider path string true "Forge provider"
// @Param        slug path string true "Organization slug"
// @Param        repoSlug path string true "Repository slug"
// @Param        jobID path string true "Ready managed draft UUID"
// @Success      200 {string} string "Raw verified UTF-8 unified dependency patch"
// @Header       200 {string} Content-Disposition "attachment; filename=hibou-remediation.patch"
// @Header       200 {string} Cache-Control "private, no-store"
// @Failure      401,403,404,409,410,500 {object} api.Response
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/remediation/{jobID}/patch [get]
func (s *Server) handleRemediationPatch(w http.ResponseWriter, r *http.Request) {
	_, _, job, ok := s.managedLoadJob(w, r, false)
	if !ok {
		return
	}
	result, err := s.managedArtifact(r.Context(), job)
	if err != nil {
		api.JSONError(w, 409, "verified patch is not available")
		return
	}
	w.Header().Set("Content-Type", "text/x-diff; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="hibou-remediation.patch"`)
	w.Header().Set("Cache-Control", "private, no-store")
	_, _ = w.Write(result.Artifact.Patch)
}

func managedOrgConsent(org *store.Organization) bool {
	var settings map[string]json.RawMessage
	if json.Unmarshal(org.Settings, &settings) != nil {
		return false
	}
	var consent bool
	_ = json.Unmarshal(settings["managed_remediation_pr_consent"], &consent)
	return consent
}

// handleRemediationConsent updates explicit organization branch/PR consent.
// @Summary      Set organization managed remediation consent
// @Description  Organization-wide admin authorization and admin:write are required; a token restricted to one repository cannot grant organization consent. This consent alone does not grant caller/App write permissions or bypass operator maintenance allowlists.
// @Tags         remediation
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        provider path string true "Forge provider"
// @Param        slug path string true "Organization slug"
// @Param        repoSlug path string true "Repository authorization context"
// @Param        payload body ManagedRemediationConsent true "Explicit consent state"
// @Success      200 {object} api.Response{data=ManagedRemediationConsent}
// @Failure      400,401,403,404,500 {object} api.Response
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/remediation/consent [put]
func (s *Server) handleRemediationConsent(w http.ResponseWriter, r *http.Request) {
	org, _, user, ok := s.loadAuthorizedRepoWithUser(w, r, true)
	if !ok {
		return
	}
	if !s.enforceOrgWideCapability(w, r, apitoken.CapAdmin, apitoken.AccessWrite, org.Slug) {
		return
	}
	access, err := s.principalRepoAccess(r, org.ID, "admin")
	if err != nil || access.scoped {
		api.JSONError(w, http.StatusForbidden, "organization-wide admin authorization is required to consent")
		return
	}
	var req ManagedRemediationConsent
	if !decodeManaged(w, r, &req) {
		return
	}
	if err := s.queries.SetManagedRemediationConsent(r.Context(), org.ID, req.Enabled); err != nil {
		api.JSONError(w, 500, "unable to save organization consent")
		return
	}
	s.writeAuditLog(r, user, orgAuditID(org.ID), auditEntry{Action: audit.ActionConfigChange,
		ResourceType: "organization", ResourceID: org.ID.String(), Context: map[string]any{"managed_remediation_pr_consent": req.Enabled}})
	api.JSON(w, 200, map[string]bool{"enabled": req.Enabled})
}

// handleRemediationPublish explicitly creates/reconciles a verified branch+PR.
// @Summary      Publish a managed remediation pull request
// @Description  Publishes only a ready, verified managed artifact at the reviewed revision; local-artifact upload is unsupported. Requires current admin authorization, vulnerabilities:write, organization consent, GitHub App propose tier and installation contents/PR write permissions. Rechecks immutable repository identity and pinned target head. Uses a complete Git tree/commit and deterministic hibou/ ref without force updates, then creates/reuses a PR with durable auditing. No merge, tag or release is performed.
// @Tags         remediation
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        provider path string true "Forge provider"
// @Param        slug path string true "Organization slug"
// @Param        repoSlug path string true "Repository slug"
// @Param        jobID path string true "Ready managed draft UUID"
// @Param        payload body ManagedRemediationRevisionRequest true "Reviewed current draft revision"
// @Success      200 {object} api.Response{data=forge.PullRequest}
// @Failure      400,401,403,404,409,410,500,503 {object} api.Response
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/remediation/{jobID}/publish [post]
func (s *Server) handleRemediationPublish(w http.ResponseWriter, r *http.Request) {
	org, repo, _, ok := s.loadAuthorizedRepoWithUser(w, r, true)
	if !ok {
		return
	}
	if !s.enforceTokenCapability(w, r, apitoken.CapVulnerabilities, apitoken.AccessWrite, org.Slug, repo.Slug) {
		return
	}
	access, err := s.principalRepoAccess(r, org.ID, "admin")
	if err != nil || access.repoRole("admin", repo.ID) != "admin" {
		api.JSONError(w, http.StatusForbidden, "repository admin authorization is required to publish")
		return
	}
	_, _, job, ok := s.managedLoadJob(w, r, true)
	if !ok {
		return
	}
	if !managedOrgConsent(org) {
		api.JSONError(w, 403, "organization has not consented to managed remediation pull requests")
		return
	}
	var req ManagedRemediationRevisionRequest
	if !decodeManaged(w, r, &req) {
		return
	}
	if req.Revision != job.Revision {
		api.JSONError(w, 409, "draft revision changed")
		return
	}
	result, err := s.managedArtifact(r.Context(), job)
	if err != nil {
		api.JSONError(w, 409, "verified patch is not ready")
		return
	}
	ctx, provider, live, err := s.managedLiveTarget(r.Context(), repo)
	if err != nil {
		api.JSONError(w, 409, "repository forge identity unavailable")
		return
	}
	publisher, ok := provider.(forge.AtomicRemediationPublisher)
	if !ok {
		api.JSONError(w, 503, "atomic remediation publication is unavailable for this forge")
		return
	}
	branch, err := remediation.BranchName(job.TargetBranch, job.BaseSHA, result.Artifact.SHA256)
	if err != nil {
		api.JSONError(w, 409, "invalid target branch")
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var published *forge.PullRequest
	err = s.queries.WithRemediationPublication(ctx, repo.ID, job.ID, req.Revision, func(locked *store.RemediationJob) error {
		currentOrg, err := s.queries.GetOrganizationByID(ctx, org.ID)
		if err != nil || currentOrg == nil || !managedOrgConsent(currentOrg) {
			return errors.New("organization consent was revoked")
		}
		if locked.ArtifactKey != job.ArtifactKey {
			return store.ErrRemediationConflict
		}
		published, err = publisher.PublishRemediation(ctx, live.Owner, live.Name, forge.AtomicRemediationRequest{
			BaseSHA: job.BaseSHA, Target: job.TargetBranch, Branch: branch, ArtifactSHA: result.Artifact.SHA256, Files: result.Files,
			Audit: func(action string, detail any) error {
				return s.queries.RecordRemediationEvent(ctx, job.ID, action, detail)
			},
		})
		return err
	})
	if err != nil {
		api.JSONError(w, 409, "publication refused or incomplete; retry reconciles without overwriting existing commits: "+err.Error())
		return
	}
	api.JSON(w, 200, published)
}
