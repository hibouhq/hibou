package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/config"
	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/metrics"
	"github.com/hibouhq/hibou/internal/secretscan"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/worker"
)

const (
	maxSecretScanErrorLen = 500
	gitZeroSHA            = "0000000000000000000000000000000000000000"
)

// errSecretScanSkipped marks a job that completes without scanning (repo too
// large, ref gone). Recorded as complete, never retried — retrying cannot
// change the outcome.
var errSecretScanSkipped = errors.New("secret scan skipped")

// secretScanExecuteHook lets tests intercept job execution; production always
// runs executeSecretScanJob.
var secretScanExecuteHook = func(ctx context.Context, srv *Server, job *store.SecretScanJob) error {
	return srv.executeSecretScanJob(ctx, job)
}

func buildSecretScanProviders(cfg config.Config, log zerolog.Logger) []secretscan.SecretScanProvider {
	providers := make([]secretscan.SecretScanProvider, 0, len(cfg.SecretScan.Providers))
	for _, name := range cfg.SecretScan.Providers {
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "gitleaks":
			provider, err := secretscan.NewGitleaksProvider(log)
			if err != nil {
				// Missing binary must not fail startup: an API-only pod without
				// gitleaks still serves; the worker image carries the binary.
				log.Warn().Err(err).Msg("secret scan provider gitleaks unavailable, skipping")
				continue
			}
			providers = append(providers, provider)
		case "trufflehog":
			// DISABLED ON PURPOSE (2026-07-28), code kept for when it can be
			// re-enabled. TruffleHog re-clones the checkout we already made via a
			// file:// URI, and git's local transport needs /bin/sh for that.
			// Shipping a shell in a security scanner's image to satisfy one
			// engine is a worse trade than losing the engine: gitleaks and
			// betterleaks need no shell (strace-verified), so the runtime image
			// stays shell-free.
			//
			// To re-enable, one of: teach the provider to scan in place without a
			// second clone, hand trufflehog the remote URL instead of the local
			// path, or accept busybox in apko.yaml.
			log.Warn().Msg("secret scan provider trufflehog is disabled in this build (needs a shell in the runtime image); ignoring it")
			continue
		case "betterleaks":
			provider, err := secretscan.NewBetterleaksProvider(log)
			if err != nil {
				log.Warn().Err(err).Msg("secret scan provider betterleaks unavailable, skipping")
				continue
			}
			providers = append(providers, provider)
		default:
			log.Warn().Str("provider", name).Msg("unknown secret scan provider, skipping")
		}
	}
	// Hibou detecting its own hibou_pat_ tokens on the push-check path is never
	// a configuration choice — but only augment a working setup: alone it would
	// make baseline repo scans "complete" without having scanned anything.
	if len(providers) > 0 {
		providers = append(providers, secretscan.NewHibouTokenProvider(log))
	}
	return providers
}

func (s *Server) runSecretScanLoop(ctx context.Context) {
	s.runSecretScanPass(ctx)

	ticker := time.NewTicker(s.cfg.SecretScan.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runSecretScanPass(ctx)
		}
	}
}

// runSecretScanPass dispatches jobs until the queue is empty or every
// concurrency slot is busy. Scale-out is worker replicas, not goroutines: the
// slots bound clone disk and CPU per pod.
func (s *Server) runSecretScanPass(ctx context.Context) {
	for {
		started, err := s.startNextSecretScanJob(ctx)
		if err != nil {
			s.log.Error().Err(err).Msg("secret scan pass failed")
			return
		}
		if !started {
			return
		}
	}
}

func (s *Server) startNextSecretScanJob(ctx context.Context) (bool, error) {
	if s.secretScanner == nil || s.secretScanSlots == nil || s.isDraining() {
		return false, nil
	}

	select {
	case s.secretScanSlots <- struct{}{}:
	default:
		return false, nil
	}
	release := func() { <-s.secretScanSlots }

	maxAttempts := int32(s.cfg.SecretScan.MaxAttempts) //nolint:gosec // validated 1..100 at config load
	job, err := s.queries.ClaimNextSecretScanJob(ctx, s.artifactWorkerID, time.Now().Add(s.artifactProcessingLeaseDuration()), maxAttempts)
	if err != nil || job == nil {
		release()
		return false, err
	}

	go func() {
		defer release()
		s.processClaimedSecretScanJob(ctx, job)
	}()
	return true, nil
}

func (s *Server) processClaimedSecretScanJob(ctx context.Context, job *store.SecretScanJob) {
	started := time.Now()
	// Recorded on every exit path, including abandonment, so a worker that keeps
	// losing claims is visible instead of just quiet.
	defer func() { metrics.SecretScanDuration.WithLabelValues(job.Mode).Observe(time.Since(started).Seconds()) }()

	lease := worker.LeaseFunc(func(leaseCtx context.Context, expiresAt time.Time) (bool, error) {
		return s.queries.RenewSecretScanJobClaim(leaseCtx, job.ID, s.artifactWorkerID, expiresAt)
	})

	err := worker.Run(ctx, lease, worker.Config{
		LeaseDuration:     s.cfg.Worker.LeaseDuration,
		HeartbeatInterval: s.cfg.Worker.HeartbeatInterval,
	}, func(runCtx context.Context) error {
		// The timeout bounds a hung-but-alive scan; the lease covers a dead
		// worker. Independent — a long scan renews its lease and is legal.
		scanCtx, cancel := context.WithTimeout(runCtx, s.cfg.SecretScan.Timeout)
		defer cancel()
		return secretScanExecuteHook(scanCtx, s, job)
	})

	switch {
	case worker.IsClaimLost(err):
		metrics.SecretScansTotal.WithLabelValues(job.Mode, "abandoned").Inc()
		s.log.Warn().Str("job_id", job.ID.String()).Str("worker_id", s.artifactWorkerID).Msg("secret scan abandoned after claim ownership was lost")
	case errors.Is(err, errSecretScanSkipped):
		metrics.SecretScansTotal.WithLabelValues(job.Mode, "skipped").Inc()
		if _, completeErr := s.queries.CompleteSecretScanJob(ctx, job.ID, s.artifactWorkerID); completeErr != nil {
			s.log.Error().Err(completeErr).Str("job_id", job.ID.String()).Msg("finalize skipped secret scan")
		}
		s.log.Warn().Err(err).Str("job_id", job.ID.String()).Str("repo_id", job.RepoID.String()).Msg("secret scan skipped")
	case err != nil:
		metrics.SecretScansTotal.WithLabelValues(job.Mode, "failed").Inc()
		markFinished := int(job.Attempts) >= s.cfg.SecretScan.MaxAttempts
		if _, failErr := s.queries.FailSecretScanJob(ctx, job.ID, s.artifactWorkerID, truncateSecretScanError(err), markFinished); failErr != nil {
			s.log.Error().Err(failErr).Str("job_id", job.ID.String()).Msg("finalize failed secret scan")
		}
		s.log.Error().Err(err).Str("job_id", job.ID.String()).Str("repo_id", job.RepoID.String()).Bool("mark_finished", markFinished).Msg("secret scan failed")
	default:
		metrics.SecretScansTotal.WithLabelValues(job.Mode, "complete").Inc()
		if _, completeErr := s.queries.CompleteSecretScanJob(ctx, job.ID, s.artifactWorkerID); completeErr != nil {
			s.log.Error().Err(completeErr).Str("job_id", job.ID.String()).Msg("finalize completed secret scan")
		}
	}
}

func (s *Server) executeSecretScanJob(ctx context.Context, job *store.SecretScanJob) error {
	repo, err := s.queries.GetRepositoryByID(ctx, job.RepoID)
	if err != nil {
		return fmt.Errorf("load repository: %w", err)
	}
	if repo == nil {
		return fmt.Errorf("%w: repository %s no longer exists", errSecretScanSkipped, job.RepoID)
	}

	provider, ok := s.forges[repo.Provider]
	if !ok {
		return fmt.Errorf("no forge provider configured for %q", repo.Provider)
	}

	target, err := s.resolveSecretScanTarget(ctx, provider, repo)
	if err != nil {
		return err
	}

	if maxMB := s.cfg.SecretScan.MaxRepoMB; maxMB > 0 && target.sizeKB > 0 && target.sizeKB/1024 > int64(maxMB) {
		return fmt.Errorf("%w: repository %s is %dMB, over the secret_scan.max_repo_mb limit of %dMB", errSecretScanSkipped, repo.Slug, target.sizeKB/1024, maxMB)
	}

	var token string
	if auth, ok := provider.(forge.CloneAuthProvider); ok {
		token, err = auth.CloneToken(ctx, target.owner)
		if err != nil {
			return fmt.Errorf("mint clone token for %s/%s: %w", target.owner, target.name, err)
		}
	}

	snapshot, err := s.resolveSecretScanSnapshot(ctx, job, provider, target)
	if err != nil {
		return err
	}

	branch := strings.TrimPrefix(job.RefName, "refs/heads/")
	if job.Mode == store.SecretScanModeIncremental && job.FromCommit != "" && job.FromCommit != gitZeroSHA {
		_, err = s.secretScanner.RunIncrementalScan(ctx, repo.ID, snapshot.ID, target.cloneURL, branch, job.FromCommit, job.ToCommit, token)
	} else {
		// A full job with no commit range is a baseline (enrolment, manual
		// rescan): scan every branch so branch-only history isn't dark forever.
		// A new-branch push records its head and stays scoped to that branch.
		allBranches := strings.TrimSpace(job.FromCommit) == "" && strings.TrimSpace(job.ToCommit) == ""
		_, err = s.secretScanner.RunFullScan(ctx, repo.ID, snapshot.ID, target.cloneURL, branch, token, allBranches)
	}
	if err != nil {
		return err
	}
	s.completeScanOnlySnapshot(ctx, repo.ID, snapshot)
	return nil
}

type secretScanTarget struct {
	owner    string
	name     string
	cloneURL string
	sizeKB   int64
}

// resolveSecretScanTarget prefers the mirrored forge_repositories row and falls
// back to a live provider call, which also supplies the size when the forge
// reports one.
func (s *Server) resolveSecretScanTarget(ctx context.Context, provider forge.Provider, repo *store.Repository) (secretScanTarget, error) {
	target, err := s.mirroredSecretScanTarget(ctx, repo)
	if err != nil {
		return secretScanTarget{}, err
	}

	needsLive := target.cloneURL == "" || s.cfg.SecretScan.MaxRepoMB > 0
	if needsLive {
		if err := s.refreshSecretScanTargetFromForge(ctx, provider, repo, &target); err != nil {
			return secretScanTarget{}, err
		}
	}
	if target.cloneURL == "" {
		return secretScanTarget{}, fmt.Errorf("no clone url resolvable for repository %s", repo.Slug)
	}
	return target, nil
}

func (s *Server) mirroredSecretScanTarget(ctx context.Context, repo *store.Repository) (secretScanTarget, error) {
	target := secretScanTarget{}
	forgeRepo, err := s.queries.GetForgeRepositoryByProviderRepoID(ctx, repo.Provider, repo.ProviderID)
	if err != nil {
		return target, fmt.Errorf("load forge repository: %w", err)
	}
	if forgeRepo != nil {
		target.owner = forgeRepo.Owner
		target.name = forgeRepo.Name
		if forgeRepo.HTMLURL != "" {
			target.cloneURL = strings.TrimRight(forgeRepo.HTMLURL, "/") + ".git"
		}
	}
	if target.owner == "" {
		// No mirrored row: the org name is the forge-side login.
		org, orgErr := s.queries.GetOrganizationByID(ctx, repo.OrgID)
		if orgErr != nil {
			return target, fmt.Errorf("load organization: %w", orgErr)
		}
		if org != nil {
			target.owner = org.Name
		}
	}
	if target.name == "" {
		target.name = repo.Name
	}
	return target, nil
}

func (s *Server) refreshSecretScanTargetFromForge(ctx context.Context, provider forge.Provider, repo *store.Repository, target *secretScanTarget) error {
	live, err := provider.GetRepository(ctx, target.owner, target.name)
	if err != nil {
		if target.cloneURL == "" {
			return fmt.Errorf("resolve clone url for %s: %w", repo.Slug, err)
		}
		// Size stays unknown; the scan proceeds with the mirrored URL.
		s.log.Warn().Err(err).Str("repo", repo.Slug).Msg("could not fetch live repository for secret scan, using mirrored clone url")
		return nil
	}
	if live.CloneURL != "" {
		target.cloneURL = live.CloneURL
	}
	if live.Owner != "" {
		target.owner = live.Owner
	}
	if live.Name != "" {
		target.name = live.Name
	}
	target.sizeKB = live.SizeKB
	return nil
}

// resolveSecretScanSnapshot finds or creates the snapshot findings hang on.
// A push-triggered job usually has no snapshot: secret scans are not CI
// uploads. The snapshot is created as a pending placeholder — the same shape
// the PR webhook uses — so the CI upload for the commit adopts the row
// (uploads reuse pending run-less snapshots) instead of racing it with a
// duplicate, and so a just-pushed commit never masquerades as the ref's
// latest complete analysis. Scan-only repos complete the placeholder when
// the scan finishes (completeScanOnlySnapshot).
//
// An enrolment job knows even less: no ref row and no head SHA exist yet, so
// both are resolved from the forge rather than skipped.
func (s *Server) resolveSecretScanSnapshot(ctx context.Context, job *store.SecretScanJob, provider forge.Provider, target secretScanTarget) (*store.Snapshot, error) {
	if job.SnapshotID != nil {
		snapshot, err := s.queries.GetSnapshotByID(ctx, *job.SnapshotID)
		if err != nil {
			return nil, fmt.Errorf("load job snapshot: %w", err)
		}
		if snapshot != nil {
			return snapshot, nil
		}
	}

	ref, err := s.queries.GetRefByRepoAndName(ctx, job.RepoID, job.RefName, refTypeFromName(job.RefName))
	if err != nil {
		return nil, fmt.Errorf("load ref %s: %w", job.RefName, err)
	}

	commit, err := s.resolveSecretScanCommit(ctx, job, ref, provider, target)
	if err != nil {
		return nil, err
	}

	if ref == nil {
		ref, err = s.queries.UpsertRef(ctx, job.RepoID, job.RefName, refTypeFromName(job.RefName), store.UpsertRefOptions{LatestCommitSHA: &commit})
		if err != nil {
			return nil, fmt.Errorf("create ref %s: %w", job.RefName, err)
		}
	}

	snapshot, err := s.queries.GetSnapshotByRefCommit(ctx, ref.ID, commit)
	if err != nil {
		return nil, fmt.Errorf("load snapshot at %s: %w", commit, err)
	}
	if snapshot != nil {
		return snapshot, nil
	}
	snapshot, err = s.queries.CreatePlaceholderSnapshot(ctx, ref.ID, commit)
	if err != nil {
		return nil, fmt.Errorf("create snapshot at %s: %w", commit, err)
	}
	if snapshot == nil {
		// Lost a creation race (CI upload or another webhook); adopt the row.
		snapshot, err = s.queries.GetSnapshotByRefCommit(ctx, ref.ID, commit)
		if err != nil || snapshot == nil {
			return nil, fmt.Errorf("load raced snapshot at %s: %w", commit, err)
		}
	}
	return snapshot, nil
}

// completeScanOnlySnapshot keeps scan findings readable on repos that never
// upload: with no CI to adopt and finalize the pending placeholder, the
// findings would hang on a snapshot data views never resolve. On repos with
// upload history the placeholder is left pending for CI to adopt — that is
// what keeps a just-pushed commit out of the "latest complete" data views
// until its analysis actually lands.
func (s *Server) completeScanOnlySnapshot(ctx context.Context, repoID uuid.UUID, snapshot *store.Snapshot) {
	if snapshot == nil || snapshot.Status != store.SnapshotStatusPending {
		return
	}
	hasUploads, err := s.queries.RepoHasUploadActivity(ctx, repoID)
	if err != nil {
		s.log.Warn().Err(err).Str("repo_id", repoID.String()).Str("snapshot_id", snapshot.ID.String()).Msg("check repo upload activity after secret scan")
		return
	}
	if hasUploads {
		return
	}
	if _, err := s.queries.CompleteSnapshot(ctx, snapshot.ID); err != nil && !errors.Is(err, store.ErrSnapshotNotCompletable) {
		s.log.Warn().Err(err).Str("snapshot_id", snapshot.ID.String()).Msg("complete scan-only snapshot")
	}
}

// maybeEnqueueSecretScan records a job for a push; the clone happens on
// whichever worker claims it, never on the webhook path. Enqueue is gated on
// config alone — the API pod may lack the gitleaks binary, the worker has it.
func (s *Server) maybeEnqueueSecretScan(ctx context.Context, repo *store.Repository, refType store.RefType, refName string, event forge.PushEvent) {
	if !s.cfg.SecretScan.Enabled || !s.cfg.SecretScan.OnPush {
		return
	}
	if refType != store.RefTypeBranch {
		return
	}
	after := strings.TrimSpace(event.After)
	if after == "" || after == gitZeroSHA {
		// Branch deletion: nothing to scan.
		return
	}

	mode := store.SecretScanModeIncremental
	from := strings.TrimSpace(event.Before)
	if from == "" || from == gitZeroSHA {
		// New branch or unknown base: no range to diff against.
		mode = store.SecretScanModeFull
		from = ""
	}

	if _, err := s.queries.EnqueueSecretScanJob(ctx, store.EnqueueSecretScanJobParams{
		RepoID:     repo.ID,
		RefName:    refName,
		Mode:       mode,
		FromCommit: from,
		ToCommit:   after,
	}); err != nil {
		// The push webhook must succeed regardless; the enrolment full scan or
		// the next push covers the gap.
		s.log.Error().Err(err).Str("repo_id", repo.ID.String()).Str("ref", refName).Msg("enqueue secret scan job")
	}
}

func (s *Server) resolveSecretScanCommit(ctx context.Context, job *store.SecretScanJob, ref *store.Ref, provider forge.Provider, target secretScanTarget) (string, error) {
	if commit := strings.TrimSpace(job.ToCommit); commit != "" {
		return commit, nil
	}
	if ref != nil && ref.LatestCommitSHA != nil {
		if commit := strings.TrimSpace(*ref.LatestCommitSHA); commit != "" {
			return commit, nil
		}
	}
	branch, err := provider.GetBranch(ctx, target.owner, target.name, strings.TrimPrefix(job.RefName, "refs/heads/"))
	if err != nil {
		return "", fmt.Errorf("resolve head of %s: %w", job.RefName, err)
	}
	if branch == nil || strings.TrimSpace(branch.SHA) == "" {
		return "", fmt.Errorf("%w: branch %s has no head commit", errSecretScanSkipped, job.RefName)
	}
	return strings.TrimSpace(branch.SHA), nil
}

// enqueueEnrollmentSecretScan baselines a newly enrolled repository with one
// full-history scan of its default branch. Best-effort: enrolment must succeed
// regardless, and the first push covers the gap.
func (s *Server) enqueueEnrollmentSecretScan(ctx context.Context, repo *store.Repository) {
	if !s.cfg.SecretScan.Enabled || repo == nil {
		return
	}
	refName := normalizeStoredRefName(strings.TrimSpace(repo.DefaultBranch))
	if refName == "" {
		return
	}
	if _, err := s.queries.EnqueueSecretScanJob(ctx, store.EnqueueSecretScanJobParams{
		RepoID:  repo.ID,
		RefName: refName,
		Mode:    store.SecretScanModeFull,
	}); err != nil {
		s.log.Error().Err(err).Str("repo_id", repo.ID.String()).Msg("enqueue enrolment secret scan")
	}
}

// handleTriggerSecretScan enqueues a full scan of a branch (default branch
// unless ?ref= names another). It only records the job — the clone happens on
// whichever worker claims it, so this stays cheap on the API pod.
func (s *Server) handleTriggerSecretScan(w http.ResponseWriter, r *http.Request) {
	org, repo, user, ok := s.loadAuthorizedRepoWithUser(w, r, true)
	if !ok {
		return
	}

	if !s.cfg.SecretScan.Enabled {
		api.JSONError(w, http.StatusConflict, "secret scanning is not enabled")
		return
	}

	refName := strings.TrimSpace(r.URL.Query().Get("ref"))
	if refName == "" {
		refName = repo.DefaultBranch
	}
	refName = normalizeStoredRefName(refName)
	if refName == "" || refTypeFromName(refName) != store.RefTypeBranch {
		api.JSONError(w, http.StatusBadRequest, "secret scans run on branches; pass a branch ref")
		return
	}

	job, err := s.queries.EnqueueSecretScanJob(r.Context(), store.EnqueueSecretScanJobParams{
		RepoID:  repo.ID,
		RefName: refName,
		Mode:    store.SecretScanModeFull,
	})
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to enqueue secret scan")
		return
	}

	s.writeRepositoryAuditLog(r, user, org.ID, repo.ID, audit.ActionScanTrigger, map[string]any{
		"job_id": job.ID.String(), "ref": refName, "mode": job.Mode,
	})

	api.JSON(w, http.StatusAccepted, struct {
		JobID  uuid.UUID `json:"job_id"`
		Ref    string    `json:"ref"`
		Mode   string    `json:"mode"`
		Status string    `json:"status"`
	}{JobID: job.ID, Ref: refName, Mode: job.Mode, Status: job.Status})
}

// handleListSecretScanJobs surfaces recent jobs so a queued-but-failing scan
// is visible (binary missing, clone auth, oversized repo) instead of silently
// producing no findings.
func (s *Server) handleListSecretScanJobs(w http.ResponseWriter, r *http.Request) {
	_, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}
	jobs, err := s.queries.ListSecretScanJobsByRepo(r.Context(), repo.ID, 20)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list secret scan jobs")
		return
	}
	api.JSON(w, http.StatusOK, jobs)
}

const maxSecretCheckPatchBytes = 1 << 20

// handleSecretScanCheck is the synchronous push-check path (ADR-010): a
// pre-receive hook or the CLI submits the patch content — the commits exist
// nowhere Hibou can clone — and gets a verdict. Persists nothing.
func (s *Server) handleSecretScanCheck(w http.ResponseWriter, r *http.Request) {
	if !s.hasPrincipal(r) {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	// Deliberately unbound to an org/repo: the verdict concerns only the
	// caller's own submitted patch and nothing is persisted, so secrets:read is
	// the whole requirement — pre-receive hooks cannot reliably name hibou
	// slugs. This makes secrets:read include push-check compute; documented in
	// docs/api-tokens.md.
	if !s.enforceTokenCapability(w, r, apitoken.CapSecrets, apitoken.AccessRead, "", "") {
		return
	}
	if s.secretScanner == nil {
		api.JSONError(w, http.StatusConflict, "secret scanning is not available on this server")
		return
	}

	patch, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxSecretCheckPatchBytes))
	if err != nil {
		api.JSONError(w, http.StatusRequestEntityTooLarge, "patch exceeds the 1MB check limit; rely on the post-push scan")
		return
	}

	// The caller's push is blocked waiting, so this path gets its own small
	// limiter — never the worker slots — and refuses instead of queueing.
	// Fail-open vs fail-closed on a refusal is the hook's decision.
	select {
	case s.secretCheckSlots <- struct{}{}:
		defer func() { <-s.secretCheckSlots }()
	default:
		api.JSONError(w, http.StatusServiceUnavailable, "secret check is at capacity, retry or fail open")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.SecretScan.Timeout)
	defer cancel()
	findings, err := s.secretScanner.CheckPatch(ctx, patch)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "secret check failed: "+truncateSecretScanError(err))
		return
	}

	results := make([]secretCheckFinding, 0, len(findings))
	for _, finding := range findings {
		results = append(results, secretCheckFinding{
			Tool:       finding.Tool,
			RuleID:     finding.RuleID,
			Severity:   finding.Severity,
			FilePath:   finding.FilePath,
			Line:       finding.StartLine,
			SecretType: finding.SecretType,
			SecretHash: finding.SecretHash,
			Verified:   finding.Verified,
		})
	}
	api.JSON(w, http.StatusOK, secretCheckResponse{Block: len(results) > 0, Findings: results})
}

// secretCheckFinding never carries the secret itself — hash only (ADR-010).
type secretCheckFinding struct {
	Tool       string `json:"tool"`
	RuleID     string `json:"rule_id"`
	Severity   string `json:"severity"`
	FilePath   string `json:"file_path"`
	Line       int32  `json:"line"`
	SecretType string `json:"secret_type"`
	SecretHash string `json:"secret_hash"`
	Verified   bool   `json:"verified"`
}

type secretCheckResponse struct {
	Block    bool                 `json:"block"`
	Findings []secretCheckFinding `json:"findings"`
}

// releaseSecretScanClaims hands unfinished jobs back on shutdown. In-flight
// scans are already cancelled with the runtime context; a late owner-guarded
// Complete/Fail no-ops once the claim is cleared, and a re-run is safe because
// ingest dedups by fingerprint.
func (s *Server) releaseSecretScanClaims(ctx context.Context) error {
	if s.queries == nil || s.secretScanner == nil || strings.TrimSpace(s.artifactWorkerID) == "" {
		return nil
	}
	count, err := s.queries.ReleaseSecretScanJobClaims(ctx, s.artifactWorkerID)
	if err != nil {
		return fmt.Errorf("release secret scan claims: %w", err)
	}
	if count > 0 {
		s.log.Info().Int64("released_claims", count).Str("worker_id", s.artifactWorkerID).Msg("released secret scan claims during shutdown")
	}
	return nil
}

func truncateSecretScanError(err error) string {
	message := err.Error()
	if len(message) > maxSecretScanErrorLen {
		return message[:maxSecretScanErrorLen]
	}
	return message
}
