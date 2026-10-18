package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/depinventory"
	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/secretscan"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/version"
	"github.com/hibouhq/hibou/internal/worker"
)

// Built-in dependency inventory (ADR-045 §4.1). A job per push to an eager
// ref: the worker checks out the repository's lockfiles and manifests at
// the commit (blobless, sparse, nothing executed), extracts them, renders a
// CycloneDX document and stores it as a snapshot artifact. From there the
// artifact processing loop ingests it exactly like an uploaded SBOM, so
// components, the dependency graph, advisory scans, releases, coverage and
// gates all follow without a second pipeline.
//
// Nothing is written to the object store: the inventory is ingested
// straight into the snapshot's components, labels and dependency graph, and
// the run row keeps the digest, extractor version and module completeness.
// Exports regenerate a document from the rows. Only what a user uploads or
// records (CI SBOMs, deliverables) is stored as a file.

const (
	// depInventoryProducer is the producer key of server-side extraction
	// (ADR-034 §2, ADR-045 §5).
	depInventoryProducer = "dependency-inventory:hibou"
	// depInventoryArtifactFilename is the source name the ingestion labels
	// every component with ("sbom:<filename>"), which is how the Sources
	// column and the shipped rule tell extraction from an upload. No file of
	// that name is stored.
	depInventoryArtifactFilename = "hibou-depinventory.cdx.json"
)

var errDepExtractionSkipped = errors.New("dependency extraction skipped")

func (s *Server) runDepExtractionLoop(ctx context.Context) {
	s.runDepExtractionPass(ctx)
	ticker := time.NewTicker(s.cfg.DepInventory.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runDepExtractionPass(ctx)
		}
	}
}

func (s *Server) runDepExtractionPass(ctx context.Context) {
	for {
		started, err := s.startNextDepExtractionJob(ctx)
		if err != nil {
			s.log.Error().Err(err).Msg("dependency extraction pass failed")
			return
		}
		if !started {
			return
		}
	}
}

func (s *Server) startNextDepExtractionJob(ctx context.Context) (bool, error) {
	if s.depExtractionSlots == nil || s.isDraining() {
		return false, nil
	}
	select {
	case s.depExtractionSlots <- struct{}{}:
	default:
		return false, nil
	}
	release := func() { <-s.depExtractionSlots }

	maxAttempts := int32(s.cfg.DepInventory.MaxAttempts) // #nosec G115 -- validated 1..100 at config load
	job, err := s.queries.ClaimNextDepExtractionJob(ctx, s.artifactWorkerID, time.Now().Add(s.artifactProcessingLeaseDuration()), maxAttempts)
	if err != nil || job == nil {
		release()
		return false, err
	}
	go func() {
		defer release()
		s.processClaimedDepExtractionJob(ctx, job)
	}()
	return true, nil
}

func (s *Server) processClaimedDepExtractionJob(ctx context.Context, job *store.DepExtractionJob) {
	lease := worker.LeaseFunc(func(leaseCtx context.Context, expiresAt time.Time) (bool, error) {
		return s.queries.RenewDepExtractionJobClaim(leaseCtx, job.ID, s.artifactWorkerID, expiresAt)
	})
	var snapshotID *uuid.UUID
	err := worker.Run(ctx, lease, worker.Config{
		LeaseDuration:     s.cfg.Worker.LeaseDuration,
		HeartbeatInterval: s.cfg.Worker.HeartbeatInterval,
	}, func(runCtx context.Context) error {
		jobCtx, cancel := context.WithTimeout(runCtx, s.cfg.DepInventory.Timeout)
		defer cancel()
		var runErr error
		snapshotID, runErr = s.executeDepExtractionJob(jobCtx, job)
		return runErr
	})

	logger := s.log.With().Str("job_id", job.ID.String()).Str("repo_id", job.RepoID.String()).Str("ref", job.RefName).Logger()
	switch {
	case worker.IsClaimLost(err):
		logger.Warn().Msg("dependency extraction abandoned after claim ownership was lost")
	case errors.Is(err, errDepExtractionSkipped):
		if _, completeErr := s.queries.CompleteDepExtractionJob(ctx, job.ID, s.artifactWorkerID, snapshotID); completeErr != nil {
			logger.Error().Err(completeErr).Msg("finalize skipped dependency extraction")
		}
		logger.Warn().Err(err).Msg("dependency extraction skipped")
	case err != nil:
		markFinished := int(job.Attempts) >= s.cfg.DepInventory.MaxAttempts
		if _, failErr := s.queries.FailDepExtractionJob(ctx, job.ID, s.artifactWorkerID, truncateSecretScanError(err), markFinished); failErr != nil {
			logger.Error().Err(failErr).Msg("finalize failed dependency extraction")
		}
		logger.Error().Err(err).Bool("mark_finished", markFinished).Msg("dependency extraction failed")
	default:
		if _, completeErr := s.queries.CompleteDepExtractionJob(ctx, job.ID, s.artifactWorkerID, snapshotID); completeErr != nil {
			logger.Error().Err(completeErr).Msg("finalize completed dependency extraction")
		}
	}
}

// executeDepExtractionJob does one extraction and returns the snapshot it
// fed. It is idempotent per (snapshot, digest): a re-run after a crash
// finds its own earlier run and stops.
func (s *Server) executeDepExtractionJob(ctx context.Context, job *store.DepExtractionJob) (*uuid.UUID, error) {
	repo, err := s.queries.GetRepositoryByID(ctx, job.RepoID)
	if err != nil {
		return nil, fmt.Errorf("load repository: %w", err)
	}
	if repo == nil {
		return nil, fmt.Errorf("%w: repository %s no longer exists", errDepExtractionSkipped, job.RepoID)
	}
	provider, ok := s.forges[repo.Provider]
	if !ok {
		return nil, fmt.Errorf("no forge provider configured for %q", repo.Provider)
	}
	target, err := s.resolveSecretScanTarget(ctx, provider, repo)
	if err != nil {
		if errors.Is(err, errSecretScanSkipped) {
			return nil, fmt.Errorf("%w: %w", errDepExtractionSkipped, err)
		}
		return nil, err
	}
	var token string
	if auth, ok := provider.(forge.CloneAuthProvider); ok {
		token, err = auth.CloneToken(ctx, target.owner, target.name)
		if err != nil {
			s.log.Warn().Err(err).Str("repo", repo.Slug).Msg("clone token minting failed, attempting tokenless checkout")
			token = ""
		}
	}

	refType := refTypeFromName(job.RefName)
	ref, err := s.queries.GetRefByRepoAndName(ctx, repo.ID, job.RefName, refType)
	if err != nil {
		return nil, fmt.Errorf("load ref %s: %w", job.RefName, err)
	}
	commit := strings.TrimSpace(job.CommitSHA)
	if commit == "" && ref != nil && ref.LatestCommitSHA != nil {
		commit = strings.TrimSpace(*ref.LatestCommitSHA)
	}
	if commit == gitZeroSHA {
		return nil, fmt.Errorf("%w: ref %s was deleted", errDepExtractionSkipped, job.RefName)
	}

	// A pull request ref is not a branch the clone can ask for; its head is
	// fetched by commit from a clone of the default branch (reachable from
	// the forge's advertised PR refs).
	cloneRef := job.RefName
	if refType == store.RefTypePullRequest {
		cloneRef = normalizeStoredRefName(strings.TrimSpace(repo.DefaultBranch))
		if commit == "" {
			return nil, fmt.Errorf("%w: pull request %s has no head commit", errDepExtractionSkipped, job.RefName)
		}
	}
	// `dependencies.exclude` (ADR-045 §8): fixtures and examples are neither
	// checked out nor inventoried.
	var exclude []string
	if loaded, _, err := s.loadBoundRepoConfig(ctx, repo); err == nil && loaded != nil && loaded.Dependencies != nil {
		exclude = loaded.Dependencies.Exclude
	}
	// Excluded manifests are neither checked out nor inventoried, but they
	// are listed on the producer run so the exclusion is visible (ADR-034).
	var excluded []store.SkippedFile
	selectPath := func(p string) bool {
		if !depinventory.IsExtractionPath(p) {
			return false
		}
		if depinventory.IsExcludedPath(p, exclude) {
			excluded = append(excluded, store.SkippedFile{Path: p, Reason: depinventory.SkipReasonExcluded})
			return false
		}
		return true
	}
	checkout, err := secretscan.CheckoutManifests(ctx, s.cfg.DepInventory.TempDir, target.cloneURL, cloneRef, commit, token, selectPath)
	if err != nil {
		return nil, err
	}
	defer checkout.Close()
	commit = checkout.Commit

	if ref == nil {
		ref, err = s.queries.UpsertRef(ctx, repo.ID, job.RefName, refType, store.UpsertRefOptions{LatestCommitSHA: &commit})
		if err != nil {
			return nil, fmt.Errorf("create ref %s: %w", job.RefName, err)
		}
	}
	snapshot, err := s.resolveDepExtractionSnapshot(ctx, job, ref, commit)
	if err != nil {
		return nil, err
	}

	existing, err := s.queries.GetDepExtractionRunBySnapshot(ctx, snapshot.ID)
	if err != nil {
		return nil, fmt.Errorf("load extraction run: %w", err)
	}
	if existing != nil && existing.InputDigest == checkout.Digest && existing.ExtractorVersion == depinventory.Version {
		return &snapshot.ID, nil
	}
	// CI ran the same extractor on this commit (ADR-045 §4.2): its document
	// is the inventory, with the resolve-mode additions the server cannot
	// make. The server-side run is skipped, and says so.
	if ciInventory, err := s.snapshotHasCIInventory(ctx, snapshot.ID); err != nil {
		return nil, err
	} else if ciInventory {
		detail := "skipped: the repository ran hibou-deps in CI for this commit"
		s.recordDepExtractionProducerRun(ctx, snapshot.ID, nil, nil, &detail, excluded)
		if snapshot.Status == store.SnapshotStatusPending {
			s.completeScanOnlySnapshot(ctx, repo.ID, snapshot)
		}
		return &snapshot.ID, nil
	}

	if len(checkout.Paths) == 0 {
		detail := "no lockfile or manifest recognised at this commit"
		s.recordDepExtractionProducerRun(ctx, snapshot.ID, nil, nil, &detail, excluded)
		s.completeScanOnlySnapshot(ctx, repo.ID, snapshot)
		return &snapshot.ID, nil
	}

	// Digest reuse: same inputs, same extractor, same rows. The earlier
	// snapshot's extraction rows are copied; nothing is re-read or stored.
	if !checkout.TreeTruncated {
		prior, err := s.queries.GetLatestDepExtractionRunByDigest(ctx, repo.ID, checkout.Digest, depinventory.Version)
		if err != nil {
			return nil, fmt.Errorf("look up extraction by digest: %w", err)
		}
		if prior != nil && prior.SnapshotID != snapshot.ID {
			if err := s.reuseExtractedInventory(ctx, repo, snapshot, commit, checkout.Digest, prior, excluded); err == nil {
				if snapshot.Status == store.SnapshotStatusPending {
					s.completeScanOnlySnapshot(ctx, repo.ID, snapshot)
				}
				return &snapshot.ID, nil
			} else {
				s.log.Warn().Err(err).Str("snapshot_id", snapshot.ID.String()).Msg("digest reuse failed; extracting instead")
			}
		}
	}

	inv, err := depinventory.Extract(ctx, checkout.Dir, depinventory.Options{
		Exclude: exclude,
		Warn: func(message string) {
			s.log.Warn().Str("repo", repo.Slug).Str("commit", shortSHA(commit)).Msg("dependency extraction: " + message)
		},
	})
	if err != nil {
		detail := truncateSecretScanError(err)
		s.recordDepExtractionProducerRun(ctx, snapshot.ID, nil, err, &detail, excluded)
		return &snapshot.ID, err
	}
	document, err := depinventory.ToCycloneDX(inv, repo.Slug, version.Version, time.Now())
	if err != nil {
		return &snapshot.ID, fmt.Errorf("render inventory: %w", err)
	}
	if err := s.ingestExtractedInventory(ctx, snapshot, document); err != nil {
		return &snapshot.ID, err
	}
	sum := sha256.Sum256(document)
	run, err := s.queries.InsertDepExtractionRun(ctx, store.InsertDepExtractionRunParams{
		RepoID:           repo.ID,
		SnapshotID:       snapshot.ID,
		CommitSHA:        commit,
		InputDigest:      checkout.Digest,
		ExtractorVersion: depinventory.Version,
		SHA256:           hex.EncodeToString(sum[:]),
		SizeBytes:        int64(len(document)),
		ComponentCount:   len(inv.Components),
		Modules:          extractionModules(inv),
		Updaters:         extractionUpdaters(inv),
	})
	if err != nil {
		return &snapshot.ID, fmt.Errorf("record extraction run: %w", err)
	}
	// The run is what the source is known by (its set was recorded by the
	// ingestion); a snapshot with the same input digest shares it.
	if run != nil {
		if err := s.queries.AttachInventorySource(ctx, snapshot.ID, "sbom:"+depInventoryArtifactFilename, nil, nil, &run.ID); err != nil {
			return &snapshot.ID, fmt.Errorf("link extraction run to its inventory source: %w", err)
		}
	}
	s.recordDepExtractionProducerRun(ctx, snapshot.ID, inv, nil, nil, excluded)
	if snapshot.Status == store.SnapshotStatusPending {
		s.completeScanOnlySnapshot(ctx, repo.ID, snapshot)
	}
	s.log.Info().Str("repo", repo.Slug).Str("ref", job.RefName).Str("commit", shortSHA(commit)).Int("components", len(inv.Components)).Int("modules", len(inv.Modules)).Dur("duration", inv.Duration).Msg("dependency inventory extracted")
	return &snapshot.ID, nil
}

// snapshotHasCIInventory reports whether an inventory from the CI run of
// the built-in extractor (uploaded under its tool name) exists for the
// snapshot.
func (s *Server) snapshotHasCIInventory(ctx context.Context, snapshotID uuid.UUID) (bool, error) {
	artifacts, err := s.queries.ListSnapshotArtifactsBySnapshot(ctx, snapshotID)
	if err != nil {
		return false, fmt.Errorf("list snapshot artifacts: %w", err)
	}
	for _, artifact := range artifacts {
		if artifact.Kind != "sbom" || artifact.ToolName == nil || *artifact.ToolName != depinventory.ToolName {
			continue
		}
		// A deliverable recorded with hibou release scan is not a CI run.
		if artifact.Origin != store.ArtifactOriginManual {
			return true, nil
		}
	}
	return false, nil
}

// ---- Extractor upgrades (ADR-045 §4.3.1) ----

// runDepExtractionUpgradeLoop re-extracts, after an upgrade, the inputs of
// the default branch's latest snapshots and of pinned releases: once at
// start-up and then daily, a bounded page per pass so a large instance
// catches up over several passes. Same digest, newer extractor: the
// document is re-read and ingested additively; nothing is removed and no
// finding is marked resolved by it.
func (s *Server) runDepExtractionUpgradeLoop(ctx context.Context) {
	s.runDepExtractionUpgradePass(ctx)
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runDepExtractionUpgradePass(ctx)
		}
	}
}

const depExtractionUpgradePageSize = 100

func (s *Server) runDepExtractionUpgradePass(ctx context.Context) {
	if s.db == nil || !s.cfg.DepInventory.Enabled {
		return
	}
	_, err := store.WithLeaderLock(ctx, s.db, store.LockDepExtractionUpgrade, func(ctx context.Context) error {
		outdated, err := s.queries.ListOutdatedDepExtractionRuns(ctx, depinventory.Version, depExtractionUpgradePageSize)
		if err != nil {
			return err
		}
		queued := 0
		perRepo := make(map[uuid.UUID]int)
		for _, run := range outdated {
			// One per repository per pass: an instance with a thousand
			// repositories spreads the work instead of queuing it all.
			if perRepo[run.RepoID] >= 1 {
				continue
			}
			snapshotID := run.SnapshotID
			if _, err := s.queries.EnqueueDepExtractionJob(ctx, store.EnqueueDepExtractionJobParams{
				RepoID:     run.RepoID,
				RefName:    run.RefName,
				CommitSHA:  run.CommitSHA,
				Reason:     store.DepExtractionReasonUpgrade,
				SnapshotID: &snapshotID,
			}); err != nil {
				s.log.Warn().Err(err).Str("snapshot_id", run.SnapshotID.String()).Msg("queue extractor-upgrade extraction")
				continue
			}
			perRepo[run.RepoID]++
			queued++
		}
		if queued > 0 {
			s.log.Info().Int("queued", queued).Int("outdated", len(outdated)).Str("extractor", depinventory.Version).Msg("extractor upgrade: re-extraction queued")
		}
		return nil
	})
	if err != nil {
		s.log.Warn().Err(err).Msg("extractor upgrade pass")
	}
}

// resolveDepExtractionSnapshot finds or creates the snapshot of (ref,
// commit). A placeholder is pending until the repository's own rule
// completes it (completeScanOnlySnapshot), the same as secret scans.
func (s *Server) resolveDepExtractionSnapshot(ctx context.Context, job *store.DepExtractionJob, ref *store.Ref, commit string) (*store.Snapshot, error) {
	if job.SnapshotID != nil {
		snapshot, err := s.queries.GetSnapshotByID(ctx, *job.SnapshotID)
		if err != nil {
			return nil, fmt.Errorf("load job snapshot: %w", err)
		}
		if snapshot != nil && strings.EqualFold(snapshot.CommitSHA, commit) {
			return snapshot, nil
		}
	}
	snapshot, err := s.queries.GetSnapshotByRefCommit(ctx, ref.ID, commit)
	if err != nil {
		return nil, fmt.Errorf("load snapshot at %s: %w", shortSHA(commit), err)
	}
	if snapshot != nil {
		return snapshot, nil
	}
	snapshot, err = s.queries.CreatePlaceholderSnapshot(ctx, ref.ID, commit)
	if err != nil {
		return nil, fmt.Errorf("create snapshot at %s: %w", shortSHA(commit), err)
	}
	if snapshot == nil {
		snapshot, err = s.queries.GetSnapshotByRefCommit(ctx, ref.ID, commit)
		if err != nil || snapshot == nil {
			return nil, fmt.Errorf("load raced snapshot at %s: %w", shortSHA(commit), err)
		}
	}
	return snapshot, nil
}

// reuseExtractedInventory copies an earlier run's rows under this snapshot
// and records a run that points back to it.
func (s *Server) reuseExtractedInventory(ctx context.Context, repo *store.Repository, snapshot *store.Snapshot, commit, digest string, prior *store.DepExtractionRun, skipped []store.SkippedFile) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	queries := s.queries.WithTx(tx)
	priorID := prior.ID
	run, err := queries.InsertDepExtractionRun(ctx, store.InsertDepExtractionRunParams{
		RepoID:           repo.ID,
		SnapshotID:       snapshot.ID,
		CommitSHA:        commit,
		InputDigest:      digest,
		ExtractorVersion: depinventory.Version,
		SHA256:           prior.SHA256,
		SizeBytes:        prior.SizeBytes,
		ComponentCount:   prior.ComponentCount,
		Modules:          prior.Modules,
		Updaters:         prior.Updaters,
		ReusedFrom:       &priorID,
	})
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("record reused extraction run: %w", err)
	}
	// One source row pointing at the prior run's set: no component rows
	// are written for an unchanged inventory (ADR-045, Database section).
	var runID *uuid.UUID
	if run != nil {
		runID = &run.ID
	}
	copied, err := queries.ReuseInventorySource(ctx, prior.SnapshotID, snapshot.ID, "sbom:"+depInventoryArtifactFilename, runID)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("reuse extracted inventory: %w", err)
	}
	if err := tx.Commit(); err != nil {
		_ = tx.Rollback()
		return err
	}
	s.recordDepExtractionProducerRunFromModules(ctx, snapshot.ID, prior.Modules, nil, skipped)
	s.afterArtifactIngest(ctx, snapshot)
	if copied > 0 {
		s.enqueueAdvisoryScan(snapshot.ID, "system")
	}
	s.reconcileReleasesForSnapshot(ctx, snapshot.ID)
	s.refreshScanCoverageForSnapshot(ctx, snapshot.ID)
	s.log.Info().Str("repo", repo.Slug).Str("commit", shortSHA(commit)).Str("reused_from", prior.SnapshotID.String()).Int("components", copied).Msg("dependency inventory reused by digest")
	return nil
}

func extractionModules(inv *depinventory.Inventory) []store.DepExtractionModule {
	modules := make([]store.DepExtractionModule, 0, len(inv.Modules))
	for _, module := range inv.Modules {
		entry := store.DepExtractionModule{
			Path:       module.Path,
			Files:      module.Files,
			Complete:   module.Complete,
			Reason:     module.Reason,
			Ecosystems: module.Ecosystems,
		}
		for _, cfg := range inv.InstallConfig[module.Path] {
			entry.InstallConfig = append(entry.InstallConfig, store.DepInstallConfig{
				Tool:          cfg.Tool,
				Path:          cfg.Path,
				Setting:       cfg.Setting,
				Present:       cfg.Present,
				WindowSeconds: int64(cfg.Window / time.Second),
				Value:         cfg.Value,
				Note:          cfg.Note,
			})
		}
		modules = append(modules, entry)
	}
	return modules
}

func extractionUpdaters(inv *depinventory.Inventory) []store.DepUpdaterConfig {
	updaters := make([]store.DepUpdaterConfig, 0, len(inv.Updaters))
	for _, cfg := range inv.Updaters {
		updaters = append(updaters, store.DepUpdaterConfig{
			Tool:          cfg.Tool,
			Path:          cfg.Path,
			Present:       cfg.Present,
			WindowSeconds: int64(cfg.Window / time.Second),
			Value:         cfg.Value,
		})
	}
	return updaters
}

// recordDepExtractionProducerRun stores the run (ADR-034 §2): complete when
// every module has a recorded source, partial when one is manifest-only or
// a file could not be read, failed on error. Scope paths are the modules.
//
// skipped lists the files deliberately left out (dependencies.exclude):
// they are recorded with their reason and do not make the run partial.
func (s *Server) recordDepExtractionProducerRun(ctx context.Context, snapshotID uuid.UUID, inv *depinventory.Inventory, runErr error, detail *string, skipped []store.SkippedFile) {
	var modules []store.DepExtractionModule
	if inv != nil {
		modules = extractionModules(inv)
		if len(inv.FileErrors) > 0 && runErr == nil {
			text := fmt.Sprintf("%d file(s) could not be read: %s", len(inv.FileErrors), strings.Join(inv.FileErrors, "; "))
			text = truncateSecretScanError(errors.New(text))
			detail = &text
		}
	}
	if runErr != nil {
		run := store.ProducerRunInput{Producer: depInventoryProducer, Scope: store.ProducerScopeFull, ScopeDeclared: true, Outcome: store.ProducerOutcomeFailed, Detail: detail, SkippedFiles: skipped}
		v := depinventory.Version
		run.Version = &v
		if _, err := s.queries.UpsertSnapshotProducerRun(ctx, snapshotID, run); err != nil {
			s.log.Warn().Err(err).Str("snapshot", snapshotID.String()).Msg("record dependency extraction producer run")
		}
		return
	}
	s.recordDepExtractionProducerRunFromModules(ctx, snapshotID, modules, detail, skipped)
}

func (s *Server) recordDepExtractionProducerRunFromModules(ctx context.Context, snapshotID uuid.UUID, modules []store.DepExtractionModule, detail *string, skipped []store.SkippedFile) {
	v := depinventory.Version
	run := store.ProducerRunInput{
		Producer:      depInventoryProducer,
		Version:       &v,
		Scope:         store.ProducerScopeFull,
		ScopeDeclared: true,
		Outcome:       store.ProducerOutcomeCompleted,
		SkippedFiles:  skipped,
		Detail:        detail,
	}
	var reasons []string
	for _, module := range modules {
		run.ScopePaths = append(run.ScopePaths, module.Path)
		if !module.Complete {
			reasons = append(reasons, module.Path+": "+module.Reason)
		}
	}
	if len(reasons) > 0 || detail != nil {
		run.Outcome = store.ProducerOutcomePartial
		if len(reasons) > 0 {
			text := strings.Join(reasons, "; ")
			if detail != nil {
				text = *detail + "; " + text
			}
			text = truncateSecretScanError(errors.New(text))
			run.Detail = &text
		}
	}
	if _, err := s.queries.UpsertSnapshotProducerRun(ctx, snapshotID, run); err != nil {
		s.log.Warn().Err(err).Str("snapshot", snapshotID.String()).Msg("record dependency extraction producer run")
	}
}

// maybeEnqueueDepExtraction records a job for a push to an eager ref: the
// default branch, or a tag the repository's release pattern accepts
// (ADR-045 §4.1.1). Other branches stay lazy. The webhook must succeed
// regardless; a failed enqueue is logged and the next push covers it.
func (s *Server) maybeEnqueueDepExtraction(ctx context.Context, repo *store.Repository, refType store.RefType, refName string, event forge.PushEvent) {
	if !s.cfg.DepInventory.Enabled || !s.cfg.DepInventory.OnPush || repo == nil {
		return
	}
	after := strings.TrimSpace(event.After)
	if after == "" || after == gitZeroSHA {
		return
	}
	reason := ""
	switch refType {
	case store.RefTypeBranch:
		if branchIsEager(refName, repo.DefaultBranch, s.eagerBranchPatterns(ctx, repo)) {
			reason = store.DepExtractionReasonPush
		}
	case store.RefTypeTag:
		pattern, ok := s.releaseTagPatternForRepo(ctx, repo.ID)
		if ok && pattern != nil && pattern.MatchString(refName) {
			reason = store.DepExtractionReasonRelease
		}
	}
	if reason == "" {
		return
	}
	if _, err := s.queries.EnqueueDepExtractionJob(ctx, store.EnqueueDepExtractionJobParams{
		RepoID:    repo.ID,
		RefName:   refName,
		CommitSHA: after,
		Reason:    reason,
	}); err != nil {
		s.log.Error().Err(err).Str("repo_id", repo.ID.String()).Str("ref", refName).Msg("enqueue dependency extraction job")
	}
}

// enqueueEnrollmentDepExtraction inventories the default branch once at
// enrolment, so a repository has dependencies before its first push.
func (s *Server) enqueueEnrollmentDepExtraction(ctx context.Context, repo *store.Repository) {
	if !s.cfg.DepInventory.Enabled || repo == nil {
		return
	}
	refName := normalizeStoredRefName(strings.TrimSpace(repo.DefaultBranch))
	if refName == "" {
		return
	}
	if _, err := s.queries.EnqueueDepExtractionJob(ctx, store.EnqueueDepExtractionJobParams{
		RepoID:  repo.ID,
		RefName: refName,
		Reason:  store.DepExtractionReasonEnrollment,
	}); err != nil {
		s.log.Error().Err(err).Str("repo_id", repo.ID.String()).Msg("enqueue enrolment dependency extraction")
	}
}

// handleTriggerDepExtraction enqueues an extraction of a branch or tag
// (default branch unless ?ref= names another). Admins only: it clones.
func (s *Server) handleTriggerDepExtraction(w http.ResponseWriter, r *http.Request) {
	_, repo, _, ok := s.loadAuthorizedRepoWithUser(w, r, true)
	if !ok {
		return
	}
	if !s.cfg.DepInventory.Enabled {
		api.JSONError(w, http.StatusConflict, "dependency inventory extraction is disabled on this instance")
		return
	}
	refName := normalizeStoredRefName(strings.TrimSpace(r.URL.Query().Get("ref")))
	if refName == "" {
		refName = normalizeStoredRefName(strings.TrimSpace(repo.DefaultBranch))
	}
	if refName == "" {
		api.JSONError(w, http.StatusBadRequest, "no ref to extract: pass ?ref= or set a default branch")
		return
	}
	job, err := s.queries.EnqueueDepExtractionJob(r.Context(), store.EnqueueDepExtractionJobParams{
		RepoID:  repo.ID,
		RefName: refName,
		Reason:  store.DepExtractionReasonManual,
	})
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to enqueue dependency extraction")
		return
	}
	api.JSON(w, http.StatusAccepted, job)
}

// releaseDepExtractionClaims hands this worker's claims back during
// shutdown, like the secret-scan claims.
func (s *Server) releaseDepExtractionClaims(ctx context.Context) error {
	if s.queries == nil || s.depExtractionSlots == nil || strings.TrimSpace(s.artifactWorkerID) == "" {
		return nil
	}
	count, err := s.queries.ReleaseDepExtractionJobClaims(ctx, s.artifactWorkerID)
	if err != nil {
		return fmt.Errorf("release dependency extraction claims: %w", err)
	}
	if count > 0 {
		s.log.Info().Int64("released_claims", count).Str("worker_id", s.artifactWorkerID).Msg("released dependency extraction claims during shutdown")
	}
	return nil
}

// ---- Eager branches, lazy reads, releases (ADR-045 §4.1.1, §4.3) ----

// eagerPatternTTL bounds how often a repository's .hibou.yaml is read for
// its eager branch patterns on push. The loader has no cache of its own,
// and every push to any branch would otherwise be a forge call.
const eagerPatternTTL = 10 * time.Minute

type eagerPatterns struct {
	patterns []string
	expires  time.Time
}

// eagerBranchPatterns returns `dependencies.branches` of the repository's
// config, cached per repository. A config that cannot be read yields no
// patterns: the default branch stays eager regardless.
func (s *Server) eagerBranchPatterns(ctx context.Context, repo *store.Repository) []string {
	if cached, ok := s.eagerPatterns.Load(repo.ID); ok {
		if entry, ok := cached.(eagerPatterns); ok && time.Now().Before(entry.expires) {
			return entry.patterns
		}
	}
	var patterns []string
	if cfg, _, err := s.loadBoundRepoConfig(ctx, repo); err == nil && cfg != nil && cfg.Dependencies != nil {
		patterns = append(patterns, cfg.Dependencies.Branches...)
	}
	s.eagerPatterns.Store(repo.ID, eagerPatterns{patterns: patterns, expires: time.Now().Add(eagerPatternTTL)})
	return patterns
}

// branchIsEager reports whether a branch is extracted on every push: the
// default branch, or one matching a configured pattern (same glob rules as
// quality gate branches).
func branchIsEager(refName, defaultBranch string, patterns []string) bool {
	if refName == normalizeStoredRefName(strings.TrimSpace(defaultBranch)) {
		return true
	}
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if pattern == refName {
			return true
		}
		if matched, err := path.Match(pattern, refName); err == nil && matched {
			return true
		}
	}
	return false
}

// enqueueLazyDepExtraction records a job for a ref somebody opened that has
// no inventory yet (ADR-045 §4.1.1). Coalesced per (repo, ref), so a page
// reloading every few seconds costs one job.
func (s *Server) enqueueLazyDepExtraction(ctx context.Context, repo *store.Repository, refName string) {
	if !s.cfg.DepInventory.Enabled || repo == nil || strings.TrimSpace(refName) == "" {
		return
	}
	if _, err := s.queries.EnqueueDepExtractionJob(ctx, store.EnqueueDepExtractionJobParams{
		RepoID:  repo.ID,
		RefName: refName,
		Reason:  store.DepExtractionReasonLazy,
	}); err != nil {
		s.log.Warn().Err(err).Str("repo_id", repo.ID.String()).Str("ref", refName).Msg("enqueue lazy dependency extraction")
	}
}

type depExtractionStatusResponse struct {
	Enabled bool                    `json:"enabled"`
	Ref     string                  `json:"ref"`
	Job     *store.DepExtractionJob `json:"job,omitempty"`
	Run     *store.DepExtractionRun `json:"run,omitempty"`
	// CurrentExtractorVersion is what this server extracts with; a run with
	// an older version is re-extracted by the upgrade pass (ADR-045 §4.3.1).
	CurrentExtractorVersion string `json:"current_extractor_version"`
}

// handleGetDepExtractionStatus answers "is an inventory on its way for
// this ref?": the latest job and, when the ref has a snapshot, its run.
func (s *Server) handleGetDepExtractionStatus(w http.ResponseWriter, r *http.Request) {
	_, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}
	refName := resolveRequestedRefName(r, repo)
	if refName == "" {
		api.JSONError(w, http.StatusBadRequest, "ref is required")
		return
	}
	response := depExtractionStatusResponse{Enabled: s.cfg.DepInventory.Enabled, Ref: refName, CurrentExtractorVersion: depinventory.Version}
	job, err := s.queries.GetLatestDepExtractionJobForRef(r.Context(), repo.ID, refName)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load extraction status")
		return
	}
	response.Job = job
	if job != nil && job.SnapshotID != nil {
		if run, err := s.queries.GetDepExtractionRunBySnapshot(r.Context(), *job.SnapshotID); err == nil {
			response.Run = run
		}
	}
	api.JSON(w, http.StatusOK, response)
}

// handleExtractReleaseDependencies enqueues an extraction of one release's
// tag, onto the release's pinned snapshot (ADR-045 §4.3). Release managers
// and admins.
func (s *Server) handleExtractReleaseDependencies(w http.ResponseWriter, r *http.Request) {
	_, repo, _, release, ok := s.loadReleaseForManager(w, r)
	if !ok {
		return
	}
	if !s.cfg.DepInventory.Enabled {
		api.JSONError(w, http.StatusConflict, "dependency inventory extraction is disabled on this instance")
		return
	}
	job, err := s.enqueueReleaseExtraction(r.Context(), repo, release)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to enqueue dependency extraction")
		return
	}
	if job == nil {
		api.JSONError(w, http.StatusConflict, "release has no tag ref to extract")
		return
	}
	api.JSON(w, http.StatusAccepted, job)
}

// handleExtractAllReleases queues every release of the repository that has
// no inventory yet, newest first (ADR-045 §4.3 "Backfill all releases").
func (s *Server) handleExtractAllReleases(w http.ResponseWriter, r *http.Request) {
	org, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return
	}
	if !s.requireReleaseManager(r, w, org.ID) {
		return
	}
	if !s.cfg.DepInventory.Enabled {
		api.JSONError(w, http.StatusConflict, "dependency inventory extraction is disabled on this instance")
		return
	}
	queued, skipped := 0, 0
	const pageSize = 200
	for offset := 0; ; offset += pageSize {
		releases, total, err := s.queries.ListReleasesByRepo(r.Context(), repo.ID, pageSize, offset)
		if err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to list releases")
			return
		}
		for i := range releases {
			release := releases[i]
			if release.SnapshotID != nil {
				run, err := s.queries.GetDepExtractionRunBySnapshot(r.Context(), *release.SnapshotID)
				if err == nil && run != nil {
					skipped++
					continue
				}
			}
			job, err := s.enqueueReleaseExtraction(r.Context(), repo, &release)
			if err != nil || job == nil {
				skipped++
				continue
			}
			queued++
		}
		if offset+len(releases) >= total || len(releases) == 0 {
			break
		}
	}
	api.JSON(w, http.StatusAccepted, map[string]int{"queued": queued, "skipped": skipped})
}

// enqueueReleaseExtraction records a job for a release's tag, bound to its
// pinned snapshot and commit so the inventory lands on the build clients
// run, not on wherever the tag points today.
func (s *Server) enqueueReleaseExtraction(ctx context.Context, repo *store.Repository, release *store.Release) (*store.DepExtractionJob, error) {
	ref, err := s.queries.GetRefByID(ctx, release.RefID)
	if err != nil {
		return nil, err
	}
	if ref == nil {
		return nil, nil
	}
	params := store.EnqueueDepExtractionJobParams{
		RepoID:     repo.ID,
		RefName:    ref.Name,
		Reason:     store.DepExtractionReasonRelease,
		SnapshotID: release.SnapshotID,
	}
	if release.SnapshotID != nil {
		if snapshot, err := s.queries.GetSnapshotByID(ctx, *release.SnapshotID); err == nil && snapshot != nil {
			params.CommitSHA = snapshot.CommitSHA
		}
	}
	return s.queries.EnqueueDepExtractionJob(ctx, params)
}

// ingestExtractedInventory ingests an extraction's document directly, with
// no stored object: the components, labels and graph are the inventory.
// A pending snapshot gets it too; completion never removes components.
func (s *Server) ingestExtractedInventory(ctx context.Context, snapshot *store.Snapshot, document []byte) error {
	format, tool := "cyclonedx-json", depinventory.ToolName
	artifact := store.SnapshotArtifact{SnapshotID: snapshot.ID, Kind: "sbom", Format: &format, ToolName: &tool, Filename: depInventoryArtifactFilename, Origin: store.ArtifactOriginServer}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	queries := s.queries.WithTx(tx)
	ingested, err := s.ingestSBOMArtifact(ctx, queries, snapshot, loadedSnapshotArtifact{artifact: artifact, content: document})
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("ingest inventory: %w", err)
	}
	if err := tx.Commit(); err != nil {
		_ = tx.Rollback()
		return err
	}
	s.afterArtifactIngest(ctx, snapshot)
	if ingested > 0 {
		s.enqueueAdvisoryScan(snapshot.ID, "system")
	}
	s.reconcileReleasesForSnapshot(ctx, snapshot.ID)
	s.refreshScanCoverageForSnapshot(ctx, snapshot.ID)
	return nil
}

// ingestInventoryNow ingests the document into a snapshot that is past
// pending (a release's completed snapshot): the artifact processing loop
// only claims snapshots whose processing has not finished, so this runs
// the same ingestion inline and the same follow-ups.
func (s *Server) ingestInventoryNow(ctx context.Context, snapshot *store.Snapshot, artifactID *uuid.UUID, params store.CreateSnapshotArtifactParams, document []byte) error {
	if artifactID == nil {
		return nil
	}
	artifact := store.SnapshotArtifact{
		ID:         *artifactID,
		SnapshotID: snapshot.ID,
		Kind:       params.Kind,
		Format:     params.Format,
		ToolName:   params.ToolName,
		ObjectKey:  params.ObjectKey,
		SHA256:     params.SHA256,
		SizeBytes:  params.SizeBytes,
		Filename:   params.Filename,
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	queries := s.queries.WithTx(tx)
	ingested, err := s.ingestSBOMArtifact(ctx, queries, snapshot, loadedSnapshotArtifact{artifact: artifact, content: document})
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("ingest inventory: %w", err)
	}
	if err := tx.Commit(); err != nil {
		_ = tx.Rollback()
		return err
	}
	s.afterArtifactIngest(ctx, snapshot)
	if ingested > 0 {
		s.enqueueAdvisoryScan(snapshot.ID, "system")
	}
	s.reconcileReleasesForSnapshot(ctx, snapshot.ID)
	s.refreshScanCoverageForSnapshot(ctx, snapshot.ID)
	return nil
}

// maybeEnqueuePRDepExtraction records a job for a pull request head when
// its diff touches a lockfile or manifest (ADR-045 §4.1.2). When the
// comparison is unavailable the extraction runs anyway: a sparse checkout
// is cheaper than a wrong "nothing changed".
func (s *Server) maybeEnqueuePRDepExtraction(ctx context.Context, repo *store.Repository, ref *store.Ref, headSHA string) {
	if !s.cfg.DepInventory.Enabled || !s.cfg.DepInventory.OnPush || repo == nil || ref == nil {
		return
	}
	touchesManifest := true
	if ref.MergeTargetRefID != nil {
		if target, err := s.queries.GetRefByID(ctx, *ref.MergeTargetRefID); err == nil && target != nil && target.LatestCommitSHA != nil && *target.LatestCommitSHA != "" {
			if index, err := s.presenceComparison(ctx, repo, *target.LatestCommitSHA, headSHA, true); err == nil && !index.unsupported && !index.truncated {
				touchesManifest = false
				for path := range index.files {
					if depinventory.IsExtractionPath(path) {
						touchesManifest = true
						break
					}
				}
			}
		}
	}
	if !touchesManifest {
		return
	}
	if _, err := s.queries.EnqueueDepExtractionJob(ctx, store.EnqueueDepExtractionJobParams{
		RepoID:    repo.ID,
		RefName:   ref.Name,
		CommitSHA: headSHA,
		Reason:    store.DepExtractionReasonPullRequest,
	}); err != nil {
		s.log.Error().Err(err).Str("repo_id", repo.ID.String()).Str("ref", ref.Name).Msg("enqueue pull request dependency extraction")
	}
}
