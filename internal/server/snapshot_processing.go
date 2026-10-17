package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/events"
	"github.com/hibouhq/hibou/internal/findings"
	"github.com/hibouhq/hibou/internal/sarif"
	"github.com/hibouhq/hibou/internal/sbom"
	"github.com/hibouhq/hibou/internal/store"
)

const (
	artifactProcessingInterval    = 5 * time.Second
	artifactProcessingMaxAttempts = int32(3)
	maxArtifactProcessingErrorLen = 500
)

type artifactProcessingRun struct {
	ctx    context.Context
	cancel context.CancelCauseFunc
	done   chan struct{}
}

var processClaimedSnapshotHook = func(ctx context.Context, srv *Server, snapshot *store.Snapshot) (*artifactProcessingResult, error) {
	return srv.processClaimedArtifactSnapshotBase(ctx, snapshot)
}

type loadedSnapshotArtifact struct {
	artifact store.SnapshotArtifact
	content  []byte
}

type artifactProcessingResult struct {
	warning            string
	componentsIngested int
}

type artifactProcessingFailure struct {
	artifactID uuid.UUID
	kind       string
	err        error
}

func (s *Server) runArtifactProcessingLoop(ctx context.Context) {
	s.runArtifactProcessingPass(ctx)

	ticker := time.NewTicker(artifactProcessingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runArtifactProcessingPass(ctx)
		}
	}
}

func (s *Server) runArtifactProcessingPass(ctx context.Context) {
	// Close out what the claimer can no longer reach, or it shows as
	// in-progress for ever.
	if finalized, err := s.queries.FinalizeUnreachableArtifactProcessing(ctx, artifactProcessingMaxAttempts); err != nil {
		s.log.Warn().Err(err).Msg("failed to finalize unreachable artifact processing")
	} else if finalized > 0 {
		s.log.Info().Int64("snapshots", finalized).
			Msg("recorded snapshots as failed after artifact processing stopped without finishing")
	}

	for {
		processed, err := s.processNextArtifactSnapshot(ctx)
		if err != nil {
			s.log.Error().Err(err).Msg("artifact processing pass failed")
			return
		}
		if !processed {
			return
		}
	}
}

func (s *Server) processNextArtifactSnapshot(ctx context.Context) (bool, error) {
	if s.objStore == nil {
		// Defensive only: server startup now fails if the configured artifact store cannot initialize.
		return false, nil
	}
	if s.isDraining() {
		return false, nil
	}
	if strings.TrimSpace(s.artifactWorkerID) == "" {
		s.artifactWorkerID = newArtifactWorkerID()
	}

	snapshot, err := s.queries.ClaimNextArtifactProcessingSnapshot(ctx, s.artifactWorkerID, time.Now().Add(s.artifactProcessingLeaseDuration()), artifactProcessingMaxAttempts)
	if err != nil {
		return false, err
	}
	if snapshot == nil {
		return false, nil
	}
	if !s.tryStartArtifactProcessing(snapshot.ID) {
		return false, nil
	}
	defer s.finishArtifactProcessing(snapshot.ID)
	run := s.startArtifactProcessingRun(ctx, snapshot.ID)
	defer s.stopArtifactProcessingRun(run)

	result, err := s.processClaimedArtifactSnapshot(run.ctx, snapshot)
	if err != nil {
		if s.shouldAbandonArtifactProcessing(run, err, snapshot.ID) {
			return true, nil
		}
		markFinished := snapshot.ArtifactProcessingAttempts >= int(artifactProcessingMaxAttempts)
		message := truncateArtifactProcessingError(err)
		if _, failErr := s.queries.FailArtifactProcessingSnapshot(ctx, snapshot.ID, s.artifactWorkerID, markFinished, message); failErr != nil {
			return true, errors.Join(
				fmt.Errorf("process snapshot %s: %w", snapshot.ID, err),
				fmt.Errorf("finalize failure: %w", failErr),
			)
		}
		s.log.Error().Err(err).Str("snapshot_id", snapshot.ID.String()).Bool("mark_finished", markFinished).Msg("artifact processing failed")
		return true, nil
	}

	if result == nil {
		result = &artifactProcessingResult{}
	}
	if err := s.completeArtifactProcessingSnapshot(ctx, run, snapshot.ID, result.warning, result.componentsIngested); err != nil {
		if run.ctx.Err() != nil || errors.Is(context.Cause(run.ctx), store.ErrArtifactProcessingClaimLost) {
			return true, nil
		}
		return true, err
	}
	return true, nil
}

func (s *Server) shouldAbandonArtifactProcessing(run *artifactProcessingRun, err error, snapshotID uuid.UUID) bool {
	if errors.Is(err, store.ErrArtifactProcessingClaimLost) || errors.Is(context.Cause(run.ctx), store.ErrArtifactProcessingClaimLost) {
		s.log.Warn().Str("snapshot_id", snapshotID.String()).Str("worker_id", s.artifactWorkerID).Msg("artifact processing abandoned after claim ownership was lost")
		return true
	}
	if run.ctx.Err() == nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	s.log.Warn().Str("snapshot_id", snapshotID.String()).Str("worker_id", s.artifactWorkerID).Msg("artifact processing abandoned after processing context was canceled")
	return true
}

func (s *Server) processClaimedArtifactSnapshot(ctx context.Context, snapshot *store.Snapshot) (*artifactProcessingResult, error) {
	if processClaimedSnapshotHook == nil {
		return s.processClaimedArtifactSnapshotBase(ctx, snapshot)
	}
	return processClaimedSnapshotHook(ctx, s, snapshot)
}

func (s *Server) processClaimedArtifactSnapshotBase(ctx context.Context, snapshot *store.Snapshot) (*artifactProcessingResult, error) {
	artifacts, err := s.loadClaimableSnapshotArtifacts(ctx, snapshot.ID)
	if err != nil {
		return nil, err
	}
	result := &artifactProcessingResult{}
	// Read before any transaction: it may ask the forge.
	scopes := s.resolveConfiguredScopes(ctx, snapshot, artifacts)

	failures := make([]artifactProcessingFailure, 0)
	for _, artifact := range artifacts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		componentsIngested, err := s.processClaimableSnapshotArtifact(ctx, snapshot, artifact, scopes)
		if err != nil {
			if shouldAbortArtifactProcessing(err) {
				return nil, err
			}
			failures = append(failures, artifactProcessingFailure{
				artifactID: artifact.ID,
				kind:       artifact.Kind,
				err:        err,
			})
			s.recordFailedArtifactRun(ctx, snapshot, artifact, err)
			continue
		}
		result.componentsIngested += componentsIngested
	}

	if len(failures) == 0 {
		// Empty claimable sets can still happen if artifacts disappear after claim but before load.
		// Treat that the same as an all-success pass so the caller completes the owned snapshot.
		s.afterArtifactIngest(ctx, snapshot)
		return result, nil
	}
	message := truncateArtifactProcessingMessage(formatArtifactProcessingFailures(failures))
	if len(failures) == len(artifacts) {
		return nil, errors.New(message)
	}
	s.afterArtifactIngest(ctx, snapshot)
	result.warning = message
	return result, nil
}

func (s *Server) processClaimableSnapshotArtifact(ctx context.Context, snapshot *store.Snapshot, artifact store.SnapshotArtifact, scopes *configuredScopes) (int, error) {
	loadedArtifact, err := s.loadSnapshotArtifact(ctx, artifact)
	if err != nil {
		return 0, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	queries := s.queries.WithTx(tx)
	componentsIngested := 0
	switch loadedArtifact.artifact.Kind {
	case "sarif":
		if err := s.ingestSARIFArtifact(ctx, queries, snapshot, loadedArtifact, scopes); err != nil {
			_ = tx.Rollback()
			return 0, err
		}
	case "sbom":
		componentsIngested, err = s.ingestSBOMArtifact(ctx, queries, snapshot, loadedArtifact)
		if err != nil {
			_ = tx.Rollback()
			return 0, err
		}
	}

	if err := tx.Commit(); err != nil {
		_ = tx.Rollback()
		return 0, err
	}
	return componentsIngested, nil
}

func (s *Server) completeArtifactProcessingSnapshot(ctx context.Context, run *artifactProcessingRun, snapshotID uuid.UUID, warning string, componentsIngested int) error {
	var err error
	if warning == "" {
		_, err = s.queries.CompleteArtifactProcessingSnapshot(ctx, snapshotID, s.artifactWorkerID)
	} else {
		_, err = s.queries.CompleteArtifactProcessingSnapshotWithWarning(ctx, snapshotID, s.artifactWorkerID, warning)
		if err != nil && run != nil && s.shouldAbandonArtifactProcessing(run, err, snapshotID) {
			return nil
		}
	}
	if err != nil {
		return err
	}
	if componentsIngested > 0 {
		s.enqueueAdvisoryScan(snapshotID, "system")
	}
	s.reconcileReleasesForSnapshot(ctx, snapshotID)
	s.refreshScanCoverageForSnapshot(ctx, snapshotID)
	// The gate must not depend on the advisory scan happening. ScanCompleted is
	// published only by the advisory scanner, and that only runs when components
	// were ingested — so a coverage-only or SARIF-only PR never got a gate check
	// at all, and a failing provider silently suppressed it. Processing finished,
	// so ask for a recompute regardless; the publisher decides whether the
	// snapshot's ref is gate-eligible.
	if s.bus != nil {
		s.bus.Publish(context.WithoutCancel(ctx), events.Event{
			Type:    events.GateRecomputeRequested,
			Payload: map[string]any{"snapshot_id": snapshotID.String()},
		})
	}
	return nil
}

// defaultReleaseTagPattern decides which tags are releases (ADR-024 §5) when
// the repo does not configure its own: semver-ish versions with an optional v
// prefix (v1.2.3, 1.2, v2.0.0-rc.1). Repos override it as code via
// `releases.tag_pattern` in .hibou.yaml.
var defaultReleaseTagPattern = regexp.MustCompile(`^v?\d+\.\d+(\.\d+)?([-+][0-9A-Za-z.-]+)?$`)

// releaseTagPatternForRepo resolves the repo's release tag pattern from its
// .hibou.yaml. Config-as-code: devs own the pattern.
//
// "File absent" and "file unreadable" are different facts: an absent file (or
// section, or loader) means the repo uses the platform default; a transport
// error (forge partially down) means we don't know the repo's intent — the
// caller must NOT guess with the default, or an outage could silently derive
// a release a custom pattern excludes, or miss one it requires. It returns
// ok=false in that case; the periodic reconcile sweep retries once the forge
// answers again.
func (s *Server) releaseTagPatternForRepo(ctx context.Context, repoID uuid.UUID) (*regexp.Regexp, bool) {
	if s.repoConfigLoader == nil {
		return defaultReleaseTagPattern, true
	}
	repo, err := s.queries.GetRepositoryByID(ctx, repoID)
	if err != nil || repo == nil {
		return nil, false
	}
	owner, name, ok := s.boundRepoCoordinates(ctx, repo)
	if !ok {
		return defaultReleaseTagPattern, true
	}
	cfg, err := s.repoConfigLoader.Load(ctx, repo.Provider, owner, name, repo.DefaultBranch)
	if err != nil {
		return nil, false
	}
	if cfg == nil {
		// No .hibou.yaml (or an invalid one, which the loader ignores by
		// contract): the platform default is the repo's configuration.
		return defaultReleaseTagPattern, true
	}
	if custom := cfg.Releases.CompiledTagPattern(); custom != nil {
		return custom, true
	}
	return defaultReleaseTagPattern, true
}

// reconcileReleasesForSnapshot derives release state from a freshly completed
// snapshot (ADR-024 §5). Releases are never hand-created:
//   - a snapshot-less release of this ref (forge webhook landed before the
//     upload) adopts the snapshot;
//   - a version tag with no release row derives one;
//   - a re-tagged version (same tag, different commit) repoints silently only
//     while no client runs the release — otherwise it flags a divergence for a
//     release manager to adopt or keep.
func (s *Server) reconcileReleasesForSnapshot(ctx context.Context, snapshotID uuid.UUID) {
	snapshot, err := s.queries.GetSnapshotByID(ctx, snapshotID)
	if err != nil || snapshot == nil {
		return
	}
	attached, err := s.queries.AttachSnapshotToReleasesByRef(ctx, snapshot.RefID, snapshotID)
	if err != nil {
		s.log.Warn().Err(err).Str("snapshot_id", snapshotID.String()).Msg("failed to attach snapshot to releases")
		return
	}
	if attached > 0 {
		if err := s.pinReleaseSnapshot(ctx, snapshotID); err != nil {
			s.log.Warn().Err(err).Str("snapshot_id", snapshotID.String()).Msg("failed to pin release snapshot; retention may prune it")
		}
	}

	ref, err := s.queries.GetRefByID(ctx, snapshot.RefID)
	if err != nil || ref == nil {
		return
	}
	if ref.RefType != store.RefTypeTag {
		return
	}
	pattern, ok := s.releaseTagPatternForRepo(ctx, ref.RepoID)
	if !ok {
		// Forge unreachable: don't guess the repo's release intent. The
		// periodic reconcile sweep re-runs this once the config is readable.
		s.log.Warn().Str("tag", ref.Name).Str("snapshot_id", snapshotID.String()).Msg("release derivation deferred: repo config unreadable (forge down?)")
		return
	}
	if !pattern.MatchString(ref.Name) {
		return
	}

	release, err := s.queries.GetReleaseByRepoVersion(ctx, ref.RepoID, ref.Name)
	if err != nil {
		s.log.Warn().Err(err).Str("tag", ref.Name).Msg("failed to load release for tag snapshot")
		return
	}

	if release == nil {
		if _, err := s.queries.UpsertRelease(ctx, store.UpsertReleaseParams{
			RepoID:      ref.RepoID,
			RefID:       ref.ID,
			SnapshotID:  &snapshotID,
			Version:     ref.Name,
			Source:      store.ReleaseSourceTag,
			PublishedAt: &snapshot.CreatedAt,
		}); err != nil {
			s.log.Warn().Err(err).Str("tag", ref.Name).Msg("failed to derive release from tag snapshot")
			return
		}
		s.log.Info().Str("tag", ref.Name).Str("snapshot_id", snapshotID.String()).Msg("release derived from version tag")
		s.pinAfterRepoint(ctx, snapshotID, nil, uuid.Nil)
		return
	}

	if release.SnapshotID == nil || *release.SnapshotID == snapshotID {
		// attach above covered the nil case; identical snapshot needs nothing.
		return
	}

	current, err := s.queries.GetSnapshotByID(ctx, *release.SnapshotID)
	if err != nil {
		return
	}
	if current == nil || current.CommitSHA == snapshot.CommitSHA {
		// Same code, newer analysis — follow it.
		if _, err := s.queries.SetReleaseSnapshot(ctx, release.ID, snapshotID); err != nil {
			s.log.Warn().Err(err).Str("tag", ref.Name).Msg("failed to refresh release snapshot")
			return
		}
		s.pinAfterRepoint(ctx, snapshotID, release.SnapshotID, release.ID)
		return
	}

	// The tag moved to another commit.
	if release.DismissedCommitSHA == snapshot.CommitSHA {
		return
	}
	activeDeployments, err := s.queries.CountActiveDeploymentsByRelease(ctx, release.ID)
	if err != nil {
		return
	}
	if activeDeployments == 0 {
		// Nobody runs it: the re-tag is a correction, follow it silently.
		if _, err := s.queries.SetReleaseSnapshot(ctx, release.ID, snapshotID); err != nil {
			s.log.Warn().Err(err).Str("tag", ref.Name).Msg("failed to repoint re-tagged release")
			return
		}
		s.log.Info().Str("tag", ref.Name).Str("old_commit", current.CommitSHA).Str("new_commit", snapshot.CommitSHA).Msg("release repointed after re-tag (no active deployments)")
		s.pinAfterRepoint(ctx, snapshotID, release.SnapshotID, release.ID)
		return
	}
	if release.PendingSnapshotID != nil && *release.PendingSnapshotID == snapshotID {
		return
	}
	if _, err := s.queries.SetReleaseDivergence(ctx, release.ID, snapshotID); err != nil {
		s.log.Warn().Err(err).Str("tag", ref.Name).Msg("failed to flag release divergence")
		return
	}
	s.log.Warn().Str("tag", ref.Name).Str("shipped_commit", current.CommitSHA).Str("tag_commit", snapshot.CommitSHA).Int64("active_deployments", activeDeployments).Msg("release diverged: tag recreated on another commit while clients run it")
}

// pinAfterRepoint pins the snapshot a release now references and unpins the
// one it left, when no other release still needs it.
func (s *Server) pinAfterRepoint(ctx context.Context, newSnapshotID uuid.UUID, previousSnapshotID *uuid.UUID, releaseID uuid.UUID) {
	if err := s.pinReleaseSnapshot(ctx, newSnapshotID); err != nil {
		s.log.Warn().Err(err).Str("snapshot_id", newSnapshotID.String()).Msg("failed to pin release snapshot; retention may prune it")
	}
	if previousSnapshotID != nil && releaseID != uuid.Nil {
		s.unpinSnapshotIfUnreferenced(ctx, *previousSnapshotID, releaseID)
	}
}

func (s *Server) artifactProcessingLeaseDuration() time.Duration {
	if s.cfg.Worker.LeaseDuration > 0 {
		return s.cfg.Worker.LeaseDuration
	}
	return 5 * time.Minute
}

func (s *Server) artifactProcessingHeartbeatInterval() time.Duration {
	if s.cfg.Worker.HeartbeatInterval > 0 {
		return s.cfg.Worker.HeartbeatInterval
	}
	return s.artifactProcessingLeaseDuration() / 3
}

func (s *Server) startArtifactProcessingRun(ctx context.Context, snapshotID uuid.UUID) *artifactProcessingRun {
	runCtx, cancel := context.WithCancelCause(ctx)
	run := &artifactProcessingRun{ctx: runCtx, cancel: cancel, done: make(chan struct{})}
	interval := s.artifactProcessingHeartbeatInterval()
	if interval <= 0 {
		close(run.done)
		return run
	}
	go s.runArtifactProcessingHeartbeat(run, snapshotID, interval)
	return run
}

func (s *Server) stopArtifactProcessingRun(run *artifactProcessingRun) {
	run.cancel(nil)
	<-run.done
}

func (s *Server) runArtifactProcessingHeartbeat(run *artifactProcessingRun, snapshotID uuid.UUID, interval time.Duration) {
	defer close(run.done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-run.ctx.Done():
			return
		case <-ticker.C:
			renewed, err := s.queries.RenewArtifactProcessingSnapshotClaim(run.ctx, snapshotID, s.artifactWorkerID, time.Now().Add(s.artifactProcessingLeaseDuration()))
			if err != nil {
				if run.ctx.Err() != nil {
					return
				}
				run.cancel(fmt.Errorf("renew artifact processing claim: %w", err))
				return
			}
			if renewed == 0 {
				run.cancel(store.ErrArtifactProcessingClaimLost)
				return
			}
		}
	}
}

func (s *Server) loadClaimableSnapshotArtifacts(ctx context.Context, snapshotID uuid.UUID) ([]store.SnapshotArtifact, error) {
	artifacts, err := s.queries.ListSnapshotArtifactsBySnapshot(ctx, snapshotID)
	if err != nil {
		return nil, err
	}

	claimable := make([]store.SnapshotArtifact, 0, len(artifacts))
	for _, artifact := range artifacts {
		if !isClaimableSnapshotArtifact(artifact) {
			continue
		}
		claimable = append(claimable, artifact)
	}

	return claimable, nil
}

func (s *Server) loadSnapshotArtifact(ctx context.Context, artifact store.SnapshotArtifact) (loadedSnapshotArtifact, error) {
	reader, err := s.objStore.Get(ctx, artifact.ObjectKey)
	if err != nil {
		return loadedSnapshotArtifact{}, fmt.Errorf("load artifact %s: %w", artifact.ObjectKey, err)
	}
	content, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil {
		return loadedSnapshotArtifact{}, fmt.Errorf("read artifact %s: %w", artifact.ObjectKey, readErr)
	}
	if closeErr != nil {
		return loadedSnapshotArtifact{}, fmt.Errorf("close artifact %s: %w", artifact.ObjectKey, closeErr)
	}
	return loadedSnapshotArtifact{artifact: artifact, content: content}, nil
}

func (s *Server) ingestSARIFArtifact(ctx context.Context, queries *store.Queries, snapshot *store.Snapshot, artifact loadedSnapshotArtifact, scopes *configuredScopes) error {
	doc, err := sarif.Parse(bytes.NewReader(artifact.content))
	if err != nil {
		return fmt.Errorf("parse sarif artifact %s: %w", artifact.artifact.ID, err)
	}
	// The fallback identity (results without a scanner or content
	// fingerprint) is scoped to the repo, not the ref: a ref-scoped key gave
	// the same finding different fingerprints on a PR and on its target, so
	// triage recorded on main did not apply in the PR.
	ref, err := queries.GetRefByID(ctx, snapshot.RefID)
	if err != nil {
		return fmt.Errorf("load ref for sarif artifact %s: %w", artifact.artifact.ID, err)
	}
	if ref == nil {
		return fmt.Errorf("load ref for sarif artifact %s: ref %s not found", artifact.artifact.ID, snapshot.RefID)
	}
	parsedFindings, err := sarif.ExtractFindings(doc, ref.RepoID.String())
	if err != nil {
		return fmt.Errorf("extract sarif findings %s: %w", artifact.artifact.ID, err)
	}
	genericFindings := make([]findings.GenericFinding, 0, len(parsedFindings))
	droppedAdvisories, droppedSecrets := 0, 0
	for _, finding := range parsedFindings {
		// Scanners that also do dependency scanning interleave advisories
		// (rule ID = CVE/GHSA/…) with real SAST results; the SBOM pipeline
		// already reports those with component context, so keeping them would
		// double-count every dependency vulnerability as a SAST finding.
		if sarif.IsAdvisoryFinding(finding.RuleID, finding.Rule) {
			droppedAdvisories++
			continue
		}
		// Trivy also interleaves secret detections; the secret scanner owns
		// those, so a SAST copy would duplicate every leaked credential.
		if sarif.IsSecretFinding(finding.Rule) {
			droppedSecrets++
			continue
		}
		genericFindings = append(genericFindings, findings.GenericFinding{
			Tool:                     finding.Tool,
			ToolVersion:              finding.ToolVersion,
			TraceFiles:               finding.TraceFiles,
			RuleID:                   finding.RuleID,
			Severity:                 finding.Severity,
			FilePath:                 finding.FilePath,
			StartLine:                finding.StartLine,
			EndLine:                  finding.EndLine,
			Message:                  finding.Message,
			Fingerprint:              finding.Fingerprint,
			Rule:                     scanRuleInput(finding.Rule),
			ResultCWEs:               finding.ResultCWEs,
			Suppressed:               finding.Suppressed,
			SuppressionKind:          finding.SuppressionKind,
			SuppressionJustification: finding.SuppressionJustification,
		})
	}
	if droppedAdvisories > 0 {
		s.log.Info().
			Str("snapshot", snapshot.ID.String()).
			Int("dropped", droppedAdvisories).
			Msg("skipped dependency advisories reported as SAST findings")
	}
	if droppedSecrets > 0 {
		s.log.Info().
			Str("snapshot", snapshot.ID.String()).
			Int("dropped", droppedSecrets).
			Msg("skipped secret detections reported as SAST findings")
	}
	_, err = findings.NewIngester(queries, s.log).Ingest(ctx, snapshot.ID, genericFindings)
	if err != nil {
		return fmt.Errorf("ingest sarif findings %s: %w", artifact.artifact.ID, err)
	}
	if err := queries.ReplaceArtifactProducerRuns(ctx, snapshot.ID, artifact.artifact.ID, sarifProducerRuns(doc, artifact.artifact, scopes)); err != nil {
		return fmt.Errorf("record producer runs %s: %w", artifact.artifact.ID, err)
	}
	if artifact.artifact.PlanID != nil && artifact.artifact.PlanJobID != nil {
		if err := queries.BindArtifactToPlanJob(ctx, artifact.artifact.ID, *artifact.artifact.PlanID, *artifact.artifact.PlanJobID); err != nil {
			return fmt.Errorf("bind producer runs to plan job %s: %w", artifact.artifact.ID, err)
		}
	}
	return nil
}

// afterArtifactIngest runs the cross-snapshot steps once every artifact is
// ingested, before the snapshot completes and the gate reads it: triage
// follows re-keyed findings first (its pairing must see only reported rows),
// then findings the producers did not re-check are carried forward.
func (s *Server) afterArtifactIngest(ctx context.Context, snapshot *store.Snapshot) {
	s.carryTriageAcrossRekeys(ctx, snapshot)
	s.reconcileFindingPresence(ctx, snapshot.ID)
}

// sarifProducerRuns turns each SARIF run into its producer_runs row (ADR-034
// §2): the run's own evidence, completed by what the uploader declared.
// SARIF wins for the version. Scope comes from the upload's declaration,
// else from .hibou.yaml's scanners section, else it is an assumed full run.
func sarifProducerRuns(doc *sarif.Document, artifact store.SnapshotArtifact, scopes *configuredScopes) []store.ProducerRunInput {
	evidence := sarif.ExtractRunEvidence(doc)
	runs := make([]store.ProducerRunInput, 0, len(evidence))
	for _, run := range evidence {
		producer := run.Producer
		if producer == "" && artifact.ToolName != nil {
			producer = strings.ToLower(strings.TrimSpace(*artifact.ToolName))
		}
		input := store.ProducerRunInput{
			Producer:      producer,
			Version:       artifact.ToolVersion,
			ConfigDigest:  artifact.ConfigDigest,
			Scope:         store.ProducerScopeFull,
			ScopeDeclared: artifact.Scope != nil,
			ScopePaths:    artifact.ScopePaths,
			Outcome:       run.Outcome,
			FindingCount:  run.FindingCount,
		}
		if run.Version != "" {
			version := run.Version
			input.Version = &version
		}
		if artifact.Scope != nil {
			input.Scope = *artifact.Scope
		} else {
			input.Scope, input.ScopePaths, input.ScopeDeclared = scopes.runScope(producer)
		}
		if input.Scope == store.ProducerScopePartial && input.Outcome == store.ProducerOutcomeCompleted {
			input.Outcome = store.ProducerOutcomePartial
		}
		if run.Detail != "" {
			detail := run.Detail
			input.Detail = &detail
		}
		input.SkippedFiles = make([]store.SkippedFile, len(run.Skipped))
		for i, skipped := range run.Skipped {
			input.SkippedFiles[i] = store.SkippedFile{Path: skipped.Path, Reason: skipped.Reason}
		}
		runs = append(runs, input)
	}
	return runs
}

// recordFailedArtifactRun marks a SARIF artifact that could not be ingested
// as a failed run of its producer, so its findings read as not re-checked
// instead of fixed. Best effort, outside the rolled-back ingest transaction.
func (s *Server) recordFailedArtifactRun(ctx context.Context, snapshot *store.Snapshot, artifact store.SnapshotArtifact, cause error) {
	if artifact.Kind != "sarif" || s.queries == nil {
		return
	}
	producer := "unknown"
	if artifact.ToolName != nil && strings.TrimSpace(*artifact.ToolName) != "" {
		producer = strings.ToLower(strings.TrimSpace(*artifact.ToolName))
	}
	detail := truncateArtifactProcessingMessage(cause.Error())
	if err := s.queries.ReplaceArtifactProducerRuns(ctx, snapshot.ID, artifact.ID, []store.ProducerRunInput{{
		Producer:      producer,
		Version:       artifact.ToolVersion,
		ConfigDigest:  artifact.ConfigDigest,
		Scope:         store.ProducerScopeFull,
		ScopeDeclared: artifact.Scope != nil,
		Outcome:       store.ProducerOutcomeFailed,
		Detail:        &detail,
	}}); err != nil {
		s.log.Warn().Err(err).Str("artifact", artifact.ID.String()).Msg("record failed producer run")
	}
}

// scanRuleInput maps a parsed SARIF rule descriptor onto the generic ingest
// input consumed by the findings package (keeps sarif and findings decoupled).
func scanRuleInput(rule *sarif.RuleDescriptor) *findings.ScanRuleInput {
	if rule == nil {
		return nil
	}
	return &findings.ScanRuleInput{
		Name:             rule.Name,
		ShortDescription: rule.ShortDescription,
		FullDescription:  rule.FullDescription,
		HelpURI:          rule.HelpURI,
		HelpMarkdown:     rule.HelpMarkdown,
		DefaultLevel:     rule.DefaultLevel,
		SecuritySeverity: rule.SecuritySeverity,
		Precision:        rule.Precision,
		CWEs:             rule.CWEs,
		Tags:             rule.Tags,
		Properties:       rule.Properties,
	}
}

func (s *Server) ingestSBOMArtifact(ctx context.Context, queries *store.Queries, snapshot *store.Snapshot, artifact loadedSnapshotArtifact) (int, error) {
	format := optionalStringValue(artifact.artifact.Format)
	componentsBefore, err := queries.CountComponentsBySnapshot(ctx, snapshot.ID)
	if err != nil {
		return 0, fmt.Errorf("count snapshot components before ingest %s: %w", snapshot.ID, err)
	}
	switch format {
	case "cyclonedx-json":
		if err := s.ingestCycloneDXSBOMArtifact(ctx, queries, snapshot, artifact); err != nil {
			return 0, err
		}
	case "spdx-json":
		if err := s.ingestSPDXSBOMArtifact(ctx, queries, snapshot, artifact); err != nil {
			return 0, err
		}
	default:
		return 0, nil
	}
	componentsAfter, err := queries.CountComponentsBySnapshot(ctx, snapshot.ID)
	if err != nil {
		return 0, fmt.Errorf("count snapshot components after ingest %s: %w", snapshot.ID, err)
	}
	if componentsAfter <= componentsBefore {
		return 0, nil
	}
	return int(componentsAfter - componentsBefore), nil
}

// componentProvenanceLabels records WHICH uploaded artifact a component came
// from. A snapshot routinely ingests several SBOMs (one per language tree, plus
// a container image), and after ingest they collapse into one flat component
// set — so today there is no way to tell a Go dependency from a frontend one, or
// a shipped image layer from a source-tree scan. Storing the artifact's own
// filename is the smallest thing that makes that recoverable, and it is the
// prerequisite for ever attaching a distribution ("shipped" vs "source") to an
// upload.
//
// The key set is flat because the column is merged with jsonb `||`; see the
// AttachComponentToSnapshot query.
func componentProvenanceLabels(artifact store.SnapshotArtifact) json.RawMessage {
	filename := strings.TrimSpace(artifact.Filename)
	if filename == "" {
		// Nothing worth recording — an unnamed upload tells us no more than the
		// snapshot already does.
		return nil
	}
	labels := map[string]any{"sbom:" + filename: true}
	if kind := strings.TrimSpace(artifact.Kind); kind != "" {
		labels["sbom_kind:"+kind] = true
	}
	encoded, err := json.Marshal(labels)
	if err != nil {
		// A map of strings cannot fail to marshal; degrade to no labels rather
		// than failing an ingest over provenance metadata.
		return nil
	}
	return encoded
}

func (s *Server) ingestCycloneDXSBOMArtifact(ctx context.Context, queries *store.Queries, snapshot *store.Snapshot, artifact loadedSnapshotArtifact) error {
	components, dependencies, rootBomRef, bomRefIndex, err := sbom.ParseCycloneDXJSONGraph(artifact.content)
	if err != nil {
		return fmt.Errorf("parse sbom artifact %s: %w", artifact.artifact.ID, err)
	}
	componentIDsByBomRef := make(map[string]uuid.UUID, len(bomRefIndex))
	provenance := componentProvenanceLabels(artifact.artifact)
	for _, component := range components {
		storedComponent, err := queries.UpsertComponent(ctx, component.PURL, component.Name, component.Version, component.Ecosystem, component.Licenses)
		if err != nil {
			return fmt.Errorf("upsert component %s: %w", component.PURL, err)
		}
		// The built-in extractor's properties (relationship, scope, module,
		// registry) become labels next to the artifact's own (ADR-045 §5).
		if err := queries.AttachComponentToSnapshot(ctx, snapshot.ID, storedComponent.ID, componentLabelsWithProperties(provenance, component)); err != nil {
			return fmt.Errorf("attach component %s to snapshot: %w", component.PURL, err)
		}
		for _, bomRef := range component.BomRefs {
			componentIDsByBomRef[bomRef] = storedComponent.ID
		}
	}
	if err := upsertCycloneDXDependencyRoot(ctx, queries, snapshot.ID, rootBomRef, componentIDsByBomRef); err != nil {
		return err
	}
	if err := upsertCycloneDXDependencies(ctx, queries, snapshot.ID, dependencies, componentIDsByBomRef); err != nil {
		return err
	}
	return nil
}

func (s *Server) ingestSPDXSBOMArtifact(ctx context.Context, queries *store.Queries, snapshot *store.Snapshot, artifact loadedSnapshotArtifact) error {
	components, err := sbom.ParseSPDXJSON(artifact.content)
	if err != nil {
		return fmt.Errorf("parse sbom artifact %s: %w", artifact.artifact.ID, err)
	}
	provenance := componentProvenanceLabels(artifact.artifact)
	for _, component := range components {
		storedComponent, err := queries.UpsertComponent(ctx, component.PURL, component.Name, component.Version, component.Ecosystem, component.Licenses)
		if err != nil {
			return fmt.Errorf("upsert component %s: %w", component.PURL, err)
		}
		if err := queries.AttachComponentToSnapshot(ctx, snapshot.ID, storedComponent.ID, provenance); err != nil {
			return fmt.Errorf("attach component %s to snapshot: %w", component.PURL, err)
		}
	}
	return nil
}

func upsertCycloneDXDependencyRoot(ctx context.Context, queries *store.Queries, snapshotID uuid.UUID, rootBomRef string, componentIDsByBomRef map[string]uuid.UUID) error {
	if rootBomRef == "" {
		return nil
	}
	componentID, ok := componentIDsByBomRef[rootBomRef]
	if !ok {
		return nil
	}
	if err := queries.UpsertSnapshotDependencyRoot(ctx, snapshotID, componentID); err != nil {
		return fmt.Errorf("upsert snapshot dependency root %s: %w", rootBomRef, err)
	}
	return nil
}

func upsertCycloneDXDependencies(ctx context.Context, queries *store.Queries, snapshotID uuid.UUID, dependencies []sbom.ParsedDependency, componentIDsByBomRef map[string]uuid.UUID) error {
	for _, dependency := range dependencies {
		componentID, ok := componentIDsByBomRef[dependency.Ref]
		if !ok {
			continue
		}
		for _, dependsOnRef := range dependency.DependsOn {
			dependsOnID, ok := componentIDsByBomRef[dependsOnRef]
			if !ok || dependsOnID == componentID {
				continue
			}
			if err := queries.UpsertComponentDependency(ctx, snapshotID, componentID, dependsOnID); err != nil {
				return fmt.Errorf("upsert component dependency %s -> %s: %w", dependency.Ref, dependsOnRef, err)
			}
		}
	}
	return nil
}

func isClaimableSnapshotArtifact(artifact store.SnapshotArtifact) bool {
	switch artifact.Kind {
	case "sarif":
		return true
	case "sbom":
		format := optionalStringValue(artifact.Format)
		return format == "cyclonedx-json" || format == "spdx-json"
	default:
		return false
	}
}

func optionalStringValue(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}

func truncateArtifactProcessingError(err error) string {
	if err == nil {
		return ""
	}
	return truncateArtifactProcessingMessage(err.Error())
}

func truncateArtifactProcessingMessage(message string) string {
	message = strings.TrimSpace(message)
	if len(message) <= maxArtifactProcessingErrorLen {
		return message
	}
	return message[:maxArtifactProcessingErrorLen]
}

func shouldAbortArtifactProcessing(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, store.ErrArtifactProcessingClaimLost)
}

func formatArtifactProcessingFailures(failures []artifactProcessingFailure) string {
	parts := make([]string, 0, len(failures))
	for _, failure := range failures {
		parts = append(parts, fmt.Sprintf("%s %s: %v", failure.kind, failure.artifactID, failure.err))
	}
	if len(parts) == 1 {
		return "artifact ingest warning: " + parts[0]
	}
	return "artifact ingest warnings: " + strings.Join(parts, "; ")
}

// refreshScanCoverageForSnapshot updates the scanner coverage inventory
// (ADR-035 §6) when a default-branch snapshot finishes: its runs are the
// inventory's evidence.
func (s *Server) refreshScanCoverageForSnapshot(ctx context.Context, snapshotID uuid.UUID) {
	if s.scanCatalog == nil {
		return
	}
	snapshot, err := s.queries.GetSnapshotByID(ctx, snapshotID)
	if err != nil || snapshot == nil {
		return
	}
	ref, err := s.queries.GetRefByID(ctx, snapshot.RefID)
	if err != nil || ref == nil {
		return
	}
	repo, err := s.queries.GetRepositoryByID(ctx, ref.RepoID)
	if err != nil || repo == nil || ref.Name != repo.DefaultBranch {
		return
	}
	s.refreshScanCoverageAsync(repo)
}
