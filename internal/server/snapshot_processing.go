package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"

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

	failures := make([]artifactProcessingFailure, 0)
	for _, artifact := range artifacts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		componentsIngested, err := s.processClaimableSnapshotArtifact(ctx, snapshot, artifact)
		if err != nil {
			if shouldAbortArtifactProcessing(err) {
				return nil, err
			}
			failures = append(failures, artifactProcessingFailure{
				artifactID: artifact.ID,
				kind:       artifact.Kind,
				err:        err,
			})
			continue
		}
		result.componentsIngested += componentsIngested
	}

	if len(failures) == 0 {
		// Empty claimable sets can still happen if artifacts disappear after claim but before load.
		// Treat that the same as an all-success pass so the caller completes the owned snapshot.
		return result, nil
	}
	message := truncateArtifactProcessingMessage(formatArtifactProcessingFailures(failures))
	if len(failures) == len(artifacts) {
		return nil, errors.New(message)
	}
	result.warning = message
	return result, nil
}

func (s *Server) processClaimableSnapshotArtifact(ctx context.Context, snapshot *store.Snapshot, artifact store.SnapshotArtifact) (int, error) {
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
		if err := s.ingestSARIFArtifact(ctx, queries, snapshot, loadedArtifact); err != nil {
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
	return nil
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

func (s *Server) ingestSARIFArtifact(ctx context.Context, queries *store.Queries, snapshot *store.Snapshot, artifact loadedSnapshotArtifact) error {
	doc, err := sarif.Parse(bytes.NewReader(artifact.content))
	if err != nil {
		return fmt.Errorf("parse sarif artifact %s: %w", artifact.artifact.ID, err)
	}
	parsedFindings, err := sarif.ExtractFindings(doc, snapshot.RefID.String())
	if err != nil {
		return fmt.Errorf("extract sarif findings %s: %w", artifact.artifact.ID, err)
	}
	genericFindings := make([]findings.GenericFinding, 0, len(parsedFindings))
	for _, finding := range parsedFindings {
		genericFindings = append(genericFindings, findings.GenericFinding{
			Tool:        finding.Tool,
			RuleID:      finding.RuleID,
			Severity:    finding.Severity,
			FilePath:    finding.FilePath,
			StartLine:   finding.StartLine,
			EndLine:     finding.EndLine,
			Message:     finding.Message,
			Fingerprint: finding.Fingerprint,
			Rule:        scanRuleInput(finding.Rule),
		})
	}
	_, err = findings.NewIngester(queries, s.log).Ingest(ctx, snapshot.ID, genericFindings)
	if err != nil {
		return fmt.Errorf("ingest sarif findings %s: %w", artifact.artifact.ID, err)
	}
	return nil
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

func (s *Server) ingestCycloneDXSBOMArtifact(ctx context.Context, queries *store.Queries, snapshot *store.Snapshot, artifact loadedSnapshotArtifact) error {
	components, dependencies, rootBomRef, bomRefIndex, err := sbom.ParseCycloneDXJSONGraph(artifact.content)
	if err != nil {
		return fmt.Errorf("parse sbom artifact %s: %w", artifact.artifact.ID, err)
	}
	componentIDsByBomRef := make(map[string]uuid.UUID, len(bomRefIndex))
	for _, component := range components {
		storedComponent, err := queries.UpsertComponent(ctx, component.PURL, component.Name, component.Version, component.Ecosystem)
		if err != nil {
			return fmt.Errorf("upsert component %s: %w", component.PURL, err)
		}
		if err := queries.AttachComponentToSnapshot(ctx, snapshot.ID, storedComponent.ID); err != nil {
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
	for _, component := range components {
		storedComponent, err := queries.UpsertComponent(ctx, component.PURL, component.Name, component.Version, component.Ecosystem)
		if err != nil {
			return fmt.Errorf("upsert component %s: %w", component.PURL, err)
		}
		if err := queries.AttachComponentToSnapshot(ctx, snapshot.ID, storedComponent.ID); err != nil {
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
