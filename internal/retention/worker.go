package retention

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/events"
	"github.com/hibouhq/hibou/internal/objstore"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

const batchSize int32 = 100
const refPageSize = 200
const notificationThrottleWindow = 6 * time.Hour

type Worker struct {
	store                              WorkerStore
	objStore                           objstore.Store
	auditLog                           auditLogger
	bus                                eventPublisher
	log                                zerolog.Logger
	policy                             RetentionPolicy
	pendingWindow                      time.Duration
	now                                func() time.Time
	mu                                 sync.Mutex
	throttle                           map[string]time.Time
	loggedFindingsProtectionLimitation bool
}

type WorkerStore interface {
	ListRepositoriesForRetention(ctx context.Context) ([]store.Repository, error)
	ListRefsByRepo(ctx context.Context, repoID uuid.UUID, limit, offset int) ([]store.Ref, int, error)
	ListSnapshotsForRetentionTimeline(ctx context.Context, repoID, refID uuid.UUID) ([]store.Snapshot, error)
	ListVulnerabilitySummaryBySnapshot(ctx context.Context, snapshotID uuid.UUID) ([]dbgen.ListVulnerabilitySummaryBySnapshotRow, error)
	ListStalePendingSnapshots(ctx context.Context, before time.Time, limit int32) ([]dbgen.Snapshot, error)
	ListSnapshotArtifactObjectKeys(ctx context.Context, snapshotID uuid.UUID) ([]string, error)
	ArchiveSnapshot(ctx context.Context, id uuid.UUID) error
	MarkSnapshotFailed(ctx context.Context, id uuid.UUID) error
	PurgeSnapshot(ctx context.Context, id uuid.UUID) error
	RollupSnapshotVulnerabilities(ctx context.Context, snapshotID uuid.UUID) (int64, error)
	GetSnapshotVulnRollup(ctx context.Context, snapshotID uuid.UUID) (store.SnapshotVulnRollup, bool, error)
}

type auditLogger interface {
	CreateAuditLog(ctx context.Context, arg dbgen.CreateAuditLogParams) (dbgen.AuditLog, error)
}

type eventPublisher interface {
	Publish(ctx context.Context, evt events.Event)
}

type thinDecision string

const (
	thinDecisionNone    thinDecision = "none"
	thinDecisionArchive thinDecision = "archive"
	thinDecisionPurge   thinDecision = "purge"
)

type snapshotCandidate struct {
	Snapshot     store.Snapshot
	Severity     int
	Protected    bool
	Ref          store.Ref
	Repository   store.Repository
	ThinReason   string
	ThinDecision thinDecision
}

func NewWorker(store WorkerStore, objStore objstore.Store, auditLog auditLogger, bus eventPublisher, log zerolog.Logger, policy RetentionPolicy, pendingWindow time.Duration) *Worker {
	return &Worker{
		store:         store,
		objStore:      objStore,
		auditLog:      auditLog,
		bus:           bus,
		log:           log,
		policy:        policy,
		pendingWindow: pendingWindow,
		now:           time.Now,
		throttle:      make(map[string]time.Time),
	}
}

func (w *Worker) Run(ctx context.Context) error {
	if w.store == nil {
		return nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	now := w.now().UTC()
	repositories, err := w.store.ListRepositoriesForRetention(ctx)
	if err != nil {
		return err
	}
	for _, repo := range repositories {
		if err := w.runRepository(ctx, now, repo); err != nil {
			return err
		}
	}

	return nil
}

func (w *Worker) runRepository(ctx context.Context, now time.Time, repo store.Repository) error {
	refs, err := w.listAllRefs(ctx, repo.ID)
	if err != nil {
		return err
	}

	plan := make(map[uuid.UUID]*snapshotCandidate)
	allCandidates := make(map[uuid.UUID]snapshotCandidate)
	var envelopeInputs []SnapshotInfo

	for _, ref := range refs {
		snapshots, err := w.store.ListSnapshotsForRetentionTimeline(ctx, repo.ID, ref.ID)
		if err != nil {
			return err
		}
		if len(snapshots) == 0 {
			continue
		}

		latestID := snapshots[len(snapshots)-1].ID
		policy := w.policyForRef(ref)
		infos := make([]SnapshotInfo, 0, len(snapshots))
		candidates := make([]snapshotCandidate, 0, len(snapshots))

		for _, snapshot := range snapshots {
			severity, err := w.snapshotSeverity(ctx, snapshot.ID)
			if err != nil {
				return err
			}
			protected := w.isProtectedSnapshot(snapshot, ref, latestID)
			candidate := snapshotCandidate{
				Snapshot:   snapshot,
				Severity:   severity,
				Protected:  protected,
				Ref:        ref,
				Repository: repo,
			}
			allCandidates[snapshot.ID] = candidate
			candidates = append(candidates, candidate)
			if isTierRepresentativeEligibleStatus(snapshot.Status) {
				infos = append(infos, SnapshotInfo{
					ID:        snapshot.ID,
					CreatedAt: snapshot.CreatedAt,
					Bytes:     snapshot.ArtifactBytes,
					Severity:  severity,
					Protected: protected || !isRetentionEligibleStatus(snapshot.Status),
				})
			}
		}

		if isClosedPullRequest(ref) && policy.PRSnapshots.AfterClose == ThinPurge {
			for _, candidate := range candidates {
				if candidate.Protected || !isRetentionEligibleStatus(candidate.Snapshot.Status) {
					continue
				}
				if policy.PRSnapshots.KeepAll > 0 && now.Sub(candidate.Snapshot.CreatedAt) <= policy.PRSnapshots.KeepAll {
					continue
				}
				w.recordPlan(plan, &candidate, "pr_after_close", thinDecisionPurge)
			}
		}

		if policy.FailedRetention > 0 {
			for _, candidate := range candidates {
				if candidate.Snapshot.Status != store.SnapshotStatusFailed || candidate.Protected {
					continue
				}
				if now.Sub(candidate.Snapshot.CreatedAt) <= policy.FailedRetention {
					continue
				}
				w.recordPlan(plan, &candidate, "failed_retention", thinDecisionPurge)
			}
		}

		if policy.Tiers.Enabled {
			keepSet := selectTimelineKeep(infos, now, policy)
			for _, candidate := range candidates {
				if candidate.Protected || !isTierThinEligibleStatus(candidate.Snapshot.Status) {
					continue
				}
				if _, ok := keepSet[candidate.Snapshot.ID]; ok {
					continue
				}
				w.recordPlan(plan, &candidate, "tiers", thinDecisionForPolicy(w.policy.OnThin))
			}
		}

		for _, candidate := range candidates {
			if plan[candidate.Snapshot.ID] != nil {
				continue
			}
			envelopeInputs = append(envelopeInputs, SnapshotInfo{
				ID:        candidate.Snapshot.ID,
				CreatedAt: candidate.Snapshot.CreatedAt,
				Bytes:     candidate.Snapshot.ArtifactBytes,
				Severity:  candidate.Severity,
				Protected: candidate.Protected || !isRetentionEligibleStatus(candidate.Snapshot.Status),
			})
		}
	}

	remainingBytes := repo.RetentionArtifactBytes - plannedReclaimBytes(plan)

	if w.shouldWarn(repo, remainingBytes) {
		w.publishRetentionEvent(ctx, repo, events.RetentionWarnAt, map[string]any{
			"usage_ratio": float64(remainingBytes) / float64(maxInt64(w.policy.Storage.Budget, 1)),
		})
	}

	if w.policy.Storage.Budget > 0 && remainingBytes > w.policy.Storage.Budget {
		w.publishRetentionEvent(ctx, repo, events.RetentionEviction, map[string]any{
			"current_bytes": remainingBytes,
			"budget_bytes":  w.policy.Storage.Budget,
		})
		targetBytes := int64(float64(w.policy.Storage.Budget) * w.policy.Storage.Target)
		for _, id := range planEviction(envelopeInputs, remainingBytes, targetBytes, w.policy.Storage.EvictOrder, now) {
			if plan[id] != nil {
				continue
			}
			candidate, ok := allCandidates[id]
			if !ok {
				continue
			}
			w.recordPlan(plan, &candidate, "envelope", thinDecisionForPolicy(w.policy.OnThin))
		}
		remainingBytes = repo.RetentionArtifactBytes - plannedReclaimBytes(plan)
		if remainingBytes > targetBytes {
			w.publishRetentionEvent(ctx, repo, events.RetentionProtected, map[string]any{
				"current_bytes": remainingBytes,
				"target_bytes":  targetBytes,
				"budget_bytes":  w.policy.Storage.Budget,
			})
		}
	}

	planned := make([]*snapshotCandidate, 0, len(plan))
	for _, candidate := range plan {
		planned = append(planned, candidate)
	}
	sort.Slice(planned, func(i, j int) bool {
		if !planned[i].Snapshot.CreatedAt.Equal(planned[j].Snapshot.CreatedAt) {
			return planned[i].Snapshot.CreatedAt.Before(planned[j].Snapshot.CreatedAt)
		}
		return lessID(planned[i].Snapshot.ID, planned[j].Snapshot.ID)
	})

	for _, candidate := range planned {
		if err := w.applyPlan(ctx, *candidate); err != nil {
			return err
		}
	}

	return nil
}

func (w *Worker) shouldWarn(repo store.Repository, currentBytes int64) bool {
	if w.policy.Storage.Budget <= 0 || w.policy.Storage.WarnAt <= 0 {
		return false
	}
	warnBytes := int64(float64(w.policy.Storage.Budget) * w.policy.Storage.WarnAt)
	return currentBytes >= warnBytes && currentBytes < w.policy.Storage.Budget
}

func (w *Worker) applyPlan(ctx context.Context, candidate snapshotCandidate) error {
	decision := thinDecisionForPolicy(w.policy.OnThin)
	if candidate.ThinDecision != thinDecisionNone {
		decision = candidate.ThinDecision
	}
	if decision == thinDecisionNone {
		return nil
	}

	w.log.Info().
		Str("snapshot_id", candidate.Snapshot.ID.String()).
		Str("repo_id", candidate.Repository.ID.String()).
		Str("reason", candidate.ThinReason).
		Str("decision", string(decision)).
		Bool("dry_run", w.policy.DryRun).
		Bool("auto_purge", w.policy.AutoPurge).
		Msg("retention decision")

	if w.policy.DryRun || !w.policy.AutoPurge {
		return nil
	}

	keys, err := w.store.ListSnapshotArtifactObjectKeys(ctx, candidate.Snapshot.ID)
	if err != nil {
		return err
	}
	for _, key := range keys {
		if err := w.deleteArtifact(ctx, key); err != nil {
			return err
		}
	}

	switch decision {
	case thinDecisionArchive:
		if candidate.Snapshot.Status != store.SnapshotStatusArchived {
			if err := w.store.ArchiveSnapshot(ctx, candidate.Snapshot.ID); err != nil {
				return err
			}
			// Downsample: keep a compact severity/type rollup for trend continuity
			// and drop the detail vulnerability rows (ADR db-review P0.1).
			if _, err := w.store.RollupSnapshotVulnerabilities(ctx, candidate.Snapshot.ID); err != nil {
				return err
			}
			w.writeAuditLog(ctx, audit.ActionRetentionArchive, candidate)
		}
	case thinDecisionPurge:
		if candidate.Snapshot.Status != store.SnapshotStatusPurged {
			if err := w.store.PurgeSnapshot(ctx, candidate.Snapshot.ID); err != nil {
				return err
			}
			w.writeAuditLog(ctx, audit.ActionRetentionPurge, candidate)
		}
	}
	return nil
}

func (w *Worker) SweepStalePending(ctx context.Context) error {
	if w.store == nil || w.pendingWindow <= 0 {
		return nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	cutoff := time.Now().Add(-w.pendingWindow)
	staleSnapshots, err := w.store.ListStalePendingSnapshots(ctx, cutoff, batchSize)
	if err != nil {
		return err
	}
	for _, snapshot := range staleSnapshots {
		if err := w.store.MarkSnapshotFailed(ctx, snapshot.ID); err != nil {
			return err
		}
		w.log.Info().Str("snapshot_id", snapshot.ID.String()).Msg("failed stale pending snapshot")
	}

	return nil
}

func (w *Worker) listAllRefs(ctx context.Context, repoID uuid.UUID) ([]store.Ref, error) {
	offset := 0
	refs := make([]store.Ref, 0, refPageSize)
	for {
		rows, total, err := w.store.ListRefsByRepo(ctx, repoID, refPageSize, offset)
		if err != nil {
			return nil, err
		}
		refs = append(refs, rows...)
		offset += len(rows)
		if offset >= total || len(rows) == 0 {
			return refs, nil
		}
	}
}

func (w *Worker) snapshotSeverity(ctx context.Context, snapshotID uuid.UUID) (int, error) {
	rows, err := w.store.ListVulnerabilitySummaryBySnapshot(ctx, snapshotID)
	if err != nil {
		return 0, err
	}
	if len(rows) > 0 {
		highest := 0
		for _, row := range rows {
			if score := severityScore(row.Severity); score > highest {
				highest = score
			}
		}
		return highest, nil
	}
	// No detail rows: the snapshot may have been downsampled on archive. Derive
	// severity from the retained rollup so tier selection stays correct.
	return w.rollupSeverity(ctx, snapshotID)
}

func (w *Worker) rollupSeverity(ctx context.Context, snapshotID uuid.UUID) (int, error) {
	rollup, ok, err := w.store.GetSnapshotVulnRollup(ctx, snapshotID)
	if err != nil || !ok {
		return 0, err
	}
	counts := map[string]map[string]int64{}
	if err := json.Unmarshal(rollup.Counts, &counts); err != nil {
		return 0, nil //nolint:nilerr // a malformed rollup should not stall retention; treat as no severity signal.
	}
	highest := 0
	for _, bySeverity := range counts {
		for severity, count := range bySeverity {
			if count == 0 {
				continue
			}
			if score := severityScore(severity); score > highest {
				highest = score
			}
		}
	}
	return highest, nil
}

func severityScore(level string) int {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

func (w *Worker) policyForRef(ref store.Ref) RetentionPolicy {
	policy := w.policy
	if ref.RefType == store.RefTypePullRequest && policy.PRSnapshots.KeepAll > 0 {
		policy.KeepAll = policy.PRSnapshots.KeepAll
	}
	return policy
}

func (w *Worker) isProtectedSnapshot(snapshot store.Snapshot, ref store.Ref, latestID uuid.UUID) bool {
	protected := snapshot.Pinned || snapshot.RetentionHold || !isRetentionEligibleStatus(snapshot.Status)
	if w.policy.Pin.Tags && snapshot.Tag != nil && strings.TrimSpace(*snapshot.Tag) != "" {
		protected = true
	}
	if w.policy.Pin.LatestPerRef && snapshot.ID == latestID {
		protected = true
	}
	if hasPinnedLabel(snapshot.Labels, w.policy.Pin.Labels) {
		protected = true
	}
	if w.policy.Pin.ReferencedByOpenFindings && !w.loggedFindingsProtectionLimitation {
		w.loggedFindingsProtectionLimitation = true
		w.log.Warn().Msg("retention pin.referenced_by_open_findings is configured but cannot be evaluated from current stored fields; worker only enforces pinned, retention_hold, tag, label, and latest_per_ref protections")
	}
	_ = ref
	return protected
}

func hasPinnedLabel(labels, keepLabels []string) bool {
	if len(labels) == 0 || len(keepLabels) == 0 {
		return false
	}
	allowed := make(map[string]struct{}, len(keepLabels))
	for _, label := range keepLabels {
		allowed[strings.TrimSpace(label)] = struct{}{}
	}
	for _, label := range labels {
		if _, ok := allowed[strings.TrimSpace(label)]; ok {
			return true
		}
	}
	return false
}

func thinDecisionForPolicy(policy OnThinPolicy) thinDecision {
	if policy.Summary == ThinPurge {
		return thinDecisionPurge
	}
	if policy.Artifacts == ThinPurge {
		return thinDecisionArchive
	}
	return thinDecisionNone
}

func reclaimableBytes(candidate snapshotCandidate) int64 {
	if candidate.Snapshot.ArtifactBytes <= 0 {
		return 0
	}
	decision := candidate.ThinDecision
	if decision == thinDecisionNone {
		decision = thinDecisionForPolicy(OnThinPolicy{Artifacts: ThinPurge, Summary: ThinKeep})
	}
	switch decision {
	case thinDecisionArchive, thinDecisionPurge:
		return candidate.Snapshot.ArtifactBytes
	default:
		return 0
	}
}

func plannedReclaimBytes(plan map[uuid.UUID]*snapshotCandidate) int64 {
	var total int64
	for _, candidate := range plan {
		total += reclaimableBytes(*candidate)
	}
	return total
}

func isRetentionEligibleStatus(status store.SnapshotStatus) bool {
	switch status {
	case store.SnapshotStatusComplete, store.SnapshotStatusActive, store.SnapshotStatusArchived, store.SnapshotStatusFailed:
		return true
	default:
		return false
	}
}

func isTierRepresentativeEligibleStatus(status store.SnapshotStatus) bool {
	return isRetentionEligibleStatus(status) && status != store.SnapshotStatusFailed
}

func isTierThinEligibleStatus(status store.SnapshotStatus) bool {
	return isRetentionEligibleStatus(status) && status != store.SnapshotStatusFailed
}

func isClosedPullRequest(ref store.Ref) bool {
	if ref.RefType != store.RefTypePullRequest || ref.PrState == nil {
		return false
	}
	state := strings.ToLower(strings.TrimSpace(*ref.PrState))
	return state == "closed" || state == "merged"
}

func (w *Worker) recordPlan(plan map[uuid.UUID]*snapshotCandidate, candidate *snapshotCandidate, reason string, decision thinDecision) {
	if existing, ok := plan[candidate.Snapshot.ID]; ok {
		if existing.ThinDecision == thinDecisionPurge {
			return
		}
		if decision == thinDecisionPurge {
			existing.ThinDecision = thinDecisionPurge
		}
		if existing.ThinReason == "" {
			existing.ThinReason = reason
		}
		return
	}
	cloned := *candidate
	cloned.ThinReason = reason
	cloned.ThinDecision = decision
	plan[candidate.Snapshot.ID] = &cloned
}

func (w *Worker) publishRetentionEvent(ctx context.Context, repo store.Repository, eventType events.Type, payload map[string]any) {
	if w.bus == nil {
		return
	}
	key := repo.ID.String() + ":" + string(eventType)
	now := w.now().UTC()
	if last, ok := w.throttle[key]; ok && now.Sub(last) < notificationThrottleWindow {
		return
	}
	w.throttle[key] = now
	if payload == nil {
		payload = make(map[string]any)
	}
	payload["repo_id"] = repo.ID.String()
	payload["org_id"] = repo.OrgID.String()
	payload["repo_name"] = repo.Name
	w.bus.Publish(ctx, events.Event{Type: eventType, Payload: payload, Timestamp: now})
}

func (w *Worker) writeAuditLog(ctx context.Context, action string, candidate snapshotCandidate) {
	if w.auditLog == nil {
		return
	}
	payload, err := json.Marshal(map[string]any{
		"repo_id":       candidate.Repository.ID.String(),
		"ref_id":        candidate.Ref.ID.String(),
		"ref_name":      candidate.Ref.Name,
		"snapshot_id":   candidate.Snapshot.ID.String(),
		"status_before": candidate.Snapshot.Status,
		"reason":        candidate.ThinReason,
		"decision":      candidate.ThinDecision,
	})
	if err != nil {
		w.log.Warn().Err(err).Str("snapshot_id", candidate.Snapshot.ID.String()).Msg("marshal retention audit context")
		return
	}
	_, _ = w.auditLog.CreateAuditLog(ctx, dbgen.CreateAuditLogParams{
		ActorType:    audit.ActorSystem,
		ActorDisplay: "retention-worker",
		Action:       action,
		ResourceType: "snapshot",
		ResourceID:   candidate.Snapshot.ID.String(),
		OrgID:        uuid.NullUUID{UUID: candidate.Repository.OrgID, Valid: true},
		Context:      payload,
	})
}

func (w *Worker) deleteArtifact(ctx context.Context, key string) error {
	if w.objStore == nil || key == "" {
		return nil
	}
	if err := w.objStore.Delete(ctx, key); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func maxInt64(left, right int64) int64 {
	if left > right {
		return left
	}
	return right
}
