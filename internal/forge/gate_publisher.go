package forge

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/delta"
	"github.com/hibouhq/hibou/internal/events"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// gateUpdateTopic is the WebSocket topic browsers subscribe to for live PR gate
// refreshes. Delivered via the WS fanout, which bridges cross-replica over
// Postgres LISTEN/NOTIFY (ADR-015), so an update posted on any replica reaches
// clients connected to any other.
const gateUpdateTopic = "gate.updated"

// LiveGateNotifier broadcasts a live PR-gate update to connected browsers. The
// server supplies a WS-fanout-backed implementation; forge cannot import ws
// directly (import cycle), so it depends on this small interface instead.
type LiveGateNotifier interface {
	PublishGateUpdate(ctx context.Context, topic string, payload []byte)
}

type GatePublisher struct {
	forges           map[string]Provider
	delta            *delta.Service
	bus              *events.Bus
	store            GatePublisherStore
	repoConfigLoader RepoConfigLoader
	live             LiveGateNotifier
	baseURL          string
	// advisoryScanEnabled gates the scan-readiness precondition (PLAN §1): on
	// an instance that never scans, waiting for a scan would block every gate
	// forever. Set from the server's advisory-scan configuration.
	advisoryScanEnabled bool
	log                 zerolog.Logger
}

// SetAdvisoryScanEnabled wires the server's advisory-scan configuration in;
// see the field comment. Called once at construction time, before Subscribe.
func (a *GatePublisher) SetAdvisoryScanEnabled(enabled bool) {
	if a != nil {
		a.advisoryScanEnabled = enabled
	}
}

const securityStatusContext = "hibou/security"

type GatePublisherStore interface {
	GetRepoByID(ctx context.Context, id uuid.UUID) (dbgen.Repository, error)
	GetSnapshotByID(ctx context.Context, id uuid.UUID) (dbgen.Snapshot, error)
	GetRefByID(ctx context.Context, id uuid.UUID) (dbgen.Ref, error)
	GetLatestSnapshotByRef(ctx context.Context, refID uuid.UUID) (dbgen.Snapshot, error)
	GetOrgSlug(ctx context.Context, orgID uuid.UUID) (string, error)
	ListOpenPRRefs(ctx context.Context, repoID uuid.UUID) ([]dbgen.Ref, error)
	ListRepoIDsByOrg(ctx context.Context, orgID uuid.UUID) ([]uuid.UUID, error)
	ListUnsyncedPRCheckRefIDs(ctx context.Context, limit int32) ([]uuid.UUID, error)
	UpsertPRCheck(ctx context.Context, in store.UpsertPRCheckInput) error
	// ReplacePRCheckResolvedFingerprints records what this PR fixes, so the
	// findings list can show "a PR already fixes this" without recomputing
	// deltas (TODO-FEAT finding-detail §1).
	ReplacePRCheckResolvedFingerprints(ctx context.Context, repoID uuid.UUID, headSHA string, fingerprints []string) error
	// GetGateScanReadiness reports whether a snapshot's advisory scan state
	// allows an honest gate verdict (PLAN §1).
	GetGateScanReadiness(ctx context.Context, snapshotID uuid.UUID) (dbgen.GetGateScanReadinessRow, error)
	// GetSnapshotByRefCommit resolves the base snapshot at the exact commit CI
	// merged against (PLAN §2/§5); sql.ErrNoRows when it is gone.
	GetSnapshotByRefCommit(ctx context.Context, refID uuid.UUID, commitSHA string) (dbgen.Snapshot, error)
}

type RepoConfigLoader interface {
	LoadGateConfig(ctx context.Context, providerID, owner, repo, defaultBranch, targetBranch string) (*delta.GateConfig, error)
	// LoadEnforcement returns the gate enforcement mode ("advisory"|"blocking") for
	// the target branch; advisory (the default) never blocks the PR.
	LoadEnforcement(ctx context.Context, providerID, owner, repo, defaultBranch, targetBranch string) (string, error)
}

// Enforcement modes. Kept as local constants (the forge package cannot import
// repoconfig — repoconfig imports forge). Must match repoconfig.Enforcement*.
const (
	enforcementAdvisory = "advisory"
	enforcementBlocking = "blocking"
)

func NewGatePublisher(forges map[string]Provider, deltaSvc *delta.Service, bus *events.Bus, store GatePublisherStore, repoConfigLoader RepoConfigLoader, live LiveGateNotifier, baseURL string, log zerolog.Logger) *GatePublisher {
	if forges == nil {
		forges = map[string]Provider{}
	}
	return &GatePublisher{
		forges:           forges,
		delta:            deltaSvc,
		bus:              bus,
		store:            store,
		repoConfigLoader: repoConfigLoader,
		live:             live,
		baseURL:          strings.TrimRight(baseURL, "/"),
		log:              log.With().Str("component", "forge.gatePublisher").Logger(),
	}
}

// Subscribe registers event handlers. The gatePublisher re-publishes the PR gate
// check on scan completion AND on any gate-affecting change (VEX/false-positive
// dismissal, manual override, advisory re-eval) via GateRecomputeRequested — so
// the forge check flips live without a CI re-run. See ADR-018.
func (a *GatePublisher) Subscribe() {
	if a == nil || a.bus == nil {
		return
	}
	// context.WithoutCancel on every handler: the publisher (an advisory-scan
	// goroutine with a deferred cancel, a request that just returned) tears its
	// context down the moment it finishes, and that cancellation killed the
	// authoritative post-scan publish mid-flight on dogfood — leaving a
	// mid-scan "passed" as the PR's final word.
	a.bus.Subscribe(events.ScanCompleted, func(ctx context.Context, event events.Event) {
		a.handleScanCompleted(context.WithoutCancel(ctx), event.Payload)
	})
	// A secret scan lands findings after upload analysis, so an already-posted
	// gate check would otherwise go stale the moment a leak is found.
	a.bus.Subscribe(events.SecretScanCompleted, func(ctx context.Context, event events.Event) {
		a.handleScanCompleted(context.WithoutCancel(ctx), event.Payload)
	})
	a.bus.Subscribe(events.GateRecomputeRequested, func(ctx context.Context, event events.Event) {
		a.handleRecomputeRequested(context.WithoutCancel(ctx), event.Payload)
	})
}

func (a *GatePublisher) handleScanCompleted(ctx context.Context, payload any) {
	if a == nil || a.store == nil || a.delta == nil {
		return
	}
	if snapshotID := snapshotIDFromPayload(payload); snapshotID != uuid.Nil {
		a.publishForSnapshotID(ctx, snapshotID)
	}
}

// publishForSnapshotID routes a snapshot to the right gate action: a PR ref
// publishes (or posts in-progress when not yet computable), a branch ref
// refreshes the gates of open PRs targeting it.
func (a *GatePublisher) publishForSnapshotID(ctx context.Context, snapshotID uuid.UUID) {
	if a == nil || a.store == nil || a.delta == nil || snapshotID == uuid.Nil {
		return
	}
	snapshot, err := a.store.GetSnapshotByID(ctx, snapshotID)
	if err != nil {
		a.log.Error().Err(err).Str("snapshot_id", snapshotID.String()).Msg("load snapshot for gatePublisher")
		return
	}
	ref, err := a.store.GetRefByID(ctx, snapshot.RefID)
	if err != nil {
		a.log.Error().Err(err).Str("ref_id", snapshot.RefID.String()).Msg("load ref for gatePublisher")
		return
	}
	if snapshot.ID == uuid.Nil || ref.ID == uuid.Nil {
		return
	}

	switch ref.RefType {
	case dbgen.RefTypePullRequest:
		if snapshot.Status != dbgen.SnapshotStatusComplete && snapshot.Status != dbgen.SnapshotStatusActive {
			// Only analyzed snapshots may be gate input — a pending/failed one
			// evaluates as empty ("0 findings — passed"). Show the waiting
			// state on the current head instead.
			a.publishGateWaitingForUpload(ctx, ref)
			return
		}
		if head, stale := snapshotBehindHead(snapshot, ref); stale {
			// The PR moved past this snapshot (push before CI uploaded, or a
			// force-push): a verdict for a stale commit is a lie. Post the
			// pending state ON THE CURRENT HEAD instead, naming what we wait
			// for; the head's own upload publishes the real verdict.
			a.publishGateWaitingForHead(ctx, snapshot, ref, head)
			return
		}
		if state := a.advisoryScanState(ctx, snapshot.ID); state != scanStateReady {
			// A verdict computed before the advisory scan finished sees no
			// dependency findings: everything on the base reads "resolved" and
			// the malware/KEV blocks cannot fire (observed: PR #11 passed with
			// a known-exploited dependency). Wait, visibly.
			a.publishGateScanPending(ctx, snapshot, ref, snapshot.CommitSha, state)
			return
		}
		annotation, ok := a.buildGateContext(ctx, snapshot, ref)
		if !ok {
			// The gate is not computable yet (target branch has no snapshot, or
			// the merge target is unknown until the PR webhook lands). Post an
			// in-progress check so the PR shows "Hibou is working" instead of
			// nothing at all; a later recompute resolves it.
			a.publishGatePendingForRef(ctx, snapshot, ref)
			return
		}
		if state := a.advisoryScanState(ctx, annotation.targetSnapshot.ID); state != scanStateReady {
			// Symmetric: a mid-scan BASE snapshot is missing findings, so the
			// delta reports them as introduced by the PR — a false failure.
			a.publishGateScanPending(ctx, snapshot, ref, snapshot.CommitSha, state)
			return
		}
		a.evaluateAndPublish(ctx, annotation)
	case dbgen.RefTypeBranch:
		// The base branch moved (new snapshot on a branch): open PRs targeting it
		// now have a different delta, so refresh their gate checks — no CI re-run.
		a.recomputeOpenPRsForTargetRef(ctx, ref.RepoID, ref.ID)
	}
}

// snapshotBehindHead reports whether the ref's webhook-tracked head has moved
// past the snapshot we would evaluate — the "gate comment stamps a commit
// that is not the PR head" bug.
func snapshotBehindHead(snapshot dbgen.Snapshot, ref dbgen.Ref) (string, bool) {
	head := ""
	if ref.LatestCommitSha.Valid {
		head = strings.TrimSpace(ref.LatestCommitSha.String)
	}
	return head, head != "" && snapshot.CommitSha != "" && head != snapshot.CommitSha
}

// publishGateWaitingForHead posts the pending state against the PR's CURRENT
// head commit, naming it — so a fresh push always shows a check immediately
// ("waiting for scan of <head>") and stale verdicts never masquerade as
// current. No verdict is persisted.
func (a *GatePublisher) publishGateWaitingForHead(ctx context.Context, snapshot dbgen.Snapshot, ref dbgen.Ref, headSHA string) {
	repo, provider, owner, name, ok := a.loadGateRepository(ctx, ref)
	if !ok {
		return
	}
	orgSlug, err := a.store.GetOrgSlug(ctx, repo.OrgID)
	if err != nil {
		a.log.Debug().Err(err).Str("org_id", repo.OrgID.String()).Msg("load org slug for waiting gate check")
	}
	// The check must attach to the head the reviewer is looking at.
	headSnapshot := snapshot
	headSnapshot.CommitSha = headSHA
	annotation := &gateContext{
		snapshot: headSnapshot,
		prRef:    ref,
		repo:     repo,
		provider: provider,
		owner:    owner,
		name:     name,
		orgSlug:  orgSlug,
	}
	status := gatePendingStatus()
	status.description = "Waiting for scan of " + shortCommit(headSHA)
	status.title = "Quality gate — waiting for scan of " + shortCommit(headSHA)
	status.summary = fmt.Sprintf(
		"The pull request head moved to %s but its scan has not been uploaded yet. The last evaluated commit was %s; this check updates automatically when the new head's upload arrives.",
		shortCommit(headSHA), shortCommit(snapshot.CommitSha))
	a.publishGateStatusOnly(ctx, annotation, status)
}

// publishGatePendingForRef posts an in-progress check for a PR snapshot whose
// gate cannot be evaluated yet. It never persists a verdict — the row stays
// untouched so a later recompute writes the real outcome.
func (a *GatePublisher) publishGatePendingForRef(ctx context.Context, snapshot dbgen.Snapshot, ref dbgen.Ref) {
	repo, provider, owner, name, ok := a.loadGateRepository(ctx, ref)
	if !ok {
		return
	}
	orgSlug, err := a.store.GetOrgSlug(ctx, repo.OrgID)
	if err != nil {
		a.log.Debug().Err(err).Str("org_id", repo.OrgID.String()).Msg("load org slug for pending gate check")
	}
	annotation := &gateContext{
		snapshot: snapshot,
		prRef:    ref,
		repo:     repo,
		provider: provider,
		owner:    owner,
		name:     name,
		orgSlug:  orgSlug,
	}
	a.publishGateStatusOnly(ctx, annotation, gatePendingStatus())
}

// gatePendingStatus is the "still computing" state: an empty check-run
// conclusion (yellow in-progress on GitHub) and a pending commit status.
func gatePendingStatus() gateStatus {
	return gateStatus{
		state:       "pending",
		conclusion:  "",
		description: "Waiting for the base branch snapshot to compare against",
		title:       "Quality gate in progress",
		summary:     "Hibou received this change and is waiting on the data it needs to evaluate the quality gate (usually the target branch's latest snapshot). This check updates automatically once the comparison is available.",
	}
}

func (a *GatePublisher) recomputeOpenPRsForTargetRef(ctx context.Context, repoID, targetRefID uuid.UUID) {
	refs, err := a.store.ListOpenPRRefs(ctx, repoID)
	if err != nil {
		a.log.Error().Err(err).Str("repo_id", repoID.String()).Msg("list open PR refs for base-branch recompute")
		return
	}
	for i := range refs {
		if refs[i].MergeTargetRefID.Valid && refs[i].MergeTargetRefID.UUID == targetRefID {
			a.PublishGateForRef(ctx, refs[i].ID)
		}
	}
}

// handleRecomputeRequested re-evaluates the gate for the PR head(s) affected by a
// gate-relevant change. Payload keys: "ref_id" (a single PR ref), else "repo_id"
// (all open PRs in the repo), else "org_id" (all open PRs across the org's repos).
func (a *GatePublisher) handleRecomputeRequested(ctx context.Context, payload any) {
	if a == nil || a.store == nil || a.delta == nil {
		return
	}
	data, _ := payload.(map[string]any)

	// snapshot_id is what artifact processing knows: same routing as a completed
	// scan (PR ref → publish, branch ref → refresh PRs targeting it).
	if snapshotID := snapshotIDFromPayload(payload); snapshotID != uuid.Nil {
		a.publishForSnapshotID(ctx, snapshotID)
		return
	}
	if refID := uuidFromString(valueString(data, "ref_id")); refID != uuid.Nil {
		a.PublishGateForRef(ctx, refID)
		return
	}
	if repoID := uuidFromString(valueString(data, "repo_id")); repoID != uuid.Nil {
		a.recomputeOpenPRsForRepo(ctx, repoID)
		return
	}
	if orgID := uuidFromString(valueString(data, "org_id")); orgID != uuid.Nil {
		repoIDs, err := a.store.ListRepoIDsByOrg(ctx, orgID)
		if err != nil {
			a.log.Error().Err(err).Str("org_id", orgID.String()).Msg("list repos for gate recompute")
			return
		}
		for _, repoID := range repoIDs {
			a.recomputeOpenPRsForRepo(ctx, repoID)
		}
	}
}

func (a *GatePublisher) recomputeOpenPRsForRepo(ctx context.Context, repoID uuid.UUID) {
	refs, err := a.store.ListOpenPRRefs(ctx, repoID)
	if err != nil {
		a.log.Error().Err(err).Str("repo_id", repoID.String()).Msg("list open PR refs for gate recompute")
		return
	}
	for i := range refs {
		a.PublishGateForRef(ctx, refs[i].ID)
	}
}

// PublishGateForRef re-evaluates and re-publishes the gate check for a PR ref's
// current head snapshot. Safe to call from any gate-affecting code path; a no-op
// for non-PR refs. A PR head with no analyzed snapshot gets the in-progress
// "waiting for upload" check — same context, so branch protection blocks the
// merge until the real verdict replaces it.
func (a *GatePublisher) PublishGateForRef(ctx context.Context, refID uuid.UUID) {
	if a == nil || a.store == nil || a.delta == nil || refID == uuid.Nil {
		return
	}
	ref, err := a.store.GetRefByID(ctx, refID)
	if err != nil {
		a.log.Error().Err(err).Str("ref_id", refID.String()).Msg("load ref for gate recompute")
		return
	}
	if ref.ID == uuid.Nil || ref.RefType != dbgen.RefTypePullRequest {
		return
	}
	snapshot, err := a.store.GetLatestSnapshotByRef(ctx, ref.ID)
	if err != nil || snapshot.ID == uuid.Nil {
		// No analyzed head snapshot yet (PR opened / pushed, CI not uploaded):
		// post the pending check on the webhook-tracked head so the PR is
		// blocked-and-informative instead of blank.
		a.publishGateWaitingForUpload(ctx, ref)
		return
	}
	if snapshot.Status != dbgen.SnapshotStatusComplete && snapshot.Status != dbgen.SnapshotStatusActive {
		// Same guard publishForSnapshotID has had all along; without it this
		// path evaluated a webhook-created pending placeholder — zero findings
		// against the full base — and published "passed" on a PR that
		// introduced a known-exploited dependency (dogfood, PR #11 retest).
		a.publishGateWaitingForUpload(ctx, ref)
		return
	}
	if head, stale := snapshotBehindHead(snapshot, ref); stale {
		a.publishGateWaitingForHead(ctx, snapshot, ref, head)
		return
	}
	if state := a.advisoryScanState(ctx, snapshot.ID); state != scanStateReady {
		a.publishGateScanPending(ctx, snapshot, ref, snapshot.CommitSha, state)
		return
	}
	annotation, ok := a.buildGateContext(ctx, snapshot, ref)
	if !ok {
		// Head is analyzed but the comparison is not computable yet (target
		// branch has no snapshot / merge target unknown).
		a.publishGatePendingForRef(ctx, snapshot, ref)
		return
	}
	if state := a.advisoryScanState(ctx, annotation.targetSnapshot.ID); state != scanStateReady {
		a.publishGateScanPending(ctx, snapshot, ref, snapshot.CommitSha, state)
		return
	}
	a.evaluateAndPublish(ctx, annotation)
}

// Advisory-scan readiness of a snapshot as gate input (PLAN §1).
type advisoryScanState string

const (
	scanStateReady   advisoryScanState = "ready"
	scanStateWaiting advisoryScanState = "waiting"
	scanStateFailed  advisoryScanState = "failed"
)

// advisoryScanState reports whether a snapshot's findings are complete enough
// for an honest verdict. Ready when: advisory scanning is disabled on this
// instance; the snapshot has no components (nothing to scan — coverage-only
// and SARIF-only uploads must still get their check, see
// snapshot_processing's recompute note); or ANY advisory scan has completed —
// a newer re-scan running on top of a completed one must not flip a published
// verdict back to pending. Degrades open on a readiness-read error: a broken
// readiness query must not silence every gate on the instance.
func (a *GatePublisher) advisoryScanState(ctx context.Context, snapshotID uuid.UUID) advisoryScanState {
	if !a.advisoryScanEnabled || snapshotID == uuid.Nil {
		return scanStateReady
	}
	readiness, err := a.store.GetGateScanReadiness(ctx, snapshotID)
	if err != nil {
		a.log.Error().Err(err).Str("snapshot_id", snapshotID.String()).Msg("read gate scan readiness; evaluating without the guard")
		return scanStateReady
	}
	switch {
	case readiness.HasCompleteScan, !readiness.HasComponents:
		return scanStateReady
	case readiness.LatestStatus == "failed":
		return scanStateFailed
	default:
		// Scan pending/running — or not yet created: processing enqueues the
		// scan asynchronously, so "components but no scan row" is the enqueue
		// race, not a snapshot that will never be scanned.
		return scanStateWaiting
	}
}

// publishGateScanPending posts the in-progress state while the snapshot's
// advisory scan is not a done deal. No verdict is persisted.
func (a *GatePublisher) publishGateScanPending(ctx context.Context, snapshot dbgen.Snapshot, ref dbgen.Ref, headSHA string, state advisoryScanState) {
	repo, provider, owner, name, ok := a.loadGateRepository(ctx, ref)
	if !ok {
		return
	}
	orgSlug, err := a.store.GetOrgSlug(ctx, repo.OrgID)
	if err != nil {
		a.log.Debug().Err(err).Str("org_id", repo.OrgID.String()).Msg("load org slug for scan-pending gate check")
	}
	annotation := &gateContext{
		snapshot: snapshot,
		prRef:    ref,
		repo:     repo,
		provider: provider,
		owner:    owner,
		name:     name,
		orgSlug:  orgSlug,
	}
	status := gatePendingStatus()
	if state == scanStateFailed {
		status.description = "Advisory scan failed — retrying"
		status.title = "Quality gate — advisory scan failed, will retry"
		status.summary = fmt.Sprintf(
			"The advisory scan for commit %s failed, so the dependency findings are incomplete and no verdict can be published. Hibou retries scans automatically; this check updates when a scan completes.",
			shortCommit(headSHA))
	} else {
		status.description = "Advisory scan in progress for " + shortCommit(headSHA)
		status.title = "Quality gate — advisory scan in progress"
		status.summary = fmt.Sprintf(
			"The analysis upload for commit %s arrived and its components are being matched against advisory databases. Publishing a verdict before that finishes would miss dependency findings entirely, so this check waits and updates automatically.",
			shortCommit(headSHA))
	}
	a.publishGateStatusOnly(ctx, annotation, status)
}

// publishGateWaitingForUpload posts the in-progress check for a PR whose
// current head has NO analyzed snapshot at all. Same check context as the
// verdict ("hibou/security") — forges cannot delete checks, so the pending
// state is later updated in place rather than removed.
func (a *GatePublisher) publishGateWaitingForUpload(ctx context.Context, ref dbgen.Ref) {
	head := ""
	if ref.LatestCommitSha.Valid {
		head = strings.TrimSpace(ref.LatestCommitSha.String)
	}
	if head == "" {
		// Nothing to attach a check to.
		return
	}
	repo, provider, owner, name, ok := a.loadGateRepository(ctx, ref)
	if !ok {
		return
	}
	orgSlug, err := a.store.GetOrgSlug(ctx, repo.OrgID)
	if err != nil {
		a.log.Debug().Err(err).Str("org_id", repo.OrgID.String()).Msg("load org slug for waiting-for-upload gate check")
	}
	annotation := &gateContext{
		snapshot: dbgen.Snapshot{RefID: ref.ID, CommitSha: head},
		prRef:    ref,
		repo:     repo,
		provider: provider,
		owner:    owner,
		name:     name,
		orgSlug:  orgSlug,
	}
	status := gatePendingStatus()
	status.description = "Waiting for upload for " + shortCommit(head)
	status.title = "Quality gate — waiting for upload"
	status.summary = fmt.Sprintf(
		"Hibou has not received an analysis upload (SBOM/SARIF/coverage) for commit %s yet. CI's upload publishes the real verdict here; if branch protection requires this check, the merge stays blocked until then.",
		shortCommit(head))
	a.publishGateStatusOnly(ctx, annotation, status)
}

// ReconcileUnsynced retries publishing gate checks whose last forge post failed
// (forge_synced_at IS NULL). Idempotent: re-runs the full publish for each PR ref.
func (a *GatePublisher) ReconcileUnsynced(ctx context.Context, limit int32) {
	if a == nil || a.store == nil {
		return
	}
	refIDs, err := a.store.ListUnsyncedPRCheckRefIDs(ctx, limit)
	if err != nil {
		a.log.Error().Err(err).Msg("list unsynced pr_checks for reconcile")
		return
	}
	for _, refID := range refIDs {
		a.PublishGateForRef(ctx, refID)
	}
}

// StartReconcileLoop periodically retries unsynced gate checks until ctx is done.
// Wire from the server's background loops (single call; safe to leave unwired).
func (a *GatePublisher) StartReconcileLoop(ctx context.Context, interval time.Duration) {
	if a == nil || interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.ReconcileUnsynced(ctx, 100)
		}
	}
}

func (a *GatePublisher) evaluateAndPublish(ctx context.Context, annotation *gateContext) {
	gateResult, deltaResult, ok := a.evaluateGate(ctx, annotation)
	if !ok {
		return
	}
	enforcement := a.loadEnforcementMode(ctx, annotation)
	status := gateForgeStatus(gateResult, deltaResult, enforcement)
	a.publishGate(ctx, annotation, gateResult, deltaResult, status)
	a.upsertGateComment(ctx, annotation, gateResult, deltaResult, status)
	a.publishGateEvent(ctx, status.eventType, annotation.repo, annotation.snapshot, gateResult)
	a.broadcastGateUpdate(ctx, annotation, gateResult, status)
}

// gateCommentMarker identifies Hibou's sticky PR comment so re-runs edit the
// same one instead of posting a new comment each time.
const gateCommentMarker = "<!-- hibou:quality-gate -->"

// CommentProvider is implemented by forges that can maintain a single sticky PR
// comment. Providers without it skip the comment.
type CommentProvider interface {
	SupportsPRComments() bool
	UpsertPRComment(ctx context.Context, owner, repo string, prNumber int, marker, body string) error
}

func (a *GatePublisher) upsertGateComment(ctx context.Context, annotation *gateContext, gateResult *delta.GateResult, deltaResult *delta.DeltaResult, status gateStatus) {
	provider, ok := annotation.provider.(CommentProvider)
	if !ok || !provider.SupportsPRComments() {
		return
	}
	prNumber, err := strconv.Atoi(prNumberFromRefName(annotation.prRef.Name))
	if err != nil {
		return
	}
	body := a.buildGateCommentBody(annotation, gateResult, deltaResult, status)
	if err := provider.UpsertPRComment(ctx, annotation.owner, annotation.name, prNumber, gateCommentMarker, body); err != nil {
		a.log.Warn().Err(err).Str("repo_id", annotation.repo.ID.String()).Msg("upsert PR quality-gate comment")
	}
}

// malwareFindings returns the PR's new findings that are known-malicious
// packages — the one class of finding that must never read like an ordinary
// threshold breach on the PR.
func malwareFindings(deltaResult *delta.DeltaResult) []store.Vulnerability {
	if deltaResult == nil {
		return nil
	}
	malware := make([]store.Vulnerability, 0, 2)
	for _, finding := range deltaResult.New {
		if strings.EqualFold(strings.TrimSpace(finding.Type), "malware") {
			malware = append(malware, finding)
		}
	}
	return malware
}

// malwareAlertMarkdown renders the unmissable malware callout. GitHub and
// Forgejo render [!CAUTION] as a red alert box; forges without alert support
// degrade to a plain blockquote, which still reads correctly.
func malwareAlertMarkdown(malware []store.Vulnerability) string {
	if len(malware) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("> [!CAUTION]\n")
	b.WriteString("> ### 🚨 Malware detected in this change\n")
	b.WriteString("> This pull request introduces known-malicious packages. **Do not merge.** Remove these packages entirely — do not upgrade them, and rotate any credentials exposed to environments where they were installed.\n")
	b.WriteString(">\n> | Package | Advisory | Severity |\n> | --- | --- | --- |\n")
	for _, finding := range malware {
		fmt.Fprintf(&b, "> | `%s` | %s | %s |\n", componentLabel(finding), advisoryMarkdownLink(finding.PrimaryIdentifierValue), string(finding.Severity))
	}
	return b.String()
}

// componentLabel names a finding's package as name@version, falling back to
// the finding title.
func componentLabel(finding store.Vulnerability) string {
	if finding.ComponentName != nil && strings.TrimSpace(*finding.ComponentName) != "" {
		label := strings.TrimSpace(*finding.ComponentName)
		if finding.ComponentVersion != nil && strings.TrimSpace(*finding.ComponentVersion) != "" {
			label += "@" + strings.TrimSpace(*finding.ComponentVersion)
		}
		return label
	}
	return finding.Title
}

// advisoryMarkdownLink links an advisory id to its public database when the id
// family is recognized; unrecognized ids render as plain text.
func advisoryMarkdownLink(identifier string) string {
	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		return "—"
	}
	upper := strings.ToUpper(identifier)
	switch {
	case strings.HasPrefix(upper, "GHSA-"):
		return fmt.Sprintf("[%s](https://github.com/advisories/%s)", identifier, identifier)
	case strings.HasPrefix(upper, "MAL-"), strings.HasPrefix(upper, "CVE-"):
		return fmt.Sprintf("[%s](https://osv.dev/vulnerability/%s)", identifier, identifier)
	}
	return identifier
}

// severityChips summarizes new findings as compact per-severity counts,
// worst first: "🔴 2 critical · 🟠 1 high".
func severityChips(newFindings []store.Vulnerability) string {
	counts := map[string]int{}
	for _, finding := range newFindings {
		counts[strings.ToLower(string(finding.Severity))]++
	}
	order := []struct{ key, dot string }{
		{"critical", "🔴"}, {"high", "🟠"}, {"medium", "🟡"}, {"unknown", "⚫"}, {"low", "🔵"}, {"info", "⚪"},
	}
	chips := make([]string, 0, len(order))
	for _, level := range order {
		if counts[level.key] > 0 {
			chips = append(chips, fmt.Sprintf("%s %d %s", level.dot, counts[level.key], level.key))
		}
	}
	return strings.Join(chips, " · ")
}

// isMalwareReason recognizes the reason line evaluateMalwareBlock produces so
// the comment does not say the same thing twice when the alert box is shown.
func isMalwareReason(reason string) bool {
	return strings.Contains(reason, "malicious packages introduced")
}

func (a *GatePublisher) buildGateCommentBody(annotation *gateContext, gateResult *delta.GateResult, deltaResult *delta.DeltaResult, status gateStatus) string {
	malware := malwareFindings(deltaResult)

	verdict := "✅ Quality gate passed"
	switch {
	case len(malware) > 0:
		verdict = "🚨 Malware detected — do not merge"
	case status.state == "failure":
		verdict = "❌ Quality gate failed"
	case status.conclusion == "neutral":
		verdict = "⚠️ Quality gate — advisory"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "### Hibou · %s\n\n", verdict)

	if alert := malwareAlertMarkdown(malware); alert != "" {
		b.WriteString(alert)
		b.WriteString("\n")
	}

	// Remaining gate reasons — the malware alert already covers its own.
	reasons := make([]string, 0)
	for _, reason := range gateReasons(gateResult) {
		if len(malware) > 0 && isMalwareReason(reason) {
			continue
		}
		reasons = append(reasons, reason)
	}
	if len(reasons) > 0 {
		b.WriteString("**Gate findings**\n\n")
		for _, reason := range reasons {
			fmt.Fprintf(&b, "- %s\n", reason)
		}
		b.WriteString("\n")
	}

	if deltaResult != nil {
		fmt.Fprintf(&b, "| 🆕 New | ✅ Resolved | ♻️ Unchanged |\n| :---: | :---: | :---: |\n| %d | %d | %d |\n\n",
			len(deltaResult.New), len(deltaResult.Resolved), deltaResult.Unchanged)
		if chips := severityChips(deltaResult.New); chips != "" {
			fmt.Fprintf(&b, "**New by severity:** %s\n\n", chips)
		}
	}

	links := make([]string, 0, 2)
	if prURL := a.gateTargetURL(annotation); prURL != "" {
		links = append(links, fmt.Sprintf("[Review coverage & diff on Hibou](%s)", prURL))
	}
	if repoURL := a.repoOverviewURL(annotation); repoURL != "" {
		links = append(links, fmt.Sprintf("[Open repository in Hibou](%s)", repoURL))
	}
	if len(links) > 0 {
		b.WriteString(strings.Join(links, " · "))
		b.WriteString("\n")
	}

	// No timestamp: the forge already shows "edited X ago", and a
	// deterministic body is what lets UpsertPRComment skip no-op edits.
	fmt.Fprintf(&b, "\n<sub>%s</sub>\n", provenanceLine(annotation))
	return b.String()
}

// provenanceLine names what was evaluated — and, when CI recorded it, what was
// ACTUALLY built (PLAN §2): a pull_request build tests an ephemeral merge of
// the head onto the base, not the head itself. SHAs are written in full on
// purpose: every forge auto-links full commit SHAs in PR comments and renders
// them short, which gives working links on self-hosted instances without this
// side knowing any web URL.
func provenanceLine(annotation *gateContext) string {
	head := strings.TrimSpace(annotation.snapshot.CommitSha)
	merge := strings.TrimSpace(annotation.snapshot.MergeCommitSha)
	base := strings.TrimSpace(annotation.snapshot.BaseCommitSha)
	if merge == "" && base == "" {
		return "evaluated commit " + head
	}
	line := "evaluated commit " + head + " (head)"
	if merge != "" {
		line += " — tested as merge " + merge
	}
	if base != "" {
		joiner := " onto "
		if merge == "" {
			joiner = " — tested against "
		}
		line += joiner + annotation.targetRef.Name + " @ " + base
	}
	return line
}

func (a *GatePublisher) repoOverviewURL(annotation *gateContext) string {
	if a.baseURL == "" || annotation.orgSlug == "" {
		return ""
	}
	return fmt.Sprintf("%s/orgs/%s/%s/repos/%s", a.baseURL, annotation.repo.Provider, annotation.orgSlug, annotation.repo.Slug)
}

func shortCommit(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}

// broadcastGateUpdate pushes a live PR-gate refresh to subscribed browsers over
// the WS fanout (cross-replica via Postgres LISTEN/NOTIFY). No-op when no live
// notifier is configured. The payload carries enough to match a PR gate page.
func (a *GatePublisher) broadcastGateUpdate(ctx context.Context, annotation *gateContext, gateResult *delta.GateResult, status gateStatus) {
	if a.live == nil {
		return
	}
	payload, err := json.Marshal(map[string]any{
		"provider":  annotation.repo.Provider,
		"org_slug":  annotation.orgSlug,
		"repo_slug": annotation.repo.Slug,
		"pr_number": prNumberFromRefName(annotation.prRef.Name),
		"head_sha":  annotation.snapshot.CommitSha,
		"state":     status.state,
		"passed":    gateResult != nil && gateResult.Passed,
	})
	if err != nil {
		return
	}
	a.live.PublishGateUpdate(ctx, gateUpdateTopic, payload)
}

type gateContext struct {
	snapshot       dbgen.Snapshot
	targetSnapshot dbgen.Snapshot
	prRef          dbgen.Ref
	targetRef      dbgen.Ref
	repo           dbgen.Repository
	provider       Provider
	owner          string
	name           string
	orgSlug        string
	// claimsVerified: the delta base is the CURRENT base head, per the CI
	// upload's recorded base commit — the precondition for recording "this PR
	// fixes X" claims (PLAN §5).
	claimsVerified bool
}

func snapshotIDFromPayload(payload any) uuid.UUID {
	data, _ := payload.(map[string]any)
	return uuidFromString(valueString(data, "snapshot_id"))
}

func (a *GatePublisher) buildGateContext(ctx context.Context, snapshot dbgen.Snapshot, ref dbgen.Ref) (*gateContext, bool) {
	targetRef, targetSnapshot, ok := a.loadPRTargetContext(ctx, ref)
	if !ok {
		return nil, false
	}
	// Claims honesty (PLAN §5): "this PR fixes X" may only be asserted when
	// the delta was computed against the base branch AS IT IS NOW. The CI
	// upload records which base commit the build merged against; when it
	// matches the latest base snapshot, the claim is verified.
	latestTargetCommit := targetSnapshot.CommitSha
	claimsVerified := snapshot.BaseCommitSha != "" && snapshot.BaseCommitSha == latestTargetCommit
	// Delta honesty (PLAN §2/§5): when CI built against an OLDER base commit
	// and that base's snapshot still exists, compare against it — against a
	// newer base, everything the base gained since reads as "resolved by this
	// PR", which is how July PRs claimed 94 fixes each.
	if !claimsVerified && snapshot.BaseCommitSha != "" {
		if exact, err := a.store.GetSnapshotByRefCommit(ctx, targetRef.ID, snapshot.BaseCommitSha); err == nil &&
			exact.ID != uuid.Nil && (exact.Status == dbgen.SnapshotStatusComplete || exact.Status == dbgen.SnapshotStatusActive) {
			targetSnapshot = exact
		}
	}
	repo, provider, owner, name, ok := a.loadGateRepository(ctx, ref)
	if !ok {
		return nil, false
	}
	orgSlug, err := a.store.GetOrgSlug(ctx, repo.OrgID)
	if err != nil {
		a.log.Debug().Err(err).Str("org_id", repo.OrgID.String()).Msg("load org slug for gatePublisher deep link")
	}
	return &gateContext{
		snapshot:       snapshot,
		targetSnapshot: targetSnapshot,
		prRef:          ref,
		targetRef:      targetRef,
		repo:           repo,
		provider:       provider,
		owner:          owner,
		name:           name,
		orgSlug:        orgSlug,
		claimsVerified: claimsVerified,
	}, true
}

func (a *GatePublisher) loadPRTargetContext(ctx context.Context, ref dbgen.Ref) (dbgen.Ref, dbgen.Snapshot, bool) {
	if !ref.MergeTargetRefID.Valid {
		a.log.Debug().Str("ref_id", ref.ID.String()).Msg("skip PR annotation without merge target ref")
		return dbgen.Ref{}, dbgen.Snapshot{}, false
	}
	targetRef, err := a.store.GetRefByID(ctx, ref.MergeTargetRefID.UUID)
	if err != nil {
		a.log.Error().Err(err).Str("target_ref_id", ref.MergeTargetRefID.UUID.String()).Msg("load target ref for gatePublisher")
		return dbgen.Ref{}, dbgen.Snapshot{}, false
	}
	if targetRef.ID == uuid.Nil {
		a.log.Debug().Str("target_ref_id", ref.MergeTargetRefID.UUID.String()).Msg("skip PR annotation without target ref")
		return dbgen.Ref{}, dbgen.Snapshot{}, false
	}
	targetSnapshot, err := a.store.GetLatestSnapshotByRef(ctx, ref.MergeTargetRefID.UUID)
	if err != nil {
		a.log.Error().Err(err).Str("target_ref_id", ref.MergeTargetRefID.UUID.String()).Msg("load target snapshot for gatePublisher")
		return dbgen.Ref{}, dbgen.Snapshot{}, false
	}
	if targetSnapshot.ID == uuid.Nil {
		a.log.Debug().Str("target_ref_id", ref.MergeTargetRefID.UUID.String()).Msg("skip PR annotation without target snapshot")
		return dbgen.Ref{}, dbgen.Snapshot{}, false
	}
	return targetRef, targetSnapshot, true
}

func (a *GatePublisher) loadGateRepository(ctx context.Context, ref dbgen.Ref) (dbgen.Repository, Provider, string, string, bool) {
	repo, err := a.store.GetRepoByID(ctx, ref.RepoID)
	if err != nil {
		a.log.Error().Err(err).Str("repo_id", ref.RepoID.String()).Msg("load repository for gatePublisher")
		return dbgen.Repository{}, nil, "", "", false
	}
	if repo.ID == uuid.Nil {
		return dbgen.Repository{}, nil, "", "", false
	}
	provider := a.forges[repo.Provider]
	if provider == nil {
		a.log.Debug().Str("provider", repo.Provider).Str("repo_id", repo.ID.String()).Msg("skip annotation without forge provider")
		return dbgen.Repository{}, nil, "", "", false
	}
	owner, name, ok := repoCoordinates(repo)
	if !ok {
		a.log.Debug().Str("repo_id", repo.ID.String()).Msg("skip annotation without repository coordinates")
		return dbgen.Repository{}, nil, "", "", false
	}
	return repo, provider, owner, name, true
}

func (a *GatePublisher) evaluateGate(ctx context.Context, annotation *gateContext) (*delta.GateResult, *delta.DeltaResult, bool) {
	deltaResult, err := a.delta.ComputeDelta(ctx, annotation.snapshot.ID, annotation.targetSnapshot.ID)
	if err != nil {
		a.log.Error().Err(err).Str("snapshot_id", annotation.snapshot.ID.String()).Msg("compute PR delta")
		return nil, nil, false
	}
	gateConfig := a.loadGateConfig(ctx, annotation)
	if gateConfig == nil {
		gateConfig = &delta.GateConfig{}
	}
	gateConfig.HeadSnapshotID = annotation.snapshot.ID
	gateConfig.BaseSnapshotID = annotation.targetSnapshot.ID
	gateResult, err := a.delta.EvaluateGatesWithConfig(ctx, annotation.repo.ID, annotation.repo.OrgID, deltaResult, gateConfig)
	if err != nil {
		a.log.Error().Err(err).Str("repo_id", annotation.repo.ID.String()).Msg("evaluate PR gates")
		return nil, nil, false
	}
	return gateResult, deltaResult, true
}

func (a *GatePublisher) loadGateConfig(ctx context.Context, annotation *gateContext) *delta.GateConfig {
	if a.repoConfigLoader == nil {
		return nil
	}
	gateConfig, err := a.repoConfigLoader.LoadGateConfig(ctx, annotation.repo.Provider, annotation.owner, annotation.name, annotation.repo.DefaultBranch, annotation.targetRef.Name)
	if err != nil {
		a.log.Warn().Err(err).Str("repo_id", annotation.repo.ID.String()).Msg("load repo config for gatePublisher, falling back to DB gates")
		return nil
	}
	return gateConfig
}

func (a *GatePublisher) loadEnforcementMode(ctx context.Context, annotation *gateContext) string {
	if a.repoConfigLoader == nil {
		return enforcementAdvisory
	}
	enforcement, err := a.repoConfigLoader.LoadEnforcement(ctx, annotation.repo.Provider, annotation.owner, annotation.name, annotation.repo.DefaultBranch, annotation.targetRef.Name)
	if err != nil {
		a.log.Warn().Err(err).Str("repo_id", annotation.repo.ID.String()).Msg("load gate enforcement, defaulting to advisory")
		return enforcementAdvisory
	}
	if strings.TrimSpace(enforcement) == "" {
		return enforcementAdvisory
	}
	return enforcement
}

// gateStatus is the resolved forge representation of a gate outcome, covering
// both the commit-status shape (state + short description) and the richer
// check-run shape (conclusion + markdown title/summary).
type gateStatus struct {
	state       string // commit-status: success|failure|pending|error
	conclusion  string // check-run: success|failure|neutral
	description string // short, commit-status (<=140 chars)
	title       string // check-run title
	summary     string // check-run markdown body
	annotations []CheckRunAnnotation
	enforcement string
	eventType   events.Type
}

// gateForgeStatus maps a gate result + enforcement mode to what we publish.
// Advisory (default) never blocks: check runs use the neutral conclusion, and
// commit-status-only forges post success with a warning in the description.
func gateForgeStatus(gateResult *delta.GateResult, deltaResult *delta.DeltaResult, enforcement string) gateStatus {
	// Inline code annotations for new findings (rendered on the PR by forges that
	// support a native check run; ignored on commit-status-only forges).
	annotations := gateAnnotations(deltaResult)

	if gateResult != nil && gateResult.Passed {
		return gateStatus{
			state:       "success",
			conclusion:  "success",
			description: "All gates passed",
			title:       "Quality gate passed",
			summary:     "All Hibou quality gates passed for this change.",
			annotations: annotations,
			enforcement: enforcement,
			eventType:   events.GatePassed,
		}
	}

	reasons := gateReasons(gateResult)
	malware := malwareFindings(deltaResult)
	short := gateFailureDescription(reasons, deltaResult)
	summary := gateFailureSummary(reasons, enforcement, malware)

	title := "Quality gate failed"
	advisoryTitle := "Quality gate (advisory)"
	if len(malware) > 0 {
		// Malware must be legible from the check list alone, before anyone
		// opens the details.
		title = "🚨 Malware detected — quality gate failed"
		advisoryTitle = "🚨 Malware detected (advisory)"
		short = truncate("🚨 "+short, 140)
	}

	if enforcement == enforcementBlocking {
		return gateStatus{
			state:       "failure",
			conclusion:  "failure",
			description: short,
			title:       title,
			summary:     summary,
			annotations: annotations,
			enforcement: enforcement,
			eventType:   events.GateFailed,
		}
	}
	// Advisory: informational, never blocks. Commit statuses have no neutral state,
	// so post success and surface the verdict in the description; check runs use the
	// neutral conclusion.
	return gateStatus{
		state:       "success",
		conclusion:  "neutral",
		description: truncate("Advisory: "+short, 140),
		title:       advisoryTitle,
		summary:     summary,
		annotations: annotations,
		enforcement: enforcement,
		eventType:   events.GateFailed,
	}
}

// maxCheckRunAnnotations is the GitHub Checks API per-request annotation cap.
const maxCheckRunAnnotations = 50

// gateAnnotations builds inline code annotations from the PR's new findings that
// carry a file/line location. Capped at the forge per-request limit.
func gateAnnotations(deltaResult *delta.DeltaResult) []CheckRunAnnotation {
	if deltaResult == nil {
		return nil
	}
	out := make([]CheckRunAnnotation, 0, len(deltaResult.New))
	for i := range deltaResult.New {
		finding := deltaResult.New[i]
		if finding.FilePath == nil || strings.TrimSpace(*finding.FilePath) == "" || finding.StartLine == nil {
			continue
		}
		start := int(*finding.StartLine)
		end := start
		if finding.EndLine != nil && int(*finding.EndLine) >= start {
			end = int(*finding.EndLine)
		}
		message := strings.TrimSpace(finding.Title)
		if message == "" {
			message = "New security finding introduced by this change."
		}
		out = append(out, CheckRunAnnotation{
			Path:      strings.TrimPrefix(strings.TrimSpace(*finding.FilePath), "./"),
			StartLine: start,
			EndLine:   end,
			Level:     annotationLevel(string(finding.Severity)),
			Title:     "hibou: new " + strings.ToLower(string(finding.Severity)) + " finding",
			Message:   message,
		})
		if len(out) >= maxCheckRunAnnotations {
			break
		}
	}
	return out
}

// annotationLevel maps a finding severity to a forge annotation level
// (notice|warning|failure).
func annotationLevel(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "high":
		return "failure"
	case "medium":
		return "warning"
	default:
		return "notice"
	}
}

func gateReasons(gateResult *delta.GateResult) []string {
	if gateResult == nil {
		return nil
	}
	return gateResult.Reasons
}

func gateFailureDescription(reasons []string, deltaResult *delta.DeltaResult) string {
	if len(reasons) > 0 {
		return truncate(strings.Join(reasons, "; "), 140)
	}
	count := 0
	if deltaResult != nil {
		count = len(deltaResult.New)
	}
	return fmt.Sprintf("%d new vulnerabilities", count)
}

func gateFailureSummary(reasons []string, enforcement string, malware []store.Vulnerability) string {
	var b strings.Builder
	if alert := malwareAlertMarkdown(malware); alert != "" {
		b.WriteString(alert)
		b.WriteString("\n")
	}
	if enforcement == enforcementBlocking {
		b.WriteString("**Quality gate failed.** This check is enforcing — it can block the merge if required by branch protection.\n\n")
	} else {
		b.WriteString("**Quality gate would fail** (advisory — this check does not block the merge).\n\n")
	}
	listed := 0
	for _, reason := range reasons {
		if len(malware) > 0 && isMalwareReason(reason) {
			continue
		}
		b.WriteString("- ")
		b.WriteString(reason)
		b.WriteString("\n")
		listed++
	}
	if listed == 0 && len(malware) == 0 {
		b.WriteString("- One or more new findings crossed the configured thresholds.\n")
	}
	b.WriteString("\nOpen the details link to triage: dismiss a false positive, add a VEX statement, or override the gate — the check updates automatically, no CI re-run required.")
	return b.String()
}

// CheckRunProvider is implemented by forges that support a native check run with a
// markdown summary and its own conclusion (GitHub App mode). Providers that do not
// implement it fall back to the commit status. CreateOrUpdateCheckRun must be
// idempotent per (head SHA, name): update the existing run in place, else create.
type CheckRunProvider interface {
	SupportsCheckRuns() bool
	CreateOrUpdateCheckRun(ctx context.Context, owner, repo string, run CheckRun) (string, error)
}

type CheckRun struct {
	Name    string
	HeadSHA string
	// Conclusion is success|failure|neutral, or empty for "still running" —
	// which forges render as a pending/in-progress check that a later update
	// resolves.
	Conclusion  string
	Title       string
	Summary     string
	DetailsURL  string
	Annotations []CheckRunAnnotation
}

// CheckRunAnnotation is an inline code annotation on the PR diff. Only forges with
// a native check run that supports annotations (GitHub) render these; others ignore
// them and fall back to the commit status.
type CheckRunAnnotation struct {
	Path      string // repo-relative file path
	StartLine int
	EndLine   int
	Level     string // notice|warning|failure
	Title     string
	Message   string
}

// publishGate posts the gate outcome to the forge (native check run when the
// provider supports it, else a commit status) and persists it to pr_checks so
// re-evaluations (VEX dismissal, override, advisory re-scan) idempotently re-sync
// the same (repo, head SHA, context) row without a CI re-run. Post and persistence
// are decoupled: a failed post is recorded (forge_synced_at NULL + last_error) for
// the reconcile loop to retry.
func (a *GatePublisher) publishGate(ctx context.Context, annotation *gateContext, gateResult *delta.GateResult, deltaResult *delta.DeltaResult, status gateStatus) {
	targetURL, externalID, syncErr := a.pushGateToForge(ctx, annotation, status)
	a.persistGate(ctx, annotation, gateResult, status, targetURL, externalID, syncErr, deltaResult)
}

// publishGateStatusOnly pushes a check to the forge without recording a verdict.
// Used for the in-progress state, where there is no outcome to persist yet.
func (a *GatePublisher) publishGateStatusOnly(ctx context.Context, annotation *gateContext, status gateStatus) {
	// Errors are already logged inside; a failed in-progress post is not worth
	// escalating since the next recompute overwrites it.
	_, _, _ = a.pushGateToForge(ctx, annotation, status)
}

func (a *GatePublisher) pushGateToForge(ctx context.Context, annotation *gateContext, status gateStatus) (string, string, error) {
	targetURL := a.gateTargetURL(annotation)

	var (
		syncErr    error
		externalID string
	)
	if cr, ok := annotation.provider.(CheckRunProvider); ok && cr.SupportsCheckRuns() {
		id, err := cr.CreateOrUpdateCheckRun(ctx, annotation.owner, annotation.name, CheckRun{
			Name:        securityStatusContext,
			HeadSHA:     annotation.snapshot.CommitSha,
			Conclusion:  status.conclusion,
			Title:       status.title,
			Summary:     summaryWithLink(status.summary, targetURL),
			DetailsURL:  targetURL,
			Annotations: status.annotations,
		})
		if err != nil {
			syncErr = err
			a.log.Error().Err(err).Str("repo_id", annotation.repo.ID.String()).Str("commit_sha", annotation.snapshot.CommitSha).Msg("create/update check run")
		} else {
			externalID = id
		}
	} else if err := annotation.provider.CreateCommitStatus(ctx, annotation.owner, annotation.name, annotation.snapshot.CommitSha, CommitStatus{
		State:       status.state,
		Context:     securityStatusContext,
		TargetURL:   targetURL,
		Description: status.description,
	}); err != nil {
		syncErr = err
		a.log.Error().Err(err).Str("repo_id", annotation.repo.ID.String()).Str("commit_sha", annotation.snapshot.CommitSha).Msg("create commit status")
	}

	return targetURL, externalID, syncErr
}

func summaryWithLink(summary, targetURL string) string {
	if targetURL == "" {
		return summary
	}
	return summary + fmt.Sprintf("\n\n[Review the coverage & diff on Hibou](%s)", targetURL)
}

func (a *GatePublisher) persistGate(ctx context.Context, annotation *gateContext, gateResult *delta.GateResult, status gateStatus, targetURL, externalID string, syncErr error, deltaResult *delta.DeltaResult) {
	if a.store == nil {
		return
	}
	var (
		reasons []string
		passed  bool
	)
	if gateResult != nil {
		reasons = gateResult.Reasons
		passed = gateResult.Passed
	}
	input := store.UpsertPRCheckInput{
		RepoID:      annotation.repo.ID,
		HeadSha:     annotation.snapshot.CommitSha,
		Context:     securityStatusContext,
		State:       status.state,
		Conclusion:  status.conclusion,
		Enforcement: status.enforcement,
		Passed:      passed,
		Reasons:     reasons,
		ExternalID:  externalID,
		TargetURL:   targetURL,
	}
	if annotation.prRef.ID != uuid.Nil {
		refID := annotation.prRef.ID
		input.RefID = &refID
	}
	if syncErr != nil {
		input.LastError = syncErr.Error()
	} else {
		now := time.Now().UTC()
		input.ForgeSyncedAt = &now
	}
	if annotation.claimsVerified {
		input.ClaimsBaseSha = annotation.targetSnapshot.CommitSha
	}
	if err := a.store.UpsertPRCheck(ctx, input); err != nil {
		a.log.Error().Err(err).Str("repo_id", annotation.repo.ID.String()).Str("commit_sha", annotation.snapshot.CommitSha).Msg("persist pr_check")
		return
	}

	// Best-effort: the resolved set powers the "fix in #N" chip, never the
	// gate verdict, so a failure here must not fail the publish. Recorded ONLY
	// when verified against the current base head (PLAN §5): without that, a
	// stale PR "resolves" everything the base gained since its snapshot, and a
	// mid-scan verdict once claimed 631 fixes. An unverified evaluation writes
	// an EMPTY set — clearing claims that stopped being verifiable beats
	// advertising fixes nobody made.
	if deltaResult != nil {
		fingerprints := make([]string, 0, len(deltaResult.Resolved))
		if annotation.claimsVerified {
			for _, vulnerability := range deltaResult.Resolved {
				if vulnerability.Fingerprint != "" {
					fingerprints = append(fingerprints, vulnerability.Fingerprint)
				}
			}
		}
		if err := a.store.ReplacePRCheckResolvedFingerprints(ctx, annotation.repo.ID, annotation.snapshot.CommitSha, fingerprints); err != nil {
			a.log.Debug().Err(err).Str("repo_id", annotation.repo.ID.String()).Msg("persist pr_check resolved fingerprints")
		}
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 1 {
		return s[:max]
	}
	return s[:max-1] + "…"
}

// gateTargetURL builds the deep link to the Hibou PR gate page, where a user can
// dismiss a finding / add VEX / override and flip the check live. Empty when no
// base URL is configured (e.g. local dev). Matches the SPA route shape
// /orgs/:provider/:slug/repos/:repoSlug/pulls/:pr (see site/src/router.ts).
func (a *GatePublisher) gateTargetURL(annotation *gateContext) string {
	if a.baseURL == "" || annotation.orgSlug == "" {
		return ""
	}
	base := fmt.Sprintf("%s/orgs/%s/%s/repos/%s", a.baseURL, annotation.repo.Provider, annotation.orgSlug, annotation.repo.Slug)
	// The compare page is the one PR surface (ADR-023 removed the standalone
	// gate page); base/head resolve by canonical ref name.
	if annotation.prRef.Name != "" && annotation.targetRef.Name != "" {
		return base + "/compare?base=" + url.QueryEscape(annotation.targetRef.Name) + "&head=" + url.QueryEscape(annotation.prRef.Name)
	}
	return base
}

// prNumberFromRefName extracts N from a canonical PR ref name (refs/pull/N or
// refs/merge-requests/N).
func prNumberFromRefName(name string) string {
	trimmed := strings.TrimSpace(name)
	for _, prefix := range []string{"refs/pull/", "refs/merge-requests/"} {
		if rest, ok := strings.CutPrefix(trimmed, prefix); ok {
			return strings.TrimSuffix(strings.TrimSuffix(rest, "/head"), "/merge")
		}
	}
	return ""
}

func (a *GatePublisher) publishGateEvent(ctx context.Context, eventType events.Type, repo dbgen.Repository, snapshot dbgen.Snapshot, result *delta.GateResult) {
	if a.bus == nil || result == nil {
		return
	}
	payload := map[string]any{
		"org_id":      repo.OrgID.String(),
		"repo_id":     repo.ID.String(),
		"repo_name":   repo.Name,
		"snapshot_id": snapshot.ID.String(),
	}
	if len(result.Reasons) > 0 {
		payload["reason"] = strings.Join(result.Reasons, "; ")
		payload["severity"] = "high"
	}
	a.bus.Publish(ctx, events.Event{Type: eventType, Payload: payload})
}

type GatePublisherStoreAdapter struct {
	queries *store.Queries
}

func NewGatePublisherStoreAdapter(queries *store.Queries) *GatePublisherStoreAdapter {
	return &GatePublisherStoreAdapter{queries: queries}
}

func (a *GatePublisherStoreAdapter) GetGateScanReadiness(ctx context.Context, snapshotID uuid.UUID) (dbgen.GetGateScanReadinessRow, error) {
	return a.queries.GetGateScanReadiness(ctx, snapshotID)
}

func (a *GatePublisherStoreAdapter) GetSnapshotByRefCommit(ctx context.Context, refID uuid.UUID, commitSHA string) (dbgen.Snapshot, error) {
	return a.queries.GetSnapshotRowByRefCommit(ctx, refID, commitSHA)
}

func (a *GatePublisherStoreAdapter) GetRepoByID(ctx context.Context, id uuid.UUID) (dbgen.Repository, error) {
	repo, err := a.queries.GetRepositoryByID(ctx, id)
	if err != nil || repo == nil {
		return dbgen.Repository{}, err
	}
	return dbgen.Repository{
		ID:            repo.ID,
		OrgID:         repo.OrgID,
		TeamID:        uuidToNull(repo.TeamID),
		Name:          repo.Name,
		Slug:          repo.Slug,
		Provider:      repo.Provider,
		ProviderID:    repo.ProviderID,
		DefaultBranch: repo.DefaultBranch,
		SyncState:     repo.SyncState,
		CreatedAt:     repo.CreatedAt,
		UpdatedAt:     repo.UpdatedAt,
	}, nil
}

func (a *GatePublisherStoreAdapter) GetSnapshotByID(ctx context.Context, id uuid.UUID) (dbgen.Snapshot, error) {
	snapshot, err := a.queries.GetSnapshotByID(ctx, id)
	if err != nil || snapshot == nil {
		return dbgen.Snapshot{}, err
	}
	return dbgen.Snapshot{
		ID:        snapshot.ID,
		RefID:     snapshot.RefID,
		CommitSha: snapshot.CommitSHA,
		Status:    snapshot.Status,
		CreatedAt: snapshot.CreatedAt,
	}, nil
}

func (a *GatePublisherStoreAdapter) GetRefByID(ctx context.Context, id uuid.UUID) (dbgen.Ref, error) {
	ref, err := a.queries.GetRefByID(ctx, id)
	if err != nil || ref == nil {
		return dbgen.Ref{}, err
	}
	return dbgen.Ref{
		ID:               ref.ID,
		RepoID:           ref.RepoID,
		Name:             ref.Name,
		RefType:          ref.RefType,
		ProviderID:       stringToNull(ref.ProviderID),
		MergeTargetRefID: uuidToNull(ref.MergeTargetRefID),
		LatestCommitSha:  stringToNull(ref.LatestCommitSHA),
		CreatedAt:        ref.CreatedAt,
		UpdatedAt:        ref.UpdatedAt,
	}, nil
}

// ReplacePRCheckResolvedFingerprints resolves the check row by (repo, head)
// and rewrites its resolved-fingerprint set.
func (a *GatePublisherStoreAdapter) ReplacePRCheckResolvedFingerprints(ctx context.Context, repoID uuid.UUID, headSHA string, fingerprints []string) error {
	check, err := a.queries.GetPRCheck(ctx, repoID, headSHA, securityStatusContext)
	if err != nil || check == nil {
		return err
	}
	return a.queries.ReplacePRCheckResolvedFingerprints(ctx, check.ID, fingerprints)
}

func (a *GatePublisherStoreAdapter) UpsertPRCheck(ctx context.Context, in store.UpsertPRCheckInput) error {
	_, err := a.queries.UpsertPRCheck(ctx, in)
	return err
}

// GetLatestSnapshotByRef returns the latest ANALYZED (complete/active)
// snapshot. Pending placeholders and in-flight uploads must never be gate
// input: evaluating an empty snapshot reads as "0 findings — passed".
func (a *GatePublisherStoreAdapter) GetLatestSnapshotByRef(ctx context.Context, refID uuid.UUID) (dbgen.Snapshot, error) {
	snapshot, err := a.queries.GetLatestCompleteSnapshotByRef(ctx, refID)
	if err != nil || snapshot == nil {
		return dbgen.Snapshot{}, err
	}
	return dbgen.Snapshot{
		ID:        snapshot.ID,
		RefID:     snapshot.RefID,
		CommitSha: snapshot.CommitSHA,
		Status:    snapshot.Status,
		CreatedAt: snapshot.CreatedAt,
	}, nil
}

func (a *GatePublisherStoreAdapter) GetOrgSlug(ctx context.Context, orgID uuid.UUID) (string, error) {
	org, err := a.queries.GetOrganizationByID(ctx, orgID)
	if err != nil || org == nil {
		return "", err
	}
	return org.Slug, nil
}

// ListOpenPRRefs returns PR refs that are not closed/merged (open or unknown
// state), for recomputing the gate check after a repo-scoped change.
func (a *GatePublisherStoreAdapter) ListOpenPRRefs(ctx context.Context, repoID uuid.UUID) ([]dbgen.Ref, error) {
	refs, err := a.queries.ListPullRequestRefs(ctx, repoID, 500, 0)
	if err != nil {
		return nil, err
	}
	out := make([]dbgen.Ref, 0, len(refs))
	for i := range refs {
		if state := refs[i].PrState; state != nil && *state != "open" {
			continue
		}
		ref := dbgen.Ref{ID: refs[i].ID}
		if target := refs[i].MergeTargetRefID; target != nil {
			ref.MergeTargetRefID = uuid.NullUUID{UUID: *target, Valid: true}
		}
		out = append(out, ref)
	}
	return out, nil
}

func (a *GatePublisherStoreAdapter) ListRepoIDsByOrg(ctx context.Context, orgID uuid.UUID) ([]uuid.UUID, error) {
	repos, _, err := a.queries.ListRepositoriesByOrg(ctx, orgID, 1000, 0)
	if err != nil {
		return nil, err
	}
	ids := make([]uuid.UUID, 0, len(repos))
	for i := range repos {
		ids = append(ids, repos[i].ID)
	}
	return ids, nil
}

// ListUnsyncedPRCheckRefIDs returns the PR ref IDs of gate checks whose forge post
// has not succeeded yet, for the reconcile/retry loop. Rows without a ref are
// skipped (they cannot be recomputed by ref).
func (a *GatePublisherStoreAdapter) ListUnsyncedPRCheckRefIDs(ctx context.Context, limit int32) ([]uuid.UUID, error) {
	checks, err := a.queries.ListUnsyncedPRChecks(ctx, limit)
	if err != nil {
		return nil, err
	}
	ids := make([]uuid.UUID, 0, len(checks))
	for i := range checks {
		if checks[i].RefID.Valid {
			ids = append(ids, checks[i].RefID.UUID)
		}
	}
	return ids, nil
}

func repoCoordinates(repo dbgen.Repository) (string, string, bool) {
	for _, candidate := range []string{repo.ProviderID, repo.Name, repo.Slug} {
		if owner, name, ok := splitCoordinate(candidate); ok {
			return owner, name, true
		}
	}
	return "", "", false
}

func splitCoordinate(value string) (string, string, bool) {
	trimmed := strings.TrimSpace(value)
	parts := strings.Split(trimmed, "/")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return "", "", false
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), true
}

func valueString(data map[string]any, key string) string {
	if data == nil {
		return ""
	}
	if raw, ok := data[key].(string); ok {
		return strings.TrimSpace(raw)
	}
	return ""
}

func uuidFromString(value string) uuid.UUID {
	parsed, _ := uuid.Parse(strings.TrimSpace(value))
	return parsed
}

func uuidToNull(value *uuid.UUID) uuid.NullUUID {
	if value == nil {
		return uuid.NullUUID{}
	}
	return uuid.NullUUID{UUID: *value, Valid: true}
}

func stringToNull(value *string) sql.NullString {
	if value == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *value, Valid: true}
}
