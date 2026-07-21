package forge

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/delta"
	"github.com/hibouhq/hibou/internal/events"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type Annotator struct {
	forges           map[string]Provider
	delta            *delta.Service
	bus              *events.Bus
	store            AnnotatorStore
	repoConfigLoader RepoConfigLoader
	baseURL          string
	log              zerolog.Logger
}

const securityStatusContext = "hibou/security"

type AnnotatorStore interface {
	GetRepoByID(ctx context.Context, id uuid.UUID) (dbgen.Repository, error)
	GetSnapshotByID(ctx context.Context, id uuid.UUID) (dbgen.Snapshot, error)
	GetRefByID(ctx context.Context, id uuid.UUID) (dbgen.Ref, error)
	GetLatestSnapshotByRef(ctx context.Context, refID uuid.UUID) (dbgen.Snapshot, error)
	GetOrgSlug(ctx context.Context, orgID uuid.UUID) (string, error)
	ListOpenPRRefs(ctx context.Context, repoID uuid.UUID) ([]dbgen.Ref, error)
	ListRepoIDsByOrg(ctx context.Context, orgID uuid.UUID) ([]uuid.UUID, error)
	ListUnsyncedPRCheckRefIDs(ctx context.Context, limit int32) ([]uuid.UUID, error)
	UpsertPRCheck(ctx context.Context, in store.UpsertPRCheckInput) error
}

type RepoConfigLoader interface {
	LoadWeaknessGate(ctx context.Context, providerID, owner, repo, defaultBranch, targetBranch string) (*delta.WeaknessGate, error)
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

func NewAnnotator(forges map[string]Provider, deltaSvc *delta.Service, bus *events.Bus, store AnnotatorStore, repoConfigLoader RepoConfigLoader, baseURL string, log zerolog.Logger) *Annotator {
	if forges == nil {
		forges = map[string]Provider{}
	}
	return &Annotator{
		forges:           forges,
		delta:            deltaSvc,
		bus:              bus,
		store:            store,
		repoConfigLoader: repoConfigLoader,
		baseURL:          strings.TrimRight(baseURL, "/"),
		log:              log.With().Str("component", "forge.annotator").Logger(),
	}
}

// Subscribe registers event handlers. The annotator re-publishes the PR gate
// check on scan completion AND on any gate-affecting change (VEX/false-positive
// dismissal, manual override, advisory re-eval) via GateRecomputeRequested — so
// the forge check flips live without a CI re-run. See ADR-018.
func (a *Annotator) Subscribe() {
	if a == nil || a.bus == nil {
		return
	}
	a.bus.Subscribe(events.ScanCompleted, func(ctx context.Context, event events.Event) {
		a.handleScanCompleted(ctx, event.Payload)
	})
	a.bus.Subscribe(events.GateRecomputeRequested, func(ctx context.Context, event events.Event) {
		a.handleRecomputeRequested(ctx, event.Payload)
	})
}

func (a *Annotator) handleScanCompleted(ctx context.Context, payload any) {
	if a == nil || a.store == nil || a.delta == nil {
		return
	}
	snapshotID := snapshotIDFromPayload(payload)
	if snapshotID == uuid.Nil {
		return
	}
	snapshot, err := a.store.GetSnapshotByID(ctx, snapshotID)
	if err != nil {
		a.log.Error().Err(err).Str("snapshot_id", snapshotID.String()).Msg("load snapshot for annotator")
		return
	}
	ref, err := a.store.GetRefByID(ctx, snapshot.RefID)
	if err != nil {
		a.log.Error().Err(err).Str("ref_id", snapshot.RefID.String()).Msg("load ref for annotator")
		return
	}
	if snapshot.ID == uuid.Nil || ref.ID == uuid.Nil {
		return
	}

	switch ref.RefType {
	case dbgen.RefTypePullRequest:
		if annotation, ok := a.buildAnnotationContext(ctx, snapshot, ref); ok {
			a.evaluateAndPublish(ctx, annotation)
		}
	case dbgen.RefTypeBranch:
		// The base branch moved (new snapshot on a branch): open PRs targeting it
		// now have a different delta, so refresh their gate checks — no CI re-run.
		a.recomputeOpenPRsForTargetRef(ctx, ref.RepoID, ref.ID)
	}
}

func (a *Annotator) recomputeOpenPRsForTargetRef(ctx context.Context, repoID, targetRefID uuid.UUID) {
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
func (a *Annotator) handleRecomputeRequested(ctx context.Context, payload any) {
	if a == nil || a.store == nil || a.delta == nil {
		return
	}
	data, _ := payload.(map[string]any)

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

func (a *Annotator) recomputeOpenPRsForRepo(ctx context.Context, repoID uuid.UUID) {
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
// for non-PR refs or refs without a scanned head/target snapshot.
func (a *Annotator) PublishGateForRef(ctx context.Context, refID uuid.UUID) {
	if a == nil || a.store == nil || a.delta == nil || refID == uuid.Nil {
		return
	}
	annotation, ok := a.loadAnnotationContextFromRef(ctx, refID)
	if !ok {
		return
	}
	a.evaluateAndPublish(ctx, annotation)
}

// ReconcileUnsynced retries publishing gate checks whose last forge post failed
// (forge_synced_at IS NULL). Idempotent: re-runs the full publish for each PR ref.
func (a *Annotator) ReconcileUnsynced(ctx context.Context, limit int32) {
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
func (a *Annotator) StartReconcileLoop(ctx context.Context, interval time.Duration) {
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

func (a *Annotator) evaluateAndPublish(ctx context.Context, annotation *annotationContext) {
	gateResult, deltaResult, ok := a.evaluateAnnotationGate(ctx, annotation)
	if !ok {
		return
	}
	enforcement := a.loadAnnotationEnforcement(ctx, annotation)
	status := gateForgeStatus(gateResult, deltaResult, enforcement)
	a.publishGate(ctx, annotation, gateResult, status)
	a.publishGateEvent(ctx, status.eventType, annotation.repo, annotation.snapshot, gateResult)
}

type annotationContext struct {
	snapshot       dbgen.Snapshot
	targetSnapshot dbgen.Snapshot
	prRef          dbgen.Ref
	targetRef      dbgen.Ref
	repo           dbgen.Repository
	provider       Provider
	owner          string
	name           string
	orgSlug        string
}

func snapshotIDFromPayload(payload any) uuid.UUID {
	data, _ := payload.(map[string]any)
	return uuidFromString(valueString(data, "snapshot_id"))
}

func (a *Annotator) loadAnnotationContextFromRef(ctx context.Context, refID uuid.UUID) (*annotationContext, bool) {
	ref, err := a.store.GetRefByID(ctx, refID)
	if err != nil {
		a.log.Error().Err(err).Str("ref_id", refID.String()).Msg("load ref for gate recompute")
		return nil, false
	}
	if ref.ID == uuid.Nil || ref.RefType != dbgen.RefTypePullRequest {
		return nil, false
	}
	snapshot, err := a.store.GetLatestSnapshotByRef(ctx, ref.ID)
	if err != nil || snapshot.ID == uuid.Nil {
		// No scanned head snapshot yet (e.g. PR opened but CI not uploaded).
		return nil, false
	}
	return a.buildAnnotationContext(ctx, snapshot, ref)
}

func (a *Annotator) buildAnnotationContext(ctx context.Context, snapshot dbgen.Snapshot, ref dbgen.Ref) (*annotationContext, bool) {
	targetRef, targetSnapshot, ok := a.loadPRTargetContext(ctx, ref)
	if !ok {
		return nil, false
	}
	repo, provider, owner, name, ok := a.loadAnnotationRepository(ctx, ref)
	if !ok {
		return nil, false
	}
	orgSlug, err := a.store.GetOrgSlug(ctx, repo.OrgID)
	if err != nil {
		a.log.Debug().Err(err).Str("org_id", repo.OrgID.String()).Msg("load org slug for annotator deep link")
	}
	return &annotationContext{snapshot: snapshot, targetSnapshot: targetSnapshot, prRef: ref, targetRef: targetRef, repo: repo, provider: provider, owner: owner, name: name, orgSlug: orgSlug}, true
}

func (a *Annotator) loadPRTargetContext(ctx context.Context, ref dbgen.Ref) (dbgen.Ref, dbgen.Snapshot, bool) {
	if !ref.MergeTargetRefID.Valid {
		a.log.Debug().Str("ref_id", ref.ID.String()).Msg("skip PR annotation without merge target ref")
		return dbgen.Ref{}, dbgen.Snapshot{}, false
	}
	targetRef, err := a.store.GetRefByID(ctx, ref.MergeTargetRefID.UUID)
	if err != nil {
		a.log.Error().Err(err).Str("target_ref_id", ref.MergeTargetRefID.UUID.String()).Msg("load target ref for annotator")
		return dbgen.Ref{}, dbgen.Snapshot{}, false
	}
	if targetRef.ID == uuid.Nil {
		a.log.Debug().Str("target_ref_id", ref.MergeTargetRefID.UUID.String()).Msg("skip PR annotation without target ref")
		return dbgen.Ref{}, dbgen.Snapshot{}, false
	}
	targetSnapshot, err := a.store.GetLatestSnapshotByRef(ctx, ref.MergeTargetRefID.UUID)
	if err != nil {
		a.log.Error().Err(err).Str("target_ref_id", ref.MergeTargetRefID.UUID.String()).Msg("load target snapshot for annotator")
		return dbgen.Ref{}, dbgen.Snapshot{}, false
	}
	if targetSnapshot.ID == uuid.Nil {
		a.log.Debug().Str("target_ref_id", ref.MergeTargetRefID.UUID.String()).Msg("skip PR annotation without target snapshot")
		return dbgen.Ref{}, dbgen.Snapshot{}, false
	}
	return targetRef, targetSnapshot, true
}

func (a *Annotator) loadAnnotationRepository(ctx context.Context, ref dbgen.Ref) (dbgen.Repository, Provider, string, string, bool) {
	repo, err := a.store.GetRepoByID(ctx, ref.RepoID)
	if err != nil {
		a.log.Error().Err(err).Str("repo_id", ref.RepoID.String()).Msg("load repository for annotator")
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

func (a *Annotator) evaluateAnnotationGate(ctx context.Context, annotation *annotationContext) (*delta.GateResult, *delta.DeltaResult, bool) {
	deltaResult, err := a.delta.ComputeDelta(ctx, annotation.snapshot.ID, annotation.targetSnapshot.ID)
	if err != nil {
		a.log.Error().Err(err).Str("snapshot_id", annotation.snapshot.ID.String()).Msg("compute PR delta")
		return nil, nil, false
	}
	weaknessGate := a.loadAnnotationWeaknessGate(ctx, annotation)
	gateResult, err := a.delta.EvaluateGatesWithConfig(ctx, annotation.repo.ID, annotation.repo.OrgID, deltaResult, weaknessGate)
	if err != nil {
		a.log.Error().Err(err).Str("repo_id", annotation.repo.ID.String()).Msg("evaluate PR gates")
		return nil, nil, false
	}
	return gateResult, deltaResult, true
}

func (a *Annotator) loadAnnotationWeaknessGate(ctx context.Context, annotation *annotationContext) *delta.WeaknessGate {
	if a.repoConfigLoader == nil {
		return nil
	}
	weaknessGate, err := a.repoConfigLoader.LoadWeaknessGate(ctx, annotation.repo.Provider, annotation.owner, annotation.name, annotation.repo.DefaultBranch, annotation.targetRef.Name)
	if err != nil {
		a.log.Warn().Err(err).Str("repo_id", annotation.repo.ID.String()).Msg("load repo config for annotator, falling back to DB gates")
		return nil
	}
	return weaknessGate
}

func (a *Annotator) loadAnnotationEnforcement(ctx context.Context, annotation *annotationContext) string {
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
	enforcement string
	eventType   events.Type
}

// gateForgeStatus maps a gate result + enforcement mode to what we publish.
// Advisory (default) never blocks: check runs use the neutral conclusion, and
// commit-status-only forges post success with a warning in the description.
func gateForgeStatus(gateResult *delta.GateResult, deltaResult *delta.DeltaResult, enforcement string) gateStatus {
	if gateResult != nil && gateResult.Passed {
		return gateStatus{
			state:       "success",
			conclusion:  "success",
			description: "All gates passed",
			title:       "Quality gate passed",
			summary:     "All Hibou quality gates passed for this change.",
			enforcement: enforcement,
			eventType:   events.GatePassed,
		}
	}

	reasons := gateReasons(gateResult)
	short := gateFailureDescription(reasons, deltaResult)
	summary := gateFailureSummary(reasons, enforcement)

	if enforcement == enforcementBlocking {
		return gateStatus{
			state:       "failure",
			conclusion:  "failure",
			description: short,
			title:       "Quality gate failed",
			summary:     summary,
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
		title:       "Quality gate (advisory)",
		summary:     summary,
		enforcement: enforcement,
		eventType:   events.GateFailed,
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

func gateFailureSummary(reasons []string, enforcement string) string {
	var b strings.Builder
	if enforcement == enforcementBlocking {
		b.WriteString("**Quality gate failed.** This check is enforcing — it can block the merge if required by branch protection.\n\n")
	} else {
		b.WriteString("**Quality gate would fail** (advisory — this check does not block the merge).\n\n")
	}
	if len(reasons) > 0 {
		for _, reason := range reasons {
			b.WriteString("- ")
			b.WriteString(reason)
			b.WriteString("\n")
		}
	} else {
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
	Name       string
	HeadSHA    string
	Conclusion string // success|failure|neutral
	Title      string
	Summary    string
	DetailsURL string
}

// publishGate posts the gate outcome to the forge (native check run when the
// provider supports it, else a commit status) and persists it to pr_checks so
// re-evaluations (VEX dismissal, override, advisory re-scan) idempotently re-sync
// the same (repo, head SHA, context) row without a CI re-run. Post and persistence
// are decoupled: a failed post is recorded (forge_synced_at NULL + last_error) for
// the reconcile loop to retry.
func (a *Annotator) publishGate(ctx context.Context, annotation *annotationContext, gateResult *delta.GateResult, status gateStatus) {
	targetURL := a.gateTargetURL(annotation)

	var (
		syncErr    error
		externalID string
	)
	if cr, ok := annotation.provider.(CheckRunProvider); ok && cr.SupportsCheckRuns() {
		id, err := cr.CreateOrUpdateCheckRun(ctx, annotation.owner, annotation.name, CheckRun{
			Name:       securityStatusContext,
			HeadSHA:    annotation.snapshot.CommitSha,
			Conclusion: status.conclusion,
			Title:      status.title,
			Summary:    status.summary,
			DetailsURL: targetURL,
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

	a.persistGate(ctx, annotation, gateResult, status, targetURL, externalID, syncErr)
}

func (a *Annotator) persistGate(ctx context.Context, annotation *annotationContext, gateResult *delta.GateResult, status gateStatus, targetURL, externalID string, syncErr error) {
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
	if err := a.store.UpsertPRCheck(ctx, input); err != nil {
		a.log.Error().Err(err).Str("repo_id", annotation.repo.ID.String()).Str("commit_sha", annotation.snapshot.CommitSha).Msg("persist pr_check")
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
func (a *Annotator) gateTargetURL(annotation *annotationContext) string {
	if a.baseURL == "" || annotation.orgSlug == "" {
		return ""
	}
	base := fmt.Sprintf("%s/orgs/%s/%s/repos/%s", a.baseURL, annotation.repo.Provider, annotation.orgSlug, annotation.repo.Slug)
	if pr := prNumberFromRefName(annotation.prRef.Name); pr != "" {
		return base + "/pulls/" + pr
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

func (a *Annotator) publishGateEvent(ctx context.Context, eventType events.Type, repo dbgen.Repository, snapshot dbgen.Snapshot, result *delta.GateResult) {
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

type AnnotatorStoreAdapter struct {
	queries *store.Queries
}

func NewAnnotatorStoreAdapter(queries *store.Queries) *AnnotatorStoreAdapter {
	return &AnnotatorStoreAdapter{queries: queries}
}

func (a *AnnotatorStoreAdapter) GetRepoByID(ctx context.Context, id uuid.UUID) (dbgen.Repository, error) {
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

func (a *AnnotatorStoreAdapter) GetSnapshotByID(ctx context.Context, id uuid.UUID) (dbgen.Snapshot, error) {
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

func (a *AnnotatorStoreAdapter) GetRefByID(ctx context.Context, id uuid.UUID) (dbgen.Ref, error) {
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

func (a *AnnotatorStoreAdapter) UpsertPRCheck(ctx context.Context, in store.UpsertPRCheckInput) error {
	_, err := a.queries.UpsertPRCheck(ctx, in)
	return err
}

func (a *AnnotatorStoreAdapter) GetLatestSnapshotByRef(ctx context.Context, refID uuid.UUID) (dbgen.Snapshot, error) {
	snapshot, err := a.queries.GetLatestSnapshotByRef(ctx, refID)
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

func (a *AnnotatorStoreAdapter) GetOrgSlug(ctx context.Context, orgID uuid.UUID) (string, error) {
	org, err := a.queries.GetOrganizationByID(ctx, orgID)
	if err != nil || org == nil {
		return "", err
	}
	return org.Slug, nil
}

// ListOpenPRRefs returns PR refs that are not closed/merged (open or unknown
// state), for recomputing the gate check after a repo-scoped change.
func (a *AnnotatorStoreAdapter) ListOpenPRRefs(ctx context.Context, repoID uuid.UUID) ([]dbgen.Ref, error) {
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

func (a *AnnotatorStoreAdapter) ListRepoIDsByOrg(ctx context.Context, orgID uuid.UUID) ([]uuid.UUID, error) {
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
func (a *AnnotatorStoreAdapter) ListUnsyncedPRCheckRefIDs(ctx context.Context, limit int32) ([]uuid.UUID, error) {
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
