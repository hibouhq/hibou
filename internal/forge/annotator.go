package forge

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

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
	log              zerolog.Logger
}

const securityStatusContext = "hibou/security"

type AnnotatorStore interface {
	GetRepoByID(ctx context.Context, id uuid.UUID) (dbgen.Repository, error)
	GetSnapshotByID(ctx context.Context, id uuid.UUID) (dbgen.Snapshot, error)
	GetRefByID(ctx context.Context, id uuid.UUID) (dbgen.Ref, error)
	GetLatestSnapshotByRef(ctx context.Context, refID uuid.UUID) (dbgen.Snapshot, error)
}

type RepoConfigLoader interface {
	LoadWeaknessGate(ctx context.Context, providerID, owner, repo, defaultBranch, targetBranch string) (*delta.WeaknessGate, error)
}

func NewAnnotator(forges map[string]Provider, deltaSvc *delta.Service, bus *events.Bus, store AnnotatorStore, repoConfigLoader RepoConfigLoader, log zerolog.Logger) *Annotator {
	if forges == nil {
		forges = map[string]Provider{}
	}
	return &Annotator{
		forges:           forges,
		delta:            deltaSvc,
		bus:              bus,
		store:            store,
		repoConfigLoader: repoConfigLoader,
		log:              log.With().Str("component", "forge.annotator").Logger(),
	}
}

// Subscribe registers event handlers for scan completion on PR snapshots.
func (a *Annotator) Subscribe() {
	if a == nil || a.bus == nil {
		return
	}
	a.bus.Subscribe(events.ScanCompleted, func(ctx context.Context, event events.Event) {
		a.handleScanCompleted(ctx, event.Payload)
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

	annotation, ok := a.loadAnnotationContext(ctx, snapshotID)
	if !ok {
		return
	}
	gateResult, deltaResult, ok := a.evaluateAnnotationGate(ctx, annotation)
	if !ok {
		return
	}
	state, description, eventType := annotationGateStatus(gateResult, deltaResult)
	if !a.publishAnnotationStatus(ctx, annotation, state, description) {
		return
	}
	a.publishGateEvent(ctx, eventType, annotation.repo, annotation.snapshot, gateResult)
}

type annotationContext struct {
	snapshot       dbgen.Snapshot
	targetSnapshot dbgen.Snapshot
	targetRef      dbgen.Ref
	repo           dbgen.Repository
	provider       Provider
	owner          string
	name           string
}

func snapshotIDFromPayload(payload any) uuid.UUID {
	data, _ := payload.(map[string]any)
	return uuidFromString(valueString(data, "snapshot_id"))
}

func (a *Annotator) loadAnnotationContext(ctx context.Context, snapshotID uuid.UUID) (*annotationContext, bool) {
	snapshot, ref, ok := a.loadPRSnapshotContext(ctx, snapshotID)
	if !ok {
		return nil, false
	}
	targetRef, targetSnapshot, ok := a.loadPRTargetContext(ctx, ref)
	if !ok {
		return nil, false
	}
	repo, provider, owner, name, ok := a.loadAnnotationRepository(ctx, ref)
	if !ok {
		return nil, false
	}
	return &annotationContext{snapshot: snapshot, targetSnapshot: targetSnapshot, targetRef: targetRef, repo: repo, provider: provider, owner: owner, name: name}, true
}

func (a *Annotator) loadPRSnapshotContext(ctx context.Context, snapshotID uuid.UUID) (dbgen.Snapshot, dbgen.Ref, bool) {
	snapshot, err := a.store.GetSnapshotByID(ctx, snapshotID)
	if err != nil {
		a.log.Error().Err(err).Str("snapshot_id", snapshotID.String()).Msg("load snapshot for annotator")
		return dbgen.Snapshot{}, dbgen.Ref{}, false
	}
	if snapshot.ID == uuid.Nil {
		return dbgen.Snapshot{}, dbgen.Ref{}, false
	}
	ref, err := a.store.GetRefByID(ctx, snapshot.RefID)
	if err != nil {
		a.log.Error().Err(err).Str("ref_id", snapshot.RefID.String()).Msg("load ref for annotator")
		return dbgen.Snapshot{}, dbgen.Ref{}, false
	}
	if ref.ID == uuid.Nil || ref.RefType != dbgen.RefTypePullRequest {
		return dbgen.Snapshot{}, dbgen.Ref{}, false
	}
	return snapshot, ref, true
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

func annotationGateStatus(gateResult *delta.GateResult, deltaResult *delta.DeltaResult) (string, string, events.Type) {
	if gateResult != nil && gateResult.Passed {
		return "success", "All gates passed", events.GatePassed
	}
	return "failure", fmt.Sprintf("%d new vulnerabilities", len(deltaResult.New)), events.GateFailed
}

func (a *Annotator) publishAnnotationStatus(ctx context.Context, annotation *annotationContext, state, description string) bool {
	if err := annotation.provider.CreateCommitStatus(ctx, annotation.owner, annotation.name, annotation.snapshot.CommitSha, CommitStatus{
		State:       state,
		Context:     securityStatusContext,
		Description: description,
	}); err != nil {
		a.log.Error().Err(err).Str("repo_id", annotation.repo.ID.String()).Str("commit_sha", annotation.snapshot.CommitSha).Msg("create commit status")
		return false
	}
	return true
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
		ID:             snapshot.ID,
		RefID:          snapshot.RefID,
		CommitSha:      snapshot.CommitSHA,
		Label:          stringToNull(snapshot.Label),
		Status:         snapshot.Status,
		RawArtifactUrl: stringToNull(snapshot.RawArtifactURL),
		CreatedAt:      snapshot.CreatedAt,
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

func (a *AnnotatorStoreAdapter) GetLatestSnapshotByRef(ctx context.Context, refID uuid.UUID) (dbgen.Snapshot, error) {
	snapshot, err := a.queries.GetLatestSnapshotByRef(ctx, refID)
	if err != nil || snapshot == nil {
		return dbgen.Snapshot{}, err
	}
	return dbgen.Snapshot{
		ID:             snapshot.ID,
		RefID:          snapshot.RefID,
		CommitSha:      snapshot.CommitSHA,
		Label:          stringToNull(snapshot.Label),
		Status:         snapshot.Status,
		RawArtifactUrl: stringToNull(snapshot.RawArtifactURL),
		CreatedAt:      snapshot.CreatedAt,
	}, nil
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
