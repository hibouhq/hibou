package forge

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/lehibou/internal/delta"
	"github.com/hibouhq/lehibou/internal/events"
	"github.com/hibouhq/lehibou/internal/store"
	"github.com/hibouhq/lehibou/internal/store/dbgen"
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
	data, _ := payload.(map[string]any)
	snapshotID := uuidFromString(valueString(data, "snapshot_id"))
	if snapshotID == uuid.Nil {
		return
	}

	snapshot, err := a.store.GetSnapshotByID(ctx, snapshotID)
	if err != nil {
		a.log.Error().Err(err).Str("snapshot_id", snapshotID.String()).Msg("load snapshot for annotator")
		return
	}
	if snapshot.ID == uuid.Nil {
		return
	}
	ref, err := a.store.GetRefByID(ctx, snapshot.RefID)
	if err != nil {
		a.log.Error().Err(err).Str("ref_id", snapshot.RefID.String()).Msg("load ref for annotator")
		return
	}
	if ref.ID == uuid.Nil || ref.RefType != dbgen.RefTypePullRequest {
		return
	}
	if !ref.MergeTargetRefID.Valid {
		a.log.Debug().Str("ref_id", ref.ID.String()).Msg("skip PR annotation without merge target ref")
		return
	}
	targetRef, err := a.store.GetRefByID(ctx, ref.MergeTargetRefID.UUID)
	if err != nil {
		a.log.Error().Err(err).Str("target_ref_id", ref.MergeTargetRefID.UUID.String()).Msg("load target ref for annotator")
		return
	}
	if targetRef.ID == uuid.Nil {
		a.log.Debug().Str("target_ref_id", ref.MergeTargetRefID.UUID.String()).Msg("skip PR annotation without target ref")
		return
	}
	targetSnapshot, err := a.store.GetLatestSnapshotByRef(ctx, ref.MergeTargetRefID.UUID)
	if err != nil {
		a.log.Error().Err(err).Str("target_ref_id", ref.MergeTargetRefID.UUID.String()).Msg("load target snapshot for annotator")
		return
	}
	if targetSnapshot.ID == uuid.Nil {
		a.log.Debug().Str("target_ref_id", ref.MergeTargetRefID.UUID.String()).Msg("skip PR annotation without target snapshot")
		return
	}
	repo, err := a.store.GetRepoByID(ctx, ref.RepoID)
	if err != nil {
		a.log.Error().Err(err).Str("repo_id", ref.RepoID.String()).Msg("load repository for annotator")
		return
	}
	if repo.ID == uuid.Nil {
		return
	}
	provider := a.forges[repo.Provider]
	if provider == nil {
		a.log.Debug().Str("provider", repo.Provider).Str("repo_id", repo.ID.String()).Msg("skip annotation without forge provider")
		return
	}
	owner, name, ok := repoCoordinates(repo)
	if !ok {
		a.log.Debug().Str("repo_id", repo.ID.String()).Msg("skip annotation without repository coordinates")
		return
	}

	deltaResult, err := a.delta.ComputeDelta(ctx, snapshot.ID, targetSnapshot.ID)
	if err != nil {
		a.log.Error().Err(err).Str("snapshot_id", snapshot.ID.String()).Msg("compute PR delta")
		return
	}
	var weaknessGate *delta.WeaknessGate
	if a.repoConfigLoader != nil {
		weaknessGate, err = a.repoConfigLoader.LoadWeaknessGate(ctx, repo.Provider, owner, name, repo.DefaultBranch, targetRef.Name)
		if err != nil {
			a.log.Warn().Err(err).Str("repo_id", repo.ID.String()).Msg("load repo config for annotator, falling back to DB gates")
			weaknessGate = nil
		}
	}
	gateResult, err := a.delta.EvaluateGatesWithConfig(ctx, repo.ID, repo.OrgID, deltaResult, weaknessGate)
	if err != nil {
		a.log.Error().Err(err).Str("repo_id", repo.ID.String()).Msg("evaluate PR gates")
		return
	}

	state := "success"
	description := "All gates passed"
	eventType := events.GatePassed
	if !gateResult.Passed {
		state = "failure"
		description = fmt.Sprintf("%d new vulnerabilities", len(deltaResult.New))
		eventType = events.GateFailed
	}
	// Forge status APIs converge on sha+context, so retries rewrite the same
	// logical security status instead of introducing a second status identity.
	if err := provider.CreateCommitStatus(ctx, owner, name, snapshot.CommitSha, CommitStatus{
		State:       state,
		Context:     securityStatusContext,
		Description: description,
	}); err != nil {
		a.log.Error().Err(err).Str("repo_id", repo.ID.String()).Str("commit_sha", snapshot.CommitSha).Msg("create commit status")
		return
	}
	a.publishGateEvent(ctx, eventType, repo, snapshot, gateResult)
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
