package compliance

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/lehibou/internal/store"
	"github.com/hibouhq/lehibou/internal/store/dbgen"
)

type StoreAdapter struct {
	queries *store.Queries
}

func NewStoreAdapter(queries *store.Queries) *StoreAdapter {
	return &StoreAdapter{queries: queries}
}

func (a *StoreAdapter) GetRepoBySlug(ctx context.Context, orgID uuid.UUID, slug string) (dbgen.Repository, error) {
	repo, err := a.queries.GetRepositoryBySlug(ctx, orgID, slug)
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

func (a *StoreAdapter) GetOrganizationByID(ctx context.Context, id uuid.UUID) (dbgen.Organization, error) {
	org, err := a.queries.GetOrganizationByID(ctx, id)
	if err != nil || org == nil {
		return dbgen.Organization{}, err
	}
	return dbgen.Organization{
		ID:          org.ID,
		Name:        org.Name,
		Slug:        org.Slug,
		DisplayName: org.DisplayName,
		Settings:    org.Settings,
		CreatedAt:   org.CreatedAt,
		UpdatedAt:   org.UpdatedAt,
	}, nil
}

func (a *StoreAdapter) GetSnapshotAtDate(ctx context.Context, arg dbgen.GetSnapshotAtDateParams) (dbgen.Snapshot, error) {
	snapshot, err := a.queries.GetSnapshotAtDate(ctx, arg.RepoID, arg.Name, arg.CreatedAt)
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
		ArtifactKey:    snapshot.ArtifactKey,
	}, nil
}

func (a *StoreAdapter) ListVulnMatchesBySnapshot(ctx context.Context, snapshotID uuid.UUID) ([]dbgen.VulnMatch, error) {
	return a.queries.ListVulnMatchesBySnapshot(ctx, snapshotID)
}

func (a *StoreAdapter) ListFindingsBySnapshot(ctx context.Context, arg dbgen.ListFindingsBySnapshotParams) ([]dbgen.Finding, error) {
	return a.queries.ListAllFindingsBySnapshot(ctx, arg.SnapshotID)
}

func (a *StoreAdapter) GetAdvisoriesByIDs(ctx context.Context, ids []uuid.UUID) ([]dbgen.Advisory, error) {
	return a.queries.GetAdvisoriesByIDs(ctx, ids)
}

func (a *StoreAdapter) GetComponentsByIDs(ctx context.Context, ids []uuid.UUID) ([]dbgen.Component, error) {
	return a.queries.GetComponentsByIDs(ctx, ids)
}

func (a *StoreAdapter) ListVEXStatementsByAdvisory(ctx context.Context, arg dbgen.ListVEXStatementsByAdvisoryParams) ([]dbgen.VexStatement, error) {
	return a.queries.ListVEXStatementsByAdvisory(ctx, arg)
}

func (a *StoreAdapter) GetRefByID(ctx context.Context, id uuid.UUID) (dbgen.Ref, error) {
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

func (a *StoreAdapter) CountRepositoriesByOrg(ctx context.Context, orgID uuid.UUID) (int64, error) {
	return a.queries.CountRepositoriesByOrg(ctx, orgID)
}

func (a *StoreAdapter) CountVEXStatementsByOrg(ctx context.Context, orgID uuid.UUID) (int64, error) {
	return a.queries.CountVEXStatementsByOrg(ctx, orgID)
}

func (a *StoreAdapter) ListVEXStatementsByOrg(ctx context.Context, arg dbgen.ListVEXStatementsByOrgParams) ([]dbgen.VexStatement, error) {
	return a.queries.ListVEXStatementsByOrg(ctx, arg)
}

func (a *StoreAdapter) CountAuditLogsByOrg(ctx context.Context, orgID uuid.UUID) (int64, error) {
	return a.queries.CountAuditLogsByOrg(ctx, orgID)
}

func (a *StoreAdapter) ListAuditLogs(ctx context.Context, arg dbgen.ListAuditLogsParams) ([]dbgen.AuditLog, error) {
	return a.queries.ListAuditLogs(ctx, arg)
}

func (a *StoreAdapter) ListQualityGatesByOrg(ctx context.Context, orgID uuid.UUID) ([]dbgen.QualityGate, error) {
	return a.queries.ListQualityGatesByOrg(ctx, orgID)
}

func (a *StoreAdapter) CountVulnMatchesByOrg(ctx context.Context, orgID uuid.UUID) (int64, error) {
	return a.queries.CountVulnMatchesByOrg(ctx, orgID)
}

func (a *StoreAdapter) CountFindingsByOrg(ctx context.Context, orgID uuid.UUID) (int64, error) {
	return a.queries.CountFindingsByOrg(ctx, orgID)
}

func (a *StoreAdapter) CountScansByOrg(ctx context.Context, orgID uuid.UUID) (int64, error) {
	return a.queries.CountScansByOrg(ctx, orgID)
}

func (a *StoreAdapter) LatestScanByOrg(ctx context.Context, orgID uuid.UUID) (time.Time, error) {
	return a.queries.LatestScanCompletedAtByOrg(ctx, orgID)
}

func (a *StoreAdapter) CountMalwareAdvisoriesByOrg(ctx context.Context, orgID uuid.UUID) (int64, error) {
	return a.queries.CountMalwareAdvisoriesByOrg(ctx, orgID)
}

func (a *StoreAdapter) CountComponentsByOrg(ctx context.Context, orgID uuid.UUID) (int64, error) {
	return a.queries.CountComponentsByOrg(ctx, orgID)
}

func stringToNull(value *string) sql.NullString {
	if value == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *value, Valid: true}
}

func uuidToNull(value *uuid.UUID) uuid.NullUUID {
	if value == nil {
		return uuid.NullUUID{}
	}
	return uuid.NullUUID{UUID: *value, Valid: true}
}
