package delta

import (
	"context"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type StoreAdapter struct {
	queries *store.Queries
}

func NewStoreAdapter(queries *store.Queries) *StoreAdapter {
	return &StoreAdapter{queries: queries}
}

func (a *StoreAdapter) ListAllVulnerabilitiesBySnapshot(ctx context.Context, snapshotID uuid.UUID) ([]store.Vulnerability, error) {
	return a.queries.ListAllVulnerabilitiesBySnapshot(ctx, snapshotID)
}

func (a *StoreAdapter) GetAdvisoryByID(ctx context.Context, id uuid.UUID) (dbgen.Advisory, error) {
	return a.queries.GetAdvisoryByID(ctx, id)
}

func (a *StoreAdapter) GetEffectiveVEXStatus(ctx context.Context, arg dbgen.GetEffectiveVEXStatusParams) (dbgen.VexStatement, error) {
	return a.queries.GetEffectiveVEXStatus(ctx, arg)
}

func (a *StoreAdapter) GetSnapshotByID(ctx context.Context, id uuid.UUID) (*store.Snapshot, error) {
	return a.queries.GetSnapshotByID(ctx, id)
}

func (a *StoreAdapter) GetRefByID(ctx context.Context, id uuid.UUID) (*store.Ref, error) {
	return a.queries.GetRefByID(ctx, id)
}

func (a *StoreAdapter) GetRepositoryByID(ctx context.Context, id uuid.UUID) (*store.Repository, error) {
	return a.queries.GetRepositoryByID(ctx, id)
}

func (a *StoreAdapter) GetComponentByID(ctx context.Context, id uuid.UUID) (dbgen.Component, error) {
	return a.queries.GetComponentByID(ctx, id)
}

func (a *StoreAdapter) ListQualityGatesByRepo(ctx context.Context, repoID uuid.UUID) ([]dbgen.QualityGate, error) {
	return a.queries.ListQualityGatesByRepo(ctx, uuid.NullUUID{UUID: repoID, Valid: repoID != uuid.Nil})
}

func (a *StoreAdapter) ListOrgWideQualityGates(ctx context.Context, orgID uuid.UUID) ([]dbgen.QualityGate, error) {
	return a.queries.ListOrgWideQualityGates(ctx, orgID)
}
