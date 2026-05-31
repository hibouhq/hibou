package delta

import (
	"context"
	"database/sql"

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

func (a *StoreAdapter) ListVulnMatchesBySnapshot(ctx context.Context, snapshotID uuid.UUID) ([]dbgen.VulnMatch, error) {
	return a.queries.ListVulnMatchesBySnapshot(ctx, snapshotID)
}

func (a *StoreAdapter) ListFindingsBySnapshot(ctx context.Context, arg dbgen.ListFindingsBySnapshotParams) ([]dbgen.Finding, error) {
	findings, _, err := a.queries.ListFindingsBySnapshot(ctx, arg.SnapshotID, int(arg.Limit), int(arg.Offset))
	if err != nil {
		return nil, err
	}
	rows := make([]dbgen.Finding, 0, len(findings))
	for _, finding := range findings {
		rows = append(rows, dbgen.Finding{
			ID:           finding.ID,
			SnapshotID:   finding.SnapshotID,
			Tool:         finding.Tool,
			RuleID:       finding.RuleID,
			Severity:     finding.Severity,
			Status:       finding.Status,
			FilePath:     finding.FilePath,
			StartLine:    int32ToNull(finding.StartLine),
			EndLine:      int32ToNull(finding.EndLine),
			LocationHash: finding.LocationHash,
			Message:      finding.Message,
			Fingerprint:  stringToNull(finding.Fingerprint),
			Metadata:     finding.Metadata,
			CreatedAt:    finding.CreatedAt,
		})
	}
	return rows, nil
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

func int32ToNull(value *int32) sql.NullInt32 {
	if value == nil {
		return sql.NullInt32{}
	}
	return sql.NullInt32{Int32: *value, Valid: true}
}

func stringToNull(value *string) sql.NullString {
	if value == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *value, Valid: true}
}
