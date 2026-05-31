package toolcatalog

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/lehibou/internal/store"
)

type StoreAdapter struct {
	queries *store.Queries
}

func NewStoreAdapter(queries *store.Queries) *StoreAdapter {
	return &StoreAdapter{queries: queries}
}

func (a *StoreAdapter) ListAdvisoryProviderStats(ctx context.Context, orgID uuid.UUID) ([]AdvisoryProviderStat, error) {
	rows, err := a.queries.ListAdvisoryProviderStats(ctx, orgID)
	if err != nil {
		return nil, err
	}
	stats := make([]AdvisoryProviderStat, 0, len(rows))
	for _, row := range rows {
		stats = append(stats, AdvisoryProviderStat{
			Provider:        row.Provider,
			LastCompletedAt: interfaceTimeValue(row.LastCompletedAt),
			TotalAdvisories: row.TotalAdvisories,
			RepoCount:       row.RepoCount,
			LastErrorAt:     interfaceTimeValue(row.LastErrorAt),
			LastError:       interfaceStringValue(row.LastError),
		})
	}
	return stats, nil
}

func (a *StoreAdapter) ListVulnerabilityToolStats(ctx context.Context, orgID uuid.UUID) ([]FindingToolStat, error) {
	rows, err := a.queries.ListVulnerabilityToolStats(ctx, orgID)
	if err != nil {
		return nil, err
	}
	stats := make([]FindingToolStat, 0, len(rows))
	for _, row := range rows {
		stats = append(stats, FindingToolStat{
			Tool:         row.ScannerName,
			FindingCount: row.Count,
		})
	}
	return stats, nil
}

func (a *StoreAdapter) ListVEXSourceStats(ctx context.Context, orgID uuid.UUID) ([]VEXSourceStat, error) {
	rows, err := a.queries.ListVEXSourceStats(ctx, orgID)
	if err != nil {
		return nil, err
	}
	stats := make([]VEXSourceStat, 0, len(rows))
	for _, row := range rows {
		stats = append(stats, VEXSourceStat{
			Source:         row.Source,
			LastSeenAt:     interfaceTimeValue(row.LastSeenAt),
			StatementCount: row.StatementCount,
			RepoCount:      row.RepoCount,
		})
	}
	return stats, nil
}

func (a *StoreAdapter) ListComponentEcosystemStats(ctx context.Context, orgID uuid.UUID) ([]ComponentEcosystemStat, error) {
	rows, err := a.queries.ListComponentEcosystemStats(ctx, orgID)
	if err != nil {
		return nil, err
	}
	stats := make([]ComponentEcosystemStat, 0, len(rows))
	for _, row := range rows {
		stats = append(stats, ComponentEcosystemStat{
			Ecosystem:      row.Ecosystem,
			ComponentCount: row.ComponentCount,
			RepoCount:      row.RepoCount,
			LastSeenAt:     interfaceTimeValue(row.LastSeenAt),
		})
	}
	return stats, nil
}

func (a *StoreAdapter) ListCoverageSnapshotStats(ctx context.Context, orgID uuid.UUID) ([]CoverageSnapshotStat, error) {
	rows, err := a.queries.ListCoverageSnapshotStats(ctx, orgID)
	if err != nil {
		return nil, err
	}
	stats := make([]CoverageSnapshotStat, 0, len(rows))
	for _, row := range rows {
		stats = append(stats, CoverageSnapshotStat{
			Label:         strings.ToLower(interfaceStringValue(row.Label)),
			LastSeenAt:    interfaceTimeValue(row.LastSeenAt),
			SnapshotCount: row.SnapshotCount,
			RepoCount:     row.RepoCount,
		})
	}
	return stats, nil

}

func interfaceTimeValue(value any) time.Time {
	switch typed := value.(type) {
	case nil:
		return time.Time{}
	case time.Time:
		return typed.UTC()
	case *time.Time:
		if typed == nil {
			return time.Time{}
		}
		return typed.UTC()
	case sql.NullTime:
		if typed.Valid {
			return typed.Time.UTC()
		}
	case *sql.NullTime:
		if typed != nil && typed.Valid {
			return typed.Time.UTC()
		}
	}
	return time.Time{}
}

func interfaceStringValue(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case *string:
		if typed == nil {
			return ""
		}
		return *typed
	case []byte:
		return string(typed)
	case sql.NullString:
		if typed.Valid {
			return typed.String
		}
	case *sql.NullString:
		if typed != nil && typed.Valid {
			return typed.String
		}
	default:
		return fmt.Sprint(typed)
	}
	return ""
}

var _ Store = (*StoreAdapter)(nil)
