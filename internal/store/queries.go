package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type Queries struct {
	db    *dbgen.Queries
	sqlDB *sql.DB
}

type ListComponentsBySnapshotWithVulnsRow = dbgen.ListComponentsBySnapshotWithVulnsRow
type ListComponentDependencyEdgesBySnapshotRow = dbgen.ListComponentDependencyEdgesBySnapshotRow

func NewQueries(db *sql.DB) *Queries {
	return &Queries{db: dbgen.New(db), sqlDB: db}
}

func (q *Queries) BeginTx(ctx context.Context) (*sql.Tx, error) {
	return q.sqlDB.BeginTx(ctx, nil)
}

func (q *Queries) WithTx(tx *sql.Tx) *Queries {
	return &Queries{db: q.db.WithTx(tx), sqlDB: q.sqlDB}
}

func (q *Queries) GetAdvisoryCache(ctx context.Context, arg dbgen.GetAdvisoryCacheParams) (dbgen.AdvisoryCache, error) {
	return q.db.GetAdvisoryCache(ctx, arg)
}

func (q *Queries) UpsertAdvisoryCache(ctx context.Context, arg dbgen.UpsertAdvisoryCacheParams) error {
	return q.db.UpsertAdvisoryCache(ctx, arg)
}

func (q *Queries) InvalidateAdvisoryCacheByPackage(ctx context.Context, arg dbgen.InvalidateAdvisoryCacheByPackageParams) error {
	return q.db.InvalidateAdvisoryCacheByPackage(ctx, arg)
}

func (q *Queries) InvalidateAdvisoryCacheByProvider(ctx context.Context, provider string) error {
	return q.db.InvalidateAdvisoryCacheByProvider(ctx, provider)
}

func (q *Queries) ListComponentsBySnapshot(ctx context.Context, snapshotID uuid.UUID) ([]dbgen.Component, error) {
	return q.db.ListComponentsBySnapshot(ctx, snapshotID)
}

func (q *Queries) ListComponentsBySnapshotWithVulns(ctx context.Context, snapshotID uuid.UUID) ([]dbgen.ListComponentsBySnapshotWithVulnsRow, error) {
	return q.db.ListComponentsBySnapshotWithVulns(ctx, snapshotID)
}

func (q *Queries) ListComponentDependencyEdgesBySnapshot(ctx context.Context, snapshotID uuid.UUID) ([]dbgen.ListComponentDependencyEdgesBySnapshotRow, error) {
	return q.db.ListComponentDependencyEdgesBySnapshot(ctx, snapshotID)
}

func (q *Queries) GetSnapshotDependencyRoot(ctx context.Context, snapshotID uuid.UUID) (*string, error) {
	rootRef, err := q.db.GetSnapshotDependencyRoot(ctx, snapshotID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &rootRef, nil
}

func (q *Queries) CountComponentsBySnapshot(ctx context.Context, snapshotID uuid.UUID) (int64, error) {
	return q.db.CountComponentsBySnapshot(ctx, snapshotID)
}

func (q *Queries) GetComponentByID(ctx context.Context, id uuid.UUID) (dbgen.Component, error) {
	return q.db.GetComponentByID(ctx, id)
}

func (q *Queries) GetComponentsByIDs(ctx context.Context, ids []uuid.UUID) ([]dbgen.Component, error) {
	return q.db.GetComponentsByIDs(ctx, ids)
}

func (q *Queries) UpsertAdvisory(ctx context.Context, arg dbgen.UpsertAdvisoryParams) (dbgen.Advisory, error) {
	return q.db.UpsertAdvisory(ctx, arg)
}

func (q *Queries) UpdateAdvisoryCanonicalID(ctx context.Context, arg dbgen.UpdateAdvisoryCanonicalIDParams) error {
	return q.db.UpdateAdvisoryCanonicalID(ctx, arg)
}

func (q *Queries) UpsertAdvisoryAlias(ctx context.Context, arg dbgen.UpsertAdvisoryAliasParams) error {
	return q.db.UpsertAdvisoryAlias(ctx, arg)
}

func (q *Queries) ListAliasesByAdvisoryIDs(ctx context.Context, advisoryIDs []uuid.UUID) ([]dbgen.AdvisoryAlias, error) {
	return q.db.ListAliasesByAdvisoryIDs(ctx, advisoryIDs)
}

func (q *Queries) UpsertAdvisorySource(ctx context.Context, arg dbgen.UpsertAdvisorySourceParams) error {
	return q.db.UpsertAdvisorySource(ctx, arg)
}

func (q *Queries) ListSourcesByAdvisory(ctx context.Context, advisoryID uuid.UUID) ([]dbgen.AdvisorySource, error) {
	return q.db.ListSourcesByAdvisory(ctx, advisoryID)
}

func (q *Queries) ListSourcesByAdvisoryIDs(ctx context.Context, advisoryIDs []uuid.UUID) ([]dbgen.AdvisorySource, error) {
	return q.db.ListSourcesByAdvisoryIDs(ctx, advisoryIDs)
}

func (q *Queries) CreateAffectedRange(ctx context.Context, arg dbgen.CreateAffectedRangeParams) (dbgen.AffectedRange, error) {
	// nil slice would reach Postgres as NULL; the column is NOT NULL.
	if arg.VulnerableSymbols == nil {
		arg.VulnerableSymbols = []string{}
	}
	return q.db.CreateAffectedRange(ctx, arg)
}

func (q *Queries) ListAffectedRangesByAdvisoryIDs(ctx context.Context, advisoryIDs []uuid.UUID) ([]dbgen.AffectedRange, error) {
	return q.db.ListAffectedRangesByAdvisoryIDs(ctx, advisoryIDs)
}

func (q *Queries) DeleteAffectedRangesByAdvisoryAndSource(ctx context.Context, arg dbgen.DeleteAffectedRangesByAdvisoryAndSourceParams) error {
	return q.db.DeleteAffectedRangesByAdvisoryAndSource(ctx, arg)
}

func (q *Queries) ListAffectedRangesByPackage(ctx context.Context, arg dbgen.ListAffectedRangesByPackageParams) ([]dbgen.AffectedRange, error) {
	return q.db.ListAffectedRangesByPackage(ctx, arg)
}

func (q *Queries) GetAdvisoryByAlias(ctx context.Context, alias string) (dbgen.Advisory, error) {
	return q.db.GetAdvisoryByAlias(ctx, alias)
}

func (q *Queries) GetAdvisoryByCanonicalID(ctx context.Context, canonicalID string) (dbgen.Advisory, error) {
	return q.db.GetAdvisoryByCanonicalID(ctx, canonicalID)
}

func (q *Queries) CreateScan(ctx context.Context, arg dbgen.CreateScanParams) (dbgen.Scan, error) {
	return q.db.CreateScan(ctx, arg)
}

func (q *Queries) UpdateScanStatus(ctx context.Context, arg dbgen.UpdateScanStatusParams) (dbgen.Scan, error) {
	return q.db.UpdateScanStatus(ctx, arg)
}

func (q *Queries) CreateScanProvider(ctx context.Context, arg dbgen.CreateScanProviderParams) (dbgen.ScanProvider, error) {
	return q.db.CreateScanProvider(ctx, arg)
}

func (q *Queries) UpdateScanProvider(ctx context.Context, arg dbgen.UpdateScanProviderParams) (dbgen.ScanProvider, error) {
	return q.db.UpdateScanProvider(ctx, arg)
}

func (q *Queries) CreateAuditLog(ctx context.Context, arg dbgen.CreateAuditLogParams) (dbgen.AuditLog, error) {
	return q.db.CreateAuditLog(ctx, arg)
}

// FindingActivityEntry is one audited action on a finding, already narrowed to
// the fields the finding timeline may show. The raw audit row is deliberately
// not returned: it carries IP, user agent and token identifiers that only org
// admins may see.
type FindingActivityEntry struct {
	ID           uuid.UUID       `json:"id"`
	ActorType    string          `json:"actor_type"`
	ActorDisplay string          `json:"actor_display"`
	Action       string          `json:"action"`
	Context      json.RawMessage `json:"-"`
	CreatedAt    time.Time       `json:"created_at"`
}

// ListFindingActivity returns audit entries for one fingerprint of one
// repository, restricted to the given actions, newest first.
func (q *Queries) ListFindingActivity(ctx context.Context, orgID uuid.UUID, repoID uuid.UUID, fingerprint string, actions []string, limit int) ([]FindingActivityEntry, error) {
	rows, err := q.db.ListFindingActivity(ctx, dbgen.ListFindingActivityParams{
		OrgID:       uuid.NullUUID{UUID: orgID, Valid: true},
		RepoID:      repoID.String(),
		Fingerprint: fingerprint,
		Actions:     actions,
		RowLimit:    int32(limit), //nolint:gosec // G115: limit is a small server-side constant.
	})
	if err != nil {
		return nil, err
	}
	out := make([]FindingActivityEntry, len(rows))
	for i, row := range rows {
		out[i] = FindingActivityEntry{
			ID:           row.ID,
			ActorType:    row.ActorType,
			ActorDisplay: row.ActorDisplay,
			Action:       row.Action,
			Context:      row.Context,
			CreatedAt:    row.CreatedAt,
		}
	}
	return out, nil
}

func (q *Queries) CreateNotification(ctx context.Context, arg dbgen.CreateNotificationParams) (dbgen.Notification, error) {
	return q.db.CreateNotification(ctx, arg)
}

func (q *Queries) ListNotificationsByUser(ctx context.Context, arg dbgen.ListNotificationsByUserParams) ([]dbgen.Notification, error) {
	return q.db.ListNotificationsByUser(ctx, arg)
}

func (q *Queries) CountUnreadNotifications(ctx context.Context, userID uuid.UUID) (int64, error) {
	return q.db.CountUnreadNotifications(ctx, userID)
}

func (q *Queries) MarkNotificationRead(ctx context.Context, arg dbgen.MarkNotificationReadParams) error {
	return q.db.MarkNotificationRead(ctx, arg)
}

func (q *Queries) MarkAllNotificationsRead(ctx context.Context, userID uuid.UUID) error {
	return q.db.MarkAllNotificationsRead(ctx, userID)
}

func (q *Queries) CountNotificationsByUser(ctx context.Context, userID uuid.UUID) (int64, error) {
	const query = `SELECT COUNT(*)::bigint FROM notifications WHERE user_id = $1`
	row := q.sqlDB.QueryRowContext(ctx, query, userID)
	var count int64
	if err := row.Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (q *Queries) GetAdvisoryByID(ctx context.Context, id uuid.UUID) (dbgen.Advisory, error) {
	return q.db.GetAdvisoryByID(ctx, id)
}

func (q *Queries) GetAdvisoriesByIDs(ctx context.Context, ids []uuid.UUID) ([]dbgen.Advisory, error) {
	return q.db.GetAdvisoriesByIDs(ctx, ids)
}

func (q *Queries) ListVulnerabilitySummaryBySnapshot(ctx context.Context, snapshotID uuid.UUID) ([]dbgen.ListVulnerabilitySummaryBySnapshotRow, error) {
	return q.db.ListVulnerabilitySummaryBySnapshot(ctx, snapshotID)
}

func (q *Queries) ListIntegrationsByOrg(ctx context.Context, orgID uuid.UUID) ([]dbgen.Integration, error) {
	return q.db.ListIntegrationsByOrg(ctx, orgID)
}

func (q *Queries) UpdateIntegrationHealth(ctx context.Context, arg dbgen.UpdateIntegrationHealthParams) error {
	return q.db.UpdateIntegrationHealth(ctx, arg)
}

func (q *Queries) ListQualityGatesByOrg(ctx context.Context, orgID uuid.UUID) ([]dbgen.QualityGate, error) {
	return q.db.ListQualityGatesByOrg(ctx, orgID)
}

func (q *Queries) ListOrgWideQualityGates(ctx context.Context, orgID uuid.UUID) ([]dbgen.QualityGate, error) {
	return q.db.ListOrgWideQualityGates(ctx, orgID)
}

func (q *Queries) ListQualityGatesByRepo(ctx context.Context, repoID uuid.NullUUID) ([]dbgen.QualityGate, error) {
	return q.db.ListQualityGatesByRepo(ctx, repoID)
}

func (q *Queries) CountRepositoriesByOrg(ctx context.Context, orgID uuid.UUID) (int64, error) {
	return q.db.CountRepositoriesByOrg(ctx, orgID)
}

func (q *Queries) CreateVEXStatement(ctx context.Context, arg dbgen.CreateVEXStatementParams) (dbgen.VexStatement, error) {
	return q.db.CreateVEXStatement(ctx, arg)
}

func (q *Queries) UpdateVEXStatement(ctx context.Context, arg dbgen.UpdateVEXStatementParams) (dbgen.VexStatement, error) {
	return q.db.UpdateVEXStatement(ctx, arg)
}

func (q *Queries) GetVEXStatementByID(ctx context.Context, id uuid.UUID) (dbgen.VexStatement, error) {
	return q.db.GetVEXStatementByID(ctx, id)
}

func (q *Queries) ListVEXStatementsByOrg(ctx context.Context, arg dbgen.ListVEXStatementsByOrgParams) ([]dbgen.VexStatement, error) {
	return q.db.ListVEXStatementsByOrg(ctx, arg)
}

func (q *Queries) ListVEXStatementsByRepo(ctx context.Context, arg dbgen.ListVEXStatementsByRepoParams) ([]dbgen.VexStatement, error) {
	return q.db.ListVEXStatementsByRepo(ctx, arg)
}

func (q *Queries) ListVEXStatementsByAdvisory(ctx context.Context, arg dbgen.ListVEXStatementsByAdvisoryParams) ([]dbgen.VexStatement, error) {
	return q.db.ListVEXStatementsByAdvisory(ctx, arg)
}

func (q *Queries) DeleteVEXStatement(ctx context.Context, arg dbgen.DeleteVEXStatementParams) error {
	return q.db.DeleteVEXStatement(ctx, arg)
}

func (q *Queries) GetEffectiveVEXStatus(ctx context.Context, arg dbgen.GetEffectiveVEXStatusParams) (dbgen.VexStatement, error) {
	return q.db.GetEffectiveVEXStatus(ctx, arg)
}

func (q *Queries) ListExpiredVEXStatements(ctx context.Context) ([]dbgen.VexStatement, error) {
	return q.db.ListExpiredVEXStatements(ctx)
}

func (q *Queries) CountVEXStatementsByOrg(ctx context.Context, orgID uuid.UUID) (int64, error) {
	return q.db.CountVEXStatementsByOrg(ctx, orgID)
}

func (q *Queries) ListAdvisoryProviderStats(ctx context.Context, orgID uuid.UUID) ([]dbgen.ListAdvisoryProviderStatsRow, error) {
	return q.db.ListAdvisoryProviderStats(ctx, orgID)
}

func (q *Queries) ListFindingToolStats(ctx context.Context, orgID uuid.UUID) ([]dbgen.ListFindingToolStatsRow, error) {
	return q.db.ListFindingToolStats(ctx, orgID)
}

func (q *Queries) ListVulnerabilityToolStats(ctx context.Context, orgID uuid.UUID) ([]dbgen.ListVulnerabilityToolStatsRow, error) {
	return q.db.ListVulnerabilityToolStats(ctx, orgID)
}

func (q *Queries) ListVEXSourceStats(ctx context.Context, orgID uuid.UUID) ([]dbgen.ListVEXSourceStatsRow, error) {
	return q.db.ListVEXSourceStats(ctx, orgID)
}

func (q *Queries) ListComponentEcosystemStats(ctx context.Context, orgID uuid.UUID) ([]dbgen.ListComponentEcosystemStatsRow, error) {
	return q.db.ListComponentEcosystemStats(ctx, orgID)
}

func (q *Queries) ListCoverageSnapshotStats(ctx context.Context, orgID uuid.UUID) ([]dbgen.ListCoverageSnapshotStatsRow, error) {
	return q.db.ListCoverageSnapshotStats(ctx, orgID)
}

func (q *Queries) CountVEXStatementsByRepo(ctx context.Context, arg dbgen.CountVEXStatementsByRepoParams) (int64, error) {
	return q.db.CountVEXStatementsByRepo(ctx, arg)
}

func (q *Queries) ListAuditLogs(ctx context.Context, arg dbgen.ListAuditLogsParams) ([]dbgen.AuditLog, error) {
	return q.db.ListAuditLogs(ctx, arg)
}

func (q *Queries) ListRecentAuditLogsByOrg(ctx context.Context, orgID uuid.UUID, since time.Time, limit int32) ([]dbgen.AuditLog, error) {
	return q.db.ListRecentAuditLogsByOrg(ctx, dbgen.ListRecentAuditLogsByOrgParams{
		OrgID:     uuid.NullUUID{UUID: orgID, Valid: true},
		CreatedAt: since,
		Limit:     limit,
	})
}

func (q *Queries) ListAuditLogsByResource(ctx context.Context, resourceType, resourceID string, limit, offset int32) ([]dbgen.AuditLog, error) {
	return q.db.ListAuditLogsByResource(ctx, dbgen.ListAuditLogsByResourceParams{
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Limit:        limit,
		Offset:       offset,
	})
}

func (q *Queries) CountAuditLogsByOrg(ctx context.Context, orgID uuid.UUID) (int64, error) {
	return q.db.CountAuditLogsByOrg(ctx, uuid.NullUUID{UUID: orgID, Valid: true})
}

func (q *Queries) CountVulnerabilitiesByOrg(ctx context.Context, orgID uuid.UUID) (int64, error) {
	return q.db.CountVulnerabilitiesByOrg(ctx, orgID)
}

func (q *Queries) CountScansByOrg(ctx context.Context, orgID uuid.UUID) (int64, error) {
	return q.db.CountScansByOrg(ctx, orgID)
}

func (q *Queries) LatestScanCompletedAtByOrg(ctx context.Context, orgID uuid.UUID) (time.Time, error) {
	const query = `
		SELECT COALESCE(MAX(sc.completed_at), TIMESTAMPTZ '1970-01-01 00:00:00+00')
		FROM scans sc
		JOIN snapshots s ON s.id = sc.snapshot_id
		WHERE s.org_id = $1
		  AND sc.status = 'complete'
	`
	var latest time.Time
	err := q.sqlDB.QueryRowContext(ctx, query, orgID).Scan(&latest)
	return latest, err
}

func (q *Queries) CountMalwareAdvisoriesByOrg(ctx context.Context, orgID uuid.UUID) (int64, error) {
	return q.db.CountMalwareAdvisoriesByOrg(ctx, orgID)
}

func (q *Queries) CountComponentsByOrg(ctx context.Context, orgID uuid.UUID) (int64, error) {
	return q.db.CountDistinctComponentsByOrg(ctx, orgID)
}

func (q *Queries) ListScansBySnapshot(ctx context.Context, snapshotID uuid.UUID) ([]dbgen.Scan, error) {
	return q.db.ListScansBySnapshot(ctx, snapshotID)
}
