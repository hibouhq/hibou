package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/lehibou/internal/store/dbgen"
)

type SecretStatus = string

const (
	SecretStatusOpen          SecretStatus = "open"
	SecretStatusRevoked       SecretStatus = "revoked"
	SecretStatusFalsePositive SecretStatus = "false_positive"
	SecretStatusRotating      SecretStatus = "rotating"
)

type SecretFinding struct {
	ID               uuid.UUID       `json:"id"`
	SnapshotID       uuid.UUID       `json:"snapshot_id"`
	Tool             string          `json:"tool"`
	RuleID           string          `json:"rule_id"`
	Severity         SeverityLevel   `json:"severity"`
	Status           SecretStatus    `json:"status"`
	StatusNote       string          `json:"status_note"`
	DiscoveryContext string          `json:"discovery_context"`
	FilePath         string          `json:"file_path"`
	StartLine        *int32          `json:"start_line,omitempty"`
	EndLine          *int32          `json:"end_line,omitempty"`
	SecretType       string          `json:"secret_type"`
	SecretHash       string          `json:"secret_hash"`
	CommitSHA        string          `json:"commit_sha"`
	AuthorEmail      string          `json:"author_email"`
	Verified         bool            `json:"verified"`
	Fingerprint      string          `json:"fingerprint"`
	Metadata         json.RawMessage `json:"metadata"`
	CreatedAt        time.Time       `json:"created_at"`
}

type SecretFindingSummaryRow = dbgen.ListSecretFindingSummaryBySnapshotRow
type SecretToolStatsRow = dbgen.SecretToolStatsRow
type SecretToolOverlapRow = dbgen.SecretToolOverlapRow
type SecretUniqueByToolRow = dbgen.SecretUniqueByToolRow

type SecretFindingSource struct {
	ID          uuid.UUID       `json:"id"`
	FindingID   uuid.UUID       `json:"finding_id"`
	Tool        string          `json:"tool"`
	RuleID      string          `json:"rule_id"`
	FirstSeenAt time.Time       `json:"first_seen_at"`
	LastSeenAt  time.Time       `json:"last_seen_at"`
	ScanCount   int32           `json:"scan_count"`
	Metadata    json.RawMessage `json:"metadata"`
}

func (q *Queries) CreateSecretFinding(ctx context.Context, snapshotID uuid.UUID, tool, ruleID string, severity SeverityLevel, status SecretStatus, discoveryContext, filePath string, startLine, endLine *int32, secretType, secretHash, commitSHA, authorEmail string, verified bool, metadata json.RawMessage, fingerprint string) (*SecretFinding, error) {
	if metadata == nil {
		metadata = json.RawMessage(`{}`)
	}

	row, err := q.db.CreateSecretFinding(ctx, dbgen.CreateSecretFindingParams{
		SnapshotID:       snapshotID,
		Tool:             tool,
		RuleID:           ruleID,
		Severity:         severity,
		Status:           status,
		DiscoveryContext: discoveryContext,
		FilePath:         filePath,
		StartLine:        nullInt32FromPtr(startLine),
		EndLine:          nullInt32FromPtr(endLine),
		SecretType:       secretType,
		SecretHash:       secretHash,
		CommitSha:        commitSHA,
		AuthorEmail:      authorEmail,
		Verified:         verified,
		Metadata:         metadata,
		Fingerprint:      fingerprint,
	})
	if err != nil {
		return nil, err
	}

	return secretFindingFromRow(row), nil
}

func (q *Queries) GetSecretFindingByID(ctx context.Context, id uuid.UUID) (*SecretFinding, error) {
	row, err := q.db.GetSecretFindingByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return secretFindingFromRow(row), nil
}

func (q *Queries) GetSecretFindingByFingerprint(ctx context.Context, snapshotID uuid.UUID, fingerprint string) (*SecretFinding, error) {
	row, err := q.db.GetSecretFindingByFingerprint(ctx, dbgen.GetSecretFindingByFingerprintParams{
		SnapshotID:  snapshotID,
		Fingerprint: fingerprint,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return secretFindingFromRow(row), nil
}

func (q *Queries) UpsertSecretFindingSource(ctx context.Context, findingID uuid.UUID, tool, ruleID string, metadata json.RawMessage) error {
	if metadata == nil {
		metadata = json.RawMessage(`{}`)
	}

	_, err := q.db.UpsertSecretFindingSource(ctx, dbgen.UpsertSecretFindingSourceParams{
		FindingID: findingID,
		Tool:      tool,
		RuleID:    ruleID,
		Metadata:  metadata,
	})
	return err
}

func (q *Queries) ListSecretFindingSourcesByFinding(ctx context.Context, findingID uuid.UUID) ([]SecretFindingSource, error) {
	rows, err := q.db.ListSecretFindingSourcesByFinding(ctx, findingID)
	if err != nil {
		return nil, err
	}

	sources := make([]SecretFindingSource, len(rows))
	for i, row := range rows {
		sources[i] = *secretFindingSourceFromRow(row)
	}

	return sources, nil
}

func (q *Queries) SecretToolStats(ctx context.Context) ([]SecretToolStatsRow, error) {
	return q.db.SecretToolStats(ctx)
}

func (q *Queries) SecretToolOverlap(ctx context.Context) ([]SecretToolOverlapRow, error) {
	return q.db.SecretToolOverlap(ctx)
}

func (q *Queries) SecretUniqueByTool(ctx context.Context) ([]SecretUniqueByToolRow, error) {
	return q.db.SecretUniqueByTool(ctx)
}

func (q *Queries) ListSecretFindingsBySnapshot(ctx context.Context, snapshotID uuid.UUID, limit, offset int) ([]SecretFinding, int, error) {
	rows, err := q.db.ListSecretFindingsBySnapshot(ctx, dbgen.ListSecretFindingsBySnapshotParams{
		SnapshotID: snapshotID,
		Limit:      int32(limit),
		Offset:     int32(offset),
	})
	if err != nil {
		return nil, 0, err
	}

	findings := make([]SecretFinding, len(rows))
	for i, row := range rows {
		findings[i] = *secretFindingFromRow(row)
	}

	total, err := q.db.CountSecretFindingsBySnapshot(ctx, snapshotID)
	if err != nil {
		return nil, 0, err
	}

	return findings, int(total), nil
}

func (q *Queries) CountSecretFindingsBySnapshot(ctx context.Context, snapshotID uuid.UUID) (int64, error) {
	return q.db.CountSecretFindingsBySnapshot(ctx, snapshotID)
}

func (q *Queries) ListSecretFindingSummaryBySnapshot(ctx context.Context, snapshotID uuid.UUID) ([]SecretFindingSummaryRow, error) {
	return q.db.ListSecretFindingSummaryBySnapshot(ctx, snapshotID)
}

func (q *Queries) ListSecretFindingsByRepo(ctx context.Context, repoID uuid.UUID, limit, offset int) ([]SecretFinding, int, error) {
	rows, err := q.db.ListSecretFindingsByRepo(ctx, dbgen.ListSecretFindingsByRepoParams{
		RepoID: repoID,
		Limit:  int32(limit),
		Offset: int32(offset),
	})
	if err != nil {
		return nil, 0, err
	}

	findings := make([]SecretFinding, len(rows))
	for i, row := range rows {
		findings[i] = *secretFindingFromRow(row)
	}

	total, err := q.db.CountSecretFindingsByRepo(ctx, repoID)
	if err != nil {
		return nil, 0, err
	}

	return findings, int(total), nil
}

func (q *Queries) ListAllSecretFindingsBySnapshot(ctx context.Context, snapshotID uuid.UUID) ([]dbgen.SecretFinding, error) {
	return q.db.ListAllSecretFindingsBySnapshot(ctx, snapshotID)
}

func (q *Queries) BulkUpdateSecretFindingStatus(ctx context.Context, ids []uuid.UUID, status SecretStatus, note string) error {
	return q.db.BulkUpdateSecretFindingStatus(ctx, dbgen.BulkUpdateSecretFindingStatusParams{Column1: ids, Status: status, StatusNote: note})
}

func (q *Queries) UpdateSecretFindingStatus(ctx context.Context, id uuid.UUID, status SecretStatus, note string) (*SecretFinding, error) {
	row, err := q.db.UpdateSecretFindingStatus(ctx, dbgen.UpdateSecretFindingStatusParams{
		ID:         id,
		Status:     status,
		StatusNote: note,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return secretFindingFromRow(row), nil
}

func secretFindingFromRow(row dbgen.SecretFinding) *SecretFinding {
	return &SecretFinding{
		ID:               row.ID,
		SnapshotID:       row.SnapshotID,
		Tool:             row.Tool,
		RuleID:           row.RuleID,
		Severity:         row.Severity,
		Status:           row.Status,
		StatusNote:       row.StatusNote,
		DiscoveryContext: row.DiscoveryContext,
		FilePath:         row.FilePath,
		StartLine:        int32PtrFromNull(row.StartLine),
		EndLine:          int32PtrFromNull(row.EndLine),
		SecretType:       row.SecretType,
		SecretHash:       row.SecretHash,
		CommitSHA:        row.CommitSha,
		AuthorEmail:      row.AuthorEmail,
		Verified:         row.Verified,
		Fingerprint:      row.Fingerprint,
		Metadata:         row.Metadata,
		CreatedAt:        row.CreatedAt,
	}
}

func secretFindingSourceFromRow(row dbgen.SecretFindingSource) *SecretFindingSource {
	return &SecretFindingSource{
		ID:          row.ID,
		FindingID:   row.FindingID,
		Tool:        row.Tool,
		RuleID:      row.RuleID,
		FirstSeenAt: row.FirstSeenAt,
		LastSeenAt:  row.LastSeenAt,
		ScanCount:   row.ScanCount,
		Metadata:    row.Metadata,
	}
}
