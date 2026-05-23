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

type SeverityLevel = dbgen.SeverityLevel

const (
	SeverityLevelCritical = dbgen.SeverityLevelCritical
	SeverityLevelHigh     = dbgen.SeverityLevelHigh
	SeverityLevelMedium   = dbgen.SeverityLevelMedium
	SeverityLevelLow      = dbgen.SeverityLevelLow
	SeverityLevelInfo     = dbgen.SeverityLevelInfo
)

type Finding struct {
	ID           uuid.UUID       `json:"id"`
	SnapshotID   uuid.UUID       `json:"snapshot_id"`
	Tool         string          `json:"tool"`
	RuleID       string          `json:"rule_id"`
	Severity     SeverityLevel   `json:"severity"`
	Status       string          `json:"status"`
	FilePath     string          `json:"file_path"`
	StartLine    *int32          `json:"start_line,omitempty"`
	EndLine      *int32          `json:"end_line,omitempty"`
	LocationHash string          `json:"location_hash"`
	Message      string          `json:"message"`
	Fingerprint  *string         `json:"fingerprint,omitempty"`
	Metadata     json.RawMessage `json:"metadata"`
	CreatedAt    time.Time       `json:"created_at"`
}

func (q *Queries) CreateFinding(ctx context.Context, snapshotID uuid.UUID, tool, ruleID string, severity SeverityLevel, status, filePath string, startLine, endLine *int32, locationHash, message string, fingerprint *string, metadata json.RawMessage) (*Finding, error) {
	if metadata == nil {
		metadata = json.RawMessage(`{}`)
	}

	row, err := q.db.CreateFinding(ctx, dbgen.CreateFindingParams{
		SnapshotID:   snapshotID,
		Tool:         tool,
		RuleID:       ruleID,
		Severity:     severity,
		Status:       status,
		FilePath:     filePath,
		StartLine:    nullInt32FromPtr(startLine),
		EndLine:      nullInt32FromPtr(endLine),
		LocationHash: locationHash,
		Message:      message,
		Fingerprint:  nullStringFromPtr(fingerprint),
		Metadata:     metadata,
	})
	if err != nil {
		return nil, err
	}

	return findingFromRow(row), nil
}

func (q *Queries) GetFindingByID(ctx context.Context, id uuid.UUID) (*Finding, error) {
	row, err := q.db.GetFindingByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return findingFromRow(row), nil
}

func (q *Queries) ListFindingsBySnapshot(ctx context.Context, snapshotID uuid.UUID, limit, offset int) ([]Finding, int, error) {
	rows, err := q.db.ListFindingsBySnapshot(ctx, dbgen.ListFindingsBySnapshotParams{
		SnapshotID: snapshotID,
		Limit:      int32(limit),
		Offset:     int32(offset),
	})
	if err != nil {
		return nil, 0, err
	}

	findings := make([]Finding, len(rows))
	for i, row := range rows {
		findings[i] = *findingFromRow(row)
	}

	total, err := q.db.CountFindingsBySnapshot(ctx, snapshotID)
	if err != nil {
		return nil, 0, err
	}

	return findings, int(total), nil
}

func (q *Queries) ListFindingsBySnapshotAndTool(ctx context.Context, snapshotID uuid.UUID, tool string, limit, offset int) ([]Finding, int, error) {
	rows, err := q.db.ListFindingsBySnapshotAndTool(ctx, dbgen.ListFindingsBySnapshotAndToolParams{
		SnapshotID: snapshotID,
		Tool:       tool,
		Limit:      int32(limit),
		Offset:     int32(offset),
	})
	if err != nil {
		return nil, 0, err
	}

	findings := make([]Finding, len(rows))
	for i, row := range rows {
		findings[i] = *findingFromRow(row)
	}

	total, err := q.db.CountFindingsBySnapshotAndTool(ctx, dbgen.CountFindingsBySnapshotAndToolParams{
		SnapshotID: snapshotID,
		Tool:       tool,
	})
	if err != nil {
		return nil, 0, err
	}

	return findings, int(total), nil
}

func findingFromRow(row dbgen.Finding) *Finding {
	return &Finding{
		ID:           row.ID,
		SnapshotID:   row.SnapshotID,
		Tool:         row.Tool,
		RuleID:       row.RuleID,
		Severity:     row.Severity,
		Status:       row.Status,
		FilePath:     row.FilePath,
		StartLine:    int32PtrFromNull(row.StartLine),
		EndLine:      int32PtrFromNull(row.EndLine),
		LocationHash: row.LocationHash,
		Message:      row.Message,
		Fingerprint:  stringPtrFromNull(row.Fingerprint),
		Metadata:     row.Metadata,
		CreatedAt:    row.CreatedAt,
	}
}