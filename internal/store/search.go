package store

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/google/uuid"
	"github.com/hibouhq/lehibou/internal/store/dbgen"
)

func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return "%" + s + "%"
}

func searchPattern(query string) string {
	trimmed := strings.TrimSpace(query)
	if trimmed == "" {
		return "%"
	}
	return escapeLike(trimmed)
}

func normalizeSeverity(level string) (SeverityLevel, bool) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case string(SeverityLevelCritical):
		return SeverityLevelCritical, true
	case string(SeverityLevelHigh):
		return SeverityLevelHigh, true
	case string(SeverityLevelMedium):
		return SeverityLevelMedium, true
	case string(SeverityLevelLow):
		return SeverityLevelLow, true
	case string(SeverityLevelInfo):
		return SeverityLevelInfo, true
	default:
		return "", false
	}
}

func (q *Queries) SearchAdvisories(ctx context.Context, orgID uuid.UUID, query, severity string, limit, offset int) ([]dbgen.Advisory, int, error) {
	pattern := searchPattern(query)
	if normalizedSeverity, ok := normalizeSeverity(severity); ok {
		rows, err := q.db.SearchAdvisoriesBySeverity(ctx, dbgen.SearchAdvisoriesBySeverityParams{
			OrgID:      orgID,
			LikeEscape: []byte(pattern),
			Severity:   normalizedSeverity,
			Limit:      int32(limit),
			Offset:     int32(offset),
		})
		if err != nil {
			return nil, 0, err
		}
		total, err := q.db.CountSearchAdvisoriesBySeverity(ctx, dbgen.CountSearchAdvisoriesBySeverityParams{
			OrgID:      orgID,
			LikeEscape: []byte(pattern),
			Severity:   normalizedSeverity,
		})
		if err != nil {
			return nil, 0, err
		}
		return rows, int(total), nil
	}

	rows, err := q.db.SearchAdvisories(ctx, dbgen.SearchAdvisoriesParams{OrgID: orgID, LikeEscape: []byte(pattern), Limit: int32(limit), Offset: int32(offset)})
	if err != nil {
		return nil, 0, err
	}
	total, err := q.db.CountSearchAdvisories(ctx, dbgen.CountSearchAdvisoriesParams{OrgID: orgID, LikeEscape: []byte(pattern)})
	if err != nil {
		return nil, 0, err
	}
	return rows, int(total), nil
}

func (q *Queries) SearchComponents(ctx context.Context, orgID uuid.UUID, query string, limit, offset int) ([]dbgen.Component, int, error) {
	pattern := searchPattern(query)
	rows, err := q.db.SearchComponents(ctx, dbgen.SearchComponentsParams{OrgID: orgID, LikeEscape: []byte(pattern), Limit: int32(limit), Offset: int32(offset)})
	if err != nil {
		return nil, 0, err
	}
	total, err := q.db.CountSearchComponents(ctx, dbgen.CountSearchComponentsParams{OrgID: orgID, LikeEscape: []byte(pattern)})
	if err != nil {
		return nil, 0, err
	}
	return rows, int(total), nil
}

func (q *Queries) SearchFindings(ctx context.Context, orgID uuid.UUID, query, severity string, limit, offset int) ([]dbgen.Finding, int, error) {
	pattern := searchPattern(query)
	if normalizedSeverity, ok := normalizeSeverity(severity); ok {
		rows, err := q.db.SearchFindingsBySeverity(ctx, dbgen.SearchFindingsBySeverityParams{
			OrgID:      orgID,
			LikeEscape: []byte(pattern),
			Severity:   normalizedSeverity,
			Limit:      int32(limit),
			Offset:     int32(offset),
		})
		if err != nil {
			return nil, 0, err
		}
		total, err := q.db.CountSearchFindingsBySeverity(ctx, dbgen.CountSearchFindingsBySeverityParams{
			OrgID:      orgID,
			LikeEscape: []byte(pattern),
			Severity:   normalizedSeverity,
		})
		if err != nil {
			return nil, 0, err
		}
		return rows, int(total), nil
	}

	rows, err := q.db.SearchFindings(ctx, dbgen.SearchFindingsParams{OrgID: orgID, LikeEscape: []byte(pattern), Limit: int32(limit), Offset: int32(offset)})
	if err != nil {
		return nil, 0, err
	}
	total, err := q.db.CountSearchFindings(ctx, dbgen.CountSearchFindingsParams{OrgID: orgID, LikeEscape: []byte(pattern)})
	if err != nil {
		return nil, 0, err
	}
	return rows, int(total), nil
}

func (q *Queries) SearchClients(ctx context.Context, orgID uuid.UUID, query string, limit, offset int) ([]Client, int, error) {
	pattern := searchPattern(query)
	rows, err := q.db.SearchClients(ctx, dbgen.SearchClientsParams{OrgID: orgID, LikeEscape: []byte(pattern), Limit: int32(limit), Offset: int32(offset)})
	if err != nil {
		return nil, 0, err
	}

	clients := make([]Client, len(rows))
	for i, row := range rows {
		clients[i] = *clientFromRow(row)
	}

	total, err := q.db.CountSearchClients(ctx, dbgen.CountSearchClientsParams{OrgID: orgID, LikeEscape: []byte(pattern)})
	if err != nil {
		return nil, 0, err
	}

	return clients, int(total), nil
}

func defaultJSON(value json.RawMessage, fallback []byte) json.RawMessage {
	if len(value) == 0 {
		return json.RawMessage(fallback)
	}
	return value
}
