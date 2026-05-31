package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/lehibou/internal/store/dbgen"
)

type VulnerabilityListOptions struct {
	Types      []string
	Severities []string
	Statuses   []string
	Scanners   []string
	Languages  []string
	FileQuery  string
	Search     string
	Sort       string
	Limit      int
	Offset     int
}

// Vulnerability is the unified security issue type.
type Vulnerability struct {
	ID                      uuid.UUID       `json:"id"`
	Type                    string          `json:"type"`
	SnapshotID              uuid.UUID       `json:"snapshot_id"`
	Title                   string          `json:"title"`
	Description             string          `json:"description"`
	PrimaryIdentifier       json.RawMessage `json:"primary_identifier,omitempty"`
	Identifiers             json.RawMessage `json:"identifiers,omitempty"`
	OriginalSeverity        SeverityLevel   `json:"original_severity"`
	Severity                SeverityLevel   `json:"severity"`
	SeverityOverrideReason  *string         `json:"severity_override_reason,omitempty"`
	SeverityOverrideBy      *uuid.UUID      `json:"severity_override_by,omitempty"`
	Status                  string          `json:"status"`
	DismissalReason         *string         `json:"dismissal_reason,omitempty"`
	StateComment            *string         `json:"state_comment,omitempty"`
	DetectedAt              time.Time       `json:"detected_at"`
	ConfirmedAt             *time.Time      `json:"confirmed_at,omitempty"`
	ConfirmedBy             *uuid.UUID      `json:"confirmed_by,omitempty"`
	DismissedAt             *time.Time      `json:"dismissed_at,omitempty"`
	DismissedBy             *uuid.UUID      `json:"dismissed_by,omitempty"`
	ResolvedAt              *time.Time      `json:"resolved_at,omitempty"`
	ResolvedBy              *uuid.UUID      `json:"resolved_by,omitempty"`
	ScannerName             string          `json:"scanner_name,omitempty"`
	ScannerVendor           string          `json:"scanner_vendor,omitempty"`
	ScannerVersion          string          `json:"scanner_version,omitempty"`
	ScannerExternalID       string          `json:"scanner_external_id,omitempty"`
	FilePath                *string         `json:"file_path,omitempty"`
	StartLine               *int32          `json:"start_line,omitempty"`
	EndLine                 *int32          `json:"end_line,omitempty"`
	LocationHash            *string         `json:"location_hash,omitempty"`
	Fingerprint             string          `json:"fingerprint"`
	ComponentID             *uuid.UUID      `json:"component_id,omitempty"`
	ComponentName           *string         `json:"component_name,omitempty"`
	ComponentVersion        *string         `json:"component_version,omitempty"`
	ComponentPurl           *string         `json:"component_purl,omitempty"`
	Ecosystem               *string         `json:"ecosystem,omitempty"`
	AdvisoryID              *uuid.UUID      `json:"advisory_id,omitempty"`
	AffectedRangeID         *uuid.UUID      `json:"affected_range_id,omitempty"`
	Language                *string         `json:"language,omitempty"`
	Confidence              *string         `json:"confidence,omitempty"`
	Solution                *string         `json:"solution,omitempty"`
	HasRemediation          bool            `json:"has_remediation"`
	RemediationLink         *string         `json:"remediation_link,omitempty"`
	Reachability            *string         `json:"reachability,omitempty"`
	OwaspTop10              *string         `json:"owasp_top_10,omitempty"`
	DueDate                 *time.Time      `json:"due_date,omitempty"`
	PresentOnDefaultBranch  bool            `json:"present_on_default_branch"`
	ResolvedOnDefaultBranch bool            `json:"resolved_on_default_branch"`
	SecretType              *string         `json:"secret_type,omitempty"`
	SecretHash              *string         `json:"secret_hash,omitempty"`
	CommitSHA               *string         `json:"commit_sha,omitempty"`
	AuthorEmail             *string         `json:"author_email,omitempty"`
	Verified                *bool           `json:"verified,omitempty"`
	CreatedBy               *uuid.UUID      `json:"created_by,omitempty"`
	Metadata                json.RawMessage `json:"metadata,omitempty"`
	CreatedAt               time.Time       `json:"created_at"`
	UpdatedAt               time.Time       `json:"updated_at"`
	FirstSeenAt             time.Time       `json:"first_seen_at"`
	LastSeenAt              time.Time       `json:"last_seen_at"`
}

func (q *Queries) CreateVulnerability(ctx context.Context, params dbgen.CreateVulnerabilityParams) (*Vulnerability, error) {
	if len(params.PrimaryIdentifier) == 0 {
		params.PrimaryIdentifier = json.RawMessage(`{}`)
	}
	if len(params.Identifiers) == 0 {
		params.Identifiers = json.RawMessage(`[]`)
	}
	if len(params.Metadata) == 0 {
		params.Metadata = json.RawMessage(`{}`)
	}

	row, err := q.db.CreateVulnerability(ctx, params)
	if err != nil {
		return nil, err
	}

	return vulnerabilityFromRow(row), nil
}

func (q *Queries) GetVulnerabilityByID(ctx context.Context, id uuid.UUID) (*Vulnerability, error) {
	row, err := q.db.GetVulnerabilityByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return vulnerabilityFromRow(row), nil
}

func (q *Queries) ListVulnerabilitiesBySnapshot(ctx context.Context, snapshotID uuid.UUID, opts VulnerabilityListOptions) ([]Vulnerability, int, error) {
	statuses := normalizeStringFilters(opts.Statuses)
	if len(statuses) == 0 {
		statuses = []string{"detected", "confirmed", "dismissed", "resolved"}
	}
	params := dbgen.ListVulnerabilitiesBySnapshotParams{
		SnapshotID: snapshotID,
		Limit:      int32(opts.Limit),  //nolint:gosec // G115: pagination values are bounded by API parsing.
		Offset:     int32(opts.Offset), //nolint:gosec // G115: pagination values are bounded by API parsing.
		Statuses:   statuses,
		Types:      normalizeStringFilters(opts.Types),
		Severities: normalizeStringFilters(opts.Severities),
		Scanners:   normalizeStringFilters(opts.Scanners),
		Languages:  normalizeStringFilters(opts.Languages),
		FileQuery:  escapeLikeFragment(opts.FileQuery),
		Search:     escapeLikeFragment(opts.Search),
		Sort:       normalizeVulnerabilitySort(opts.Sort),
	}

	rows, err := q.db.ListVulnerabilitiesBySnapshot(ctx, dbgen.ListVulnerabilitiesBySnapshotParams{
		SnapshotID: params.SnapshotID,
		Limit:      params.Limit,
		Offset:     params.Offset,
		Statuses:   params.Statuses,
		Types:      params.Types,
		Severities: params.Severities,
		Scanners:   params.Scanners,
		Languages:  params.Languages,
		FileQuery:  params.FileQuery,
		Search:     params.Search,
		Sort:       params.Sort,
	})
	if err != nil {
		return nil, 0, err
	}

	vulnerabilities := make([]Vulnerability, len(rows))
	for i, row := range rows {
		vulnerabilities[i] = *vulnerabilityFromRow(row)
	}

	total, err := q.db.CountVulnerabilitiesBySnapshot(ctx, dbgen.CountVulnerabilitiesBySnapshotParams{
		SnapshotID: params.SnapshotID,
		Statuses:   params.Statuses,
		Types:      params.Types,
		Severities: params.Severities,
		Scanners:   params.Scanners,
		Languages:  params.Languages,
		FileQuery:  params.FileQuery,
		Search:     params.Search,
	})
	if err != nil {
		return nil, 0, err
	}

	return vulnerabilities, int(total), nil
}

func (q *Queries) ListVulnerabilitiesBySnapshotDynamic(ctx context.Context, snapshotID uuid.UUID, where string, params []interface{}, sort string, limit, offset int) ([]Vulnerability, int, error) {
	baseWhere := "snapshot_id = $1"
	baseArgs := make([]interface{}, 0, len(params)+1)
	baseArgs = append(baseArgs, snapshotID)
	baseArgs = append(baseArgs, params...)

	if strings.TrimSpace(where) != "" {
		baseWhere += " AND " + where
	}

	sort = normalizeVulnerabilitySort(sort)
	sortParam := len(baseArgs) + 1
	//nolint:gosec // G201: query uses validated sort input and positional parameters.
	listSQL := fmt.Sprintf(`SELECT %s FROM vulnerabilities
WHERE %s
%s
LIMIT $%d OFFSET $%d`, vulnerabilitySelectColumns, baseWhere, vulnerabilityOrderByClause(sortParam), sortParam+1, sortParam+2)

	listArgs := append(append([]interface{}{}, baseArgs...), sort, limit, offset)
	rows, err := q.sqlDB.QueryContext(ctx, listSQL, listArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	vulnerabilities := []Vulnerability{}
	for rows.Next() {
		row, err := scanVulnerabilityRow(rows)
		if err != nil {
			return nil, 0, err
		}
		vulnerabilities = append(vulnerabilities, *vulnerabilityFromRow(row))
	}
	if err := rows.Close(); err != nil {
		return nil, 0, err
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	countSQL := "SELECT COUNT(*)::bigint FROM vulnerabilities\nWHERE " + baseWhere
	var total int64
	if err := q.sqlDB.QueryRowContext(ctx, countSQL, baseArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	return vulnerabilities, int(total), nil
}

func normalizeStringFilters(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}

	normalized := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		trimmed := strings.ToLower(strings.TrimSpace(value))
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}

	if normalized == nil {
		return []string{}
	}

	return normalized
}

func escapeLikeFragment(value string) string {
	trimmed := strings.TrimSpace(value)
	trimmed = strings.ReplaceAll(trimmed, `\`, `\\`)
	trimmed = strings.ReplaceAll(trimmed, `%`, `\%`)
	trimmed = strings.ReplaceAll(trimmed, `_`, `\_`)
	return trimmed
}

func normalizeVulnerabilitySort(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "severity_asc", "severity_desc", "status_asc", "status_desc", "detected_asc", "detected_desc":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "detected_desc"
	}
}

func (q *Queries) ListAllVulnerabilitiesBySnapshot(ctx context.Context, snapshotID uuid.UUID) ([]Vulnerability, error) {
	rows, err := q.db.ListAllVulnerabilitiesBySnapshot(ctx, snapshotID)
	if err != nil {
		return nil, err
	}

	vulnerabilities := make([]Vulnerability, len(rows))
	for i, row := range rows {
		vulnerabilities[i] = *vulnerabilityFromRow(row)
	}

	return vulnerabilities, nil
}

func (q *Queries) UpdateVulnerabilityStatus(ctx context.Context, id uuid.UUID, status string, comment, dismissalReason *string, userID *uuid.UUID) (*Vulnerability, error) {
	params := dbgen.UpdateVulnerabilityStatusParams{
		ID:           id,
		Status:       status,
		StateComment: nullStringFromPtr(comment),
		ConfirmedBy:  nullUUIDFromPtr(userID),
	}
	if dismissalReason != nil && *dismissalReason != "" {
		params.DismissalReason = dbgen.NullDismissalReason{DismissalReason: dbgen.DismissalReason(*dismissalReason), Valid: true}
	}

	row, err := q.db.UpdateVulnerabilityStatus(ctx, params)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return vulnerabilityFromRow(row), nil
}

func (q *Queries) MarkStaleVulnerabilities(ctx context.Context, snapshotID uuid.UUID, vulnType string, freshIDs []uuid.UUID) error {
	return q.db.MarkStaleVulnerabilities(ctx, dbgen.MarkStaleVulnerabilitiesParams{
		SnapshotID: snapshotID,
		VulnType:   vulnType,
		FreshIds:   freshIDs,
	})
}

func vulnerabilityFromRow(row dbgen.Vulnerability) *Vulnerability {
	return &Vulnerability{
		ID:                      row.ID,
		Type:                    row.Type,
		SnapshotID:              row.SnapshotID,
		Title:                   row.Title,
		Description:             row.Description,
		PrimaryIdentifier:       row.PrimaryIdentifier,
		Identifiers:             row.Identifiers,
		OriginalSeverity:        row.OriginalSeverity,
		Severity:                row.Severity,
		SeverityOverrideReason:  stringPtrFromNull(row.SeverityOverrideReason),
		SeverityOverrideBy:      uuidPtrFromNull(row.SeverityOverrideBy),
		Status:                  row.Status,
		DismissalReason:         dismissalReasonPtrFromNull(row.DismissalReason),
		StateComment:            stringPtrFromNull(row.StateComment),
		DetectedAt:              row.DetectedAt,
		ConfirmedAt:             timePtrFromNull(row.ConfirmedAt),
		ConfirmedBy:             uuidPtrFromNull(row.ConfirmedBy),
		DismissedAt:             timePtrFromNull(row.DismissedAt),
		DismissedBy:             uuidPtrFromNull(row.DismissedBy),
		ResolvedAt:              timePtrFromNull(row.ResolvedAt),
		ResolvedBy:              uuidPtrFromNull(row.ResolvedBy),
		ScannerName:             row.ScannerName,
		ScannerVendor:           row.ScannerVendor,
		ScannerVersion:          row.ScannerVersion,
		ScannerExternalID:       row.ScannerExternalID,
		FilePath:                stringPtrFromNull(row.FilePath),
		StartLine:               int32PtrFromNull(row.StartLine),
		EndLine:                 int32PtrFromNull(row.EndLine),
		LocationHash:            stringPtrFromNull(row.LocationHash),
		Fingerprint:             row.Fingerprint,
		ComponentID:             uuidPtrFromNull(row.ComponentID),
		ComponentName:           stringPtrFromNull(row.ComponentName),
		ComponentVersion:        stringPtrFromNull(row.ComponentVersion),
		ComponentPurl:           stringPtrFromNull(row.ComponentPurl),
		Ecosystem:               stringPtrFromNull(row.Ecosystem),
		AdvisoryID:              uuidPtrFromNull(row.AdvisoryID),
		AffectedRangeID:         uuidPtrFromNull(row.AffectedRangeID),
		Language:                stringPtrFromNull(row.Language),
		Confidence:              stringPtrFromNull(row.Confidence),
		Solution:                stringPtrFromNull(row.Solution),
		HasRemediation:          row.HasRemediation,
		RemediationLink:         stringPtrFromNull(row.RemediationLink),
		Reachability:            reachabilityPtrFromNull(row.Reachability),
		OwaspTop10:              stringPtrFromNull(row.OwaspTop10),
		DueDate:                 timePtrFromNull(row.DueDate),
		PresentOnDefaultBranch:  row.PresentOnDefaultBranch,
		ResolvedOnDefaultBranch: row.ResolvedOnDefaultBranch,
		SecretType:              stringPtrFromNull(row.SecretType),
		SecretHash:              stringPtrFromNull(row.SecretHash),
		CommitSHA:               stringPtrFromNull(row.CommitSha),
		AuthorEmail:             stringPtrFromNull(row.AuthorEmail),
		Verified:                boolPtrFromNull(row.Verified),
		CreatedBy:               uuidPtrFromNull(row.CreatedBy),
		Metadata:                row.Metadata,
		CreatedAt:               row.CreatedAt,
		UpdatedAt:               row.UpdatedAt,
		FirstSeenAt:             row.FirstSeenAt,
		LastSeenAt:              row.LastSeenAt,
	}
}

const vulnerabilitySelectColumns = "id, type, snapshot_id, title, description, primary_identifier, identifiers, original_severity, severity, severity_override_reason, severity_override_by, status, dismissal_reason, state_comment, detected_at, confirmed_at, confirmed_by, dismissed_at, dismissed_by, resolved_at, resolved_by, scanner_name, scanner_vendor, scanner_version, scanner_external_id, file_path, start_line, end_line, location_hash, fingerprint, component_id, component_name, component_version, component_purl, ecosystem, advisory_id, affected_range_id, language, confidence, solution, has_remediation, remediation_link, reachability, owasp_top_10, due_date, present_on_default_branch, resolved_on_default_branch, secret_type, secret_hash, commit_sha, author_email, verified, created_by, metadata, created_at, updated_at, first_seen_at, last_seen_at"

//nolint:dupword // SQL CASE ... END END closes nested CASE expressions.
func vulnerabilityOrderByClause(sortParam int) string {
	return fmt.Sprintf(`ORDER BY
  CASE WHEN $%d::text = 'severity_asc' THEN CASE severity
    WHEN 'info' THEN 1
    WHEN 'low' THEN 2
    WHEN 'medium' THEN 3
    WHEN 'high' THEN 4
    WHEN 'critical' THEN 5
    ELSE 0
  END END ASC,
  CASE WHEN $%d::text = 'severity_desc' THEN CASE severity
    WHEN 'info' THEN 1
    WHEN 'low' THEN 2
    WHEN 'medium' THEN 3
    WHEN 'high' THEN 4
    WHEN 'critical' THEN 5
    ELSE 0
  END END DESC,
  CASE WHEN $%d::text = 'status_asc' THEN status END ASC,
  CASE WHEN $%d::text = 'status_desc' THEN status END DESC,
  CASE WHEN $%d::text = 'detected_asc' THEN detected_at END ASC,
  CASE WHEN $%d::text = 'detected_desc' OR $%d::text = '' THEN detected_at END DESC,
  id DESC`, sortParam, sortParam, sortParam, sortParam, sortParam, sortParam, sortParam)
}

func scanVulnerabilityRow(scanner interface {
	Scan(dest ...interface{}) error
}) (dbgen.Vulnerability, error) {
	var row dbgen.Vulnerability
	err := scanner.Scan(
		&row.ID,
		&row.Type,
		&row.SnapshotID,
		&row.Title,
		&row.Description,
		&row.PrimaryIdentifier,
		&row.Identifiers,
		&row.OriginalSeverity,
		&row.Severity,
		&row.SeverityOverrideReason,
		&row.SeverityOverrideBy,
		&row.Status,
		&row.DismissalReason,
		&row.StateComment,
		&row.DetectedAt,
		&row.ConfirmedAt,
		&row.ConfirmedBy,
		&row.DismissedAt,
		&row.DismissedBy,
		&row.ResolvedAt,
		&row.ResolvedBy,
		&row.ScannerName,
		&row.ScannerVendor,
		&row.ScannerVersion,
		&row.ScannerExternalID,
		&row.FilePath,
		&row.StartLine,
		&row.EndLine,
		&row.LocationHash,
		&row.Fingerprint,
		&row.ComponentID,
		&row.ComponentName,
		&row.ComponentVersion,
		&row.ComponentPurl,
		&row.Ecosystem,
		&row.AdvisoryID,
		&row.AffectedRangeID,
		&row.Language,
		&row.Confidence,
		&row.Solution,
		&row.HasRemediation,
		&row.RemediationLink,
		&row.Reachability,
		&row.OwaspTop10,
		&row.DueDate,
		&row.PresentOnDefaultBranch,
		&row.ResolvedOnDefaultBranch,
		&row.SecretType,
		&row.SecretHash,
		&row.CommitSha,
		&row.AuthorEmail,
		&row.Verified,
		&row.CreatedBy,
		&row.Metadata,
		&row.CreatedAt,
		&row.UpdatedAt,
		&row.FirstSeenAt,
		&row.LastSeenAt,
	)
	return row, err
}

func boolPtrFromNull(value sql.NullBool) *bool {
	if !value.Valid {
		return nil
	}
	v := value.Bool
	return &v
}

func dismissalReasonPtrFromNull(value dbgen.NullDismissalReason) *string {
	if !value.Valid {
		return nil
	}
	v := string(value.DismissalReason)
	return &v
}

func reachabilityPtrFromNull(value dbgen.NullReachability) *string {
	if !value.Valid {
		return nil
	}
	v := string(value.Reachability)
	return &v
}
