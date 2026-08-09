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
	"github.com/lib/pq"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type VulnerabilityListOptions struct {
	Types      []string
	Severities []string
	Statuses   []string
	Scanners   []string
	Languages  []string
	FileQuery  string
	Search     string
	// Acceptance filters on the triage decision (ADR-023): "open" (no active
	// acceptance), "accepted" (any), or a reason kind ("risk_accepted",
	// "false_positive"). Empty means no acceptance filter.
	Acceptance string
	Sort       string
	Limit      int
	Offset     int
}

// normalizeAcceptanceFilter whitelists the acceptance filter value; anything
// unrecognized is dropped rather than silently matching nothing.
func normalizeAcceptanceFilter(value string) string {
	switch value {
	case "open", "accepted", "risk_accepted", "false_positive":
		return value
	}
	return ""
}

// Vulnerability is the unified security issue type.
type Vulnerability struct {
	ID                      uuid.UUID       `json:"id"`
	Type                    string          `json:"type"`
	SnapshotID              uuid.UUID       `json:"snapshot_id"`
	Title                   string          `json:"title"`
	Description             string          `json:"description"`
	PrimaryIdentifierKind   string          `json:"primary_identifier_kind,omitempty"`
	PrimaryIdentifierValue  string          `json:"primary_identifier_value,omitempty"`
	OriginalSeverity        SeverityLevel   `json:"original_severity"`
	Severity                SeverityLevel   `json:"severity"`
	SeverityOverrideReason  *string         `json:"severity_override_reason,omitempty"`
	SeverityOverrideBy      *uuid.UUID      `json:"severity_override_by,omitempty"`
	Status                  string          `json:"status"`
	StateComment            *string         `json:"state_comment,omitempty"`
	DetectedAt              time.Time       `json:"detected_at"`
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
	Origin                  string          `json:"origin"`
	OriginAPIKeyID          *uuid.UUID      `json:"origin_api_key_id,omitempty"`
	OriginTokenName         string          `json:"origin_token_name,omitempty"`
	OriginOwnerType         string          `json:"origin_owner_type,omitempty"`
	OriginOwnerID           *uuid.UUID      `json:"origin_owner_id,omitempty"`
	Metadata                json.RawMessage `json:"metadata,omitempty"`
	CreatedAt               time.Time       `json:"created_at"`
	UpdatedAt               time.Time       `json:"updated_at"`
	FirstSeenAt             time.Time       `json:"first_seen_at"`
	LastSeenAt              time.Time       `json:"last_seen_at"`
	// Acceptance is the ADR-023 decision projection, joined server-side in the
	// list queries. Nil = open.
	Acceptance *VulnerabilityAcceptance `json:"acceptance,omitempty"`
	// FixedInPRs lists open pull requests whose latest gate run resolves this
	// fingerprint — it changes the triage decision ("merge #12 instead of
	// accepting"). Attached by the list/detail handlers, never stored.
	FixedInPRs []FixingPullRequest `json:"fixed_in_prs,omitempty"`
}

// VulnerabilityAcceptance is the accepted decision as projected onto a
// finding row (ADR-023).
type VulnerabilityAcceptance struct {
	ReasonKind       string     `json:"reason_kind"`
	Reason           string     `json:"reason,omitempty"`
	Labels           []string   `json:"labels,omitempty"`
	VEXJustification *string    `json:"vex_justification,omitempty"`
	AcceptedBy       *uuid.UUID `json:"accepted_by,omitempty"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
}

// acceptanceFromNullable assembles the projection from the LEFT JOIN's
// nullable columns; reason_kind NULL means no acceptance row matched.
func acceptanceFromNullable(reasonKind dbgen.NullAcceptanceReasonKind, reason sql.NullString, labels []string, justification dbgen.NullVexJustification, acceptedBy uuid.NullUUID, expiresAt, createdAt sql.NullTime) *VulnerabilityAcceptance {
	if !reasonKind.Valid {
		return nil
	}
	acceptance := &VulnerabilityAcceptance{
		ReasonKind: string(reasonKind.AcceptanceReasonKind),
		Reason:     reason.String,
		Labels:     labels,
	}
	if acceptance.Labels == nil {
		acceptance.Labels = []string{}
	}
	if justification.Valid {
		value := string(justification.VexJustification)
		acceptance.VEXJustification = &value
	}
	if acceptedBy.Valid {
		id := acceptedBy.UUID
		acceptance.AcceptedBy = &id
	}
	if expiresAt.Valid {
		expires := expiresAt.Time
		acceptance.ExpiresAt = &expires
	}
	if createdAt.Valid {
		acceptance.CreatedAt = createdAt.Time
	}
	return acceptance
}

func (q *Queries) CreateVulnerability(ctx context.Context, params dbgen.CreateVulnerabilityParams) (*Vulnerability, error) {
	if len(params.Metadata) == 0 {
		params.Metadata = json.RawMessage(`{}`)
	}
	// Ingested tool reports are the overwhelming majority of writes and never
	// carry a principal; anything that does must set it deliberately.
	if params.Origin == "" {
		params.Origin = dbgen.FindingOriginScanner
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
		statuses = []string{"detected", "resolved", "suppressed"}
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
		Acceptance: normalizeAcceptanceFilter(opts.Acceptance),
		Sort:       normalizeVulnerabilitySort(opts.Sort),
	}

	rows, err := q.db.ListVulnerabilitiesBySnapshot(ctx, params)
	if err != nil {
		return nil, 0, err
	}

	vulnerabilities := make([]Vulnerability, len(rows))
	for i, row := range rows {
		vulnerability := vulnerabilityFromRow(row.Vulnerability)
		vulnerability.Acceptance = acceptanceFromNullable(row.AcceptanceReasonKind, row.AcceptanceReason, row.AcceptanceLabels, row.AcceptanceVexJustification, row.AcceptanceAcceptedBy, row.AcceptanceExpiresAt, row.AcceptanceCreatedAt)
		vulnerabilities[i] = *vulnerability
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
		Acceptance: params.Acceptance,
	})
	if err != nil {
		return nil, 0, err
	}

	return vulnerabilities, int(total), nil
}

// ListVulnerabilitiesBySnapshots returns a paginated, filtered vulnerability list
// across multiple snapshots (used for org-wide aggregation). It mirrors the
// single-snapshot filter semantics over `snapshot_id = ANY($1)`.
func (q *Queries) ListVulnerabilitiesBySnapshots(ctx context.Context, snapshotIDs []uuid.UUID, opts VulnerabilityListOptions) ([]Vulnerability, int, error) {
	if len(snapshotIDs) == 0 {
		return []Vulnerability{}, 0, nil
	}

	conds := make([]string, 0, 6)
	args := make([]interface{}, 0, 8)
	addArg := func(value interface{}) int {
		args = append(args, value)
		return len(args)
	}

	conds = append(conds, fmt.Sprintf("snapshot_id = ANY($%d)", addArg(pq.Array(snapshotIDs))))

	statuses := normalizeStringFilters(opts.Statuses)
	if len(statuses) == 0 {
		statuses = []string{"detected", "resolved", "suppressed"}
	}
	conds = append(conds, fmt.Sprintf("status = ANY($%d)", addArg(pq.Array(statuses))))

	if types := normalizeStringFilters(opts.Types); len(types) > 0 {
		conds = append(conds, fmt.Sprintf("type = ANY($%d)", addArg(pq.Array(types))))
	}
	if severities := normalizeStringFilters(opts.Severities); len(severities) > 0 {
		conds = append(conds, fmt.Sprintf("severity = ANY($%d)", addArg(pq.Array(severities))))
	}
	if scanners := normalizeStringFilters(opts.Scanners); len(scanners) > 0 {
		conds = append(conds, fmt.Sprintf("lower(scanner_name) = ANY($%d)", addArg(pq.Array(scanners))))
	}
	if search := escapeLikeFragment(opts.Search); search != "" {
		idx := addArg("%" + search + "%")
		// primary_identifier_value is included so searching a CVE/GHSA/rule id
		// finds the finding — it is the identifier users actually paste.
		conds = append(conds, fmt.Sprintf(`(title ILIKE $%d ESCAPE '\' OR component_name ILIKE $%d ESCAPE '\' OR component_purl ILIKE $%d ESCAPE '\' OR primary_identifier_value ILIKE $%d ESCAPE '\')`, idx, idx, idx, idx))
	}

	where := strings.Join(conds, " AND ")

	sort := normalizeVulnerabilitySort(opts.Sort)
	sortParam := addArg(sort)
	limitParam := addArg(int32(opts.Limit))   //nolint:gosec // G115: pagination values bounded by API parsing.
	offsetParam := addArg(int32(opts.Offset)) //nolint:gosec // G115: pagination values bounded by API parsing.

	//nolint:gosec // G201: validated sort + positional parameters only.
	listSQL := fmt.Sprintf("SELECT %s FROM vulnerabilities\nWHERE %s\n%s\nLIMIT $%d OFFSET $%d",
		vulnerabilitySelectColumns, where, vulnerabilityOrderByClause(sortParam), limitParam, offsetParam)

	rows, err := q.sqlDB.QueryContext(ctx, listSQL, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	vulnerabilities := []Vulnerability{}
	for rows.Next() {
		row, scanErr := scanVulnerabilityRow(rows)
		if scanErr != nil {
			return nil, 0, scanErr
		}
		vulnerabilities = append(vulnerabilities, *vulnerabilityFromRow(row))
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	// total ignores limit/offset/sort args (the last three).
	countArgs := args[:len(args)-3]
	countSQL := "SELECT COUNT(*)::bigint FROM vulnerabilities\nWHERE " + where
	var total int64
	if err := q.sqlDB.QueryRowContext(ctx, countSQL, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	return vulnerabilities, int(total), nil
}

func (q *Queries) ListVulnerabilitiesBySnapshotDynamic(ctx context.Context, snapshotID uuid.UUID, where string, params []interface{}, sort string, limit, offset int) ([]Vulnerability, int, error) {
	baseWhere := "v.snapshot_id = $1"
	baseArgs := make([]interface{}, 0, len(params)+1)
	baseArgs = append(baseArgs, snapshotID)
	baseArgs = append(baseArgs, params...)

	if strings.TrimSpace(where) != "" {
		baseWhere += " AND " + where
	}

	sort = normalizeVulnerabilitySort(sort)
	sortParam := len(baseArgs) + 1
	// The acceptance LEFT JOIN (ADR-023) rides the (repo_id, fingerprint)
	// unique index; filterquery conditions may reference the fa alias
	// (acceptance:/label: qualifiers), so the count shares the join.
	//nolint:gosec // G201: query uses validated sort input and positional parameters.
	listSQL := fmt.Sprintf(`SELECT v.*, %s FROM vulnerabilities v
%s
WHERE %s
%s
LIMIT $%d OFFSET $%d`, acceptanceProjectionColumns, acceptanceJoinClause, baseWhere, vulnerabilityOrderByClause(sortParam), sortParam+1, sortParam+2)

	listArgs := append(append([]interface{}{}, baseArgs...), sort, limit, offset)
	rows, err := q.sqlDB.QueryContext(ctx, listSQL, listArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	vulnerabilities := []Vulnerability{}
	for rows.Next() {
		vulnerability, err := scanVulnerabilityWithAcceptance(rows)
		if err != nil {
			return nil, 0, err
		}
		vulnerabilities = append(vulnerabilities, *vulnerability)
	}
	if err := rows.Close(); err != nil {
		return nil, 0, err
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	countSQL := "SELECT COUNT(*)::bigint FROM vulnerabilities v\n" + acceptanceJoinClause + "\nWHERE " + baseWhere
	var total int64
	if err := q.sqlDB.QueryRowContext(ctx, countSQL, baseArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	return vulnerabilities, int(total), nil
}

// VulnerabilityFacets holds per-option result counts for each filterable
// dimension. Each map is keyed by the option value (e.g. severity "high") and
// holds the number of vulnerabilities that would match if that option were
// selected, given the OTHER active filters. A dimension's own selections are
// excluded from its own facet so every option's potential count stays visible
// (standard faceted-search semantics).
type VulnerabilityFacets struct {
	Type     map[string]int `json:"type"`
	Severity map[string]int `json:"severity"`
	Status   map[string]int `json:"status"`
	Tool     map[string]int `json:"tool"`
	File     map[string]int `json:"file"`
}

// FacetVulnerabilitiesBySnapshot computes per-option counts for each filter
// dimension. For every dimension it applies the base scope (snapshot, search)
// plus all other dimensions' active filters, but NOT the dimension's own
// filter, then groups by that dimension's column.
func (q *Queries) FacetVulnerabilitiesBySnapshot(ctx context.Context, snapshotID uuid.UUID, opts VulnerabilityListOptions) (*VulnerabilityFacets, error) {
	types := normalizeStringFilters(opts.Types)
	severities := normalizeStringFilters(opts.Severities)
	statuses := normalizeStringFilters(opts.Statuses)
	if len(statuses) == 0 {
		statuses = []string{"detected", "resolved", "suppressed"}
	}
	scanners := normalizeStringFilters(opts.Scanners)
	languages := normalizeStringFilters(opts.Languages)
	fileQuery := escapeLikeFragment(opts.FileQuery)
	search := escapeLikeFragment(opts.Search)
	acceptance := normalizeAcceptanceFilter(opts.Acceptance)

	// The acceptance filter needs the finding_acceptances join; only pay for
	// it when the filter is active. Column names stay unqualified — none of
	// the referenced vulnerability columns exist on finding_acceptances.
	fromClause := "vulnerabilities"
	if acceptance != "" {
		fromClause = "vulnerabilities v LEFT JOIN finding_acceptances fa ON fa.repo_id = v.repo_id AND fa.fingerprint = v.fingerprint AND (fa.expires_at IS NULL OR fa.expires_at > now())"
	}

	// buildConds assembles WHERE conditions, omitting the filter for `exclude`
	// so that dimension's own selection does not constrain its own facet.
	buildConds := func(exclude string) (string, []interface{}) {
		conds := make([]string, 0, 7)
		args := make([]interface{}, 0, 8)
		add := func(v interface{}) int { args = append(args, v); return len(args) }

		conds = append(conds, fmt.Sprintf("snapshot_id = $%d", add(snapshotID)))
		if exclude != "status" {
			conds = append(conds, fmt.Sprintf("status = ANY($%d)", add(pq.Array(statuses))))
		}
		if exclude != "type" && len(types) > 0 {
			conds = append(conds, fmt.Sprintf("type = ANY($%d)", add(pq.Array(types))))
		}
		if exclude != "severity" && len(severities) > 0 {
			conds = append(conds, fmt.Sprintf("severity = ANY($%d)", add(pq.Array(severities))))
		}
		if exclude != "tool" && len(scanners) > 0 {
			conds = append(conds, fmt.Sprintf("lower(scanner_name) = ANY($%d)", add(pq.Array(scanners))))
		}
		if len(languages) > 0 {
			conds = append(conds, fmt.Sprintf("language = ANY($%d)", add(pq.Array(languages))))
		}
		if exclude != "file" && fileQuery != "" {
			conds = append(conds, fmt.Sprintf(`file_path ILIKE $%d ESCAPE '\'`, add("%"+fileQuery+"%")))
		}
		if search != "" {
			idx := add("%" + search + "%")
			// primary_identifier_value is included so searching a CVE/GHSA/rule id
			// finds the finding — it is the identifier users actually paste.
			conds = append(conds, fmt.Sprintf(`(title ILIKE $%d ESCAPE '\' OR component_name ILIKE $%d ESCAPE '\' OR component_purl ILIKE $%d ESCAPE '\' OR primary_identifier_value ILIKE $%d ESCAPE '\')`, idx, idx, idx, idx))
		}
		if acceptance != "" {
			switch acceptance {
			case "open":
				conds = append(conds, "fa.fingerprint IS NULL")
			case "accepted":
				conds = append(conds, "fa.fingerprint IS NOT NULL")
			default:
				conds = append(conds, fmt.Sprintf("fa.reason_kind::text = $%d", add(acceptance)))
			}
		}
		return strings.Join(conds, " AND "), args
	}

	facetMap := func(exclude, column, extraWhere, extra string) (map[string]int, error) {
		where, args := buildConds(exclude)
		//nolint:gosec // G201: `column`/`extraWhere`/`fromClause` are constant fragments; all filter values use positional params.
		query := fmt.Sprintf("SELECT %s::text AS k, COUNT(*)::bigint FROM %s WHERE %s%s GROUP BY %s%s", column, fromClause, where, extraWhere, column, extra)
		rows, err := q.sqlDB.QueryContext(ctx, query, args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()

		out := map[string]int{}
		for rows.Next() {
			var key sql.NullString
			var count int64
			if scanErr := rows.Scan(&key, &count); scanErr != nil {
				return nil, scanErr
			}
			if !key.Valid || key.String == "" {
				continue
			}
			out[key.String] = int(count)
		}
		return out, rows.Err()
	}

	facets := &VulnerabilityFacets{}
	var err error
	if facets.Type, err = facetMap("type", "type", "", ""); err != nil {
		return nil, err
	}
	if facets.Severity, err = facetMap("severity", "severity", "", ""); err != nil {
		return nil, err
	}
	if facets.Status, err = facetMap("status", "status", "", ""); err != nil {
		return nil, err
	}
	if facets.Tool, err = facetMap("tool", "scanner_name", "", ""); err != nil {
		return nil, err
	}
	// File paths are unbounded; cap to the busiest 100 so the payload stays
	// small. Dependency findings are excluded: their location is a package
	// coordinate (gopkg.in/yaml.v2@v2.2.2), not a repository file, and offering
	// those as file filters is nonsense.
	if facets.File, err = facetMap("file", "file_path", " AND type <> 'dependency'", " ORDER BY COUNT(*) DESC LIMIT 100"); err != nil {
		return nil, err
	}
	return facets, nil
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

func (q *Queries) UpdateVulnerabilityStatus(ctx context.Context, id uuid.UUID, status string, comment *string, userID *uuid.UUID) (*Vulnerability, error) {
	params := dbgen.UpdateVulnerabilityStatusParams{
		ID:           id,
		Status:       status,
		StateComment: nullStringFromPtr(comment),
		ResolvedBy:   nullUUIDFromPtr(userID),
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

// MarkStaleVulnerabilities resolves findings the fresh scan no longer
// reports and returns their identifiers (CVE/GHSA/rule) so the notification
// dedup ledger can forget them.
func (q *Queries) MarkStaleVulnerabilities(ctx context.Context, snapshotID uuid.UUID, vulnType string, freshIDs []uuid.UUID) ([]string, error) {
	return q.db.MarkStaleVulnerabilities(ctx, dbgen.MarkStaleVulnerabilitiesParams{
		SnapshotID: snapshotID,
		VulnType:   vulnType,
		FreshIds:   freshIDs,
	})
}

// MarkFindingsNotified records identifiers on the per-repo notification
// ledger and returns only the ones that were not already there.
func (q *Queries) MarkFindingsNotified(ctx context.Context, eventType string, repoID uuid.UUID, identifiers []string) ([]string, error) {
	return q.db.MarkFindingsNotified(ctx, dbgen.MarkFindingsNotifiedParams{
		EventType:   eventType,
		RepoID:      repoID,
		Identifiers: identifiers,
	})
}

// ClearFindingsNotified forgets resolved identifiers so regressions
// re-notify.
func (q *Queries) ClearFindingsNotified(ctx context.Context, eventType string, repoID uuid.UUID, identifiers []string) error {
	return q.db.ClearFindingsNotified(ctx, dbgen.ClearFindingsNotifiedParams{
		EventType:   eventType,
		RepoID:      repoID,
		Identifiers: identifiers,
	})
}

func vulnerabilityFromRow(row dbgen.Vulnerability) *Vulnerability {
	return &Vulnerability{
		ID:                      row.ID,
		Type:                    row.Type,
		SnapshotID:              row.SnapshotID,
		Title:                   row.Title,
		Description:             row.Description,
		PrimaryIdentifierKind:   row.PrimaryIdentifierKind,
		PrimaryIdentifierValue:  row.PrimaryIdentifierValue,
		OriginalSeverity:        row.OriginalSeverity,
		Severity:                row.Severity,
		SeverityOverrideReason:  stringPtrFromNull(row.SeverityOverrideReason),
		SeverityOverrideBy:      uuidPtrFromNull(row.SeverityOverrideBy),
		Status:                  row.Status,
		StateComment:            stringPtrFromNull(row.StateComment),
		DetectedAt:              row.DetectedAt,
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
		Origin:                  string(row.Origin),
		OriginAPIKeyID:          uuidPtrFromNull(row.OriginApiKeyID),
		OriginTokenName:         row.OriginTokenName,
		OriginOwnerType:         row.OriginOwnerType,
		OriginOwnerID:           uuidPtrFromNull(row.OriginOwnerID),
		Metadata:                row.Metadata,
		CreatedAt:               row.CreatedAt,
		UpdatedAt:               row.UpdatedAt,
		FirstSeenAt:             row.FirstSeenAt,
		LastSeenAt:              row.LastSeenAt,
	}
}

const acceptanceProjectionColumns = "fa.reason_kind, fa.reason, fa.labels, fa.vex_justification, fa.accepted_by, fa.expires_at, fa.created_at"

const acceptanceJoinClause = `LEFT JOIN finding_acceptances fa
  ON fa.repo_id = v.repo_id AND fa.fingerprint = v.fingerprint
  AND (fa.expires_at IS NULL OR fa.expires_at > now())`

// scanVulnerabilityWithAcceptance scans v.* (physical column order) plus the
// acceptance projection appended by the dynamic list query.
func scanVulnerabilityWithAcceptance(scanner interface {
	Scan(dest ...interface{}) error
}) (*Vulnerability, error) {
	var row dbgen.Vulnerability
	var reasonKind dbgen.NullAcceptanceReasonKind
	var reason sql.NullString
	var labels []string
	var justification dbgen.NullVexJustification
	var acceptedBy uuid.NullUUID
	var expiresAt, createdAt sql.NullTime

	dest := vulnerabilityScanDest(&row)
	dest = append(dest, &reasonKind, &reason, pq.Array(&labels), &justification, &acceptedBy, &expiresAt, &createdAt)
	if err := scanner.Scan(dest...); err != nil {
		return nil, err
	}

	vulnerability := vulnerabilityFromRow(row)
	vulnerability.Acceptance = acceptanceFromNullable(reasonKind, reason, labels, justification, acceptedBy, expiresAt, createdAt)
	return vulnerability, nil
}

const vulnerabilitySelectColumns = "id, type, snapshot_id, title, description, primary_identifier_kind, primary_identifier_value, original_severity, severity, severity_override_reason, severity_override_by, status, state_comment, detected_at, resolved_at, resolved_by, scanner_name, scanner_vendor, scanner_version, scanner_external_id, file_path, start_line, end_line, location_hash, fingerprint, component_id, component_name, component_version, component_purl, ecosystem, advisory_id, affected_range_id, language, confidence, solution, has_remediation, remediation_link, reachability, owasp_top_10, due_date, present_on_default_branch, resolved_on_default_branch, secret_type, secret_hash, commit_sha, author_email, verified, created_by, metadata, created_at, updated_at, first_seen_at, last_seen_at, origin, origin_api_key_id, origin_token_name, origin_owner_type, origin_owner_id"

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

func vulnerabilityScanDest(row *dbgen.Vulnerability) []interface{} {
	return []interface{}{
		&row.ID,
		&row.Type,
		&row.SnapshotID,
		&row.Title,
		&row.Description,
		&row.PrimaryIdentifierKind,
		&row.PrimaryIdentifierValue,
		&row.OriginalSeverity,
		&row.Severity,
		&row.SeverityOverrideReason,
		&row.SeverityOverrideBy,
		&row.Status,
		&row.StateComment,
		&row.DetectedAt,
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
		&row.Origin,
		&row.OriginApiKeyID,
		&row.OriginTokenName,
		&row.OriginOwnerType,
		&row.OriginOwnerID,
	}
}

func scanVulnerabilityRow(scanner interface {
	Scan(dest ...interface{}) error
}) (dbgen.Vulnerability, error) {
	var row dbgen.Vulnerability
	err := scanner.Scan(vulnerabilityScanDest(&row)...)
	return row, err
}

func boolPtrFromNull(value sql.NullBool) *bool {
	if !value.Valid {
		return nil
	}
	v := value.Bool
	return &v
}

func reachabilityPtrFromNull(value dbgen.NullReachability) *string {
	if !value.Valid {
		return nil
	}
	v := string(value.Reachability)
	return &v
}

// FindingAcceptance is the accepted decision on a finding (ADR-023): the row's
// existence means "accepted", reason_kind says why (risk vs false positive),
// labels organize, and vex_justification carries the standard vocabulary for
// dependency false-positives. Fingerprint-keyed so it survives snapshots.
type FindingAcceptance struct {
	ID               uuid.UUID  `json:"id"`
	RepoID           uuid.UUID  `json:"repo_id"`
	Fingerprint      string     `json:"fingerprint"`
	ReasonKind       string     `json:"reason_kind"`
	Reason           string     `json:"reason"`
	Labels           []string   `json:"labels"`
	VEXJustification *string    `json:"vex_justification,omitempty"`
	AcceptedBy       *uuid.UUID `json:"accepted_by,omitempty"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
}

func findingAcceptanceFromRow(row dbgen.FindingAcceptance) FindingAcceptance {
	out := FindingAcceptance{
		ID:          row.ID,
		RepoID:      row.RepoID,
		Fingerprint: row.Fingerprint,
		ReasonKind:  string(row.ReasonKind),
		Reason:      row.Reason,
		Labels:      row.Labels,
		CreatedAt:   row.CreatedAt,
	}
	if out.Labels == nil {
		out.Labels = []string{}
	}
	if row.VexJustification.Valid {
		justification := string(row.VexJustification.VexJustification)
		out.VEXJustification = &justification
	}
	if row.AcceptedBy.Valid {
		id := row.AcceptedBy.UUID
		out.AcceptedBy = &id
	}
	if row.ExpiresAt.Valid {
		expires := row.ExpiresAt.Time
		out.ExpiresAt = &expires
	}
	return out
}

// AcceptFindingInput is the accepted-decision write shape (ADR-023).
type AcceptFindingInput struct {
	RepoID           uuid.UUID
	Fingerprint      string
	ReasonKind       string
	Reason           string
	Labels           []string
	VEXJustification *string
	AcceptedBy       *uuid.UUID
	ExpiresAt        *time.Time
}

func (q *Queries) UpsertFindingAcceptance(ctx context.Context, input AcceptFindingInput) (FindingAcceptance, error) {
	labels := input.Labels
	if labels == nil {
		labels = []string{}
	}
	justification := dbgen.NullVexJustification{}
	if input.VEXJustification != nil {
		justification = dbgen.NullVexJustification{VexJustification: dbgen.VexJustification(*input.VEXJustification), Valid: true}
	}
	row, err := q.db.UpsertFindingAcceptance(ctx, dbgen.UpsertFindingAcceptanceParams{
		RepoID:           input.RepoID,
		Fingerprint:      input.Fingerprint,
		ReasonKind:       dbgen.AcceptanceReasonKind(input.ReasonKind),
		Reason:           input.Reason,
		Labels:           labels,
		VexJustification: justification,
		AcceptedBy:       nullUUIDFromPtr(input.AcceptedBy),
		ExpiresAt:        nullTimeFromPtr(input.ExpiresAt),
	})
	if err != nil {
		return FindingAcceptance{}, err
	}
	return findingAcceptanceFromRow(row), nil
}

func (q *Queries) DeleteFindingAcceptance(ctx context.Context, repoID uuid.UUID, fingerprint string) (bool, error) {
	affected, err := q.db.DeleteFindingAcceptance(ctx, dbgen.DeleteFindingAcceptanceParams{RepoID: repoID, Fingerprint: fingerprint})
	if err != nil {
		return false, err
	}
	return affected > 0, nil
}

func (q *Queries) ListActiveFindingAcceptancesByRepo(ctx context.Context, repoID uuid.UUID) ([]FindingAcceptance, error) {
	rows, err := q.db.ListActiveFindingAcceptancesByRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}
	out := make([]FindingAcceptance, len(rows))
	for i, row := range rows {
		out[i] = findingAcceptanceFromRow(row)
	}
	return out, nil
}

// GetActiveFindingAcceptance returns the repo's live decision for one
// fingerprint, or nil when the finding is open.
func (q *Queries) GetActiveFindingAcceptance(ctx context.Context, repoID uuid.UUID, fingerprint string) (*FindingAcceptance, error) {
	row, err := q.db.GetActiveFindingAcceptance(ctx, dbgen.GetActiveFindingAcceptanceParams{RepoID: repoID, Fingerprint: fingerprint})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	acceptance := findingAcceptanceFromRow(row)
	return &acceptance, nil
}

// GetLatestVulnerabilityByFingerprint returns the newest occurrence of a
// fingerprint on a repo — the finding-detail anchor.
func (q *Queries) GetLatestVulnerabilityByFingerprint(ctx context.Context, repoID uuid.UUID, fingerprint string) (*Vulnerability, error) {
	row, err := q.db.GetLatestVulnerabilityByFingerprint(ctx, dbgen.GetLatestVulnerabilityByFingerprintParams{RepoID: repoID, Fingerprint: fingerprint})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return vulnerabilityFromRow(row), nil
}

// FindingOccurrence is one ref whose latest snapshot currently detects the
// fingerprint.
type FindingOccurrence struct {
	RefName    string    `json:"ref_name"`
	RefType    string    `json:"ref_type"`
	CommitSHA  string    `json:"commit_sha"`
	SnapshotAt time.Time `json:"snapshot_at"`
	Status     string    `json:"status"`
}

func (q *Queries) ListFindingOccurrences(ctx context.Context, repoID uuid.UUID, fingerprint string) ([]FindingOccurrence, error) {
	rows, err := q.db.ListFindingOccurrences(ctx, dbgen.ListFindingOccurrencesParams{RepoID: repoID, Fingerprint: fingerprint})
	if err != nil {
		return nil, err
	}
	out := make([]FindingOccurrence, len(rows))
	for i, row := range rows {
		out[i] = FindingOccurrence{
			RefName:    row.RefName,
			RefType:    row.RefType,
			CommitSHA:  row.CommitSha,
			SnapshotAt: row.SnapshotAt,
			Status:     row.Status,
		}
	}
	return out, nil
}

// SetVulnerabilityReachability applies a CI analyzer's verdict to every
// matching dependency finding in the snapshot; returns rows updated.
func (q *Queries) SetVulnerabilityReachability(ctx context.Context, snapshotID uuid.UUID, reachability string, identifiers []string) (int64, error) {
	if len(identifiers) == 0 {
		return 0, nil
	}
	return q.db.SetVulnerabilityReachability(ctx, dbgen.SetVulnerabilityReachabilityParams{
		SnapshotID:   snapshotID,
		Reachability: dbgen.NullReachability{Reachability: dbgen.Reachability(reachability), Valid: true},
		Identifiers:  identifiers,
	})
}

// GetLatestSnapshotByRepoAndSHA resolves the snapshot a CI analyzer's results
// belong to.
func (q *Queries) GetLatestSnapshotByRepoAndSHA(ctx context.Context, repoID uuid.UUID, commitSHA string) (*Snapshot, error) {
	row, err := q.db.GetLatestSnapshotByRepoAndSHA(ctx, dbgen.GetLatestSnapshotByRepoAndSHAParams{RepoID: repoID, CommitSha: commitSHA})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return snapshotFromRow(row), nil
}

// SnapshotCodeRefs is the CI-posted reference inventory for one snapshot —
// what the built code actually names, per language, at that language's
// precision (Java: class-level packages, Rust: crate-level).
type SnapshotCodeRefs struct {
	// GoSymbols is the reachable third-party symbol set from the CI VTA call
	// graph ("import/path.Func", "import/path.Type.Method") — matched against
	// OSV-declared vulnerable symbols for SYMBOL-level verdicts on frozen refs.
	GoSymbols      []string
	JavaPackages   []string
	RustReferenced []string
	RustPresent    []string
}

func (r SnapshotCodeRefs) Empty() bool {
	return len(r.GoSymbols) == 0 && len(r.JavaPackages) == 0 && len(r.RustReferenced) == 0 && len(r.RustPresent) == 0
}

func (q *Queries) UpsertSnapshotCodeRefs(ctx context.Context, snapshotID uuid.UUID, refs SnapshotCodeRefs) error {
	return q.db.UpsertSnapshotCodeRefs(ctx, dbgen.UpsertSnapshotCodeRefsParams{
		SnapshotID:     snapshotID,
		GoSymbols:      nonNilStrings(refs.GoSymbols),
		JavaPackages:   nonNilStrings(refs.JavaPackages),
		RustReferenced: nonNilStrings(refs.RustReferenced),
		RustPresent:    nonNilStrings(refs.RustPresent),
	})
}

func (q *Queries) GetSnapshotCodeRefs(ctx context.Context, snapshotID uuid.UUID) (*SnapshotCodeRefs, error) {
	row, err := q.db.GetSnapshotCodeRefs(ctx, snapshotID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &SnapshotCodeRefs{
		GoSymbols:      row.GoSymbols,
		JavaPackages:   row.JavaPackages,
		RustReferenced: row.RustReferenced,
		RustPresent:    row.RustPresent,
	}, nil
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

// ApplyReachabilityFromCodeRefs classifies the snapshot's dependency findings
// against a stored reference inventory. Shared by the reachability endpoint
// (fresh CI results) and the advisory scanner (a NEWLY PUBLISHED CVE on
// unchanged code gets classified from the stored refs immediately, instead of
// waiting for the next CI run). Precision is the inventory's — class-level
// for Java, crate-level for Rust — and anything unmatched stays untouched.
func (q *Queries) ApplyReachabilityFromCodeRefs(ctx context.Context, snapshotID uuid.UUID, refs SnapshotCodeRefs) (reachableCount, unreachableCount int64, err error) {
	// Narrow projection on purpose: this runs on every build's reachability
	// post AND on every daily advisory pass that matched something — never
	// load the full snapshot finding set for it.
	rows, err := q.db.ListDependencyFindingHeadsBySnapshot(ctx, snapshotID)
	if err != nil {
		return 0, 0, err
	}
	vulnerabilities := make([]Vulnerability, 0, len(rows))
	for _, row := range rows {
		vulnerability := Vulnerability{ID: row.ID, Type: "dependency"}
		if row.Ecosystem.Valid {
			ecosystem := row.Ecosystem.String
			vulnerability.Ecosystem = &ecosystem
		}
		if row.ComponentName.Valid {
			name := row.ComponentName.String
			vulnerability.ComponentName = &name
		}
		if row.AdvisoryID.Valid {
			advisoryID := row.AdvisoryID.UUID
			vulnerability.AdvisoryID = &advisoryID
		}
		vulnerability.Reachability = reachabilityPtrFromNull(row.Reachability)
		vulnerabilities = append(vulnerabilities, vulnerability)
	}

	rustReferenced := stringSet(refs.RustReferenced)
	rustPresent := stringSet(refs.RustPresent)
	goSymbols := stringSet(refs.GoSymbols)

	// Advisory-declared vulnerable symbols, loaded once for the Go findings.
	symbolsByAdvisory := map[uuid.UUID][]string{}
	if len(goSymbols) > 0 {
		advisoryIDs := []uuid.UUID{}
		seenAdvisories := map[uuid.UUID]struct{}{}
		for _, vulnerability := range vulnerabilities {
			if vulnerability.AdvisoryID == nil || vulnerability.Ecosystem == nil {
				continue
			}
			if eco := strings.ToLower(strings.TrimSpace(*vulnerability.Ecosystem)); eco != "go" && eco != "golang" {
				continue
			}
			if _, ok := seenAdvisories[*vulnerability.AdvisoryID]; ok {
				continue
			}
			seenAdvisories[*vulnerability.AdvisoryID] = struct{}{}
			advisoryIDs = append(advisoryIDs, *vulnerability.AdvisoryID)
		}
		if len(advisoryIDs) > 0 {
			ranges, err := q.db.ListAffectedRangesByAdvisoryIDs(ctx, advisoryIDs)
			if err != nil {
				return 0, 0, err
			}
			for _, affectedRange := range ranges {
				if len(affectedRange.VulnerableSymbols) > 0 {
					symbolsByAdvisory[affectedRange.AdvisoryID] = append(symbolsByAdvisory[affectedRange.AdvisoryID], affectedRange.VulnerableSymbols...)
				}
			}
		}
	}

	reachableIDs := []uuid.UUID{}
	unreachableIDs := []uuid.UUID{}
	for _, vulnerability := range vulnerabilities {
		if vulnerability.Type != "dependency" && vulnerability.Type != "container" {
			continue
		}
		if vulnerability.ComponentName == nil {
			continue
		}
		name := strings.TrimSpace(*vulnerability.ComponentName)
		ecosystem := ""
		if vulnerability.Ecosystem != nil {
			ecosystem = strings.ToLower(strings.TrimSpace(*vulnerability.Ecosystem))
		}
		switch {
		case (ecosystem == "maven" || strings.Contains(name, ":")) && len(refs.JavaPackages) > 0:
			// Maven components are group:artifact; the group id approximates
			// the package root. Class-level: the app's bytecode references a
			// package of this artifact, or provably never does.
			group := name
			if colon := strings.Index(name, ":"); colon > 0 {
				group = name[:colon]
			}
			if javaPackageReferenced(refs.JavaPackages, group) {
				reachableIDs = append(reachableIDs, vulnerability.ID)
			} else {
				unreachableIDs = append(unreachableIDs, vulnerability.ID)
			}
		case ecosystem == "cargo" || ecosystem == "crates.io":
			if _, ok := rustReferenced[name]; ok {
				reachableIDs = append(reachableIDs, vulnerability.ID)
			} else if _, ok := rustPresent[name]; ok {
				unreachableIDs = append(unreachableIDs, vulnerability.ID)
			}
		case (ecosystem == "go" || ecosystem == "golang") && vulnerability.AdvisoryID != nil:
			// Symbol-level re-derivation. Safe-monotonic on purpose, because
			// this runs repeatedly against a FROZEN snapshot as advisory data
			// evolves (OSV enrichment adds vulnerable symbols after publish):
			//   - reachable is asserted whenever the symbols now match — it
			//     PROMOTES unknown or a stale not_reachable to reachable
			//     (revealing risk is always the safe, correct direction);
			//   - not_reachable is only used to FILL an unknown — it never
			//     auto-downgrades an existing reachable verdict, so
			//     incomplete symbol data can't hide real risk. A genuine
			//     downgrade (a call removed) arrives as a fresh snapshot whose
			//     rows start unknown, classified precisely on POST.
			declared := symbolsByAdvisory[*vulnerability.AdvisoryID]
			if len(declared) == 0 {
				continue // advisory names no symbols — never guess
			}
			matched := false
			for _, symbol := range declared {
				if _, ok := goSymbols[symbol]; ok {
					matched = true
					break
				}
			}
			current := ""
			if vulnerability.Reachability != nil {
				current = *vulnerability.Reachability
			}
			switch {
			case matched && current != "reachable":
				reachableIDs = append(reachableIDs, vulnerability.ID)
			case !matched && current == "":
				unreachableIDs = append(unreachableIDs, vulnerability.ID)
			}
		}
	}

	if len(reachableIDs) > 0 {
		if reachableCount, err = q.db.SetVulnerabilityReachabilityByIDs(ctx, dbgen.SetVulnerabilityReachabilityByIDsParams{
			Reachability: dbgen.NullReachability{Reachability: dbgen.ReachabilityReachable, Valid: true},
			Ids:          reachableIDs,
		}); err != nil {
			return reachableCount, 0, err
		}
	}
	if len(unreachableIDs) > 0 {
		if unreachableCount, err = q.db.SetVulnerabilityReachabilityByIDs(ctx, dbgen.SetVulnerabilityReachabilityByIDsParams{
			Reachability: dbgen.NullReachability{Reachability: dbgen.ReachabilityNotReachable, Valid: true},
			Ids:          unreachableIDs,
		}); err != nil {
			return reachableCount, unreachableCount, err
		}
	}
	return reachableCount, unreachableCount, nil
}

// knownJavaPackageRoots maps artifacts whose packages do NOT follow the
// group-id convention. Without an entry, a used library would be wrongly
// marked not_reachable — the one direction this heuristic must never err in.
// TODO: make this external config ?
var knownJavaPackageRoots = map[string][]string{
	"com.google.guava":           {"com.google.common"},
	"jakarta.platform":           {"jakarta"},
	"org.projectlombok":          {"lombok"},
	"mysql":                      {"com.mysql"},
	"org.postgresql":             {"org.postgresql"},
	"com.fasterxml.jackson.core": {"com.fasterxml.jackson"},
}

func javaPackageReferenced(referenced []string, group string) bool {
	group = strings.ToLower(group)
	roots := append([]string{group}, knownJavaPackageRoots[group]...)
	for _, pkg := range referenced {
		pkg = strings.ToLower(pkg)
		for _, root := range roots {
			// Either direction: group "org.apache.logging.log4j" vs referenced
			// package "org.apache.logging.log4j.util", or a short group id vs
			// a deeper reference.
			if strings.HasPrefix(pkg, root) || strings.HasPrefix(root, pkg) {
				return true
			}
		}
	}
	return false
}

func stringSet(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		out[value] = struct{}{}
	}
	return out
}

// ListRepoFingerprints returns the subset of fingerprints that belongs to the
// repository. Batch triage validates against it so a caller cannot write
// acceptances for another repo's findings.
func (q *Queries) ListRepoFingerprints(ctx context.Context, repoID uuid.UUID, fingerprints []string) ([]string, error) {
	if len(fingerprints) == 0 {
		return nil, nil
	}
	return q.db.ListRepoFingerprints(ctx, dbgen.ListRepoFingerprintsParams{
		RepoID:  repoID,
		Column2: fingerprints,
	})
}

// ListAcceptedDependencyAdvisories returns acceptance decisions on
// component-backed findings joined to their advisories, for VEX synthesis at
// export time (ADR-023).
func (q *Queries) ListAcceptedDependencyAdvisories(ctx context.Context, repoID uuid.UUID) ([]dbgen.ListAcceptedDependencyAdvisoriesRow, error) {
	return q.db.ListAcceptedDependencyAdvisories(ctx, repoID)
}

func (q *Queries) ListUnreachableDependencyAdvisories(ctx context.Context, snapshotID uuid.UUID) ([]dbgen.ListUnreachableDependencyAdvisoriesRow, error) {
	return q.db.ListUnreachableDependencyAdvisories(ctx, snapshotID)
}
