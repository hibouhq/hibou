package compliance

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/lehibou/internal/store/dbgen"
)

var ErrReportNotFound = errors.New("compliance report not found")

type Report struct {
	RepoName        string         `json:"repo_name"`
	OrgName         string         `json:"org_name"`
	AsOfDate        time.Time      `json:"as_of_date"`
	GeneratedAt     time.Time      `json:"generated_at"`
	SnapshotID      uuid.UUID      `json:"snapshot_id"`
	RefName         string         `json:"ref_name"`
	Components      int            `json:"total_components"`
	Vulnerabilities []VulnEntry    `json:"vulnerabilities"`
	Findings        []FindingEntry `json:"findings"`
	Summary         Summary        `json:"summary"`
}

type VulnEntry struct {
	CanonicalID      string `json:"canonical_id"`
	Severity         string `json:"severity"`
	ComponentName    string `json:"component_name"`
	ComponentVersion string `json:"component_version"`
	IsAffected       bool   `json:"is_affected"`
	VEXStatus        string    `json:"vex_status"`
	VEXJustification string    `json:"vex_justification,omitempty"`
	VEXSource        string    `json:"vex_source,omitempty"`
	FirstSeenAt      time.Time `json:"first_seen_at"`
}

type FindingEntry struct {
	Tool     string `json:"tool"`
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	FilePath string `json:"file_path"`
	Message  string `json:"message"`
	Status   string `json:"status"`
}

type Summary struct {
	Critical       int `json:"critical"`
	High           int `json:"high"`
	Medium         int `json:"medium"`
	Low            int `json:"low"`
	Info           int `json:"info"`
	VEXNotAffected int `json:"vex_not_affected"`
	VEXFixed       int `json:"vex_fixed"`
}

type ExportStore interface {
	GetRepoBySlug(ctx context.Context, orgID uuid.UUID, slug string) (dbgen.Repository, error)
	GetOrganizationByID(ctx context.Context, id uuid.UUID) (dbgen.Organization, error)
	GetSnapshotAtDate(ctx context.Context, arg dbgen.GetSnapshotAtDateParams) (dbgen.Snapshot, error)
	ListVulnMatchesBySnapshot(ctx context.Context, snapshotID uuid.UUID) ([]dbgen.VulnMatch, error)
	ListFindingsBySnapshot(ctx context.Context, arg dbgen.ListFindingsBySnapshotParams) ([]dbgen.Finding, error)
	GetAdvisoriesByIDs(ctx context.Context, ids []uuid.UUID) ([]dbgen.Advisory, error)
	GetComponentsByIDs(ctx context.Context, ids []uuid.UUID) ([]dbgen.Component, error)
	ListVEXStatementsByAdvisory(ctx context.Context, arg dbgen.ListVEXStatementsByAdvisoryParams) ([]dbgen.VexStatement, error)
	GetRefByID(ctx context.Context, id uuid.UUID) (dbgen.Ref, error)
}

type Service struct {
	store ExportStore
	isoStore ISO27001Store
	log   zerolog.Logger
}

func NewService(store ExportStore, log zerolog.Logger) *Service {
	service := &Service{store: store, log: log}
	if isoStore, ok := store.(ISO27001Store); ok {
		service.isoStore = isoStore
	}
	return service
}

func (s *Service) GenerateReport(ctx context.Context, orgID uuid.UUID, repoSlug string, asOfDate time.Time) (*Report, error) {
	repo, err := s.store.GetRepoBySlug(ctx, orgID, repoSlug)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrReportNotFound
	}
	if err != nil {
		return nil, err
	}
	if repo.ID == uuid.Nil {
		return nil, ErrReportNotFound
	}
	org, err := s.store.GetOrganizationByID(ctx, orgID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrReportNotFound
	}
	if err != nil {
		return nil, err
	}
	if org.ID == uuid.Nil {
		return nil, ErrReportNotFound
	}

	snapshot, err := s.store.GetSnapshotAtDate(ctx, dbgen.GetSnapshotAtDateParams{
		RepoID:    repo.ID,
		Name:      repo.DefaultBranch,
		CreatedAt: asOfDate,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrReportNotFound
	}
	if err != nil {
		return nil, err
	}
	if snapshot.ID == uuid.Nil {
		return nil, ErrReportNotFound
	}

	ref, err := s.store.GetRefByID(ctx, snapshot.RefID)
	if err != nil {
		return nil, err
	}
	vulnMatches, err := s.store.ListVulnMatchesBySnapshot(ctx, snapshot.ID)
	if err != nil {
		return nil, err
	}
	findings, err := s.store.ListFindingsBySnapshot(ctx, dbgen.ListFindingsBySnapshotParams{SnapshotID: snapshot.ID})
	if err != nil {
		return nil, err
	}
	advisoryByID, err := s.loadAdvisoriesByID(ctx, vulnMatches)
	if err != nil {
		return nil, err
	}
	componentByID, err := s.loadComponentsByID(ctx, vulnMatches)
	if err != nil {
		return nil, err
	}
	vexByAdvisory, err := s.loadVEXStatementsByAdvisory(ctx, orgID, vulnMatches)
	if err != nil {
		return nil, err
	}

	report := &Report{
		RepoName:    repo.Name,
		OrgName:     org.Name,
		AsOfDate:    asOfDate,
		GeneratedAt: time.Now().UTC(),
		SnapshotID:  snapshot.ID,
		RefName:     ref.Name,
	}

	componentSeen := make(map[uuid.UUID]struct{})
	for _, match := range vulnMatches {
		advisory, ok := advisoryByID[match.AdvisoryID]
		if !ok {
			return nil, fmt.Errorf("lookup advisory %s: %w", match.AdvisoryID, sql.ErrNoRows)
		}
		component, ok := componentByID[match.ComponentID]
		if !ok {
			return nil, fmt.Errorf("lookup component %s: %w", match.ComponentID, sql.ErrNoRows)
		}
		vexStatement := resolveVEXStatement(vexByAdvisory[match.AdvisoryID], repo.ID, component.Purl, asOfDate)
		componentSeen[component.ID] = struct{}{}
		entry := VulnEntry{
			CanonicalID:      advisory.CanonicalID,
			Severity:         string(advisory.Severity),
			ComponentName:    component.Name,
			ComponentVersion: component.Version,
			IsAffected:       match.IsAffected,
			FirstSeenAt:      match.FirstSeenAt,
		}
		if vexStatement != nil {
			entry.VEXStatus = string(vexStatement.Status)
			entry.VEXSource = string(vexStatement.Source)
			if vexStatement.Justification.Valid {
				entry.VEXJustification = string(vexStatement.Justification.VexJustification)
			}
			switch vexStatement.Status {
			case dbgen.VexStatusNotAffected:
				report.Summary.VEXNotAffected++
			case dbgen.VexStatusFixed:
				report.Summary.VEXFixed++
			}
		}
		report.Vulnerabilities = append(report.Vulnerabilities, entry)
		addSummary(&report.Summary, string(advisory.Severity))
	}

	for _, finding := range findings {
		report.Findings = append(report.Findings, FindingEntry{
			Tool:     finding.Tool,
			RuleID:   finding.RuleID,
			Severity: string(finding.Severity),
			FilePath: finding.FilePath,
			Message:  finding.Message,
			Status:   finding.Status,
		})
		addSummary(&report.Summary, string(finding.Severity))
	}
	report.Components = len(componentSeen)

	sort.Slice(report.Vulnerabilities, func(i, j int) bool {
		if report.Vulnerabilities[i].Severity == report.Vulnerabilities[j].Severity {
			return report.Vulnerabilities[i].CanonicalID < report.Vulnerabilities[j].CanonicalID
		}
		return severityRank(report.Vulnerabilities[i].Severity) < severityRank(report.Vulnerabilities[j].Severity)
	})
	sort.Slice(report.Findings, func(i, j int) bool {
		if report.Findings[i].Severity == report.Findings[j].Severity {
			return report.Findings[i].FilePath < report.Findings[j].FilePath
		}
		return severityRank(report.Findings[i].Severity) < severityRank(report.Findings[j].Severity)
	})

	s.log.Info().Str("repo_id", repo.ID.String()).Str("snapshot_id", snapshot.ID.String()).Msg("generated compliance report")
	return report, nil
}

func (s *Service) loadAdvisoriesByID(ctx context.Context, matches []dbgen.VulnMatch) (map[uuid.UUID]dbgen.Advisory, error) {
	ids := collectUniqueIDs(matches, func(match dbgen.VulnMatch) uuid.UUID {
		return match.AdvisoryID
	})
	if len(ids) == 0 {
		return map[uuid.UUID]dbgen.Advisory{}, nil
	}
	advisories, err := s.store.GetAdvisoriesByIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	items := make(map[uuid.UUID]dbgen.Advisory, len(advisories))
	for _, advisory := range advisories {
		items[advisory.ID] = advisory
	}
	return items, nil
}

func (s *Service) loadComponentsByID(ctx context.Context, matches []dbgen.VulnMatch) (map[uuid.UUID]dbgen.Component, error) {
	ids := collectUniqueIDs(matches, func(match dbgen.VulnMatch) uuid.UUID {
		return match.ComponentID
	})
	if len(ids) == 0 {
		return map[uuid.UUID]dbgen.Component{}, nil
	}
	components, err := s.store.GetComponentsByIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	items := make(map[uuid.UUID]dbgen.Component, len(components))
	for _, component := range components {
		items[component.ID] = component
	}
	return items, nil
}

func (s *Service) loadVEXStatementsByAdvisory(ctx context.Context, orgID uuid.UUID, matches []dbgen.VulnMatch) (map[uuid.UUID][]dbgen.VexStatement, error) {
	ids := collectUniqueIDs(matches, func(match dbgen.VulnMatch) uuid.UUID {
		return match.AdvisoryID
	})
	if len(ids) == 0 {
		return map[uuid.UUID][]dbgen.VexStatement{}, nil
	}
	items := make(map[uuid.UUID][]dbgen.VexStatement, len(ids))
	for _, advisoryID := range ids {
		statements, err := s.store.ListVEXStatementsByAdvisory(ctx, dbgen.ListVEXStatementsByAdvisoryParams{
			OrgID:      orgID,
			AdvisoryID: advisoryID,
		})
		if err != nil {
			return nil, err
		}
		items[advisoryID] = statements
	}
	return items, nil
}

func resolveVEXStatement(statements []dbgen.VexStatement, repoID uuid.UUID, componentPURL string, now time.Time) *dbgen.VexStatement {
	var best *dbgen.VexStatement
	bestRank := -1
	for i := range statements {
		statement := &statements[i]
		if statement.ExpiresAt.Valid && statement.ExpiresAt.Time.Before(now) {
			continue
		}
		rank, ok := vexSpecificity(statement, repoID, componentPURL)
		if !ok {
			continue
		}
		if best == nil || rank > bestRank || (rank == bestRank && statement.UpdatedAt.After(best.UpdatedAt)) {
			best = statement
			bestRank = rank
		}
	}
	return best
}

func vexSpecificity(statement *dbgen.VexStatement, repoID uuid.UUID, componentPURL string) (int, bool) {
	if statement.ComponentPurl.Valid {
		if !statement.RepoID.Valid || statement.RepoID.UUID != repoID || statement.ComponentPurl.String != componentPURL {
			return 0, false
		}
		return 3, true
	}
	if statement.RepoID.Valid {
		if statement.RepoID.UUID != repoID {
			return 0, false
		}
		return 2, true
	}
	return 1, true
}

func collectUniqueIDs(matches []dbgen.VulnMatch, getID func(dbgen.VulnMatch) uuid.UUID) []uuid.UUID {
	seen := make(map[uuid.UUID]struct{}, len(matches))
	ids := make([]uuid.UUID, 0, len(matches))
	for _, match := range matches {
		id := getID(match)
		if id == uuid.Nil {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	return ids
}

func addSummary(summary *Summary, severity string) {
	switch severity {
	case "critical":
		summary.Critical++
	case "high":
		summary.High++
	case "medium":
		summary.Medium++
	case "low":
		summary.Low++
	default:
		summary.Info++
	}
}

func severityRank(severity string) int {
	switch severity {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}
