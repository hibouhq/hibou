package compliance

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/lehibou/internal/store"
	"github.com/hibouhq/lehibou/internal/store/dbgen"
)

var ErrReportNotFound = errors.New("compliance report not found")

type Report struct {
	RepoName        string      `json:"repo_name"`
	OrgName         string      `json:"org_name"`
	AsOfDate        time.Time   `json:"as_of_date"`
	GeneratedAt     time.Time   `json:"generated_at"`
	SnapshotID      uuid.UUID   `json:"snapshot_id"`
	RefName         string      `json:"ref_name"`
	Components      int         `json:"total_components"`
	Vulnerabilities []VulnEntry `json:"vulnerabilities"`
	Summary         Summary     `json:"summary"`
}

type VulnEntry struct {
	ID               uuid.UUID `json:"id"`
	Type             string    `json:"type"`
	Title            string    `json:"title"`
	Description      string    `json:"description"`
	CanonicalID      string    `json:"canonical_id"`
	Severity         string    `json:"severity"`
	Status           string    `json:"status"`
	ScannerName      string    `json:"scanner_name"`
	FilePath         string    `json:"file_path,omitempty"`
	ComponentName    string    `json:"component_name"`
	ComponentVersion string    `json:"component_version"`
	IsAffected       bool      `json:"is_affected"`
	VEXStatus        string    `json:"vex_status"`
	VEXJustification string    `json:"vex_justification,omitempty"`
	VEXSource        string    `json:"vex_source,omitempty"`
	FirstSeenAt      time.Time `json:"first_seen_at"`
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
	ListAllVulnerabilitiesBySnapshot(ctx context.Context, snapshotID uuid.UUID) ([]store.Vulnerability, error)
	GetAdvisoriesByIDs(ctx context.Context, ids []uuid.UUID) ([]dbgen.Advisory, error)
	GetComponentsByIDs(ctx context.Context, ids []uuid.UUID) ([]dbgen.Component, error)
	ListVEXStatementsByAdvisory(ctx context.Context, arg dbgen.ListVEXStatementsByAdvisoryParams) ([]dbgen.VexStatement, error)
	GetRefByID(ctx context.Context, id uuid.UUID) (dbgen.Ref, error)
}

type Service struct {
	store    ExportStore
	isoStore ISO27001Store
	log      zerolog.Logger
}

func NewService(store ExportStore, log zerolog.Logger) *Service {
	service := &Service{store: store, log: log}
	if isoStore, ok := store.(ISO27001Store); ok {
		service.isoStore = isoStore
	}
	return service
}

func (s *Service) GenerateReport(ctx context.Context, orgID uuid.UUID, repoSlug string, asOfDate time.Time) (*Report, error) {
	data, err := s.loadReportData(ctx, orgID, repoSlug, asOfDate)
	if err != nil {
		return nil, err
	}

	report := buildComplianceReport(data.repo, data.org, data.snapshot, data.ref, asOfDate)
	if err := s.populateReportVulnerabilities(report, data, asOfDate); err != nil {
		return nil, err
	}
	sortReportVulnerabilities(report)

	s.log.Info().Str("repo_id", data.repo.ID.String()).Str("snapshot_id", data.snapshot.ID.String()).Msg("generated compliance report")
	return report, nil
}

type reportData struct {
	repo            dbgen.Repository
	org             dbgen.Organization
	snapshot        dbgen.Snapshot
	ref             dbgen.Ref
	vulnerabilities []store.Vulnerability
	advisoryByID    map[uuid.UUID]dbgen.Advisory
	componentByID   map[uuid.UUID]dbgen.Component
	vexByAdvisory   map[uuid.UUID][]dbgen.VexStatement
}

func (s *Service) loadReportData(ctx context.Context, orgID uuid.UUID, repoSlug string, asOfDate time.Time) (*reportData, error) {
	repo, err := s.loadReportRepository(ctx, orgID, repoSlug)
	if err != nil {
		return nil, err
	}
	org, err := s.loadReportOrganization(ctx, orgID)
	if err != nil {
		return nil, err
	}
	snapshot, err := s.loadReportSnapshot(ctx, repo, asOfDate)
	if err != nil {
		return nil, err
	}
	ref, err := s.store.GetRefByID(ctx, snapshot.RefID)
	if err != nil {
		return nil, err
	}
	vulnerabilities, err := s.store.ListAllVulnerabilitiesBySnapshot(ctx, snapshot.ID)
	if err != nil {
		return nil, err
	}
	advisoryByID, err := s.loadAdvisoriesByID(ctx, vulnerabilities)
	if err != nil {
		return nil, err
	}
	componentByID, err := s.loadComponentsByID(ctx, vulnerabilities)
	if err != nil {
		return nil, err
	}
	vexByAdvisory, err := s.loadVEXStatementsByAdvisory(ctx, orgID, vulnerabilities)
	if err != nil {
		return nil, err
	}
	return &reportData{
		repo:            repo,
		org:             org,
		snapshot:        snapshot,
		ref:             ref,
		vulnerabilities: vulnerabilities,
		advisoryByID:    advisoryByID,
		componentByID:   componentByID,
		vexByAdvisory:   vexByAdvisory,
	}, nil
}

func buildComplianceReport(repo dbgen.Repository, org dbgen.Organization, snapshot dbgen.Snapshot, ref dbgen.Ref, asOfDate time.Time) *Report {
	return &Report{
		RepoName:    repo.Name,
		OrgName:     org.Name,
		AsOfDate:    asOfDate,
		GeneratedAt: time.Now().UTC(),
		SnapshotID:  snapshot.ID,
		RefName:     ref.Name,
	}
}

func (s *Service) populateReportVulnerabilities(report *Report, data *reportData, asOfDate time.Time) error {
	componentSeen := make(map[uuid.UUID]struct{})
	for _, vulnerability := range data.vulnerabilities {
		entry, err := s.buildReportVulnerabilityEntry(data, vulnerability, report, asOfDate, componentSeen)
		if err != nil {
			return err
		}
		report.Vulnerabilities = append(report.Vulnerabilities, entry)
		addSummary(&report.Summary, string(vulnerability.Severity))
	}
	report.Components = len(componentSeen)
	return nil
}

func (s *Service) buildReportVulnerabilityEntry(data *reportData, vulnerability store.Vulnerability, report *Report, asOfDate time.Time, componentSeen map[uuid.UUID]struct{}) (VulnEntry, error) {
	entry := VulnEntry{
		ID:          vulnerability.ID,
		Type:        vulnerability.Type,
		Title:       vulnerability.Title,
		Description: vulnerability.Description,
		Severity:    string(vulnerability.Severity),
		Status:      vulnerability.Status,
		ScannerName: vulnerability.ScannerName,
		IsAffected:  vulnerability.Status != "resolved" && vulnerability.Status != "dismissed",
		FirstSeenAt: vulnerability.FirstSeenAt,
	}
	if vulnerability.FilePath != nil {
		entry.FilePath = *vulnerability.FilePath
	}
	applyReportComponent(&entry, data.componentByID, vulnerability.ComponentID, componentSeen)
	if err := applyReportAdvisory(&entry, report, data, vulnerability, asOfDate); err != nil {
		return VulnEntry{}, err
	}
	return entry, nil
}

func (s *Service) loadReportRepository(ctx context.Context, orgID uuid.UUID, repoSlug string) (dbgen.Repository, error) {
	repo, err := s.store.GetRepoBySlug(ctx, orgID, repoSlug)
	if errors.Is(err, sql.ErrNoRows) {
		return dbgen.Repository{}, ErrReportNotFound
	}
	if err != nil {
		return dbgen.Repository{}, err
	}
	if repo.ID == uuid.Nil {
		return dbgen.Repository{}, ErrReportNotFound
	}
	return repo, nil
}

func (s *Service) loadReportOrganization(ctx context.Context, orgID uuid.UUID) (dbgen.Organization, error) {
	org, err := s.store.GetOrganizationByID(ctx, orgID)
	if errors.Is(err, sql.ErrNoRows) {
		return dbgen.Organization{}, ErrReportNotFound
	}
	if err != nil {
		return dbgen.Organization{}, err
	}
	if org.ID == uuid.Nil {
		return dbgen.Organization{}, ErrReportNotFound
	}
	return org, nil
}

func (s *Service) loadReportSnapshot(ctx context.Context, repo dbgen.Repository, asOfDate time.Time) (dbgen.Snapshot, error) {
	snapshot, err := s.store.GetSnapshotAtDate(ctx, dbgen.GetSnapshotAtDateParams{
		RepoID:    repo.ID,
		Name:      repo.DefaultBranch,
		CreatedAt: asOfDate,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return dbgen.Snapshot{}, ErrReportNotFound
	}
	if err != nil {
		return dbgen.Snapshot{}, err
	}
	if snapshot.ID == uuid.Nil {
		return dbgen.Snapshot{}, ErrReportNotFound
	}
	return snapshot, nil
}

func applyReportComponent(entry *VulnEntry, componentByID map[uuid.UUID]dbgen.Component, componentID *uuid.UUID, componentSeen map[uuid.UUID]struct{}) {
	if componentID == nil {
		return
	}
	componentSeen[*componentID] = struct{}{}
	if component, ok := componentByID[*componentID]; ok {
		entry.ComponentName = component.Name
		entry.ComponentVersion = component.Version
	}
}

func applyReportAdvisory(entry *VulnEntry, report *Report, data *reportData, vulnerability store.Vulnerability, asOfDate time.Time) error {
	if vulnerability.AdvisoryID == nil {
		return nil
	}
	advisory, ok := data.advisoryByID[*vulnerability.AdvisoryID]
	if !ok {
		return fmt.Errorf("lookup advisory %s: %w", *vulnerability.AdvisoryID, sql.ErrNoRows)
	}
	entry.CanonicalID = advisory.CanonicalID
	componentPURL := ""
	if vulnerability.ComponentPurl != nil {
		componentPURL = *vulnerability.ComponentPurl
	}
	vexStatement := resolveVEXStatement(data.vexByAdvisory[*vulnerability.AdvisoryID], data.repo.ID, componentPURL, asOfDate)
	if vexStatement == nil {
		return nil
	}
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
	return nil
}

func sortReportVulnerabilities(report *Report) {
	sort.Slice(report.Vulnerabilities, func(i, j int) bool {
		if report.Vulnerabilities[i].Severity == report.Vulnerabilities[j].Severity {
			left := strings.TrimSpace(report.Vulnerabilities[i].CanonicalID)
			if left == "" {
				left = report.Vulnerabilities[i].Title
			}
			right := strings.TrimSpace(report.Vulnerabilities[j].CanonicalID)
			if right == "" {
				right = report.Vulnerabilities[j].Title
			}
			return left < right
		}
		return severityRank(report.Vulnerabilities[i].Severity) < severityRank(report.Vulnerabilities[j].Severity)
	})
}

func (s *Service) loadAdvisoriesByID(ctx context.Context, vulnerabilities []store.Vulnerability) (map[uuid.UUID]dbgen.Advisory, error) {
	ids := make([]uuid.UUID, 0)
	seen := make(map[uuid.UUID]struct{})
	for _, vulnerability := range vulnerabilities {
		if vulnerability.AdvisoryID == nil {
			continue
		}
		if _, ok := seen[*vulnerability.AdvisoryID]; ok {
			continue
		}
		seen[*vulnerability.AdvisoryID] = struct{}{}
		ids = append(ids, *vulnerability.AdvisoryID)
	}
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

func (s *Service) loadComponentsByID(ctx context.Context, vulnerabilities []store.Vulnerability) (map[uuid.UUID]dbgen.Component, error) {
	ids := make([]uuid.UUID, 0)
	seen := make(map[uuid.UUID]struct{})
	for _, vulnerability := range vulnerabilities {
		if vulnerability.ComponentID == nil {
			continue
		}
		if _, ok := seen[*vulnerability.ComponentID]; ok {
			continue
		}
		seen[*vulnerability.ComponentID] = struct{}{}
		ids = append(ids, *vulnerability.ComponentID)
	}
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

func (s *Service) loadVEXStatementsByAdvisory(ctx context.Context, orgID uuid.UUID, vulnerabilities []store.Vulnerability) (map[uuid.UUID][]dbgen.VexStatement, error) {
	ids := make([]uuid.UUID, 0)
	seen := make(map[uuid.UUID]struct{})
	for _, vulnerability := range vulnerabilities {
		if vulnerability.AdvisoryID == nil {
			continue
		}
		if _, ok := seen[*vulnerability.AdvisoryID]; ok {
			continue
		}
		seen[*vulnerability.AdvisoryID] = struct{}{}
		ids = append(ids, *vulnerability.AdvisoryID)
	}
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
