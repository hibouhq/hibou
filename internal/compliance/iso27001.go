package compliance

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type ControlEvidence struct {
	ControlID   string         `json:"control_id"`
	ControlName string         `json:"control_name"`
	Coverage    string         `json:"coverage"`
	Evidence    []EvidenceItem `json:"evidence"`
	Gaps        []string       `json:"gaps,omitempty"`
}

type EvidenceItem struct {
	Category    string `json:"category"`
	Description string `json:"description"`
	Metric      int64  `json:"metric"`
	DataSource  string `json:"data_source"`
}

type ISO27001Report struct {
	OrgName     string            `json:"org_name"`
	AsOfDate    time.Time         `json:"as_of_date"`
	GeneratedAt time.Time         `json:"generated_at"`
	Framework   string            `json:"framework"`
	Controls    []ControlEvidence `json:"controls"`
}

type SoAControl struct {
	ControlID     string   `json:"control_id"`
	ControlName   string   `json:"control_name"`
	Applicable    bool     `json:"applicable"`
	Coverage      string   `json:"coverage"`
	EvidenceCount int      `json:"evidence_count"`
	Gaps          []string `json:"gaps,omitempty"`
}

type StatementOfApplicability struct {
	OrgName     string       `json:"org_name"`
	AsOfDate    time.Time    `json:"as_of_date"`
	GeneratedAt time.Time    `json:"generated_at"`
	Framework   string       `json:"framework"`
	Controls    []SoAControl `json:"controls"`
}

type ISO27001Store interface {
	GetOrganizationByID(ctx context.Context, id uuid.UUID) (dbgen.Organization, error)
	CountRepositoriesByOrg(ctx context.Context, orgID uuid.UUID) (int64, error)
	CountVEXStatementsByOrg(ctx context.Context, orgID uuid.UUID) (int64, error)
	ListVEXStatementsByOrg(ctx context.Context, arg dbgen.ListVEXStatementsByOrgParams) ([]dbgen.VexStatement, error)
	CountAuditLogsByOrg(ctx context.Context, orgID uuid.UUID) (int64, error)
	ListAuditLogs(ctx context.Context, arg dbgen.ListAuditLogsParams) ([]dbgen.AuditLog, error)
	ListQualityGatesByOrg(ctx context.Context, orgID uuid.UUID) ([]dbgen.QualityGate, error)
	CountVulnerabilitiesByOrg(ctx context.Context, orgID uuid.UUID) (int64, error)
	CountScansByOrg(ctx context.Context, orgID uuid.UUID) (int64, error)
	LatestScanByOrg(ctx context.Context, orgID uuid.UUID) (time.Time, error)
	CountMalwareAdvisoriesByOrg(ctx context.Context, orgID uuid.UUID) (int64, error)
	CountComponentsByOrg(ctx context.Context, orgID uuid.UUID) (int64, error)
}

type iso27001Metrics struct {
	repoCount           int64
	vexCount            int64
	importedVEXCount    int64
	auditLogCount       int64
	gateAuditCount      int64
	gateEvaluationCount int64
	qualityGateCount    int64
	vulnerabilityCount  int64
	scanCount           int64
	scanFreshnessDays   int64
	malwareCount        int64
	componentCount      int64
	latestScanAt        time.Time
}

func (s *Service) GenerateISO27001Report(ctx context.Context, orgID uuid.UUID, asOfDate time.Time) (*ISO27001Report, error) {
	if s.isoStore == nil {
		return nil, errors.New("iso27001 store unavailable")
	}
	if asOfDate.IsZero() {
		asOfDate = time.Now().UTC()
	}
	generatedAt := time.Now().UTC()
	org, err := s.isoStore.GetOrganizationByID(ctx, orgID)
	if err != nil {
		return nil, err
	}
	metrics, err := s.loadISO27001Metrics(ctx, orgID, asOfDate)
	if err != nil {
		return nil, err
	}

	return &ISO27001Report{
		OrgName:     org.Name,
		AsOfDate:    asOfDate,
		GeneratedAt: generatedAt,
		Framework:   "ISO 27001:2022",
		Controls:    buildISO27001Controls(metrics),
	}, nil
}

func (s *Service) loadISO27001Metrics(ctx context.Context, orgID uuid.UUID, asOfDate time.Time) (iso27001Metrics, error) {
	repoCount, err := s.isoStore.CountRepositoriesByOrg(ctx, orgID)
	if err != nil {
		return iso27001Metrics{}, err
	}
	vexCount, err := s.isoStore.CountVEXStatementsByOrg(ctx, orgID)
	if err != nil {
		return iso27001Metrics{}, err
	}
	vexStatements, err := s.listAllVEXStatements(ctx, orgID)
	if err != nil {
		return iso27001Metrics{}, err
	}
	auditLogCount, err := s.isoStore.CountAuditLogsByOrg(ctx, orgID)
	if err != nil {
		return iso27001Metrics{}, err
	}
	auditLogs, err := s.listAllAuditLogs(ctx, orgID)
	if err != nil {
		return iso27001Metrics{}, err
	}
	qualityGates, err := s.isoStore.ListQualityGatesByOrg(ctx, orgID)
	if err != nil {
		return iso27001Metrics{}, err
	}
	vulnerabilityCount, err := s.isoStore.CountVulnerabilitiesByOrg(ctx, orgID)
	if err != nil {
		return iso27001Metrics{}, err
	}
	scanCount, err := s.isoStore.CountScansByOrg(ctx, orgID)
	if err != nil {
		return iso27001Metrics{}, err
	}
	latestScanAt, err := s.isoStore.LatestScanByOrg(ctx, orgID)
	if err != nil {
		return iso27001Metrics{}, err
	}
	malwareCount, err := s.isoStore.CountMalwareAdvisoriesByOrg(ctx, orgID)
	if err != nil {
		return iso27001Metrics{}, err
	}
	componentCount, err := s.isoStore.CountComponentsByOrg(ctx, orgID)
	if err != nil {
		return iso27001Metrics{}, err
	}
	return iso27001Metrics{
		repoCount:           repoCount,
		vexCount:            vexCount,
		importedVEXCount:    countVEXBySource(vexStatements, dbgen.VexSourceImported),
		auditLogCount:       auditLogCount,
		gateAuditCount:      countAuditLogs(auditLogs, isGateAuditLog),
		gateEvaluationCount: countAuditLogs(auditLogs, isGateEvaluationAuditLog),
		qualityGateCount:    int64(len(qualityGates)),
		vulnerabilityCount:  vulnerabilityCount,
		scanCount:           scanCount,
		scanFreshnessDays:   scanFreshnessDays(asOfDate, latestScanAt),
		malwareCount:        malwareCount,
		componentCount:      componentCount,
		latestScanAt:        latestScanAt,
	}, nil
}

func buildISO27001Controls(metrics iso27001Metrics) []ControlEvidence {
	return []ControlEvidence{
		fullControl("A.8.8", "Management of technical vulnerabilities",
			evidenceItem("repositories", "Repositories in scope for vulnerability management", metrics.repoCount, "repositories"),
			evidenceItem("vulnerability_scanning", "Active vulnerabilities tracked across the organization", metrics.vulnerabilityCount, "vulnerabilities"),
			evidenceItem("vex_statements", "VEX statements available to refine exploitability status", metrics.vexCount, "vex_statements"),
			evidenceItem("scans", "Recorded scan executions across repository snapshots", metrics.scanCount, "scans"),
			evidenceItem("scan_freshness_days", fmt.Sprintf("Days since most recent completed scan (%s)", metrics.latestScanAt.UTC().Format(time.RFC3339)), metrics.scanFreshnessDays, "scans"),
		),
		fullControl("A.8.25", "Secure development life cycle",
			evidenceItem("quality_gates", "Quality gate configurations enforcing security policy", metrics.qualityGateCount, "quality_gates"),
			evidenceItem("gate_audit_logs", "Audit trail entries for quality gate administration and exceptions", metrics.gateAuditCount, "audit_logs"),
		),
		fullControl("A.8.28", "Secure coding",
			evidenceItem("security_vulnerabilities", "Application and supply-chain vulnerabilities captured from security tooling", metrics.vulnerabilityCount, "vulnerabilities"),
		),
		fullControl("A.8.29", "Security testing in development and acceptance",
			evidenceItem("scan_runs", "Scan executions recorded for repository snapshots", metrics.scanCount, "scans"),
			evidenceItem("gate_evaluations", "Gate-related audit entries used as evaluation evidence", metrics.gateEvaluationCount, "audit_logs"),
		),
		partialControl("A.8.4", "Access to source code", []string{"git-level access managed by forge"},
			evidenceItem("audit_logs", "Operational audit trail for organization changes", metrics.auditLogCount, "audit_logs"),
		),
		partialControl("A.8.7", "Protection against malware", []string{"secret scanning not yet implemented"},
			evidenceItem("malware_advisories", "Malware-tagged advisories identified in dependency intelligence", metrics.malwareCount, "advisories"),
		),
		partialControl("A.8.19", "Installation of software on operational systems", []string{"no runtime agent"},
			evidenceItem("components", "Distinct software components inventoried across repository snapshots", metrics.componentCount, "components"),
		),
		partialControl("A.8.26", "Application security requirements", []string{"no security requirements template"},
			evidenceItem("quality_gate_configs", "Quality gates expressing security acceptance criteria", metrics.qualityGateCount, "quality_gates"),
		),
		partialControl("A.8.30", "Outsourced development", []string{"no contractual tracking"},
			evidenceItem("supplier_vex_imports", "Imported supplier VEX statements tracked for third-party components", metrics.importedVEXCount, "vex_statements"),
			evidenceItem("components", "Third-party component inventory available for supplier review", metrics.componentCount, "components"),
		),
	}
}

func fullControl(id, name string, evidence ...EvidenceItem) ControlEvidence {
	return ControlEvidence{ControlID: id, ControlName: name, Coverage: "full", Evidence: evidence}
}

func partialControl(id, name string, gaps []string, evidence ...EvidenceItem) ControlEvidence {
	return ControlEvidence{ControlID: id, ControlName: name, Coverage: "partial", Evidence: evidence, Gaps: gaps}
}

func isGateAuditLog(entry dbgen.AuditLog) bool {
	return strings.HasPrefix(entry.Action, "gate.")
}

func isGateEvaluationAuditLog(entry dbgen.AuditLog) bool {
	return entry.Action == audit.ActionGateOverride || strings.HasPrefix(entry.Action, "gate.")
}

func scanFreshnessDays(asOfDate, latestScanAt time.Time) int64 {
	if latestScanAt.IsZero() {
		return 0
	}
	delta := asOfDate.Sub(latestScanAt)
	if delta <= 0 {
		return 0
	}
	return int64(delta.Hours() / 24)
}

func (s *Service) GenerateStatementOfApplicability(ctx context.Context, orgID uuid.UUID, asOfDate time.Time) (*StatementOfApplicability, error) {
	report, err := s.GenerateISO27001Report(ctx, orgID, asOfDate)
	if err != nil {
		return nil, err
	}
	soa := &StatementOfApplicability{
		OrgName:     report.OrgName,
		AsOfDate:    report.AsOfDate,
		GeneratedAt: report.GeneratedAt,
		Framework:   report.Framework,
		Controls:    make([]SoAControl, 0, len(report.Controls)),
	}
	for _, control := range report.Controls {
		soa.Controls = append(soa.Controls, SoAControl{
			ControlID:     control.ControlID,
			ControlName:   control.ControlName,
			Applicable:    true,
			Coverage:      control.Coverage,
			EvidenceCount: len(control.Evidence),
			Gaps:          control.Gaps,
		})
	}
	return soa, nil
}

func (s *Service) listAllAuditLogs(ctx context.Context, orgID uuid.UUID) ([]dbgen.AuditLog, error) {
	const pageSize int32 = 500
	logs := make([]dbgen.AuditLog, 0, pageSize)
	for offset := int32(0); ; offset += pageSize {
		batch, err := s.isoStore.ListAuditLogs(ctx, dbgen.ListAuditLogsParams{
			OrgID:  uuid.NullUUID{UUID: orgID, Valid: true},
			Limit:  pageSize,
			Offset: offset,
		})
		if err != nil {
			return nil, err
		}
		logs = append(logs, batch...)
		if len(batch) < int(pageSize) {
			break
		}
	}
	return logs, nil
}

func (s *Service) listAllVEXStatements(ctx context.Context, orgID uuid.UUID) ([]dbgen.VexStatement, error) {
	const pageSize int32 = 500
	statements := make([]dbgen.VexStatement, 0, pageSize)
	for offset := int32(0); ; offset += pageSize {
		batch, err := s.isoStore.ListVEXStatementsByOrg(ctx, dbgen.ListVEXStatementsByOrgParams{
			OrgID:  orgID,
			Limit:  pageSize,
			Offset: offset,
		})
		if err != nil {
			return nil, err
		}
		statements = append(statements, batch...)
		if len(batch) < int(pageSize) {
			break
		}
	}
	return statements, nil
}

func evidenceItem(category, description string, metric int64, dataSource string) EvidenceItem {
	return EvidenceItem{Category: category, Description: description, Metric: metric, DataSource: dataSource}
}

func countAuditLogs(entries []dbgen.AuditLog, include func(dbgen.AuditLog) bool) int64 {
	var total int64
	for _, entry := range entries {
		if include(entry) {
			total++
		}
	}
	return total
}

func countVEXBySource(statements []dbgen.VexStatement, source dbgen.VexSource) int64 {
	var total int64
	for _, statement := range statements {
		if statement.Source == source {
			total++
		}
	}
	return total
}
