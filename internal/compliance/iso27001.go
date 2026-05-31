package compliance

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/lehibou/internal/audit"
	"github.com/hibouhq/lehibou/internal/store/dbgen"
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
	repoCount, err := s.isoStore.CountRepositoriesByOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	vexCount, err := s.isoStore.CountVEXStatementsByOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	vexStatements, err := s.listAllVEXStatements(ctx, orgID)
	if err != nil {
		return nil, err
	}
	auditLogCount, err := s.isoStore.CountAuditLogsByOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	auditLogs, err := s.listAllAuditLogs(ctx, orgID)
	if err != nil {
		return nil, err
	}
	qualityGates, err := s.isoStore.ListQualityGatesByOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	vulnerabilityCount, err := s.isoStore.CountVulnerabilitiesByOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	scanCount, err := s.isoStore.CountScansByOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	latestScanAt, err := s.isoStore.LatestScanByOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	malwareCount, err := s.isoStore.CountMalwareAdvisoriesByOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	componentCount, err := s.isoStore.CountComponentsByOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	importedVEXCount := countVEXBySource(vexStatements, dbgen.VexSourceImported)
	gateAuditCount := countAuditLogs(auditLogs, func(entry dbgen.AuditLog) bool {
		return strings.HasPrefix(entry.Action, "gate.")
	})
	gateEvaluationCount := countAuditLogs(auditLogs, func(entry dbgen.AuditLog) bool {
		return entry.Action == audit.ActionGateOverride || strings.HasPrefix(entry.Action, "gate.")
	})
	var scanFreshnessDays int64
	if !latestScanAt.IsZero() {
		delta := asOfDate.Sub(latestScanAt)
		if delta > 0 {
			scanFreshnessDays = int64(delta.Hours() / 24)
		}
	}

	return &ISO27001Report{
		OrgName:     org.Name,
		AsOfDate:    asOfDate,
		GeneratedAt: generatedAt,
		Framework:   "ISO 27001:2022",
		Controls: []ControlEvidence{
			{
				ControlID:   "A.8.8",
				ControlName: "Management of technical vulnerabilities",
				Coverage:    "full",
				Evidence: []EvidenceItem{
					evidenceItem("repositories", "Repositories in scope for vulnerability management", repoCount, "repositories"),
					evidenceItem("vulnerability_scanning", "Active vulnerabilities tracked across the organization", vulnerabilityCount, "vulnerabilities"),
					evidenceItem("vex_statements", "VEX statements available to refine exploitability status", vexCount, "vex_statements"),
					evidenceItem("scans", "Recorded scan executions across repository snapshots", scanCount, "scans"),
					evidenceItem("scan_freshness_days", fmt.Sprintf("Days since most recent completed scan (%s)", latestScanAt.UTC().Format(time.RFC3339)), scanFreshnessDays, "scans"),
				},
			},
			{
				ControlID:   "A.8.25",
				ControlName: "Secure development life cycle",
				Coverage:    "full",
				Evidence: []EvidenceItem{
					evidenceItem("quality_gates", "Quality gate configurations enforcing security policy", int64(len(qualityGates)), "quality_gates"),
					evidenceItem("gate_audit_logs", "Audit trail entries for quality gate administration and exceptions", gateAuditCount, "audit_logs"),
				},
			},
			{
				ControlID:   "A.8.28",
				ControlName: "Secure coding",
				Coverage:    "full",
				Evidence: []EvidenceItem{
					evidenceItem("security_vulnerabilities", "Application and supply-chain vulnerabilities captured from security tooling", vulnerabilityCount, "vulnerabilities"),
				},
			},
			{
				ControlID:   "A.8.29",
				ControlName: "Security testing in development and acceptance",
				Coverage:    "full",
				Evidence: []EvidenceItem{
					evidenceItem("scan_runs", "Scan executions recorded for repository snapshots", scanCount, "scans"),
					evidenceItem("gate_evaluations", "Gate-related audit entries used as evaluation evidence", gateEvaluationCount, "audit_logs"),
				},
			},
			{
				ControlID:   "A.8.4",
				ControlName: "Access to source code",
				Coverage:    "partial",
				Evidence: []EvidenceItem{
					evidenceItem("audit_logs", "Operational audit trail for organization changes", auditLogCount, "audit_logs"),
				},
				Gaps: []string{"git-level access managed by forge"},
			},
			{
				ControlID:   "A.8.7",
				ControlName: "Protection against malware",
				Coverage:    "partial",
				Evidence: []EvidenceItem{
					evidenceItem("malware_advisories", "Malware-tagged advisories identified in dependency intelligence", malwareCount, "advisories"),
				},
				Gaps: []string{"secret scanning not yet implemented"},
			},
			{
				ControlID:   "A.8.19",
				ControlName: "Installation of software on operational systems",
				Coverage:    "partial",
				Evidence: []EvidenceItem{
					evidenceItem("components", "Distinct software components inventoried across repository snapshots", componentCount, "components"),
				},
				Gaps: []string{"no runtime agent"},
			},
			{
				ControlID:   "A.8.26",
				ControlName: "Application security requirements",
				Coverage:    "partial",
				Evidence: []EvidenceItem{
					evidenceItem("quality_gate_configs", "Quality gates expressing security acceptance criteria", int64(len(qualityGates)), "quality_gates"),
				},
				Gaps: []string{"no security requirements template"},
			},
			{
				ControlID:   "A.8.30",
				ControlName: "Outsourced development",
				Coverage:    "partial",
				Evidence: []EvidenceItem{
					evidenceItem("supplier_vex_imports", "Imported supplier VEX statements tracked for third-party components", importedVEXCount, "vex_statements"),
					evidenceItem("components", "Third-party component inventory available for supplier review", componentCount, "components"),
				},
				Gaps: []string{"no contractual tracking"},
			},
		},
	}, nil
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
