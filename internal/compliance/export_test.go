package compliance

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hibouhq/lehibou/internal/store/dbgen"
	"github.com/rs/zerolog"
)

type stubExportStore struct {
	org                 dbgen.Organization
	repo                dbgen.Repository
	snapshot            dbgen.Snapshot
	ref                 dbgen.Ref
	vulns               []dbgen.VulnMatch
	findings            []dbgen.Finding
	advisories          []dbgen.Advisory
	components          []dbgen.Component
	repoErr             error
	shotErr             error
	advisoryBatchCalls  int
	componentBatchCalls int
}

func (s *stubExportStore) GetRepoBySlug(context.Context, uuid.UUID, string) (dbgen.Repository, error) {
	return s.repo, s.repoErr
}

func (s *stubExportStore) GetOrganizationByID(context.Context, uuid.UUID) (dbgen.Organization, error) {
	return s.org, nil
}

func (s *stubExportStore) GetSnapshotAtDate(context.Context, dbgen.GetSnapshotAtDateParams) (dbgen.Snapshot, error) {
	return s.snapshot, s.shotErr
}

func (s *stubExportStore) ListVulnMatchesBySnapshot(context.Context, uuid.UUID) ([]dbgen.VulnMatch, error) {
	return s.vulns, nil
}

func (s *stubExportStore) ListFindingsBySnapshot(context.Context, dbgen.ListFindingsBySnapshotParams) ([]dbgen.Finding, error) {
	return s.findings, nil
}

func (s *stubExportStore) GetAdvisoriesByIDs(context.Context, []uuid.UUID) ([]dbgen.Advisory, error) {
	s.advisoryBatchCalls++
	return s.advisories, nil
}

func (s *stubExportStore) GetComponentsByIDs(context.Context, []uuid.UUID) ([]dbgen.Component, error) {
	s.componentBatchCalls++
	return s.components, nil
}

func (s *stubExportStore) GetRefByID(context.Context, uuid.UUID) (dbgen.Ref, error) {
	return s.ref, nil
}

func TestGenerateReport(t *testing.T) {
	repoID := uuid.New()
	snapshotID := uuid.New()
	advisoryID := uuid.New()
	componentID := uuid.New()
	store := &stubExportStore{
		org:        dbgen.Organization{ID: uuid.New(), Name: "Acme Corp"},
		repo:       dbgen.Repository{ID: repoID, Name: "service", Slug: "service", DefaultBranch: "main"},
		snapshot:   dbgen.Snapshot{ID: snapshotID, RefID: uuid.New()},
		ref:        dbgen.Ref{Name: "main"},
		vulns:      []dbgen.VulnMatch{{SnapshotID: snapshotID, AdvisoryID: advisoryID, ComponentID: componentID, IsAffected: true, FirstSeenAt: time.Unix(1700000000, 0)}},
		findings:   []dbgen.Finding{{Tool: "semgrep", RuleID: "G101", Severity: dbgen.SeverityLevelHigh, FilePath: "main.go", Message: "issue", Status: "open"}},
		advisories: []dbgen.Advisory{{ID: advisoryID, CanonicalID: "CVE-2026-0001", Severity: dbgen.SeverityLevelCritical}},
		components: []dbgen.Component{{ID: componentID, Name: "github.com/acme/lib", Version: "1.2.3"}},
	}

	svc := NewService(store, zerolog.New(io.Discard))
	report, err := svc.GenerateReport(context.Background(), uuid.New(), "service", time.Now())
	if err != nil {
		t.Fatalf("GenerateReport() error = %v", err)
	}
	if report.SnapshotID != snapshotID {
		t.Fatalf("SnapshotID = %s, want %s", report.SnapshotID, snapshotID)
	}
	if report.OrgName != "Acme Corp" {
		t.Fatalf("OrgName = %q, want %q", report.OrgName, "Acme Corp")
	}
	if report.Components != 1 {
		t.Fatalf("Components = %d, want 1", report.Components)
	}
	if report.Summary.Critical != 1 || report.Summary.High != 1 {
		t.Fatalf("Summary = %+v, want critical=1 high=1", report.Summary)
	}
	if len(report.Vulnerabilities) != 1 || len(report.Findings) != 1 {
		t.Fatalf("unexpected report sizes: vulns=%d findings=%d", len(report.Vulnerabilities), len(report.Findings))
	}
	if store.advisoryBatchCalls != 1 || store.componentBatchCalls != 1 {
		t.Fatalf("batch lookup calls = (%d, %d), want (1, 1)", store.advisoryBatchCalls, store.componentBatchCalls)
	}
}

func TestGenerateReportNotFound(t *testing.T) {
	store := &stubExportStore{repoErr: sql.ErrNoRows}
	svc := NewService(store, zerolog.New(io.Discard))

	_, err := svc.GenerateReport(context.Background(), uuid.New(), "missing", time.Now())
	if !errors.Is(err, ErrReportNotFound) {
		t.Fatalf("GenerateReport() error = %v, want ErrReportNotFound", err)
	}
}
