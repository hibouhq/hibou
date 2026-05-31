package compliance

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/lehibou/internal/store"
	"github.com/hibouhq/lehibou/internal/store/dbgen"
)

type stubExportStore struct {
	org                 dbgen.Organization
	repo                dbgen.Repository
	snapshot            dbgen.Snapshot
	ref                 dbgen.Ref
	vulnerabilities     []store.Vulnerability
	advisories          []dbgen.Advisory
	components          []dbgen.Component
	vexStatements       map[uuid.UUID][]dbgen.VexStatement
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

func (s *stubExportStore) ListAllVulnerabilitiesBySnapshot(_ context.Context, _ uuid.UUID) ([]store.Vulnerability, error) {
	return append([]store.Vulnerability(nil), s.vulnerabilities...), nil
}

func (s *stubExportStore) GetAdvisoriesByIDs(context.Context, []uuid.UUID) ([]dbgen.Advisory, error) {
	s.advisoryBatchCalls++
	return s.advisories, nil
}

func (s *stubExportStore) GetComponentsByIDs(context.Context, []uuid.UUID) ([]dbgen.Component, error) {
	s.componentBatchCalls++
	return s.components, nil
}

func (s *stubExportStore) ListVEXStatementsByAdvisory(_ context.Context, arg dbgen.ListVEXStatementsByAdvisoryParams) ([]dbgen.VexStatement, error) {
	if s.vexStatements == nil {
		return nil, nil
	}
	return s.vexStatements[arg.AdvisoryID], nil
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
		org:      dbgen.Organization{ID: uuid.New(), Name: "Acme Corp"},
		repo:     dbgen.Repository{ID: repoID, Name: "service", Slug: "service", DefaultBranch: "main"},
		snapshot: dbgen.Snapshot{ID: snapshotID, RefID: uuid.New()},
		ref:      dbgen.Ref{Name: "main"},
		vulnerabilities: []store.Vulnerability{
			{ID: uuid.New(), SnapshotID: snapshotID, Type: "dependency", Title: "CVE-2026-0001", Severity: "critical", Status: "detected", Fingerprint: "dep-fp-1", AdvisoryID: &advisoryID, ComponentID: &componentID, ComponentPurl: strPtr("pkg:golang/github.com/acme/lib@1.2.3"), FirstSeenAt: time.Unix(1700000000, 0)},
			{ID: uuid.New(), SnapshotID: snapshotID, Type: "sast", Title: "G101", Severity: "high", Status: "detected", Fingerprint: "sast-fp-1", ScannerName: "semgrep", FilePath: strPtr("main.go"), FirstSeenAt: time.Unix(1700000000, 0)},
		},
		advisories: []dbgen.Advisory{{ID: advisoryID, CanonicalID: "CVE-2026-0001", Severity: dbgen.SeverityLevelCritical}},
		components: []dbgen.Component{{ID: componentID, Name: "github.com/acme/lib", Version: "1.2.3", Purl: "pkg:golang/github.com/acme/lib@1.2.3"}},
		vexStatements: map[uuid.UUID][]dbgen.VexStatement{
			advisoryID: {
				{
					AdvisoryID:    advisoryID,
					RepoID:        uuid.NullUUID{UUID: repoID, Valid: true},
					ComponentPurl: sql.NullString{String: "pkg:golang/github.com/acme/lib@1.2.3", Valid: true},
					Status:        dbgen.VexStatusNotAffected,
					Justification: dbgen.NullVexJustification{VexJustification: dbgen.VexJustificationComponentNotPresent, Valid: true},
					Source:        dbgen.VexSourceImported,
					UpdatedAt:     time.Unix(1700000100, 0),
				},
			},
		},
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
	if report.Summary.VEXNotAffected != 1 || report.Summary.VEXFixed != 0 {
		t.Fatalf("VEX summary = %+v, want not_affected=1 fixed=0", report.Summary)
	}
	if len(report.Vulnerabilities) != 2 {
		t.Fatalf("unexpected report size: vulns=%d, want 2", len(report.Vulnerabilities))
	}
	// Find the dependency vuln entry (has advisory/VEX)
	var depEntry *VulnEntry
	for i := range report.Vulnerabilities {
		if report.Vulnerabilities[i].Type == "dependency" {
			depEntry = &report.Vulnerabilities[i]
			break
		}
	}
	if depEntry == nil {
		t.Fatal("expected dependency vulnerability entry")
		return
	}
	if depEntry.VEXStatus != string(dbgen.VexStatusNotAffected) {
		t.Fatalf("VEXStatus = %q, want %q", depEntry.VEXStatus, dbgen.VexStatusNotAffected)
	}
	if depEntry.VEXSource != string(dbgen.VexSourceImported) {
		t.Fatalf("VEXSource = %q, want %q", depEntry.VEXSource, dbgen.VexSourceImported)
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

func strPtr(s string) *string { return &s }
