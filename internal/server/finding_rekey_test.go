package server

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

func seedRekeyFinding(t *testing.T, srv *Server, snapshotID uuid.UUID, fingerprint, file string, line int32) {
	t.Helper()
	if _, err := srv.queries.CreateVulnerability(context.Background(), dbgen.CreateVulnerabilityParams{
		Type:                   "sast",
		SnapshotID:             snapshotID,
		Title:                  "hardcoded credential",
		Description:            "Potential hardcoded credentials",
		PrimaryIdentifierKind:  "rule",
		PrimaryIdentifierValue: "G101",
		OriginalSeverity:       dbgen.SeverityLevelHigh,
		Severity:               dbgen.SeverityLevelHigh,
		Status:                 "detected",
		ScannerName:            "gosec",
		FilePath:               sql.NullString{String: file, Valid: true},
		StartLine:              sql.NullInt32{Int32: line, Valid: true},
		Fingerprint:            fingerprint,
	}); err != nil {
		t.Fatalf("CreateVulnerability(%s): %v", fingerprint, err)
	}
}

// A finding re-keyed between two snapshots of a ref (content fingerprints
// arriving, a line move) keeps its acceptance and dispute: both are copied to
// the new fingerprint, the old ones stay for refs that still report them.
func TestCarryTriageAcrossRekeys(t *testing.T) {
	srv, org, admin, _ := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)
	ctx := context.Background()
	ref, err := srv.queries.CreateRef(ctx, repo.ID, "main", store.RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	previous, err := srv.queries.CreateSnapshot(ctx, ref.ID, "sha-1", store.SnapshotStatusComplete)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	current, err := srv.queries.CreateSnapshot(ctx, ref.ID, "sha-2", store.SnapshotStatusProcessing)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	accepted, acceptedNew := uuid.NewString(), uuid.NewString()
	disputed, disputedNew := uuid.NewString(), uuid.NewString()
	seedRekeyFinding(t, srv, previous.ID, accepted, "a.go", 3)
	seedRekeyFinding(t, srv, current.ID, acceptedNew, "a.go", 3) // same line, new key
	seedRekeyFinding(t, srv, previous.ID, disputed, "b.go", 10)
	seedRekeyFinding(t, srv, current.ID, disputedNew, "b.go", 14) // moved

	if _, err := srv.queries.UpsertFindingAcceptance(ctx, store.AcceptFindingInput{
		RepoID: repo.ID, Fingerprint: accepted, ReasonKind: "risk_accepted", Reason: "test fixture", AcceptedBy: &admin.ID,
	}); err != nil {
		t.Fatalf("UpsertFindingAcceptance: %v", err)
	}
	if _, err := srv.queries.UpsertFindingDispute(ctx, repo.ID, disputed, "directive is wrong", &admin.ID); err != nil {
		t.Fatalf("UpsertFindingDispute: %v", err)
	}

	srv.carryTriageAcrossRekeys(ctx, current)

	acceptance, err := srv.queries.GetActiveFindingAcceptance(ctx, repo.ID, acceptedNew)
	if err != nil || acceptance == nil {
		t.Fatalf("acceptance not carried: %+v %v", acceptance, err)
	}
	if acceptance.Reason != "test fixture" || acceptance.AcceptedBy == nil || *acceptance.AcceptedBy != admin.ID {
		t.Fatalf("acceptance carried without its decision: %+v", acceptance)
	}
	if old, _ := srv.queries.GetActiveFindingAcceptance(ctx, repo.ID, accepted); old == nil {
		t.Fatal("old acceptance must stay for refs still reporting the old key")
	}
	if dispute, err := srv.queries.GetFindingDispute(ctx, repo.ID, disputedNew); err != nil || dispute == nil {
		t.Fatalf("dispute not carried across a line move: %+v %v", dispute, err)
	}
}
