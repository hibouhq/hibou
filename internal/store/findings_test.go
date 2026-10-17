package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

func findingParams(snapshotID uuid.UUID, fingerprint, title, severity, status string) dbgen.CreateVulnerabilityParams {
	return dbgen.CreateVulnerabilityParams{
		Type: "sast", SnapshotID: snapshotID, Title: title, Description: "desc of " + title,
		PrimaryIdentifierKind: "rule", PrimaryIdentifierValue: "G101",
		OriginalSeverity: dbgen.SeverityLevel(severity), Severity: dbgen.SeverityLevel(severity), Status: status,
		ScannerName: "gosec", Fingerprint: fingerprint,
		FilePath:  sql.NullString{String: "a.go", Valid: true},
		StartLine: sql.NullInt32{Int32: 10, Valid: true},
		Metadata:  json.RawMessage(`{"trace_files":["a.go"]}`),
	}
}

// One finding per repository across snapshots: a stable id, the rating,
// status, location and metadata of each occurrence kept per snapshot, the
// descriptive text written by the default branch only.
func TestFindingsOncePerRepository(t *testing.T) {
	db, queries := openInventoryTestDB(t)
	ctx := context.Background()
	first := createSnapshotForStatusTest(t, ctx, queries, SnapshotStatusComplete)
	row, err := queries.db.GetSnapshotByID(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	// The fixture's ref is "main", the repository's default branch.
	mainRef, err := queries.GetRefByID(ctx, row.RefID)
	if err != nil || mainRef == nil {
		t.Fatalf("ref: %v", err)
	}
	second, err := queries.CreateSnapshot(ctx, mainRef.ID, uniqueStoreTestName(t, "c2"), SnapshotStatusComplete)
	if err != nil {
		t.Fatal(err)
	}
	feature, err := queries.CreateRef(ctx, row.RepoID, "feature", RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	branch, err := queries.CreateSnapshot(ctx, feature.ID, uniqueStoreTestName(t, "c3"), SnapshotStatusComplete)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := uniqueStoreTestName(t, "fp")

	// 1. The same finding reported on two snapshots of main is one id.
	a, err := queries.CreateVulnerability(ctx, findingParams(first, fingerprint, "hardcoded credential", "high", "detected"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := queries.CreateVulnerability(ctx, findingParams(second.ID, fingerprint, "hardcoded credential (v2 wording)", "critical", "suppressed"))
	if err != nil {
		t.Fatal(err)
	}
	if a.ID != b.ID {
		t.Fatalf("one finding must keep one id: %s vs %s", a.ID, b.ID)
	}
	if a.SnapshotID != first || b.SnapshotID != second.ID {
		t.Errorf("snapshot ids %s %s", a.SnapshotID, b.SnapshotID)
	}
	// Per snapshot: the rating as scanned and the status the producer
	// reported; the text is the default branch's latest.
	a, _ = queries.GetVulnerabilityBySnapshotAndID(ctx, first, a.ID)
	if a.Severity != "high" || a.Status != "detected" || a.Title != "hardcoded credential (v2 wording)" {
		t.Errorf("first occurrence after the second report: severity %s status %s title %q", a.Severity, a.Status, a.Title)
	}
	if b.Severity != "critical" || b.Status != "suppressed" {
		t.Errorf("second occurrence: severity %s status %s", b.Severity, b.Status)
	}
	stats, _ := queries.FindingStats(ctx)
	if stats.SnapshotRows < 2 {
		t.Errorf("stats %+v", stats)
	}

	// 2. A feature branch on an older scanner neither rewrites the text
	// nor the latest location; its own location and metadata stay with
	// its snapshot.
	params := findingParams(branch.ID, fingerprint, "old wording", "medium", "detected")
	params.FilePath = sql.NullString{String: "moved/a.go", Valid: true}
	params.StartLine = sql.NullInt32{Int32: 42, Valid: true}
	params.Metadata = json.RawMessage(`{"trace_files":["moved/a.go","b.go"]}`)
	c, err := queries.CreateVulnerability(ctx, params)
	if err != nil {
		t.Fatal(err)
	}
	if c.ID != a.ID {
		t.Fatalf("branch occurrence is another finding: %s", c.ID)
	}
	if c.Title != "hardcoded credential (v2 wording)" || c.Severity != "medium" {
		t.Errorf("branch occurrence: title %q severity %s", c.Title, c.Severity)
	}
	if c.FilePath == nil || *c.FilePath != "moved/a.go" || c.StartLine == nil || *c.StartLine != 42 {
		t.Errorf("branch occurrence location %v %v", c.FilePath, c.StartLine)
	}
	if string(c.Metadata) != `{"trace_files": ["moved/a.go", "b.go"]}` && string(c.Metadata) != `{"trace_files":["moved/a.go","b.go"]}` {
		t.Errorf("branch occurrence metadata %s", c.Metadata)
	}
	latest, _ := queries.GetVulnerabilityBySnapshotAndID(ctx, second.ID, a.ID)
	if latest.FilePath == nil || *latest.FilePath != "a.go" || latest.StartLine == nil || *latest.StartLine != 10 {
		t.Errorf("main's occurrence must keep its own location: %v %v", latest.FilePath, latest.StartLine)
	}

	// 3. A person's decision is the finding's, on every snapshot.
	if _, err := queries.UpdateVulnerabilityStatus(ctx, a.ID, "resolved", nil, nil); err != nil {
		t.Fatal(err)
	}
	for _, snapshotID := range []uuid.UUID{first, second.ID, branch.ID} {
		got, err := queries.GetVulnerabilityBySnapshotAndID(ctx, snapshotID, a.ID)
		if err != nil || got.Status != "resolved" {
			t.Errorf("snapshot %s after resolution: %v %v", snapshotID, got, err)
		}
	}
	if _, err := queries.UpdateVulnerabilityStatus(ctx, a.ID, "detected", nil, nil); err != nil {
		t.Fatal(err)
	}

	// 4. The scan stopping to match a finding resolves it on that snapshot
	// only; a later report matches it again.
	other, err := queries.CreateVulnerability(ctx, findingParams(second.ID, uniqueStoreTestName(t, "fp2"), "other", "low", "detected"))
	if err != nil {
		t.Fatal(err)
	}
	stale, err := queries.MarkStaleVulnerabilities(ctx, second.ID, "sast", []uuid.UUID{other.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(stale) != 1 || stale[0] != "G101" {
		t.Errorf("stale identifiers %v", stale)
	}
	got, _ := queries.GetVulnerabilityBySnapshotAndID(ctx, second.ID, a.ID)
	if got.Status != "resolved" {
		t.Errorf("second snapshot after stale marking: %s", got.Status)
	}
	if got, _ := queries.GetVulnerabilityBySnapshotAndID(ctx, first, a.ID); got.Status != "detected" {
		t.Errorf("first snapshot must be untouched by the second's scan: %s", got.Status)
	}
	if _, err := queries.CreateVulnerability(ctx, findingParams(second.ID, fingerprint, "hardcoded credential (v2 wording)", "high", "detected")); err != nil {
		t.Fatal(err)
	}
	if got, _ := queries.GetVulnerabilityBySnapshotAndID(ctx, second.ID, a.ID); got.Status != "detected" {
		t.Errorf("re-reported finding stays resolved: %s", got.Status)
	}

	// 5. A severity override is a person's, shown on every snapshot; the
	// as-scanned rating stays in original_severity.
	user, err := queries.UpsertUser(ctx, uniqueStoreTestName(t, "u")+"@example.test", "Triager", nil, "local", uniqueStoreTestName(t, "ext"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE findings SET severity = 'low', severity_override_reason = 'mitigated', severity_override_by = $2 WHERE id = $1`, a.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	for _, snapshotID := range []uuid.UUID{first, branch.ID} {
		got, _ := queries.GetVulnerabilityBySnapshotAndID(ctx, snapshotID, a.ID)
		if got.Severity != "low" || got.OriginalSeverity == "low" {
			t.Errorf("override on %s: severity %s original %s", snapshotID, got.Severity, got.OriginalSeverity)
		}
	}

	// 6. Carry forward copies the occurrence, not the finding; the carried
	// row keeps the source's rating and location.
	third, err := queries.CreateSnapshot(ctx, feature.ID, uniqueStoreTestName(t, "c4"), SnapshotStatusComplete)
	if err != nil {
		t.Fatal(err)
	}
	lastSeen := branch.ID
	carried, err := queries.CarryVulnerabilitiesForward(ctx, third.ID, branch.ID, []CarryInput{{SourceID: a.ID, Presence: PresenceNotRechecked, Reason: "producer_missing", LastSeenSnapshotID: &lastSeen, ConsecutiveAbsences: 1}})
	if err != nil || carried != 1 {
		t.Fatalf("carry: %d %v", carried, err)
	}
	got, _ = queries.GetVulnerabilityBySnapshotAndID(ctx, third.ID, a.ID)
	if got.Presence != PresenceNotRechecked || got.LastSeenCommit == nil || *got.LastSeenCommit != branch.CommitSHA || got.FilePath == nil || *got.FilePath != "moved/a.go" {
		t.Errorf("carried row %+v", got)
	}
	rows, _ := queries.ListPresenceRowsBySnapshot(ctx, third.ID)
	if len(rows) != 1 || rows[0].ID != a.ID || string(rows[0].Metadata) == "" {
		t.Errorf("presence rows %+v", rows)
	}
	if deleted, err := queries.DeleteCarriedVulnerabilities(ctx, third.ID, []uuid.UUID{a.ID}); err != nil || deleted != 1 {
		t.Errorf("delete carried: %d %v", deleted, err)
	}

	// 7. Retention's rollup drops the snapshot's rows; the finding stays
	// for the others and the collector leaves it alone while any snapshot
	// carries it.
	if err := queries.db.DeleteVulnerabilitiesBySnapshot(ctx, branch.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := queries.GetVulnerabilityBySnapshotAndID(ctx, first, a.ID); err != nil {
		t.Errorf("finding lost with one snapshot's rows: %v", err)
	}
	if _, err := queries.CollectOrphanFindings(ctx, 100); err != nil {
		t.Fatal(err)
	}
	if exists, err := queries.FindingExists(ctx, a.ID); err != nil || !exists {
		t.Errorf("a carried finding was collected: %v %v", exists, err)
	}
}
