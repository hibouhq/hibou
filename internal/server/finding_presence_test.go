package server

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/delta"
	"github.com/hibouhq/hibou/internal/presence"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

func seedPresenceFinding(t *testing.T, srv *Server, snapshotID uuid.UUID, typ, scanner, fingerprint, file string) {
	t.Helper()
	params := dbgen.CreateVulnerabilityParams{
		Type:                   typ,
		SnapshotID:             snapshotID,
		Title:                  fingerprint,
		PrimaryIdentifierKind:  "rule",
		PrimaryIdentifierValue: "R1",
		OriginalSeverity:       dbgen.SeverityLevelHigh,
		Severity:               dbgen.SeverityLevelHigh,
		Status:                 "detected",
		ScannerName:            scanner,
		Fingerprint:            fingerprint,
	}
	if file != "" {
		params.FilePath = sql.NullString{String: file, Valid: true}
	}
	if _, err := srv.queries.CreateVulnerability(context.Background(), params); err != nil {
		t.Fatalf("CreateVulnerability(%s): %v", fingerprint, err)
	}
}

func presenceByFingerprint(t *testing.T, srv *Server, snapshotID uuid.UUID) map[string]store.Vulnerability {
	t.Helper()
	rows, err := srv.queries.ListAllVulnerabilitiesBySnapshot(context.Background(), snapshotID)
	if err != nil {
		t.Fatalf("ListAllVulnerabilitiesBySnapshot: %v", err)
	}
	out := map[string]store.Vulnerability{}
	for _, row := range rows {
		out[row.Fingerprint] = row
	}
	return out
}

func recordRun(t *testing.T, srv *Server, snapshotID uuid.UUID, run store.ProducerRunInput) {
	t.Helper()
	if _, err := srv.queries.UpsertSnapshotProducerRun(context.Background(), snapshotID, run); err != nil {
		t.Fatalf("UpsertSnapshotProducerRun: %v", err)
	}
}

// Two CI workflows on one commit make two snapshots: the second lacks the
// first's tool. Its findings must stay open as not re-checked, then go away
// once the tool covers them again.
func TestReconcileFindingPresence(t *testing.T) {
	srv, org, _, _ := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)
	ctx := context.Background()
	ref, err := srv.queries.CreateRef(ctx, repo.ID, "main", store.RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	previous, err := srv.queries.CreateSnapshot(ctx, ref.ID, "sha-workflow-a", store.SnapshotStatusComplete)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	seedPresenceFinding(t, srv, previous.ID, "sast", "gosec", "gosec-fp", "a.go")
	seedPresenceFinding(t, srv, previous.ID, "sast", "trivy", "trivy-fixed", "Dockerfile")
	seedPresenceFinding(t, srv, previous.ID, "secret", "gitleaks", "secret-fp", "config.yml")
	recordRun(t, srv, previous.ID, store.ProducerRunInput{Producer: "gosec", Scope: "full", Outcome: "completed"})
	recordRun(t, srv, previous.ID, store.ProducerRunInput{Producer: "trivy", Scope: "full", Outcome: "completed"})

	current, err := srv.queries.CreateSnapshot(ctx, ref.ID, "sha-workflow-b", store.SnapshotStatusProcessing)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	// Workflow B ran trivy only, and trivy no longer reports its finding.
	recordRun(t, srv, current.ID, store.ProducerRunInput{Producer: "trivy", Scope: "full", Outcome: "completed"})

	if !srv.reconcileFindingPresence(ctx, current.ID) {
		t.Fatal("first reconcile must report a change")
	}
	rows := presenceByFingerprint(t, srv, current.ID)
	gosec, ok := rows["gosec-fp"]
	if !ok || gosec.Presence != store.PresenceNotRechecked || derefString(gosec.PresenceReason) != presence.ReasonProducerMissing {
		t.Fatalf("gosec finding must be carried as not re-checked: %+v", gosec)
	}
	if gosec.LastSeenSnapshotID == nil || *gosec.LastSeenSnapshotID != previous.ID || derefString(gosec.LastSeenCommit) != "sha-workflow-a" {
		t.Fatalf("carried row must name where it was last seen: %+v", gosec)
	}
	if _, ok := rows["secret-fp"]; !ok {
		t.Fatal("secret finding must be carried: no secret scan on this snapshot")
	}
	if _, ok := rows["trivy-fixed"]; ok {
		t.Fatal("trivy covered the file and dropped the finding: it is resolved, not carried")
	}

	// Idempotent.
	if srv.reconcileFindingPresence(ctx, current.ID) {
		t.Fatal("second reconcile must be a no-op")
	}

	// A late secret scan (incremental, partial) keeps the secret carried with
	// a sharper reason; gosec reporting its finding again makes it a real row.
	recordRun(t, srv, current.ID, store.ProducerRunInput{Producer: presence.ProducerSecretScanning, Scope: "partial", ScopeDeclared: true, Outcome: "partial"})
	seedPresenceFinding(t, srv, current.ID, "sast", "gosec", "gosec-fp", "a.go")
	recordRun(t, srv, current.ID, store.ProducerRunInput{Producer: "gosec", Scope: "full", Outcome: "completed"})
	srv.reconcileFindingPresence(ctx, current.ID)
	rows = presenceByFingerprint(t, srv, current.ID)
	if rows["gosec-fp"].Presence != store.PresenceReported || rows["gosec-fp"].PresenceReason != nil {
		t.Fatalf("re-reported finding must be reported: %+v", rows["gosec-fp"])
	}
	if derefString(rows["secret-fp"].PresenceReason) != presence.ReasonPartialScope {
		t.Fatalf("secret reason = %v", rows["secret-fp"].PresenceReason)
	}

	// A full secret scan that does not find it any more resolves it.
	recordRun(t, srv, current.ID, store.ProducerRunInput{Producer: presence.ProducerSecretScanning, Scope: "full", ScopeDeclared: true, Outcome: "completed"})
	srv.reconcileFindingPresence(ctx, current.ID)
	if _, ok := presenceByFingerprint(t, srv, current.ID)["secret-fp"]; ok {
		t.Fatal("covered and absent: the carried secret must be removed")
	}
}

// The next snapshot carries a carried row again, keeping its origin.
func TestReconcileFindingPresenceChains(t *testing.T) {
	srv, org, _, _ := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)
	ctx := context.Background()
	ref, err := srv.queries.CreateRef(ctx, repo.ID, "main", store.RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	first, _ := srv.queries.CreateSnapshot(ctx, ref.ID, "sha-1", store.SnapshotStatusComplete)
	seedPresenceFinding(t, srv, first.ID, "sast", "gosec", "fp", "a.go")
	second, _ := srv.queries.CreateSnapshot(ctx, ref.ID, "sha-2", store.SnapshotStatusComplete)
	srv.reconcileFindingPresence(ctx, second.ID)
	third, _ := srv.queries.CreateSnapshot(ctx, ref.ID, "sha-3", store.SnapshotStatusProcessing)
	srv.reconcileFindingPresence(ctx, third.ID)
	row, ok := presenceByFingerprint(t, srv, third.ID)["fp"]
	if !ok || derefString(row.LastSeenCommit) != "sha-1" {
		t.Fatalf("chained carry must keep the original last-seen commit: %+v", row)
	}
}

// The timeline shows the gap: not re-checked on the carried snapshot, then
// re-checked when the producer reports the finding again.
func TestFindingTimelineShowsPresenceGap(t *testing.T) {
	srv, org, _, _ := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)
	ctx := context.Background()
	ref, err := srv.queries.CreateRef(ctx, repo.ID, "main", store.RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	first, _ := srv.queries.CreateSnapshot(ctx, ref.ID, "sha-1", store.SnapshotStatusComplete)
	seedPresenceFinding(t, srv, first.ID, "sast", "gosec", "gap-fp", "a.go")
	second, _ := srv.queries.CreateSnapshot(ctx, ref.ID, "sha-2", store.SnapshotStatusComplete)
	srv.reconcileFindingPresence(ctx, second.ID)
	third, _ := srv.queries.CreateSnapshot(ctx, ref.ID, "sha-3", store.SnapshotStatusComplete)
	seedPresenceFinding(t, srv, third.ID, "sast", "gosec", "gap-fp", "a.go")

	transitions, err := srv.queries.ListFindingTransitions(ctx, repo.ID, "gap-fp", 50)
	if err != nil {
		t.Fatalf("ListFindingTransitions: %v", err)
	}
	kinds := make([]string, 0, len(transitions))
	for _, transition := range transitions {
		kinds = append(kinds, scanHistoryEvent(transition).Kind)
	}
	// Newest first.
	want := []string{"rechecked", "not_rechecked", "detected"}
	if len(kinds) != len(want) {
		t.Fatalf("kinds = %v, want %v", kinds, want)
	}
	for i := range want {
		if kinds[i] != want[i] {
			t.Fatalf("kinds = %v, want %v", kinds, want)
		}
	}
	if reason := scanHistoryEvent(transitions[1]).Detail["reason"]; reason != presence.ReasonProducerMissing {
		t.Fatalf("not re-checked event reason = %v", reason)
	}
}

// End to end through artifact processing: workflow B uploads only a trivy
// SARIF on the next commit; workflow A's gosec finding stays open as not
// re-checked instead of reading as fixed in the delta.
func TestArtifactProcessingCarriesMissingProducer(t *testing.T) {
	srv, firstSnapshotID := newArtifactProcessingTestServer(t)
	ctx := context.Background()
	first, err := srv.queries.GetSnapshotByID(ctx, firstSnapshotID)
	if err != nil || first == nil {
		t.Fatalf("GetSnapshotByID: %v", err)
	}
	seedPresenceFinding(t, srv, first.ID, "sast", "gosec", "gosec-e2e", "a.go")
	recordRun(t, srv, first.ID, store.ProducerRunInput{Producer: "gosec", Scope: "full", Outcome: "completed"})

	second, err := srv.queries.CreateSnapshot(ctx, first.RefID, uniqueName(t, "commit"), store.SnapshotStatusComplete)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	writeArtifactForProcessingTest(t, srv, second.ID, "sarif", nil, strPtr("trivy"),
		`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"trivy","version":"0.60.0"}},"results":[]}]}`)
	processArtifactSnapshotForTest(t, srv, second.ID)

	row, ok := presenceByFingerprint(t, srv, second.ID)["gosec-e2e"]
	if !ok || row.Presence != store.PresenceNotRechecked {
		t.Fatalf("gosec finding must be carried: %+v (present %v)", row, ok)
	}

	deltaStore := delta.NewStoreAdapter(srv.queries)
	result, err := delta.NewService(deltaStore, zerolog.Nop(), deltaStore).ComputeDelta(ctx, second.ID, first.ID)
	if err != nil {
		t.Fatalf("ComputeDelta: %v", err)
	}
	if len(result.Resolved) != 0 || len(result.NotRechecked) != 1 {
		t.Fatalf("delta must not claim a fix: resolved=%d notRechecked=%d", len(result.Resolved), len(result.NotRechecked))
	}
}

// Same commit, producer ran, finding gone: nothing changed, so it is
// unconfirmed, not fixed. On another commit (forge cannot compare in tests)
// coverage alone decides and the resolution is recorded with its evidence.
func TestReconcileUnconfirmedAndResolutionRecord(t *testing.T) {
	srv, org, _, _ := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)
	ctx := context.Background()
	ref, err := srv.queries.CreateRef(ctx, repo.ID, "main", store.RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	gosecRun := store.ProducerRunInput{Producer: "gosec", Scope: "full", Outcome: "completed"}
	first, _ := srv.queries.CreateSnapshot(ctx, ref.ID, "same-commit", store.SnapshotStatusComplete)
	seedPresenceFinding(t, srv, first.ID, "sast", "gosec", "flaky", "a.go")
	recordRun(t, srv, first.ID, gosecRun)

	// Second workflow on the same commit: a different run, same code.
	var secondID uuid.UUID
	if err := srv.db.QueryRowContext(ctx,
		`INSERT INTO snapshots (ref_id, commit_sha, status, run_id) VALUES ($1, 'same-commit', 'complete', 'workflow-b') RETURNING id`,
		ref.ID).Scan(&secondID); err != nil {
		t.Fatalf("insert second-workflow snapshot: %v", err)
	}
	second, err := srv.queries.GetSnapshotByID(ctx, secondID)
	if err != nil || second == nil {
		t.Fatalf("GetSnapshotByID: %v", err)
	}
	recordRun(t, srv, second.ID, gosecRun)
	srv.reconcileFindingPresence(ctx, second.ID)
	row, ok := presenceByFingerprint(t, srv, second.ID)["flaky"]
	if !ok || row.Presence != store.PresenceUnconfirmed || derefString(row.PresenceReason) != presence.ReasonUnchanged || row.ConsecutiveAbsences != 1 {
		t.Fatalf("finding must be unconfirmed: %+v (present %v)", row, ok)
	}

	third, _ := srv.queries.CreateSnapshot(ctx, ref.ID, "next-commit", store.SnapshotStatusComplete)
	recordRun(t, srv, third.ID, gosecRun)
	srv.reconcileFindingPresence(ctx, third.ID)
	if _, ok := presenceByFingerprint(t, srv, third.ID)["flaky"]; ok {
		t.Fatal("covered on a new commit with change unknown: resolved, not carried")
	}
	resolutions, err := srv.queries.ListFindingResolutions(ctx, repo.ID, "flaky", 10)
	if err != nil || len(resolutions) != 1 || resolutions[0].Reason != presence.ResolvedFixed || resolutions[0].CommitSHA != "next-commit" {
		t.Fatalf("resolution record = %+v, %v", resolutions, err)
	}
	if event := resolutionHistoryEvent(resolutions[0]); event.Kind != "resolved" || event.CommitSHA != "next-commit" {
		t.Fatalf("timeline event = %+v", event)
	}

	// Re-running reconcile is idempotent for resolutions too.
	srv.reconcileFindingPresence(ctx, third.ID)
	if again, _ := srv.queries.ListFindingResolutions(ctx, repo.ID, "flaky", 10); len(again) != 1 {
		t.Fatalf("resolutions duplicated: %d", len(again))
	}
}

func TestProducerPolicyLookup(t *testing.T) {
	lookup := producerPolicyLookup([]store.ProducerPolicy{{Producer: "noisy", Policy: presence.PolicyConsecutiveAbsence, Threshold: 5}})
	if got := lookup("noisy"); got.Kind != presence.PolicyConsecutiveAbsence || got.Threshold != 5 {
		t.Fatalf("noisy = %+v", got)
	}
	if got := lookup("agent:42"); got.Kind != presence.PolicyExplicit {
		t.Fatalf("agent default = %+v", got)
	}
	if got := lookup("gosec"); got.Kind != presence.PolicyCoverage {
		t.Fatalf("default = %+v", got)
	}
}

// A producer an org admin retired stops carrying its findings: they resolve
// as producer_retired, recorded as such.
func TestReconcileRetiredProducer(t *testing.T) {
	srv, org, admin, _ := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)
	ctx := context.Background()
	if _, err := srv.queries.UpsertProducerPolicy(ctx, org.ID, store.ProducerPolicy{Producer: "oldtool", Policy: presence.PolicyRetired, Threshold: 3, UpdatedBy: &admin.ID}); err != nil {
		t.Fatal(err)
	}
	ref, _ := srv.queries.CreateRef(ctx, repo.ID, "main", store.RefTypeBranch, nil, nil, nil)
	first, _ := srv.queries.CreateSnapshot(ctx, ref.ID, "r1", store.SnapshotStatusComplete)
	seedPresenceFinding(t, srv, first.ID, "sast", "oldtool", "retired-fp", "a.go")
	second, _ := srv.queries.CreateSnapshot(ctx, ref.ID, "r2", store.SnapshotStatusComplete)
	srv.reconcileFindingPresence(ctx, second.ID)
	if _, ok := presenceByFingerprint(t, srv, second.ID)["retired-fp"]; ok {
		t.Fatal("a retired producer's finding must not be carried")
	}
	resolutions, err := srv.queries.ListFindingResolutions(ctx, repo.ID, "retired-fp", 5)
	if err != nil || len(resolutions) != 1 || resolutions[0].Reason != presence.ResolvedProducerRetired {
		t.Fatalf("resolutions = %+v, %v", resolutions, err)
	}
}
