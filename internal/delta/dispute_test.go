package delta

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	storepkg "github.com/hibouhq/hibou/internal/store"
)

// disputeMockStore layers ListFindingDisputesByRepo onto mockStore so the
// service's disputeStore assertion succeeds; the plain mockStore keeps the
// no-disputes default for every other test.
type disputeMockStore struct {
	*mockStore
	disputesByRepo map[uuid.UUID][]storepkg.FindingDispute
}

func (m *disputeMockStore) ListFindingDisputesByRepo(_ context.Context, repoID uuid.UUID) ([]storepkg.FindingDispute, error) {
	return append([]storepkg.FindingDispute(nil), m.disputesByRepo[repoID]...), nil
}

func newDisputeMockStore() (*disputeMockStore, uuid.UUID, uuid.UUID, uuid.UUID) {
	mock := &disputeMockStore{mockStore: newMockStore(), disputesByRepo: map[uuid.UUID][]storepkg.FindingDispute{}}
	prSnapshotID := uuid.New()
	targetSnapshotID := uuid.New()
	repoID := uuid.New()
	refID := uuid.New()
	mock.snapshots[prSnapshotID] = &storepkg.Snapshot{ID: prSnapshotID, RefID: refID}
	mock.snapshots[targetSnapshotID] = &storepkg.Snapshot{ID: targetSnapshotID, RefID: refID}
	mock.refs[refID] = &storepkg.Ref{ID: refID, RepoID: repoID}
	return mock, prSnapshotID, targetSnapshotID, repoID
}

// ADR-023: a scanner-suppressed finding is never gating, so a PR that
// introduces a finding together with its in-source directive must not fail the
// weakness gate — the suppressed row stays out of the delta entirely.
func TestComputeDeltaDropsSuppressedFindings(t *testing.T) {
	mock, prSnapshotID, targetSnapshotID, _ := newDisputeMockStore()
	mock.vulnsBySnapshot[prSnapshotID] = []storepkg.Vulnerability{
		{ID: uuid.New(), Type: "sast", Title: "suppressed in source", Severity: storepkg.SeverityLevelHigh, Fingerprint: "fp-suppressed", Status: "suppressed"},
		{ID: uuid.New(), Type: "sast", Title: "open", Severity: storepkg.SeverityLevelHigh, Fingerprint: "fp-open", Status: "detected"},
	}
	service := NewService(mock, zerolog.Nop())

	result, err := service.ComputeDelta(context.Background(), prSnapshotID, targetSnapshotID)
	if err != nil {
		t.Fatalf("ComputeDelta returned error: %v", err)
	}
	if len(result.New) != 1 || result.New[0].Fingerprint != "fp-open" {
		t.Fatalf("expected only the open finding to be new, got %#v", result.New)
	}
}

// ADR-026: a disputed suppression is the exception — the human contested the
// directive, so the finding counts as new risk again.
func TestComputeDeltaKeepsDisputedSuppressedFindings(t *testing.T) {
	mock, prSnapshotID, targetSnapshotID, repoID := newDisputeMockStore()
	mock.vulnsBySnapshot[prSnapshotID] = []storepkg.Vulnerability{
		{ID: uuid.New(), Type: "sast", Title: "contested", Severity: storepkg.SeverityLevelHigh, Fingerprint: "fp-disputed", Status: "suppressed"},
	}
	mock.disputesByRepo[repoID] = []storepkg.FindingDispute{{RepoID: repoID, Fingerprint: "fp-disputed", Reason: "no trust-boundary analysis was done"}}
	service := NewService(mock, zerolog.Nop())

	result, err := service.ComputeDelta(context.Background(), prSnapshotID, targetSnapshotID)
	if err != nil {
		t.Fatalf("ComputeDelta returned error: %v", err)
	}
	if len(result.New) != 1 || result.New[0].Fingerprint != "fp-disputed" {
		t.Fatalf("expected the disputed suppression to be new, got %#v", result.New)
	}
}

// Suppressing a previously open finding in the PR reads as resolving it: the
// target side has it open, the PR side's suppressed row is filtered, so the
// diff reports it resolved rather than unchanged.
func TestComputeDeltaReadsNewSuppressionAsResolved(t *testing.T) {
	mock, prSnapshotID, targetSnapshotID, _ := newDisputeMockStore()
	mock.vulnsBySnapshot[prSnapshotID] = []storepkg.Vulnerability{
		{ID: uuid.New(), Type: "sast", Title: "now suppressed", Severity: storepkg.SeverityLevelHigh, Fingerprint: "fp-1", Status: "suppressed"},
	}
	mock.vulnsBySnapshot[targetSnapshotID] = []storepkg.Vulnerability{
		{ID: uuid.New(), Type: "sast", Title: "was open", Severity: storepkg.SeverityLevelHigh, Fingerprint: "fp-1", Status: "detected"},
	}
	service := NewService(mock, zerolog.Nop())

	result, err := service.ComputeDelta(context.Background(), prSnapshotID, targetSnapshotID)
	if err != nil {
		t.Fatalf("ComputeDelta returned error: %v", err)
	}
	if len(result.New) != 0 {
		t.Fatalf("expected no new findings, got %#v", result.New)
	}
	if len(result.Resolved) != 1 || result.Resolved[0].Fingerprint != "fp-1" {
		t.Fatalf("expected the suppressed finding to read as resolved, got %#v", result.Resolved)
	}
}
