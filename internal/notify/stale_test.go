package notify

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/events"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// fakeStaleStore stands in for Postgres but keeps the durable dedup semantics:
// the "sent" set is owned by the store, not the checker, which is the whole
// point of the change.
type fakeStaleStore struct {
	orgs   []store.Organization
	stale  []dbgen.ListStaleRepositoriesRow
	sent   map[string]struct{}
	resets int
	// notified counts calls that returned "first time" — i.e. an alert was sent.
	// The event bus dispatches handlers in goroutines, so store state is the
	// only deterministic thing to assert on.
	notified int
}

func (f *fakeStaleStore) ListOrganizations(context.Context) ([]store.Organization, error) {
	return f.orgs, nil
}

func (f *fakeStaleStore) ListStaleRepositories(context.Context, time.Time) ([]dbgen.ListStaleRepositoriesRow, error) {
	return f.stale, nil
}

func (f *fakeStaleStore) MarkNotificationSent(_ context.Context, eventType string, repoID uuid.UUID) (bool, error) {
	key := eventType + "/" + repoID.String()
	if _, ok := f.sent[key]; ok {
		return false, nil
	}
	f.sent[key] = struct{}{}
	f.notified++
	return true, nil
}

func (f *fakeStaleStore) DeleteResolvedNotifications(_ context.Context, eventType string, active []uuid.UUID) error {
	f.resets++
	keep := make(map[string]struct{}, len(active))
	for _, repoID := range active {
		keep[eventType+"/"+repoID.String()] = struct{}{}
	}
	for key := range f.sent {
		if _, ok := keep[key]; !ok {
			delete(f.sent, key)
		}
	}
	return nil
}

func newStaleFixture(t *testing.T) (*StaleScanChecker, *fakeStaleStore) {
	t.Helper()
	orgID := uuid.New()
	repoID := uuid.New()
	fake := &fakeStaleStore{
		orgs: []store.Organization{{ID: orgID}},
		stale: []dbgen.ListStaleRepositoriesRow{{
			ID: repoID, OrgID: orgID, Name: "api",
		}},
		sent: map[string]struct{}{},
	}
	checker := NewStaleScanChecker(fake, events.New(zerolog.New(io.Discard)), zerolog.New(io.Discard))
	return checker, fake
}

// The bug this replaces: an in-memory set meant a pod restart (or a second
// replica) re-alerted every stale repo. Dedup now lives in the store, so a
// brand-new checker over the same store stays quiet.
func TestStaleScanDedupSurvivesCheckerRestart(t *testing.T) {
	checker, fake := newStaleFixture(t)
	ctx := context.Background()

	checker.runOnce(ctx)
	if fake.notified != 1 {
		t.Fatalf("first pass sent %d alerts, want 1", fake.notified)
	}

	checker.runOnce(ctx)
	if fake.notified != 1 {
		t.Fatalf("second pass re-alerted: %d total", fake.notified)
	}

	// A restart or a second replica: fresh checker, same store.
	restarted := NewStaleScanChecker(fake, checker.bus, zerolog.New(io.Discard))
	restarted.runOnce(ctx)
	if fake.notified != 1 {
		t.Fatalf("restarted checker re-alerted: %d total", fake.notified)
	}
}

func TestStaleScanReAlertsAfterRepoRecovers(t *testing.T) {
	checker, fake := newStaleFixture(t)
	ctx := context.Background()

	checker.runOnce(ctx)
	if fake.notified != 1 {
		t.Fatalf("want 1 alert, got %d", fake.notified)
	}

	// Repo scanned again → no longer stale → dedup entry must be cleared.
	stale := fake.stale
	fake.stale = nil
	checker.runOnce(ctx)
	if len(fake.sent) != 0 {
		t.Fatalf("resolved repo left %d dedup rows", len(fake.sent))
	}

	// Goes stale again → alert again.
	fake.stale = stale
	checker.runOnce(ctx)
	if fake.notified != 2 {
		t.Fatalf("want re-alert after recovery, got %d total", fake.notified)
	}
}
