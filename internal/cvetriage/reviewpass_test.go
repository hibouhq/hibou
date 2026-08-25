package cvetriage

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type fakeReviewStore struct {
	stale     []dbgen.ListTriageItemsNeedingReviewRow
	withdrawn []string
	reopened  []uuid.UUID
	events    []store.AdvisoryEvent
	reopenErr error
}

func (f *fakeReviewStore) ListTriageItemsNeedingReview(context.Context) ([]dbgen.ListTriageItemsNeedingReviewRow, error) {
	return f.stale, nil
}

func (f *fakeReviewStore) ListWithdrawnMappedCVEs(context.Context) ([]string, error) {
	return f.withdrawn, nil
}

func (f *fakeReviewStore) ReopenTriageItem(_ context.Context, id [16]byte) error {
	if f.reopenErr != nil {
		return f.reopenErr
	}
	f.reopened = append(f.reopened, uuid.UUID(id))
	return nil
}

func (f *fakeReviewStore) RecordAdvisoryEvent(_ context.Context, event store.AdvisoryEvent) error {
	f.events = append(f.events, event)
	return nil
}

// A revised record re-opens its decision rather than being re-decided: a
// widened range and a corrected typo look the same to a machine.
func TestReviewReopensRevisedDecisions(t *testing.T) {
	updated := time.Now().UTC()
	target := &fakeReviewStore{
		stale: []dbgen.ListTriageItemsNeedingReviewRow{{
			ID:              uuid.New(),
			CveID:           "CVE-2026-59084",
			RecordUpdatedAt: sql.NullTime{Time: updated, Valid: true},
		}},
	}

	result, err := Review(context.Background(), target)
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	if result.Reopened != 1 || len(target.reopened) != 1 {
		t.Fatalf("result = %+v, reopened = %v", result, target.reopened)
	}
	// The event carries the CNA's clock, not ours: the fact is when they
	// revised it, and stamping our own time hides the gap.
	if len(target.events) != 1 || target.events[0].Kind != store.EventCNARevised {
		t.Fatalf("events = %+v", target.events)
	}
	if !target.events[0].OccurredAt.Equal(updated) {
		t.Errorf("event stamped %v, want the record's own update time %v",
			target.events[0].OccurredAt, updated)
	}
}

func TestReviewCountsWithdrawnMappings(t *testing.T) {
	target := &fakeReviewStore{withdrawn: []string{"CVE-2026-16249", "CVE-2026-00001"}}

	result, err := Review(context.Background(), target)
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	if result.Withdrawn != 2 {
		t.Errorf("withdrawn = %d, want 2", result.Withdrawn)
	}
}

// A pass with nothing to do must be silent, not noisy: this runs every sweep.
func TestReviewIsQuietWhenNothingMoved(t *testing.T) {
	target := &fakeReviewStore{}
	result, err := Review(context.Background(), target)
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	if result.Reopened != 0 || result.Withdrawn != 0 || len(target.events) != 0 {
		t.Errorf("a quiet pass produced %+v / %d events", result, len(target.events))
	}
}

func TestReviewSurfacesReopenFailure(t *testing.T) {
	target := &fakeReviewStore{
		stale:     []dbgen.ListTriageItemsNeedingReviewRow{{ID: uuid.New(), CveID: "CVE-2026-59084"}},
		reopenErr: errors.New("database down"),
	}
	if _, err := Review(context.Background(), target); err == nil {
		t.Fatal("a failed reopen was reported as success")
	}
}
