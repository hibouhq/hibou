package cvetriage

import (
	"context"
	"fmt"

	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// ReviewResult is one pass over decisions that may no longer hold.
type ReviewResult struct {
	Reopened  int
	Withdrawn int
}

// ReviewStore is the persistence a review pass needs.
type ReviewStore interface {
	ListTriageItemsNeedingReview(ctx context.Context) ([]dbgen.ListTriageItemsNeedingReviewRow, error)
	ListWithdrawnMappedCVEs(ctx context.Context) ([]string, error)
	ReopenTriageItem(ctx context.Context, id [16]byte) error
	RecordAdvisoryEvent(ctx context.Context, event store.AdvisoryEvent) error
}

// Review re-opens decisions the world has moved out from under.
//
// Two things can invalidate a mapping without anybody touching it:
//
//   - the CNA revises the record after it was triaged. Roughly three quarters
//     of the feed is revision, so this is routine rather than exotic, and a
//     widened range can newly implicate versions somebody runs.
//   - the record is withdrawn upstream. Findings derived from it are then
//     asserting a vulnerability that no longer exists.
//
// Neither is resolved automatically. A widened range could mean more components
// are affected or that the CNA corrected a typo, and only a person can tell —
// so this re-opens the decision and says why, rather than silently re-deciding.
func Review(ctx context.Context, reviewStore ReviewStore) (ReviewResult, error) {
	result := ReviewResult{}

	stale, err := reviewStore.ListTriageItemsNeedingReview(ctx)
	if err != nil {
		return result, fmt.Errorf("list stale triage decisions: %w", err)
	}
	for _, item := range stale {
		if err := reviewStore.ReopenTriageItem(ctx, item.ID); err != nil {
			return result, fmt.Errorf("reopen %s: %w", item.CveID, err)
		}
		result.Reopened++
		occurredAt := item.CreatedAt
		if item.RecordUpdatedAt.Valid {
			occurredAt = item.RecordUpdatedAt.Time
		}
		if err := reviewStore.RecordAdvisoryEvent(ctx, store.AdvisoryEvent{
			CVEID:      item.CveID,
			Kind:       store.EventCNARevised,
			OccurredAt: occurredAt,
		}); err != nil {
			return result, err
		}
	}

	withdrawn, err := reviewStore.ListWithdrawnMappedCVEs(ctx)
	if err != nil {
		return result, fmt.Errorf("list withdrawn mapped CVEs: %w", err)
	}
	result.Withdrawn = len(withdrawn)
	return result, nil
}
