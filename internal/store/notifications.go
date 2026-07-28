package store

import (
	"context"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// MarkNotificationSent records that a repeating notification was sent for
// (eventType, repoID) and reports whether this call was the first — i.e.
// whether the caller should actually notify. Durable so a pod restart or a
// second replica cannot re-send the same alert.
func (q *Queries) MarkNotificationSent(ctx context.Context, eventType string, repoID uuid.UUID) (bool, error) {
	rows, err := q.db.MarkNotificationSent(ctx, dbgen.MarkNotificationSentParams{EventType: eventType, RepoID: repoID})
	if err != nil {
		return false, err
	}
	return rows > 0, nil
}

// DeleteResolvedNotifications forgets every repo for eventType that is not in
// activeRepoIDs, so a repo that re-offends is notified again.
func (q *Queries) DeleteResolvedNotifications(ctx context.Context, eventType string, activeRepoIDs []uuid.UUID) error {
	if activeRepoIDs == nil {
		activeRepoIDs = []uuid.UUID{}
	}
	return q.db.DeleteResolvedNotifications(ctx, dbgen.DeleteResolvedNotificationsParams{
		EventType:     eventType,
		ActiveRepoIds: activeRepoIDs,
	})
}
