package notify

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/events"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

const (
	defaultStaleScanThreshold = 48 * time.Hour
	staleScanCheckInterval    = time.Hour
)

type StaleScanChecker struct {
	store     staleScanStore
	bus       *events.Bus
	log       zerolog.Logger
	threshold time.Duration
	interval  time.Duration
}

type staleScanStore interface {
	ListOrganizations(ctx context.Context) ([]store.Organization, error)
	ListStaleRepositories(ctx context.Context, before time.Time) ([]dbgen.ListStaleRepositoriesRow, error)
	// Dedup is durable: an in-memory set re-notified every stale repo after a
	// pod restart, and duplicated alerts once a second replica ran this loop.
	MarkNotificationSent(ctx context.Context, eventType string, repoID uuid.UUID) (bool, error)
	DeleteResolvedNotifications(ctx context.Context, eventType string, activeRepoIDs []uuid.UUID) error
}

func NewStaleScanChecker(store staleScanStore, bus *events.Bus, log zerolog.Logger) *StaleScanChecker {
	return &StaleScanChecker{
		store:     store,
		bus:       bus,
		log:       log.With().Str("component", "notify.stale_scan_checker").Logger(),
		threshold: defaultStaleScanThreshold,
		interval:  staleScanCheckInterval,
	}
}

func (c *StaleScanChecker) Start(ctx context.Context) {
	if c == nil || c.store == nil || c.bus == nil {
		return
	}
	c.runOnce(ctx)
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.runOnce(ctx)
		}
	}
}

func (c *StaleScanChecker) runOnce(ctx context.Context) {
	organizations, err := c.store.ListOrganizations(ctx)
	if err != nil {
		c.log.Error().Err(err).Msg("list organizations for stale scan check")
		return
	}
	knownOrgs := make(map[uuid.UUID]struct{}, len(organizations))
	for _, org := range organizations {
		knownOrgs[org.ID] = struct{}{}
	}

	cutoff := time.Now().UTC().Add(-c.threshold)
	staleRepos, err := c.store.ListStaleRepositories(ctx, cutoff)
	if err != nil {
		c.log.Error().Err(err).Msg("list stale repositories")
		return
	}
	current := make(map[uuid.UUID]struct{}, len(staleRepos))
	for _, repo := range staleRepos {
		if _, ok := knownOrgs[repo.OrgID]; !ok {
			continue
		}
		current[repo.ID] = struct{}{}
		if !c.markNotified(ctx, repo.ID) {
			continue
		}
		lastScanAt := staleScanCompletedAt(repo.LastScanCompletedAt)
		payload := map[string]any{
			"org_id":                 repo.OrgID.String(),
			"repo_id":                repo.ID.String(),
			"repo_name":              repo.Name,
			"ref_name":               repo.DefaultBranch,
			"last_scan_completed_at": lastScanAt.Format(time.RFC3339),
		}
		if repo.TeamID.Valid {
			payload["team_id"] = repo.TeamID.UUID.String()
		}
		c.bus.Publish(ctx, events.Event{Type: events.ScanStale, Payload: payload, Timestamp: time.Now().UTC()})
	}
	c.resetResolved(ctx, current)
}

// markNotified reports whether this repo still needs an alert. A store error
// suppresses the notification rather than risking a duplicate.
func (c *StaleScanChecker) markNotified(ctx context.Context, repoID uuid.UUID) bool {
	first, err := c.store.MarkNotificationSent(ctx, string(events.ScanStale), repoID)
	if err != nil {
		c.log.Error().Err(err).Str("repo_id", repoID.String()).Msg("record stale-scan notification")
		return false
	}
	return first
}

// resetResolved forgets repos that are no longer stale, so a repo that goes
// stale again is alerted again.
func (c *StaleScanChecker) resetResolved(ctx context.Context, current map[uuid.UUID]struct{}) {
	active := make([]uuid.UUID, 0, len(current))
	for repoID := range current {
		active = append(active, repoID)
	}
	if err := c.store.DeleteResolvedNotifications(ctx, string(events.ScanStale), active); err != nil {
		c.log.Error().Err(err).Msg("clear resolved stale-scan notifications")
	}
}

func staleScanCompletedAt(raw any) time.Time {
	switch typed := raw.(type) {
	case time.Time:
		return typed.UTC()
	case *time.Time:
		if typed != nil {
			return typed.UTC()
		}
	case sql.NullTime:
		if typed.Valid {
			return typed.Time.UTC()
		}
	case *sql.NullTime:
		if typed != nil && typed.Valid {
			return typed.Time.UTC()
		}
	}
	return time.Unix(0, 0).UTC()
}
