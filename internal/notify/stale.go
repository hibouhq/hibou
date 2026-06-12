package notify

import (
	"context"
	"database/sql"
	"sync"
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

	mu       sync.Mutex
	notified map[uuid.UUID]struct{}
}

type staleScanStore interface {
	ListOrganizations(ctx context.Context) ([]store.Organization, error)
	ListStaleRepositories(ctx context.Context, before time.Time) ([]dbgen.ListStaleRepositoriesRow, error)
}

func NewStaleScanChecker(store staleScanStore, bus *events.Bus, log zerolog.Logger) *StaleScanChecker {
	return &StaleScanChecker{
		store:     store,
		bus:       bus,
		log:       log.With().Str("component", "notify.stale_scan_checker").Logger(),
		threshold: defaultStaleScanThreshold,
		interval:  staleScanCheckInterval,
		notified:  make(map[uuid.UUID]struct{}),
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
		if !c.markNotified(repo.ID) {
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
	c.resetResolved(current)
}

func (c *StaleScanChecker) markNotified(repoID uuid.UUID) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.notified[repoID]; ok {
		return false
	}
	c.notified[repoID] = struct{}{}
	return true
}

func (c *StaleScanChecker) resetResolved(current map[uuid.UUID]struct{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for repoID := range c.notified {
		if _, ok := current[repoID]; !ok {
			delete(c.notified, repoID)
		}
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
