package notify

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/events"
	"github.com/hibouhq/hibou/internal/store"
)

const (
	// tokenExpiryWarnWindow is how far ahead of expiry the warning fires —
	// expiry is mandatory on scoped tokens (ADR-020), so every token
	// eventually crosses this line and someone must hear about it in time to
	// rotate.
	tokenExpiryWarnWindow    = 7 * 24 * time.Hour
	tokenExpiryCheckInterval = 6 * time.Hour
)

// TokenExpiryChecker warns token owners before their API keys expire: the
// owning user for user-owned keys, every org admin for org-owned ones.
type TokenExpiryChecker struct {
	store    tokenExpiryStore
	bus      *events.Bus
	log      zerolog.Logger
	window   time.Duration
	interval time.Duration
}

type tokenExpiryStore interface {
	ListAPIKeysExpiringBefore(ctx context.Context, before time.Time) ([]store.APIKey, error)
	ListOrgAdminIDs(ctx context.Context, orgID uuid.UUID) ([]uuid.UUID, error)
	// The (event_type, uuid) dedup ledger is shared with the stale-scan
	// checker; here the uuid is the API key id. Durable, so restarts and extra
	// replicas cannot re-send, and resolved entries reset when a key is
	// rotated to a later expiry or revoked.
	MarkNotificationSent(ctx context.Context, eventType string, id uuid.UUID) (bool, error)
	DeleteResolvedNotifications(ctx context.Context, eventType string, activeIDs []uuid.UUID) error
}

func NewTokenExpiryChecker(store tokenExpiryStore, bus *events.Bus, log zerolog.Logger) *TokenExpiryChecker {
	return &TokenExpiryChecker{
		store:    store,
		bus:      bus,
		log:      log.With().Str("component", "notify.token_expiry_checker").Logger(),
		window:   tokenExpiryWarnWindow,
		interval: tokenExpiryCheckInterval,
	}
}

func (c *TokenExpiryChecker) Start(ctx context.Context) {
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

func (c *TokenExpiryChecker) runOnce(ctx context.Context) {
	keys, err := c.store.ListAPIKeysExpiringBefore(ctx, time.Now().UTC().Add(c.window))
	if err != nil {
		c.log.Error().Err(err).Msg("list expiring API keys")
		return
	}

	active := make([]uuid.UUID, 0, len(keys))
	for i := range keys {
		key := keys[i]
		active = append(active, key.ID)

		first, err := c.store.MarkNotificationSent(ctx, string(events.TokenExpiring), key.ID)
		if err != nil {
			c.log.Error().Err(err).Str("key_id", key.ID.String()).Msg("record token-expiry notification")
			continue
		}
		if !first {
			continue
		}

		recipients := c.recipients(ctx, &key)
		if len(recipients) == 0 {
			continue
		}

		payload := map[string]any{
			"user_ids":   uuidStrings(recipients),
			"token_id":   key.ID.String(),
			"token_name": key.Name,
			"owner_type": key.OwnerType,
			"expires_at": key.ExpiresAt.UTC().Format(time.RFC3339),
		}
		c.bus.Publish(ctx, events.Event{Type: events.TokenExpiring, Payload: payload, Timestamp: time.Now().UTC()})
	}

	if err := c.store.DeleteResolvedNotifications(ctx, string(events.TokenExpiring), active); err != nil {
		c.log.Error().Err(err).Msg("clear resolved token-expiry notifications")
	}
}

func (c *TokenExpiryChecker) recipients(ctx context.Context, key *store.APIKey) []uuid.UUID {
	if key.OwnerType == "org" && key.OwnerID != nil {
		admins, err := c.store.ListOrgAdminIDs(ctx, *key.OwnerID)
		if err != nil {
			c.log.Error().Err(err).Str("org_id", key.OwnerID.String()).Msg("list org admins for token expiry")
			return nil
		}
		return admins
	}
	return []uuid.UUID{key.UserID}
}

func uuidStrings(ids []uuid.UUID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}
