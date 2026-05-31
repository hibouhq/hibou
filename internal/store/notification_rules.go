package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/google/uuid"

	"github.com/hibouhq/lehibou/internal/store/dbgen"
)

type NotificationDestinationType = dbgen.NotificationDestinationType
type NotificationRule = dbgen.NotificationRule

const (
	NotificationDestinationTypeWebhook = dbgen.NotificationDestinationTypeWebhook
	NotificationDestinationTypeSlack   = dbgen.NotificationDestinationTypeSlack
	NotificationDestinationTypeTeams   = dbgen.NotificationDestinationTypeTeams
	NotificationDestinationTypeDiscord = dbgen.NotificationDestinationTypeDiscord
	NotificationDestinationTypeEmail   = dbgen.NotificationDestinationTypeEmail
)

func (q *Queries) CreateNotificationRule(ctx context.Context, orgID uuid.UUID, name, eventType string, conditions json.RawMessage, destinationType NotificationDestinationType, destinationConfig json.RawMessage, enabled bool) (*NotificationRule, error) {
	row, err := q.db.CreateNotificationRule(ctx, dbgen.CreateNotificationRuleParams{
		OrgID:             orgID,
		Name:              name,
		EventType:         eventType,
		Conditions:        defaultJSON(conditions, []byte("{}")),
		DestinationType:   destinationType,
		DestinationConfig: defaultJSON(destinationConfig, []byte("{}")),
		Enabled:           enabled,
	})
	if err != nil {
		return nil, err
	}

	return &row, nil
}

func (q *Queries) GetNotificationRuleByID(ctx context.Context, id uuid.UUID) (*NotificationRule, error) {
	row, err := q.db.GetNotificationRuleByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &row, nil
}

func (q *Queries) ListNotificationRulesByOrg(ctx context.Context, orgID uuid.UUID) ([]NotificationRule, error) {
	return q.db.ListNotificationRulesByOrg(ctx, orgID)
}

func (q *Queries) ListEnabledRulesByOrgAndEventType(ctx context.Context, orgID uuid.UUID, eventType string) ([]NotificationRule, error) {
	return q.db.ListEnabledRulesByOrgAndEventType(ctx, dbgen.ListEnabledRulesByOrgAndEventTypeParams{
		OrgID:     orgID,
		EventType: eventType,
	})
}

func (q *Queries) UpdateNotificationRule(ctx context.Context, id uuid.UUID, name, eventType string, conditions json.RawMessage, destinationType NotificationDestinationType, destinationConfig json.RawMessage, enabled bool) (*NotificationRule, error) {
	row, err := q.db.UpdateNotificationRule(ctx, dbgen.UpdateNotificationRuleParams{
		ID:                id,
		Name:              name,
		EventType:         eventType,
		Conditions:        defaultJSON(conditions, []byte("{}")),
		DestinationType:   destinationType,
		DestinationConfig: defaultJSON(destinationConfig, []byte("{}")),
		Enabled:           enabled,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &row, nil
}

func (q *Queries) DeleteNotificationRule(ctx context.Context, id uuid.UUID) error {
	return q.db.DeleteNotificationRule(ctx, id)
}
