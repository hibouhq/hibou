package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/google/uuid"

	"github.com/hibouhq/lehibou/internal/store/dbgen"
)

type Integration = dbgen.Integration

func (q *Queries) CreateIntegration(ctx context.Context, orgID uuid.UUID, name, integrationType string, config json.RawMessage, enabled bool) (*Integration, error) {
	row, err := q.db.CreateIntegration(ctx, dbgen.CreateIntegrationParams{
		OrgID:           orgID,
		Name:            name,
		IntegrationType: integrationType,
		Config:          defaultJSON(config, []byte("{}")),
		Enabled:         enabled,
	})
	if err != nil {
		return nil, err
	}

	return &row, nil
}

func (q *Queries) GetIntegrationByID(ctx context.Context, id uuid.UUID) (*Integration, error) {
	row, err := q.db.GetIntegrationByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &row, nil
}

func (q *Queries) UpdateIntegration(ctx context.Context, id uuid.UUID, name string, config json.RawMessage, enabled bool) (*Integration, error) {
	row, err := q.db.UpdateIntegration(ctx, dbgen.UpdateIntegrationParams{
		ID:      id,
		Name:    name,
		Config:  defaultJSON(config, []byte("{}")),
		Enabled: enabled,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &row, nil
}

func (q *Queries) DeleteIntegration(ctx context.Context, id uuid.UUID) error {
	return q.db.DeleteIntegration(ctx, id)
}
