package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type QualityGate = dbgen.QualityGate

func (q *Queries) CreateQualityGate(ctx context.Context, orgID uuid.UUID, repoID *uuid.UUID, name, description string, maxCritical, maxHigh int32, maxMedium, maxNewFindings *int32, findingSeverities []string, enabled bool) (*QualityGate, error) {
	row, err := q.db.CreateQualityGate(ctx, dbgen.CreateQualityGateParams{
		OrgID:             orgID,
		RepoID:            nullUUIDFromPtr(repoID),
		Name:              name,
		Description:       description,
		MaxCritical:       maxCritical,
		MaxHigh:           maxHigh,
		MaxMedium:         nullInt32FromPtr(maxMedium),
		MaxNewFindings:    nullInt32FromPtr(maxNewFindings),
		FindingSeverities: findingSeverities,
		Enabled:           enabled,
	})
	if err != nil {
		return nil, err
	}

	return &row, nil
}

func (q *Queries) GetQualityGateByID(ctx context.Context, id uuid.UUID) (*QualityGate, error) {
	row, err := q.db.GetQualityGateByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &row, nil
}

func (q *Queries) UpdateQualityGate(ctx context.Context, id uuid.UUID, name, description string, maxCritical, maxHigh int32, maxMedium, maxNewFindings *int32, findingSeverities []string, enabled bool) (*QualityGate, error) {
	row, err := q.db.UpdateQualityGate(ctx, dbgen.UpdateQualityGateParams{
		ID:                id,
		Name:              name,
		Description:       description,
		MaxCritical:       maxCritical,
		MaxHigh:           maxHigh,
		MaxMedium:         nullInt32FromPtr(maxMedium),
		MaxNewFindings:    nullInt32FromPtr(maxNewFindings),
		FindingSeverities: findingSeverities,
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

func (q *Queries) DeleteQualityGate(ctx context.Context, id uuid.UUID) error {
	return q.db.DeleteQualityGate(ctx, id)
}
