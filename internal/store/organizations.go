package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"encoding/json"

	"github.com/google/uuid"
	"github.com/hibouhq/lehibou/internal/store/dbgen"
)

type Organization struct {
	ID          uuid.UUID       `json:"id"`
	Name        string          `json:"name"`
	Slug        string          `json:"slug"`
	DisplayName string          `json:"display_name"`
	Settings    json.RawMessage `json:"settings"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

func (q *Queries) CreateOrganization(ctx context.Context, name, slug, displayName string) (*Organization, error) {
	row, err := q.db.CreateOrganization(ctx, dbgen.CreateOrganizationParams{
		Name:        name,
		Slug:        slug,
		DisplayName: displayName,
	})
	if err != nil {
		return nil, err
	}

	return orgFromRow(row), nil
}

func (q *Queries) GetOrganizationByID(ctx context.Context, id uuid.UUID) (*Organization, error) {
	row, err := q.db.GetOrganizationByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return orgFromRow(row), nil
}

func (q *Queries) GetOrganizationBySlug(ctx context.Context, slug string) (*Organization, error) {
	row, err := q.db.GetOrganizationBySlug(ctx, slug)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return orgFromRow(row), nil
}

func (q *Queries) ListOrganizationsByUser(ctx context.Context, userID uuid.UUID, limit, offset int) ([]Organization, int, error) {
	rows, err := q.db.ListOrganizationsByUser(ctx, dbgen.ListOrganizationsByUserParams{
		UserID: userID,
		Limit:  int32(limit),
		Offset: int32(offset),
	})
	if err != nil {
		return nil, 0, err
	}

	organizations := make([]Organization, len(rows))
	for i, row := range rows {
		organizations[i] = Organization{
			ID:          row.ID,
			Name:        row.Name,
			Slug:        row.Slug,
			DisplayName: row.DisplayName,
			Settings:    row.Settings,
			CreatedAt:   row.CreatedAt,
			UpdatedAt:   row.UpdatedAt,
		}
	}

	total, err := q.db.CountOrganizationsByUser(ctx, userID)
	if err != nil {
		return nil, 0, err
	}

	return organizations, int(total), nil
}

func (q *Queries) UpdateOrganization(ctx context.Context, id uuid.UUID, name, displayName string) (*Organization, error) {
	row, err := q.db.UpdateOrganization(ctx, dbgen.UpdateOrganizationParams{
		ID:          id,
		Name:        name,
		DisplayName: displayName,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return orgFromRow(row), nil
}

func (q *Queries) DeleteOrganization(ctx context.Context, id uuid.UUID) error {
	return q.db.DeleteOrganization(ctx, id)
}

func orgFromRow(row dbgen.Organization) *Organization {
	return &Organization{
		ID:          row.ID,
		Name:        row.Name,
		Slug:        row.Slug,
		DisplayName: row.DisplayName,
		Settings:    row.Settings,
		CreatedAt:   row.CreatedAt,
		UpdatedAt:   row.UpdatedAt,
	}
}
