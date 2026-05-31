package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/lehibou/internal/store/dbgen"
)

type Team struct {
	ID        uuid.UUID `json:"id"`
	OrgID     uuid.UUID `json:"org_id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (q *Queries) CreateTeam(ctx context.Context, orgID uuid.UUID, name, slug string) (*Team, error) {
	row, err := q.db.CreateTeam(ctx, dbgen.CreateTeamParams{
		OrgID: orgID,
		Name:  name,
		Slug:  slug,
	})
	if err != nil {
		return nil, err
	}

	return teamFromRow(row), nil
}

func (q *Queries) GetTeamByID(ctx context.Context, id uuid.UUID) (*Team, error) {
	row, err := q.db.GetTeamByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return teamFromRow(row), nil
}

func (q *Queries) GetTeamBySlug(ctx context.Context, orgID uuid.UUID, slug string) (*Team, error) {
	row, err := q.db.GetTeamBySlug(ctx, dbgen.GetTeamBySlugParams{
		OrgID: orgID,
		Slug:  slug,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return teamFromRow(row), nil
}

func (q *Queries) ListTeamsByOrg(ctx context.Context, orgID uuid.UUID, limit, offset int) ([]Team, int, error) {
	rows, err := q.db.ListTeamsByOrg(ctx, dbgen.ListTeamsByOrgParams{
		OrgID:  orgID,
		Limit:  int32(limit),  //nolint:gosec // G115: pagination values are bounded by API parsing.
		Offset: int32(offset), //nolint:gosec // G115: pagination values are bounded by API parsing.
	})
	if err != nil {
		return nil, 0, err
	}

	teams := make([]Team, len(rows))
	for i, row := range rows {
		teams[i] = *teamFromRow(row)
	}

	total, err := q.db.CountTeamsByOrg(ctx, orgID)
	if err != nil {
		return nil, 0, err
	}

	return teams, int(total), nil
}

func (q *Queries) UpdateTeam(ctx context.Context, id uuid.UUID, name, slug string) (*Team, error) {
	row, err := q.db.UpdateTeam(ctx, dbgen.UpdateTeamParams{
		ID:   id,
		Name: name,
		Slug: slug,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return teamFromRow(row), nil
}

func (q *Queries) DeleteTeam(ctx context.Context, id uuid.UUID) error {
	return q.db.DeleteTeam(ctx, id)
}

func teamFromRow(row dbgen.Team) *Team {
	return &Team{
		ID:        row.ID,
		OrgID:     row.OrgID,
		Name:      row.Name,
		Slug:      row.Slug,
		CreatedAt: row.CreatedAt,
		UpdatedAt: row.UpdatedAt,
	}
}
