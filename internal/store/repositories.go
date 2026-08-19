package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type Repository struct {
	ID                     uuid.UUID  `json:"id"`
	OrgID                  uuid.UUID  `json:"org_id"`
	TeamID                 *uuid.UUID `json:"team_id,omitempty"`
	Name                   string     `json:"name"`
	Slug                   string     `json:"slug"`
	Provider               string     `json:"provider"`
	ProviderID             string     `json:"provider_id"`
	DefaultBranch          string     `json:"default_branch"`
	SyncState              string     `json:"sync_state"`
	RetentionArtifactBytes int64      `json:"retention_artifact_bytes"`
	CreatedAt              time.Time  `json:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at"`
}

type RepositoryRetentionUsageRow struct {
	ID                     uuid.UUID  `json:"id"`
	OrgID                  uuid.UUID  `json:"org_id"`
	TeamID                 *uuid.UUID `json:"team_id,omitempty"`
	Name                   string     `json:"name"`
	Slug                   string     `json:"slug"`
	Provider               string     `json:"provider"`
	ProviderID             string     `json:"provider_id"`
	DefaultBranch          string     `json:"default_branch"`
	SyncState              string     `json:"sync_state"`
	RetentionArtifactBytes int64      `json:"retention_artifact_bytes"`
	CreatedAt              time.Time  `json:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at"`
}

func (q *Queries) CreateRepository(ctx context.Context, orgID uuid.UUID, teamID *uuid.UUID, name, slug, provider, providerID, defaultBranch, syncState string) (*Repository, error) {
	row, err := q.db.CreateRepository(ctx, dbgen.CreateRepositoryParams{
		OrgID:         orgID,
		TeamID:        nullUUIDFromPtr(teamID),
		Name:          name,
		Slug:          slug,
		Provider:      provider,
		ProviderID:    providerID,
		DefaultBranch: defaultBranch,
		SyncState:     syncState,
	})
	if err != nil {
		return nil, err
	}

	return repositoryFromFields(
		row.ID,
		row.OrgID,
		row.TeamID,
		row.Name,
		row.Slug,
		row.Provider,
		row.ProviderID,
		row.DefaultBranch,
		row.SyncState,
		row.RetentionArtifactBytes,
		row.CreatedAt,
		row.UpdatedAt,
	), nil
}

func (q *Queries) GetRepositoryByProvider(ctx context.Context, provider, providerID string) (*Repository, error) {
	const query = `
		SELECT id, org_id, team_id, name, slug, provider, provider_id, default_branch, sync_state, retention_artifact_bytes, created_at, updated_at
		FROM repositories
		WHERE provider = $1 AND provider_id = $2
		LIMIT 1
	`

	row := q.sqlDB.QueryRowContext(ctx, query, provider, providerID)
	var repository dbgen.Repository
	if err := row.Scan(
		&repository.ID,
		&repository.OrgID,
		&repository.TeamID,
		&repository.Name,
		&repository.Slug,
		&repository.Provider,
		&repository.ProviderID,
		&repository.DefaultBranch,
		&repository.SyncState,
		&repository.RetentionArtifactBytes,
		&repository.CreatedAt,
		&repository.UpdatedAt,
	); errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	return repositoryFromRow(repository), nil
}

func (q *Queries) GetRepositoryByID(ctx context.Context, id uuid.UUID) (*Repository, error) {
	row, err := q.db.GetRepositoryByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return repositoryFromFields(
		row.ID,
		row.OrgID,
		row.TeamID,
		row.Name,
		row.Slug,
		row.Provider,
		row.ProviderID,
		row.DefaultBranch,
		row.SyncState,
		row.RetentionArtifactBytes,
		row.CreatedAt,
		row.UpdatedAt,
	), nil
}

func (q *Queries) GetRepositoryBySlug(ctx context.Context, orgID uuid.UUID, slug string) (*Repository, error) {
	row, err := q.db.GetRepositoryBySlug(ctx, dbgen.GetRepositoryBySlugParams{
		OrgID: orgID,
		Slug:  slug,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return repositoryFromFields(
		row.ID,
		row.OrgID,
		row.TeamID,
		row.Name,
		row.Slug,
		row.Provider,
		row.ProviderID,
		row.DefaultBranch,
		row.SyncState,
		row.RetentionArtifactBytes,
		row.CreatedAt,
		row.UpdatedAt,
	), nil
}

func (q *Queries) GetRepositoryByProviderID(ctx context.Context, orgID uuid.UUID, provider, providerID string) (*Repository, error) {
	row, err := q.db.GetRepositoryByProviderID(ctx, dbgen.GetRepositoryByProviderIDParams{
		OrgID:      orgID,
		Provider:   provider,
		ProviderID: providerID,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return repositoryFromFields(
		row.ID,
		row.OrgID,
		row.TeamID,
		row.Name,
		row.Slug,
		row.Provider,
		row.ProviderID,
		row.DefaultBranch,
		row.SyncState,
		row.RetentionArtifactBytes,
		row.CreatedAt,
		row.UpdatedAt,
	), nil
}

func (q *Queries) ListRepositoriesByOrg(ctx context.Context, orgID uuid.UUID, limit, offset int) ([]Repository, int, error) {
	rows, err := q.db.ListRepositoriesByOrg(ctx, dbgen.ListRepositoriesByOrgParams{
		OrgID:  orgID,
		Limit:  int32(limit),  //nolint:gosec // G115: pagination values are bounded by API parsing.
		Offset: int32(offset), //nolint:gosec // G115: pagination values are bounded by API parsing.
	})
	if err != nil {
		return nil, 0, err
	}

	repositories := make([]Repository, len(rows))
	for i, row := range rows {
		repositories[i] = *repositoryFromFields(
			row.ID,
			row.OrgID,
			row.TeamID,
			row.Name,
			row.Slug,
			row.Provider,
			row.ProviderID,
			row.DefaultBranch,
			row.SyncState,
			row.RetentionArtifactBytes,
			row.CreatedAt,
			row.UpdatedAt,
		)
	}

	total, err := q.db.CountRepositoriesByOrg(ctx, orgID)
	if err != nil {
		return nil, 0, err
	}

	return repositories, int(total), nil
}

func (q *Queries) ListStaleRepositories(ctx context.Context, before time.Time) ([]dbgen.ListStaleRepositoriesRow, error) {
	return q.db.ListStaleRepositories(ctx, sql.NullTime{Time: before, Valid: true})
}

func (q *Queries) ListRepositoriesByTeam(ctx context.Context, teamID uuid.UUID, limit, offset int) ([]Repository, int, error) {
	rows, err := q.db.ListRepositoriesByTeam(ctx, dbgen.ListRepositoriesByTeamParams{
		TeamID: nullUUIDFromPtr(&teamID),
		Limit:  int32(limit),  //nolint:gosec // G115: pagination values are bounded by API parsing.
		Offset: int32(offset), //nolint:gosec // G115: pagination values are bounded by API parsing.
	})
	if err != nil {
		return nil, 0, err
	}

	repositories := make([]Repository, len(rows))
	for i, row := range rows {
		repositories[i] = *repositoryFromFields(
			row.ID,
			row.OrgID,
			row.TeamID,
			row.Name,
			row.Slug,
			row.Provider,
			row.ProviderID,
			row.DefaultBranch,
			row.SyncState,
			row.RetentionArtifactBytes,
			row.CreatedAt,
			row.UpdatedAt,
		)
	}

	total, err := q.db.CountRepositoriesByTeam(ctx, nullUUIDFromPtr(&teamID))
	if err != nil {
		return nil, 0, err
	}

	return repositories, int(total), nil
}

func (q *Queries) UpdateRepository(ctx context.Context, id uuid.UUID, teamID *uuid.UUID, name, slug, defaultBranch, syncState string) (*Repository, error) {
	row, err := q.db.UpdateRepository(ctx, dbgen.UpdateRepositoryParams{
		ID:            id,
		Name:          name,
		Slug:          slug,
		DefaultBranch: defaultBranch,
		SyncState:     syncState,
		TeamID:        nullUUIDFromPtr(teamID),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return repositoryFromFields(
		row.ID,
		row.OrgID,
		row.TeamID,
		row.Name,
		row.Slug,
		row.Provider,
		row.ProviderID,
		row.DefaultBranch,
		row.SyncState,
		row.RetentionArtifactBytes,
		row.CreatedAt,
		row.UpdatedAt,
	), nil
}

func (q *Queries) DeleteRepository(ctx context.Context, id uuid.UUID) error {
	return q.db.DeleteRepository(ctx, id)
}

// SyncRepositoryDefaultBranch makes every enrolled repository tracking the
// given forge repo follow the forge's default branch. Returns the updated
// rows; repositories already on that branch are untouched.
func (q *Queries) SyncRepositoryDefaultBranch(ctx context.Context, provider, providerKey, defaultBranch string) ([]dbgen.SyncRepositoryDefaultBranchRow, error) {
	return q.db.SyncRepositoryDefaultBranch(ctx, dbgen.SyncRepositoryDefaultBranchParams{
		Provider:      provider,
		ProviderKey:   providerKey,
		DefaultBranch: defaultBranch,
	})
}

func (q *Queries) ListRepositoryRetentionUsage(ctx context.Context) ([]RepositoryRetentionUsageRow, error) {
	rows, err := q.db.ListRepositoryRetentionUsage(ctx)
	if err != nil {
		return nil, err
	}

	usage := make([]RepositoryRetentionUsageRow, len(rows))
	for i, row := range rows {
		usage[i] = RepositoryRetentionUsageRow{
			ID:                     row.ID,
			OrgID:                  row.OrgID,
			TeamID:                 uuidPtrFromNull(row.TeamID),
			Name:                   row.Name,
			Slug:                   row.Slug,
			Provider:               row.Provider,
			ProviderID:             row.ProviderID,
			DefaultBranch:          row.DefaultBranch,
			SyncState:              row.SyncState,
			RetentionArtifactBytes: row.RetentionArtifactBytes,
			CreatedAt:              row.CreatedAt,
			UpdatedAt:              row.UpdatedAt,
		}
	}

	return usage, nil
}

func (q *Queries) ListRepositoriesForRetention(ctx context.Context) ([]Repository, error) {
	rows, err := q.db.ListRepositoriesForRetention(ctx)
	if err != nil {
		return nil, err
	}

	repositories := make([]Repository, len(rows))
	for i, row := range rows {
		repositories[i] = *repositoryFromFields(
			row.ID,
			row.OrgID,
			row.TeamID,
			row.Name,
			row.Slug,
			row.Provider,
			row.ProviderID,
			row.DefaultBranch,
			row.SyncState,
			row.RetentionArtifactBytes,
			row.CreatedAt,
			row.UpdatedAt,
		)
	}

	return repositories, nil
}

func repositoryFromRow(row dbgen.Repository) *Repository {
	return repositoryFromFields(
		row.ID,
		row.OrgID,
		row.TeamID,
		row.Name,
		row.Slug,
		row.Provider,
		row.ProviderID,
		row.DefaultBranch,
		row.SyncState,
		row.RetentionArtifactBytes,
		row.CreatedAt,
		row.UpdatedAt,
	)
}

func repositoryFromFields(id, orgID uuid.UUID, teamID uuid.NullUUID, name, slug, provider, providerID, defaultBranch, syncState string, retentionArtifactBytes int64, createdAt, updatedAt time.Time) *Repository {
	return &Repository{
		ID:                     id,
		OrgID:                  orgID,
		TeamID:                 uuidPtrFromNull(teamID),
		Name:                   name,
		Slug:                   slug,
		Provider:               provider,
		ProviderID:             providerID,
		DefaultBranch:          defaultBranch,
		SyncState:              syncState,
		RetentionArtifactBytes: retentionArtifactBytes,
		CreatedAt:              createdAt,
		UpdatedAt:              updatedAt,
	}
}
