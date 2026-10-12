package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
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

// GetRepositoryByProvider routes a forge event to the enrolled repository it
// concerns. Several orgs may hold a row for the same provider_id (legacy data
// predating the enrolment ownership check), so the row is chosen
// deterministically and only from an org bound to the repository's owner: a
// tenant that enrolled someone else's repository must never receive its
// pushes and pull requests (security audit §3.1, M4). When the owner cannot
// be derived (opaque ids without an inventory row) the oldest row wins.
func (q *Queries) GetRepositoryByProvider(ctx context.Context, provider, providerID string) (*Repository, error) {
	const query = `
		SELECT r.id, r.org_id, r.team_id, r.name, r.slug, r.provider, r.provider_id, r.default_branch, r.sync_state, r.retention_artifact_bytes, r.created_at, r.updated_at,
			o.slug, COALESCE(o.forge_account_login, '')
		FROM repositories r
		JOIN organizations o ON o.id = r.org_id
		WHERE r.provider = $1 AND r.provider_id = $2
		ORDER BY r.created_at ASC, r.id ASC
	`

	rows, err := q.sqlDB.QueryContext(ctx, query, provider, providerID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	type candidate struct {
		repo dbgen.Repository
		org  Organization
	}
	var candidates []candidate
	for rows.Next() {
		var c candidate
		if err := rows.Scan(
			&c.repo.ID,
			&c.repo.OrgID,
			&c.repo.TeamID,
			&c.repo.Name,
			&c.repo.Slug,
			&c.repo.Provider,
			&c.repo.ProviderID,
			&c.repo.DefaultBranch,
			&c.repo.SyncState,
			&c.repo.RetentionArtifactBytes,
			&c.repo.CreatedAt,
			&c.repo.UpdatedAt,
			&c.org.Slug,
			&c.org.ForgeAccountLogin,
		); err != nil {
			return nil, err
		}
		candidates = append(candidates, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(candidates) == 0 {
		return nil, nil
	}

	owner, err := q.RepositoryForgeOwner(ctx, provider, providerID)
	if err != nil {
		return nil, err
	}
	if owner == "" {
		return repositoryFromRow(candidates[0].repo), nil
	}
	for i := range candidates {
		if candidates[i].org.OwnsForgeOwner(owner) {
			return repositoryFromRow(candidates[i].repo), nil
		}
	}
	return nil, nil
}

// RepositoryForgeOwner derives the forge namespace a repository lives under:
// the owner part of an owner/name provider id, or the mirrored inventory row
// for opaque ids. Empty when neither is known.
func (q *Queries) RepositoryForgeOwner(ctx context.Context, provider, providerID string) (string, error) {
	providerID = strings.Trim(strings.TrimSpace(providerID), "/")
	if i := strings.LastIndex(providerID, "/"); i > 0 {
		return providerID[:i], nil
	}
	if providerID == "" {
		return "", nil
	}
	inv, err := q.GetForgeRepositoryByProviderRepoID(ctx, provider, providerID)
	if err != nil || inv == nil {
		return "", err
	}
	if owner := strings.TrimSpace(inv.Owner); owner != "" {
		return owner, nil
	}
	return strings.TrimSpace(inv.AccountLogin), nil
}

// ForgeOwnerBoundToOrg reports whether owner belongs to the forge account the
// org is bound to. Callers check it before any forge call that mints an
// installation token by owner on the org's behalf.
func (q *Queries) ForgeOwnerBoundToOrg(ctx context.Context, orgID uuid.UUID, owner string) (bool, error) {
	org, err := q.GetOrganizationByID(ctx, orgID)
	if err != nil || org == nil {
		return false, err
	}
	return org.OwnsForgeOwner(owner), nil
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
		Limit:  int32(limit),  // #nosec G115 -- pagination values are bounded by API parsing.
		Offset: int32(offset), // #nosec G115 -- pagination values are bounded by API parsing.
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
		Limit:  int32(limit),  // #nosec G115 -- pagination values are bounded by API parsing.
		Offset: int32(offset), // #nosec G115 -- pagination values are bounded by API parsing.
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
