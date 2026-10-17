package store

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type UserRepoAccess struct {
	UserID    uuid.UUID  `json:"user_id"`
	RepoID    uuid.UUID  `json:"repo_id"`
	Role      string     `json:"role"`
	Source    string     `json:"source"`
	SyncedAt  *time.Time `json:"synced_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

func (q *Queries) UpsertForgeUserRepoAccess(ctx context.Context, userID, repoID uuid.UUID, role string) error {
	return q.db.UpsertForgeUserRepoAccess(ctx, dbgen.UpsertForgeUserRepoAccessParams{
		UserID: userID,
		RepoID: repoID,
		Role:   role,
	})
}

func (q *Queries) PruneForgeUserRepoAccess(ctx context.Context, userID uuid.UUID, keepRepoIDs []uuid.UUID) error {
	if keepRepoIDs == nil {
		keepRepoIDs = []uuid.UUID{}
	}

	return q.db.PruneForgeUserRepoAccess(ctx, dbgen.PruneForgeUserRepoAccessParams{
		UserID:  userID,
		Column2: keepRepoIDs,
	})
}

func (q *Queries) ListUserRepoAccess(ctx context.Context, userID uuid.UUID) ([]UserRepoAccess, error) {
	rows, err := q.db.ListUserRepoAccess(ctx, userID)
	if err != nil {
		return nil, err
	}

	accessRows := make([]UserRepoAccess, len(rows))
	for i, row := range rows {
		accessRows[i] = userRepoAccessFromRow(row)
	}

	return accessRows, nil
}

func userRepoAccessFromRow(row dbgen.UserRepoAccess) UserRepoAccess {
	return UserRepoAccess{
		UserID:    row.UserID,
		RepoID:    row.RepoID,
		Role:      row.Role,
		Source:    row.Source,
		SyncedAt:  timePtrFromNull(row.SyncedAt),
		CreatedAt: row.CreatedAt,
		UpdatedAt: row.UpdatedAt,
	}
}

// IsRepoScopedOrgMember reports whether a user reaches an org only through
// per-repository forge access (an outside collaborator, or a member without
// the org's base read), so their visibility is the rows of user_repo_access
// rather than the whole organization.
func (q *Queries) IsRepoScopedOrgMember(ctx context.Context, orgID, userID uuid.UUID) (bool, error) {
	return q.db.IsRepoScopedOrgMember(ctx, dbgen.IsRepoScopedOrgMemberParams{OrgID: orgID, UserID: userID})
}

// ListUserRepoAccessInOrg maps each repository of an org the user was granted
// on the forge to the role the grant carries.
func (q *Queries) ListUserRepoAccessInOrg(ctx context.Context, orgID, userID uuid.UUID) (map[uuid.UUID]string, error) {
	rows, err := q.db.ListUserRepoAccessInOrg(ctx, dbgen.ListUserRepoAccessInOrgParams{UserID: userID, OrgID: orgID})
	if err != nil {
		return nil, err
	}
	out := make(map[uuid.UUID]string, len(rows))
	for _, row := range rows {
		out[row.RepoID] = row.Role
	}
	return out, nil
}

// ListRepoAudienceUserIDs lists the org members who may see a repository, for
// addressing live events to them rather than to every connected browser.
func (q *Queries) ListRepoAudienceUserIDs(ctx context.Context, repoID uuid.UUID) ([]uuid.UUID, error) {
	return q.db.ListRepoAudienceUserIDs(ctx, repoID)
}

// ForgeRepoGrant is a forge-synced grant with the repository's slug, for
// asking the forge again about it.
type ForgeRepoGrant struct {
	RepoID uuid.UUID
	Slug   string
	Role   string
}

// ListForgeRepoGrantsInOrg lists a user's forge-synced repository grants in
// an org, with slugs. Operator grants (source local) are not listed: the
// forge does not own them.
func (q *Queries) ListForgeRepoGrantsInOrg(ctx context.Context, orgID, userID uuid.UUID) ([]ForgeRepoGrant, error) {
	rows, err := q.sqlDB.QueryContext(ctx, `
		SELECT ura.repo_id, r.slug, ura.role
		FROM user_repo_access ura
		JOIN repositories r ON r.id = ura.repo_id
		WHERE ura.user_id = $1 AND r.org_id = $2 AND ura.source = 'forge'
		ORDER BY r.slug`, userID, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ForgeRepoGrant
	for rows.Next() {
		var grant ForgeRepoGrant
		if err := rows.Scan(&grant.RepoID, &grant.Slug, &grant.Role); err != nil {
			return nil, err
		}
		out = append(out, grant)
	}
	return out, rows.Err()
}

// DeleteForgeUserRepoAccess removes one forge-synced grant.
func (q *Queries) DeleteForgeUserRepoAccess(ctx context.Context, userID, repoID uuid.UUID) error {
	_, err := q.execer().ExecContext(ctx,
		`DELETE FROM user_repo_access WHERE user_id = $1 AND repo_id = $2 AND source = 'forge'`, userID, repoID)
	return err
}
