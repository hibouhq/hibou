package store

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type OrgMember struct {
	OrgID  uuid.UUID `json:"org_id"`
	UserID uuid.UUID `json:"user_id"`
	Role   string    `json:"role"`
	// Source is "forge" or "invite". A forge-sourced role is owned by the
	// permission sync and replaced on its next run, so a UI that offers to edit
	// one is offering a change that silently reverts.
	Source    string    `json:"source"`
	CreatedAt time.Time `json:"created_at"`
	User      *User     `json:"user,omitempty"`
}

type ForgeOrgMembership struct {
	OrgID  uuid.UUID `json:"org_id"`
	UserID uuid.UUID `json:"user_id"`
	Role   string    `json:"role"`
}

func (q *Queries) AddOrgMember(ctx context.Context, orgID, userID uuid.UUID, role string) error {
	return q.db.AddOrgMember(ctx, dbgen.AddOrgMemberParams{
		OrgID:  orgID,
		UserID: userID,
		Role:   role,
	})
}

func (q *Queries) UpsertOrgMemberRole(ctx context.Context, orgID, userID uuid.UUID, role string) error {
	return q.db.UpsertOrgMemberRole(ctx, dbgen.UpsertOrgMemberRoleParams{
		OrgID:  orgID,
		UserID: userID,
		Role:   role,
	})
}

// UpsertForgeOrgMember records an org-wide forge membership.
func (q *Queries) UpsertForgeOrgMember(ctx context.Context, orgID, userID uuid.UUID, role string) error {
	return q.UpsertForgeOrgMemberScoped(ctx, orgID, userID, role, false)
}

// UpsertForgeOrgMemberScoped records a forge membership and whether the forge
// grants it specific repositories only (repo_scoped): such a member sees
// exactly their user_repo_access rows.
func (q *Queries) UpsertForgeOrgMemberScoped(ctx context.Context, orgID, userID uuid.UUID, role string, repoScoped bool) error {
	return q.db.UpsertForgeOrgMember(ctx, dbgen.UpsertForgeOrgMemberParams{
		OrgID:      orgID,
		UserID:     userID,
		Role:       role,
		RepoScoped: repoScoped,
	})
}

// StaleForgeOrgMembership is a forge-synced membership due for re-validation.
type StaleForgeOrgMembership struct {
	OrgID             uuid.UUID
	UserID            uuid.UUID
	Role              string
	RepoScoped        bool
	SyncedAt          *time.Time
	OrgProvider       string
	OrgSlug           string
	ForgeAccountLogin string
	UserProvider      string
	ForgeLogin        string
}

// ListStaleForgeOrgMemberships lists forge memberships not confirmed since
// staleBefore, oldest first.
func (q *Queries) ListStaleForgeOrgMemberships(ctx context.Context, staleBefore time.Time, limit int) ([]StaleForgeOrgMembership, error) {
	rows, err := q.db.ListStaleForgeOrgMemberships(ctx, dbgen.ListStaleForgeOrgMembershipsParams{
		StaleBefore: sql.NullTime{Time: staleBefore, Valid: true},
		MaxRows:     int32(min(max(limit, 0), math.MaxInt32)), // #nosec G115 -- clamped to the int32 range
	})
	if err != nil {
		return nil, err
	}
	out := make([]StaleForgeOrgMembership, 0, len(rows))
	for _, row := range rows {
		out = append(out, StaleForgeOrgMembership{
			OrgID:             row.OrgID,
			UserID:            row.UserID,
			Role:              row.Role,
			RepoScoped:        row.RepoScoped,
			SyncedAt:          timePtrFromNull(row.SyncedAt),
			OrgProvider:       row.OrgProvider,
			OrgSlug:           row.OrgSlug,
			ForgeAccountLogin: row.ForgeAccountLogin.String,
			UserProvider:      row.UserProvider,
			ForgeLogin:        row.ForgeLogin.String,
		})
	}
	return out, nil
}

// ListForgeOrgMemberLogins maps org-wide forge members with a known login to
// that login, most recently confirmed first.
func (q *Queries) ListForgeOrgMemberLogins(ctx context.Context, orgID uuid.UUID, limit int) (map[uuid.UUID]string, error) {
	rows, err := q.db.ListForgeOrgMemberLogins(ctx, dbgen.ListForgeOrgMemberLoginsParams{
		OrgID:   orgID,
		MaxRows: int32(min(max(limit, 0), math.MaxInt32)), // #nosec G115 -- clamped to the int32 range
	})
	if err != nil {
		return nil, err
	}
	out := make(map[uuid.UUID]string, len(rows))
	for _, row := range rows {
		out[row.UserID] = row.ForgeLogin
	}
	return out, nil
}

// TouchForgeOrgMember marks a forge membership as confirmed now.
func (q *Queries) TouchForgeOrgMember(ctx context.Context, orgID, userID uuid.UUID) error {
	return q.db.TouchForgeOrgMember(ctx, dbgen.TouchForgeOrgMemberParams{OrgID: orgID, UserID: userID})
}

// RemoveForgeOrgAccess drops a forge membership and the forge repository
// grants in that org that came with it. Grants go first: a failure between
// the two leaves a member with fewer repositories, never a grant without one.
func (q *Queries) RemoveForgeOrgAccess(ctx context.Context, orgID, userID uuid.UUID) error {
	if err := q.db.DeleteForgeUserRepoAccessInOrg(ctx, dbgen.DeleteForgeUserRepoAccessInOrgParams{UserID: userID, OrgID: orgID}); err != nil {
		return err
	}
	return q.db.DeleteForgeOrgMember(ctx, dbgen.DeleteForgeOrgMemberParams{OrgID: orgID, UserID: userID})
}

func (q *Queries) RemoveOrgMember(ctx context.Context, orgID, userID uuid.UUID) error {
	return q.db.RemoveOrgMember(ctx, dbgen.RemoveOrgMemberParams{
		OrgID:  orgID,
		UserID: userID,
	})
}

func (q *Queries) PruneForgeOrgMembers(ctx context.Context, orgID uuid.UUID, keepUserIDs []uuid.UUID) error {
	if keepUserIDs == nil {
		keepUserIDs = []uuid.UUID{}
	}

	return q.db.PruneForgeOrgMembers(ctx, dbgen.PruneForgeOrgMembersParams{
		OrgID:   orgID,
		Column2: keepUserIDs,
	})
}

func (q *Queries) PruneForgeOrgMembersForUser(ctx context.Context, userID uuid.UUID, keepOrgIDs []uuid.UUID) error {
	if keepOrgIDs == nil {
		keepOrgIDs = []uuid.UUID{}
	}

	return q.db.PruneForgeOrgMembersForUser(ctx, dbgen.PruneForgeOrgMembersForUserParams{
		UserID:  userID,
		Column2: keepOrgIDs,
	})
}

func (q *Queries) ListOrgMembers(ctx context.Context, orgID uuid.UUID, limit, offset int) ([]OrgMember, int, error) {
	rows, err := q.db.ListOrgMembers(ctx, dbgen.ListOrgMembersParams{
		OrgID:  orgID,
		Limit:  int32(limit),  // #nosec G115 -- pagination values are bounded by API parsing.
		Offset: int32(offset), // #nosec G115 -- pagination values are bounded by API parsing.
	})
	if err != nil {
		return nil, 0, err
	}

	members := make([]OrgMember, len(rows))
	for i, row := range rows {
		members[i] = OrgMember{
			OrgID:     row.OrgID,
			UserID:    row.UserID,
			Role:      row.Role,
			Source:    row.Source,
			CreatedAt: row.CreatedAt,
			User: &User{
				ID:          row.UserID2,
				Email:       row.Email,
				DisplayName: row.DisplayName,
				AvatarURL:   stringPtrFromNull(row.AvatarUrl),
				Provider:    row.Provider,
				ProviderID:  row.ProviderID,
				CreatedAt:   row.UserCreatedAt,
				UpdatedAt:   row.UserUpdatedAt,
			},
		}
	}

	total, err := q.db.CountOrgMembers(ctx, orgID)
	if err != nil {
		return nil, 0, err
	}

	return members, int(total), nil
}

func (q *Queries) GetOrgMemberRole(ctx context.Context, orgID, userID uuid.UUID) (string, error) {
	role, err := q.db.GetOrgMemberRole(ctx, dbgen.GetOrgMemberRoleParams{
		OrgID:  orgID,
		UserID: userID,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}

	return role, nil
}

func (q *Queries) ListForgeOrgMemberIDs(ctx context.Context, orgID uuid.UUID) ([]uuid.UUID, error) {
	return q.db.ListForgeOrgMemberIDs(ctx, orgID)
}

func (q *Queries) ListForgeOrgMembershipsByUser(ctx context.Context, userID uuid.UUID) ([]ForgeOrgMembership, error) {
	rows, err := q.sqlDB.QueryContext(ctx, `
		SELECT org_id, user_id, role
		FROM org_members
		WHERE user_id = $1 AND source = 'forge'
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	memberships := make([]ForgeOrgMembership, 0)
	for rows.Next() {
		var membership ForgeOrgMembership
		if err := rows.Scan(&membership.OrgID, &membership.UserID, &membership.Role); err != nil {
			return nil, err
		}
		memberships = append(memberships, membership)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return memberships, nil
}

func (q *Queries) CountOrgAdmins(ctx context.Context, orgID uuid.UUID) (int, error) {
	total, err := q.db.CountOrgAdmins(ctx, orgID)
	if err != nil {
		return 0, err
	}

	return int(total), nil
}
