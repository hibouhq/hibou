package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type OrgMember struct {
	OrgID     uuid.UUID `json:"org_id"`
	UserID    uuid.UUID `json:"user_id"`
	Role      string    `json:"role"`
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

func (q *Queries) UpsertForgeOrgMember(ctx context.Context, orgID, userID uuid.UUID, role string) error {
	return q.db.UpsertForgeOrgMember(ctx, dbgen.UpsertForgeOrgMemberParams{
		OrgID:  orgID,
		UserID: userID,
		Role:   role,
	})
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
