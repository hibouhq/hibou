package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/hibouhq/lehibou/internal/store/dbgen"
)

type OrgMember struct {
	OrgID     uuid.UUID `json:"org_id"`
	UserID    uuid.UUID `json:"user_id"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
	User      *User     `json:"user,omitempty"`
}

func (q *Queries) AddOrgMember(ctx context.Context, orgID, userID uuid.UUID, role string) error {
	return q.db.AddOrgMember(ctx, dbgen.AddOrgMemberParams{
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

func (q *Queries) ListOrgMembers(ctx context.Context, orgID uuid.UUID, limit, offset int) ([]OrgMember, int, error) {
	rows, err := q.db.ListOrgMembers(ctx, dbgen.ListOrgMembersParams{
		OrgID:  orgID,
		Limit:  int32(limit),
		Offset: int32(offset),
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
