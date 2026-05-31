package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/lehibou/internal/store/dbgen"
)

type TeamMember struct {
	TeamID    uuid.UUID `json:"team_id"`
	UserID    uuid.UUID `json:"user_id"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
	User      *User     `json:"user,omitempty"`
}

func (q *Queries) AddTeamMember(ctx context.Context, teamID, userID uuid.UUID, role string) error {
	return q.db.AddTeamMember(ctx, dbgen.AddTeamMemberParams{
		TeamID: teamID,
		UserID: userID,
		Role:   role,
	})
}

func (q *Queries) RemoveTeamMember(ctx context.Context, teamID, userID uuid.UUID) error {
	return q.db.RemoveTeamMember(ctx, dbgen.RemoveTeamMemberParams{
		TeamID: teamID,
		UserID: userID,
	})
}

func (q *Queries) ListTeamMembers(ctx context.Context, teamID uuid.UUID, limit, offset int) ([]TeamMember, int, error) {
	rows, err := q.db.ListTeamMembers(ctx, dbgen.ListTeamMembersParams{
		TeamID: teamID,
		Limit:  int32(limit),  //nolint:gosec // G115: pagination values are bounded by API parsing.
		Offset: int32(offset), //nolint:gosec // G115: pagination values are bounded by API parsing.
	})
	if err != nil {
		return nil, 0, err
	}

	members := make([]TeamMember, len(rows))
	for i, row := range rows {
		members[i] = TeamMember{
			TeamID:    row.TeamID,
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

	total, err := q.db.CountTeamMembers(ctx, teamID)
	if err != nil {
		return nil, 0, err
	}

	return members, int(total), nil
}

func (q *Queries) GetTeamMemberRole(ctx context.Context, teamID, userID uuid.UUID) (string, error) {
	role, err := q.db.GetTeamMemberRole(ctx, dbgen.GetTeamMemberRoleParams{
		TeamID: teamID,
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
