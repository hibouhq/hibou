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
