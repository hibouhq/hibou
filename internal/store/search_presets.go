package store

import (
	"context"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// SearchPresetSurfaceFindings is the findings filter bar shared by the repo and
// org vulnerability lists.
const SearchPresetSurfaceFindings = "findings"

// ListUserSearchPresets returns one user's personal presets for a filter bar,
// ordered by name.
func (q *Queries) ListUserSearchPresets(ctx context.Context, userID uuid.UUID, surface string) ([]dbgen.SearchPreset, error) {
	return q.db.ListUserSearchPresets(ctx, dbgen.ListUserSearchPresetsParams{OwnerUserID: userID, Surface: surface})
}

// CountUserSearchPresets counts one user's personal presets for a filter bar.
func (q *Queries) CountUserSearchPresets(ctx context.Context, userID uuid.UUID, surface string) (int64, error) {
	return q.db.CountUserSearchPresets(ctx, dbgen.CountUserSearchPresetsParams{OwnerUserID: userID, Surface: surface})
}

// CreateUserSearchPreset stores a personal preset. A name already used by the
// same user on the same surface (case-insensitively) is a unique violation.
func (q *Queries) CreateUserSearchPreset(ctx context.Context, userID uuid.UUID, surface, name, query string) (dbgen.SearchPreset, error) {
	return q.db.CreateUserSearchPreset(ctx, dbgen.CreateUserSearchPresetParams{
		OwnerUserID: userID,
		Surface:     surface,
		Name:        name,
		Query:       query,
	})
}

// UpdateUserSearchPreset renames or rewrites a personal preset. Returns
// sql.ErrNoRows when the preset does not exist or belongs to someone else.
func (q *Queries) UpdateUserSearchPreset(ctx context.Context, id, userID uuid.UUID, name, query string) (dbgen.SearchPreset, error) {
	return q.db.UpdateUserSearchPreset(ctx, dbgen.UpdateUserSearchPresetParams{
		ID:          id,
		OwnerUserID: userID,
		Name:        name,
		Query:       query,
	})
}

// DeleteUserSearchPreset removes a personal preset and reports whether one was
// deleted; another user's preset is never touched.
func (q *Queries) DeleteUserSearchPreset(ctx context.Context, id, userID uuid.UUID) (bool, error) {
	rows, err := q.db.DeleteUserSearchPreset(ctx, dbgen.DeleteUserSearchPresetParams{ID: id, OwnerUserID: userID})
	return rows > 0, err
}
