package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type User struct {
	ID          uuid.UUID `json:"id"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name"`
	AvatarURL   *string   `json:"avatar_url,omitempty"`
	Provider    string    `json:"provider"`
	ProviderID  string    `json:"provider_id"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	// SessionEpoch is signed into every session cookie; bumping it revokes
	// all sessions issued before. Never serialized.
	SessionEpoch int64 `json:"-"`
	// ForgeLogin is the forge login seen at the last sign-in. Logins are
	// renamable, so it is a name to ask the forge about, never identity.
	ForgeLogin string `json:"-"`
	// SignInAllowedAt is when the sign-in allowlist last admitted the user
	// through org membership (nil: never, or since revoked).
	SignInAllowedAt *time.Time `json:"-"`
}

func (q *Queries) CreateUser(ctx context.Context, email, displayName, provider, providerID string) (*User, error) {
	row, err := q.db.CreateUser(ctx, dbgen.CreateUserParams{
		Email:       email,
		DisplayName: displayName,
		Provider:    provider,
		ProviderID:  providerID,
	})
	if err != nil {
		return nil, err
	}

	return userFromRow(row), nil
}

func (q *Queries) UpsertUser(ctx context.Context, email, displayName string, avatarURL *string, provider, providerID string) (*User, error) {
	row, err := q.db.UpsertUser(ctx, dbgen.UpsertUserParams{
		Email:       email,
		DisplayName: displayName,
		AvatarUrl:   nullStringFromPtr(avatarURL),
		Provider:    provider,
		ProviderID:  providerID,
	})
	if err != nil {
		return nil, err
	}

	return userFromRow(row), nil
}

func (q *Queries) GetUserByID(ctx context.Context, id uuid.UUID) (*User, error) {
	row, err := q.db.GetUserByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return userFromRow(row), nil
}

func (q *Queries) GetUserByProviderID(ctx context.Context, provider, providerID string) (*User, error) {
	row, err := q.db.GetUserByProviderID(ctx, dbgen.GetUserByProviderIDParams{
		Provider:   provider,
		ProviderID: providerID,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return userFromRow(row), nil
}

func (q *Queries) UpdateUser(ctx context.Context, id uuid.UUID, email, displayName string, avatarURL *string) (*User, error) {
	row, err := q.db.UpdateUser(ctx, dbgen.UpdateUserParams{
		ID:          id,
		Email:       email,
		DisplayName: displayName,
		AvatarUrl:   nullStringFromPtr(avatarURL),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return userFromRow(row), nil
}

func userFromRow(row dbgen.User) *User {
	return &User{
		ID:          row.ID,
		Email:       row.Email,
		DisplayName: row.DisplayName,
		AvatarURL:   stringPtrFromNull(row.AvatarUrl),
		Provider:    row.Provider,
		ProviderID:  row.ProviderID,
		CreatedAt:   row.CreatedAt,
		UpdatedAt:   row.UpdatedAt,

		SessionEpoch:    row.SessionEpoch,
		ForgeLogin:      row.ForgeLogin.String,
		SignInAllowedAt: timePtrFromNull(row.SigninAllowedAt),
	}
}

// SetUserForgeLogin records the forge login seen at sign-in.
func (q *Queries) SetUserForgeLogin(ctx context.Context, id uuid.UUID, login string) error {
	return q.db.SetUserForgeLogin(ctx, dbgen.SetUserForgeLoginParams{ID: id, ForgeLogin: nullString(login)})
}

// SetUserSignInAllowedAt records when the sign-in allowlist last admitted the
// user through org membership; nil clears it.
func (q *Queries) SetUserSignInAllowedAt(ctx context.Context, id uuid.UUID, at *time.Time) error {
	return q.db.SetUserSignInAllowedAt(ctx, dbgen.SetUserSignInAllowedAtParams{ID: id, AllowedAt: nullTimeFromPtr(at)})
}

// BumpUserSessionEpoch revokes every session issued to the user so far and
// returns the new epoch.
func (q *Queries) BumpUserSessionEpoch(ctx context.Context, id uuid.UUID) (int64, error) {
	return q.db.BumpUserSessionEpoch(ctx, id)
}

// CountOrgsCreatedByUser counts the orgs the user created (non-forge admin
// memberships), for the per-user org creation cap.
func (q *Queries) CountOrgsCreatedByUser(ctx context.Context, userID uuid.UUID) (int64, error) {
	return q.db.CountOrgsCreatedByUser(ctx, userID)
}
