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
	}
}
