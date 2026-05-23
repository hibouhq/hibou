package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/hibouhq/lehibou/internal/store/dbgen"
)

type APIKey struct {
	ID         uuid.UUID       `json:"id"`
	UserID     uuid.UUID       `json:"user_id"`
	Name       string          `json:"name"`
	KeyHash    string          `json:"key_hash,omitempty"`
	Scopes     json.RawMessage `json:"scopes"`
	ExpiresAt  *time.Time      `json:"expires_at,omitempty"`
	LastUsedAt *time.Time      `json:"last_used_at,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
	User       *User           `json:"user,omitempty"`
}

func HashAPIKey(rawKey string) string {
	h := sha256.Sum256([]byte(rawKey))
	return hex.EncodeToString(h[:])
}

// CreateAPIKey expects preHashedKey to already be a SHA-256 hex-encoded API key hash.
func (q *Queries) CreateAPIKey(ctx context.Context, userID uuid.UUID, name, preHashedKey string, scopes json.RawMessage, expiresAt *time.Time) (*APIKey, error) {
	row, err := q.db.CreateAPIKey(ctx, dbgen.CreateAPIKeyParams{
		UserID:    userID,
		Name:      name,
		KeyHash:   preHashedKey,
		Scopes:    scopes,
		ExpiresAt: nullTimeFromPtr(expiresAt),
	})
	if err != nil {
		return nil, err
	}

	return apiKeyFromRow(row), nil
}

func (q *Queries) GetAPIKeyByHash(ctx context.Context, keyHash string) (*APIKey, error) {
	row, err := q.db.GetAPIKeyByHash(ctx, keyHash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return apiKeyWithUserFromRow(row), nil
}

func (q *Queries) ListAPIKeysByUser(ctx context.Context, userID uuid.UUID) ([]APIKey, error) {
	rows, err := q.db.ListAPIKeysByUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	keys := make([]APIKey, len(rows))
	for i, row := range rows {
		keys[i] = *apiKeyFromRow(row)
	}

	return keys, nil
}

func (q *Queries) DeleteAPIKey(ctx context.Context, id, userID uuid.UUID) error {
	return q.db.DeleteAPIKey(ctx, dbgen.DeleteAPIKeyParams{
		ID:     id,
		UserID: userID,
	})
}

func (q *Queries) UpdateAPIKeyLastUsed(ctx context.Context, id uuid.UUID) error {
	return q.db.UpdateAPIKeyLastUsed(ctx, id)
}

func apiKeyFromRow(row dbgen.ApiKey) *APIKey {
	return &APIKey{
		ID:         row.ID,
		UserID:     row.UserID,
		Name:       row.Name,
		KeyHash:    row.KeyHash,
		Scopes:     row.Scopes,
		ExpiresAt:  timePtrFromNull(row.ExpiresAt),
		LastUsedAt: timePtrFromNull(row.LastUsedAt),
		CreatedAt:  row.CreatedAt,
	}
}

func apiKeyWithUserFromRow(row dbgen.GetAPIKeyByHashRow) *APIKey {
	key := apiKeyFromRow(dbgen.ApiKey{
		ID:         row.ID,
		UserID:     row.UserID,
		Name:       row.Name,
		KeyHash:    row.KeyHash,
		Scopes:     row.Scopes,
		ExpiresAt:  row.ExpiresAt,
		LastUsedAt: row.LastUsedAt,
		CreatedAt:  row.CreatedAt,
	})
	key.User = &User{
		ID:          row.OwnerID,
		Email:       row.Email,
		DisplayName: row.DisplayName,
		AvatarURL:   stringPtrFromNull(row.AvatarUrl),
		Provider:    row.Provider,
		ProviderID:  row.ProviderID,
		CreatedAt:   row.UserCreatedAt,
		UpdatedAt:   row.UserUpdatedAt,
	}
	return key
}
