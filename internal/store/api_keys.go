package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type APIKey struct {
	ID          uuid.UUID       `json:"id"`
	UserID      uuid.UUID       `json:"user_id"`
	Name        string          `json:"name"`
	KeyHash     string          `json:"key_hash,omitempty"`
	Scopes      json.RawMessage `json:"scopes"`
	ExpiresAt   *time.Time      `json:"expires_at,omitempty"`
	OwnerType   string          `json:"owner_type"`
	OwnerID     *uuid.UUID      `json:"owner_id,omitempty"`
	Description string          `json:"description"`
	LastUsedAt  *time.Time      `json:"last_used_at,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	User        *User           `json:"user,omitempty"`
}

func HashAPIKey(rawKey string) string {
	h := sha256.Sum256([]byte(rawKey))
	return hex.EncodeToString(h[:])
}

// CreateAPIKey expects preHashedKey to already be a SHA-256 hex-encoded API key hash.
func (q *Queries) CreateAPIKey(ctx context.Context, userID uuid.UUID, name, preHashedKey string, scopes json.RawMessage, expiresAt *time.Time, ownerType string, ownerID *uuid.UUID, description string) (*APIKey, error) {
	row, err := q.db.CreateAPIKey(ctx, dbgen.CreateAPIKeyParams{
		UserID:      userID,
		Name:        name,
		KeyHash:     preHashedKey,
		Scopes:      scopes,
		ExpiresAt:   nullTimeFromPtr(expiresAt),
		OwnerType:   ownerType,
		OwnerID:     nullUUIDFromPtr(ownerID),
		Description: description,
	})
	if err != nil {
		return nil, err
	}

	return apiKeyFromRow(row), nil
}

func (k *APIKey) Scope() (apitoken.Scope, error) {
	if !k.HasScope() {
		return apitoken.Scope{}, nil
	}

	return apitoken.Parse(k.Scopes)
}

// HasScope reports whether this key carries a non-legacy scope document.
func (k *APIKey) HasScope() bool {
	trimmed := bytes.TrimSpace(k.Scopes)
	return len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null"))
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
		keys[i] = *apiKeyFromListRow(row)
	}

	return keys, nil
}

func (q *Queries) ListAPIKeysByOrg(ctx context.Context, orgID uuid.UUID) ([]APIKey, error) {
	rows, err := q.db.ListAPIKeysByOrg(ctx, nullUUIDFromPtr(&orgID))
	if err != nil {
		return nil, err
	}

	keys := make([]APIKey, len(rows))
	for i, row := range rows {
		keys[i] = *apiKeyFromRow(dbgen.ApiKey{
			ID:          row.ID,
			UserID:      row.UserID,
			Name:        row.Name,
			KeyHash:     row.KeyHash,
			Scopes:      row.Scopes,
			ExpiresAt:   row.ExpiresAt,
			LastUsedAt:  row.LastUsedAt,
			CreatedAt:   row.CreatedAt,
			OwnerType:   row.OwnerType,
			OwnerID:     row.OwnerID,
			Description: row.Description,
		})
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

// GetAPIKeyByID scopes the lookup to the owning user so one user can never
// address another's token by id.
func (q *Queries) GetAPIKeyByID(ctx context.Context, id, userID uuid.UUID) (*APIKey, error) {
	row, err := q.db.GetAPIKeyByID(ctx, dbgen.GetAPIKeyByIDParams{ID: id, UserID: userID})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return apiKeyFromRow(row), nil
}

func (q *Queries) UpdateAPIKeyMeta(ctx context.Context, id, userID uuid.UUID, name, description string, scopes json.RawMessage, expiresAt *time.Time) (*APIKey, error) {
	row, err := q.db.UpdateAPIKeyMeta(ctx, dbgen.UpdateAPIKeyMetaParams{
		ID:          id,
		UserID:      userID,
		Name:        name,
		Description: description,
		Scopes:      scopes,
		ExpiresAt:   nullTimeFromPtr(expiresAt),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return apiKeyFromRow(row), nil
}

// Org-owned variants scope the lookup to the owning org, not the creating
// user: any current org admin can manage the token even after its creator
// leaves (ADR-020).

func (q *Queries) GetAPIKeyByOrg(ctx context.Context, id, orgID uuid.UUID) (*APIKey, error) {
	row, err := q.db.GetAPIKeyByOrg(ctx, dbgen.GetAPIKeyByOrgParams{ID: id, OwnerID: nullUUIDFromPtr(&orgID)})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return apiKeyFromRow(row), nil
}

func (q *Queries) UpdateAPIKeyMetaByOrg(ctx context.Context, id, orgID uuid.UUID, name, description string, scopes json.RawMessage, expiresAt *time.Time) (*APIKey, error) {
	row, err := q.db.UpdateAPIKeyMetaByOrg(ctx, dbgen.UpdateAPIKeyMetaByOrgParams{
		ID:          id,
		OwnerID:     nullUUIDFromPtr(&orgID),
		Name:        name,
		Description: description,
		Scopes:      scopes,
		ExpiresAt:   nullTimeFromPtr(expiresAt),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return apiKeyFromRow(row), nil
}

func (q *Queries) RotateAPIKeyByOrg(ctx context.Context, id, orgID uuid.UUID, preHashedKey string) (*APIKey, error) {
	row, err := q.db.RotateAPIKeyByOrg(ctx, dbgen.RotateAPIKeyByOrgParams{
		ID:      id,
		OwnerID: nullUUIDFromPtr(&orgID),
		KeyHash: preHashedKey,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return apiKeyFromRow(row), nil
}

func (q *Queries) DeleteAPIKeyByOrg(ctx context.Context, id, orgID uuid.UUID) (bool, error) {
	affected, err := q.db.DeleteAPIKeyByOrg(ctx, dbgen.DeleteAPIKeyByOrgParams{ID: id, OwnerID: nullUUIDFromPtr(&orgID)})
	return affected > 0, err
}

// UnscopedKeyExposure is one legacy full-access token that can act on an org
// because its owner is a member. Visibility for admins during the migration
// away from unscoped tokens — no key material, no management authority.
type UnscopedKeyExposure struct {
	ID            uuid.UUID  `json:"id"`
	Name          string     `json:"name"`
	MemberID      uuid.UUID  `json:"member_id"`
	MemberDisplay string     `json:"member_display"`
	MemberEmail   string     `json:"member_email"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	LastUsedAt    *time.Time `json:"last_used_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}

func (q *Queries) ListUnscopedAPIKeysByOrgMembers(ctx context.Context, orgID uuid.UUID) ([]UnscopedKeyExposure, error) {
	rows, err := q.db.ListUnscopedAPIKeysByOrgMembers(ctx, orgID)
	if err != nil {
		return nil, err
	}

	exposures := make([]UnscopedKeyExposure, len(rows))
	for i, row := range rows {
		exposures[i] = UnscopedKeyExposure{
			ID:            row.ID,
			Name:          row.Name,
			MemberID:      row.MemberID,
			MemberDisplay: row.MemberDisplay,
			MemberEmail:   row.MemberEmail,
			ExpiresAt:     timePtrFromNull(row.ExpiresAt),
			LastUsedAt:    timePtrFromNull(row.LastUsedAt),
			CreatedAt:     row.CreatedAt,
		}
	}

	return exposures, nil
}

// ListAPIKeysExpiringBefore returns live keys whose expiry falls within the
// warning window — already-expired keys are excluded, warning about a dead key
// helps nobody.
func (q *Queries) ListAPIKeysExpiringBefore(ctx context.Context, before time.Time) ([]APIKey, error) {
	rows, err := q.db.ListAPIKeysExpiringBefore(ctx, nullTimeFromPtr(&before))
	if err != nil {
		return nil, err
	}

	keys := make([]APIKey, len(rows))
	for i, row := range rows {
		keys[i] = *apiKeyFromRow(row)
	}

	return keys, nil
}

func (q *Queries) ListOrgAdminIDs(ctx context.Context, orgID uuid.UUID) ([]uuid.UUID, error) {
	return q.db.ListOrgAdminIDs(ctx, orgID)
}

// RotateAPIKey swaps the secret while keeping the token's identity, so scope,
// provenance already recorded against the id, and audit history all survive.
func (q *Queries) RotateAPIKey(ctx context.Context, id, userID uuid.UUID, preHashedKey string) (*APIKey, error) {
	row, err := q.db.RotateAPIKey(ctx, dbgen.RotateAPIKeyParams{
		ID:      id,
		UserID:  userID,
		KeyHash: preHashedKey,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return apiKeyFromRow(row), nil
}

func apiKeyFromRow(row dbgen.ApiKey) *APIKey {
	return &APIKey{
		ID:          row.ID,
		UserID:      row.UserID,
		Name:        row.Name,
		KeyHash:     row.KeyHash,
		Scopes:      row.Scopes,
		ExpiresAt:   timePtrFromNull(row.ExpiresAt),
		OwnerType:   row.OwnerType,
		OwnerID:     uuidPtrFromNull(row.OwnerID),
		Description: row.Description,
		LastUsedAt:  timePtrFromNull(row.LastUsedAt),
		CreatedAt:   row.CreatedAt,
	}
}

func apiKeyFromListRow(row dbgen.ListAPIKeysByUserRow) *APIKey {
	return &APIKey{
		ID:          row.ID,
		UserID:      row.UserID,
		Name:        row.Name,
		KeyHash:     row.KeyHash,
		Scopes:      row.Scopes,
		ExpiresAt:   timePtrFromNull(row.ExpiresAt),
		OwnerType:   row.OwnerType,
		OwnerID:     uuidPtrFromNull(row.OwnerID),
		Description: row.Description,
		LastUsedAt:  timePtrFromNull(row.LastUsedAt),
		CreatedAt:   row.CreatedAt,
	}
}

func apiKeyWithUserFromRow(row dbgen.GetAPIKeyByHashRow) *APIKey {
	key := apiKeyFromRow(dbgen.ApiKey{
		ID:          row.ID,
		UserID:      row.UserID,
		Name:        row.Name,
		KeyHash:     row.KeyHash,
		Scopes:      row.Scopes,
		ExpiresAt:   row.ExpiresAt,
		OwnerType:   row.OwnerType,
		OwnerID:     row.OwnerID,
		Description: row.Description,
		LastUsedAt:  row.LastUsedAt,
		CreatedAt:   row.CreatedAt,
	})
	key.User = &User{
		ID:          row.ActorUserID,
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
