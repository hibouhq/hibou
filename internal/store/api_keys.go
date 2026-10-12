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

// Approval lifecycle for org-owned tokens (ADR-022 amendment): a token
// requested by a non-admin member stays pending — and fails authentication —
// until an org admin approves it. User-owned keys are always approved.
const (
	APIKeyApprovalPending  = "pending"
	APIKeyApprovalApproved = "approved"
	APIKeyApprovalRejected = "rejected"
)

type APIKey struct {
	ID uuid.UUID `json:"id"`
	// UserID is the creating user — provenance, not identity (ADR-022). Nil
	// when the creator was deleted; org-owned keys keep working then.
	UserID      *uuid.UUID      `json:"user_id,omitempty"`
	Name        string          `json:"name"`
	KeyHash     string          `json:"key_hash,omitempty"`
	Scopes      json.RawMessage `json:"scopes"`
	ExpiresAt   *time.Time      `json:"expires_at,omitempty"`
	OwnerType   string          `json:"owner_type"`
	OwnerID     *uuid.UUID      `json:"owner_id,omitempty"`
	Description string          `json:"description"`
	LastUsedAt  *time.Time      `json:"last_used_at,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	// ApprovalStatus gates authentication for member-requested org tokens
	// (ADR-022 amendment): only "approved" tokens authenticate.
	ApprovalStatus string     `json:"approval_status"`
	ApprovedBy     *uuid.UUID `json:"approved_by,omitempty"`
	ApprovedAt     *time.Time `json:"approved_at,omitempty"`
	// CreatedByDisplay is the creator's name, populated by the org list only —
	// the review UI must show who requested a pending token.
	CreatedByDisplay string `json:"created_by_display,omitempty"`
	User             *User  `json:"user,omitempty"`
}

// IsApproved reports whether the token may authenticate. Blank tolerates rows
// read through paths that predate the column — never lock out a legacy key.
func (k *APIKey) IsApproved() bool {
	return k.ApprovalStatus == "" || k.ApprovalStatus == APIKeyApprovalApproved
}

func HashAPIKey(rawKey string) string {
	h := sha256.Sum256([]byte(rawKey))
	return hex.EncodeToString(h[:])
}

// CountAPIKeysCreatedByUser counts every key the user minted (personal and
// org-requested), for the per-user key cap.
func (q *Queries) CountAPIKeysCreatedByUser(ctx context.Context, userID uuid.UUID) (int64, error) {
	return q.db.CountAPIKeysCreatedByUser(ctx, uuid.NullUUID{UUID: userID, Valid: true})
}

// CreateAPIKey expects preHashedKey to already be a SHA-256 hex-encoded API key hash.
func (q *Queries) CreateAPIKey(ctx context.Context, userID uuid.UUID, name, preHashedKey string, scopes json.RawMessage, expiresAt *time.Time, ownerType string, ownerID *uuid.UUID, description string) (*APIKey, error) {
	return q.CreateAPIKeyWithApproval(ctx, userID, name, preHashedKey, scopes, expiresAt, ownerType, ownerID, description, APIKeyApprovalApproved)
}

// CreateAPIKeyWithApproval mints a key with an explicit approval status —
// "pending" for member-requested org tokens awaiting admin review.
func (q *Queries) CreateAPIKeyWithApproval(ctx context.Context, userID uuid.UUID, name, preHashedKey string, scopes json.RawMessage, expiresAt *time.Time, ownerType string, ownerID *uuid.UUID, description, approvalStatus string) (*APIKey, error) {
	row, err := q.db.CreateAPIKey(ctx, dbgen.CreateAPIKeyParams{
		UserID:         uuid.NullUUID{UUID: userID, Valid: true},
		Name:           name,
		KeyHash:        preHashedKey,
		Scopes:         scopes,
		ExpiresAt:      nullTimeFromPtr(expiresAt),
		OwnerType:      ownerType,
		OwnerID:        nullUUIDFromPtr(ownerID),
		Description:    description,
		ApprovalStatus: dbgen.ApiKeyApprovalStatus(approvalStatus),
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

// IsOrgOwned reports whether this key is an org service principal (ADR-022):
// it authorizes as the org, needs no living creator, and is managed by org
// admins rather than a user.
func (k *APIKey) IsOrgOwned() bool {
	return k.OwnerType == "org" && k.OwnerID != nil
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
	rows, err := q.db.ListAPIKeysByUser(ctx, uuid.NullUUID{UUID: userID, Valid: true})
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
		key := apiKeyFromRow(dbgen.ApiKey{
			ID:             row.ID,
			UserID:         row.UserID,
			Name:           row.Name,
			KeyHash:        row.KeyHash,
			Scopes:         row.Scopes,
			ExpiresAt:      row.ExpiresAt,
			LastUsedAt:     row.LastUsedAt,
			CreatedAt:      row.CreatedAt,
			OwnerType:      row.OwnerType,
			OwnerID:        row.OwnerID,
			Description:    row.Description,
			ApprovalStatus: row.ApprovalStatus,
			ApprovedBy:     row.ApprovedBy,
			ApprovedAt:     row.ApprovedAt,
		})
		key.CreatedByDisplay = row.CreatorDisplay
		keys[i] = *key
	}

	return keys, nil
}

func (q *Queries) DeleteAPIKey(ctx context.Context, id, userID uuid.UUID) error {
	return q.db.DeleteAPIKey(ctx, dbgen.DeleteAPIKeyParams{
		ID:     id,
		UserID: uuid.NullUUID{UUID: userID, Valid: true},
	})
}

func (q *Queries) UpdateAPIKeyLastUsed(ctx context.Context, id uuid.UUID) error {
	return q.db.UpdateAPIKeyLastUsed(ctx, id)
}

// GetAPIKeyByID scopes the lookup to the owning user so one user can never
// address another's token by id.
func (q *Queries) GetAPIKeyByID(ctx context.Context, id, userID uuid.UUID) (*APIKey, error) {
	row, err := q.db.GetAPIKeyByID(ctx, dbgen.GetAPIKeyByIDParams{ID: id, UserID: uuid.NullUUID{UUID: userID, Valid: true}})
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
		UserID:      uuid.NullUUID{UUID: userID, Valid: true},
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

func (q *Queries) UpdateAPIKeyMetaByOrg(ctx context.Context, id, orgID uuid.UUID, name, description string, scopes json.RawMessage, expiresAt *time.Time, approvalStatus string) (*APIKey, error) {
	row, err := q.db.UpdateAPIKeyMetaByOrg(ctx, dbgen.UpdateAPIKeyMetaByOrgParams{
		ID:             id,
		OwnerID:        nullUUIDFromPtr(&orgID),
		Name:           name,
		Description:    description,
		Scopes:         scopes,
		ExpiresAt:      nullTimeFromPtr(expiresAt),
		ApprovalStatus: dbgen.ApiKeyApprovalStatus(approvalStatus),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return apiKeyFromRow(row), nil
}

// SetAPIKeyApprovalByOrg records an org admin's approve/reject decision.
func (q *Queries) SetAPIKeyApprovalByOrg(ctx context.Context, id, orgID uuid.UUID, status string, reviewerID uuid.UUID) (*APIKey, error) {
	row, err := q.db.SetAPIKeyApprovalByOrg(ctx, dbgen.SetAPIKeyApprovalByOrgParams{
		ID:             id,
		OwnerID:        nullUUIDFromPtr(&orgID),
		ApprovalStatus: dbgen.ApiKeyApprovalStatus(status),
		ApprovedBy:     uuid.NullUUID{UUID: reviewerID, Valid: true},
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
		UserID:  uuid.NullUUID{UUID: userID, Valid: true},
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
		ID:             row.ID,
		UserID:         uuidPtrFromNull(row.UserID),
		Name:           row.Name,
		KeyHash:        row.KeyHash,
		Scopes:         row.Scopes,
		ExpiresAt:      timePtrFromNull(row.ExpiresAt),
		OwnerType:      row.OwnerType,
		OwnerID:        uuidPtrFromNull(row.OwnerID),
		Description:    row.Description,
		LastUsedAt:     timePtrFromNull(row.LastUsedAt),
		CreatedAt:      row.CreatedAt,
		ApprovalStatus: string(row.ApprovalStatus),
		ApprovedBy:     uuidPtrFromNull(row.ApprovedBy),
		ApprovedAt:     timePtrFromNull(row.ApprovedAt),
	}
}

func apiKeyFromListRow(row dbgen.ListAPIKeysByUserRow) *APIKey {
	return &APIKey{
		ID:             row.ID,
		UserID:         uuidPtrFromNull(row.UserID),
		Name:           row.Name,
		KeyHash:        row.KeyHash,
		Scopes:         row.Scopes,
		ExpiresAt:      timePtrFromNull(row.ExpiresAt),
		OwnerType:      row.OwnerType,
		OwnerID:        uuidPtrFromNull(row.OwnerID),
		Description:    row.Description,
		LastUsedAt:     timePtrFromNull(row.LastUsedAt),
		CreatedAt:      row.CreatedAt,
		ApprovalStatus: string(row.ApprovalStatus),
		ApprovedBy:     uuidPtrFromNull(row.ApprovedBy),
		ApprovedAt:     timePtrFromNull(row.ApprovedAt),
	}
}

func apiKeyWithUserFromRow(row dbgen.GetAPIKeyByHashRow) *APIKey {
	key := apiKeyFromRow(dbgen.ApiKey{
		ID:             row.ID,
		UserID:         row.UserID,
		Name:           row.Name,
		KeyHash:        row.KeyHash,
		Scopes:         row.Scopes,
		ExpiresAt:      row.ExpiresAt,
		OwnerType:      row.OwnerType,
		OwnerID:        row.OwnerID,
		Description:    row.Description,
		LastUsedAt:     row.LastUsedAt,
		CreatedAt:      row.CreatedAt,
		ApprovalStatus: row.ApprovalStatus,
		ApprovedBy:     row.ApprovedBy,
		ApprovedAt:     row.ApprovedAt,
	})
	// LEFT JOIN: no user row when the creator was deleted (ADR-022). The auth
	// layer decides what that means per owner type.
	if row.ActorUserID.Valid {
		key.User = &User{
			ID:          row.ActorUserID.UUID,
			Email:       row.Email.String,
			DisplayName: row.DisplayName.String,
			AvatarURL:   stringPtrFromNull(row.AvatarUrl),
			Provider:    row.Provider.String,
			ProviderID:  row.ProviderID.String,
			CreatedAt:   row.UserCreatedAt.Time,
			UpdatedAt:   row.UserUpdatedAt.Time,
		}
	}
	return key
}
