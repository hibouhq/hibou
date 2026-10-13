package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// Device authorization lifecycle (ADR-043): pending → approved | denied, and
// approved → consumed once the CLI collects its token.
const (
	DeviceAuthPending  = "pending"
	DeviceAuthApproved = "approved"
	DeviceAuthDenied   = "denied"
	DeviceAuthConsumed = "consumed"
)

// DeviceAuthorization is one pending or decided device login.
type DeviceAuthorization struct {
	ID                 uuid.UUID
	ClientID           string
	ClientName         string
	RequestedPreset    string
	RequesterIP        string
	RequesterUserAgent string
	Status             string
	PollInterval       time.Duration
	ApprovedBy         *uuid.UUID
	ApprovedPreset     string
	TokenExpiresAt     *time.Time
	APIKeyID           *uuid.UUID
	CreatedAt          time.Time
	ExpiresAt          time.Time
	DecidedAt          *time.Time
}

// NewDeviceAuthorization is what the code endpoint stores.
type NewDeviceAuthorization struct {
	DeviceCodeHash     string
	UserCodeHash       string
	ClientID           string
	ClientName         string
	RequestedPreset    string
	RequesterIP        string
	RequesterUserAgent string
	PollInterval       time.Duration
	ExpiresAt          time.Time
}

// DevicePoll is the state a poll observed, after recording it.
type DevicePoll struct {
	DeviceAuthorization
	// SlowDown is true when this poll came sooner than the interval allowed;
	// the stored interval has already been raised.
	SlowDown bool
}

func (q *Queries) CountPendingDeviceAuthorizationsByIP(ctx context.Context, ip string) (int, error) {
	n, err := q.db.CountPendingDeviceAuthorizationsByIP(ctx, ip)
	return int(n), err
}

func (q *Queries) CreateDeviceAuthorization(ctx context.Context, in NewDeviceAuthorization) (*DeviceAuthorization, error) {
	row, err := q.db.CreateDeviceAuthorization(ctx, dbgen.CreateDeviceAuthorizationParams{
		DeviceCodeHash:      in.DeviceCodeHash,
		UserCodeHash:        in.UserCodeHash,
		ClientID:            in.ClientID,
		ClientName:          in.ClientName,
		RequestedPreset:     in.RequestedPreset,
		RequesterIp:         in.RequesterIP,
		RequesterUserAgent:  in.RequesterUserAgent,
		PollIntervalSeconds: int32(in.PollInterval / time.Second), // #nosec G115 -- a few seconds, set by the server
		ExpiresAt:           in.ExpiresAt,
	})
	if err != nil {
		return nil, err
	}
	return deviceAuthorizationFromRow(row), nil
}

// GetLiveDeviceAuthorizationByUserCode returns the pending, unexpired request
// for a hashed user code, or nil.
func (q *Queries) GetLiveDeviceAuthorizationByUserCode(ctx context.Context, userCodeHash string) (*DeviceAuthorization, error) {
	row, err := q.db.GetLiveDeviceAuthorizationByUserCode(ctx, userCodeHash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return deviceAuthorizationFromRow(row), nil
}

// PollDeviceAuthorization records a poll for a hashed device code. It returns
// nil when no such code exists (or it was already cleaned up).
func (q *Queries) PollDeviceAuthorization(ctx context.Context, deviceCodeHash string) (*DevicePoll, error) {
	row, err := q.db.PollDeviceAuthorization(ctx, deviceCodeHash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	auth := deviceAuthorizationFromRow(dbgen.DeviceAuthorization{
		ID:                  row.ID,
		ClientID:            row.ClientID,
		ClientName:          row.ClientName,
		RequestedPreset:     row.RequestedPreset,
		RequesterIp:         row.RequesterIp,
		RequesterUserAgent:  row.RequesterUserAgent,
		Status:              row.Status,
		PollIntervalSeconds: row.PollIntervalSeconds,
		ApprovedBy:          row.ApprovedBy,
		ApprovedPreset:      row.ApprovedPreset,
		TokenExpiresAt:      row.TokenExpiresAt,
		ApiKeyID:            row.ApiKeyID,
		CreatedAt:           row.CreatedAt,
		ExpiresAt:           row.ExpiresAt,
		DecidedAt:           row.DecidedAt,
	})
	return &DevicePoll{DeviceAuthorization: *auth, SlowDown: row.PollIntervalSeconds > row.PrevInterval}, nil
}

// ApproveDeviceAuthorization approves a still-pending request. It returns nil
// when the request is no longer pending (decided, expired) — a lost race.
func (q *Queries) ApproveDeviceAuthorization(ctx context.Context, id, userID uuid.UUID, preset string, tokenExpiresAt time.Time) (*DeviceAuthorization, error) {
	row, err := q.db.ApproveDeviceAuthorization(ctx, dbgen.ApproveDeviceAuthorizationParams{
		ID:             id,
		ApprovedBy:     uuid.NullUUID{UUID: userID, Valid: true},
		ApprovedPreset: sql.NullString{String: preset, Valid: true},
		TokenExpiresAt: sql.NullTime{Time: tokenExpiresAt, Valid: true},
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return deviceAuthorizationFromRow(row), nil
}

// DenyDeviceAuthorization denies a still-pending request; nil when it is no
// longer pending.
func (q *Queries) DenyDeviceAuthorization(ctx context.Context, id, userID uuid.UUID) (*DeviceAuthorization, error) {
	row, err := q.db.DenyDeviceAuthorization(ctx, dbgen.DenyDeviceAuthorizationParams{
		ID:         id,
		ApprovedBy: uuid.NullUUID{UUID: userID, Valid: true},
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return deviceAuthorizationFromRow(row), nil
}

// ConsumeDeviceAuthorization moves an approved request to consumed; nil when
// it is not (or no longer) approved. Run it in the transaction that mints the
// key.
func (q *Queries) ConsumeDeviceAuthorization(ctx context.Context, id uuid.UUID) (*DeviceAuthorization, error) {
	row, err := q.db.ConsumeDeviceAuthorization(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return deviceAuthorizationFromRow(row), nil
}

func (q *Queries) SetDeviceAuthorizationAPIKey(ctx context.Context, id, apiKeyID uuid.UUID) error {
	return q.db.SetDeviceAuthorizationAPIKey(ctx, dbgen.SetDeviceAuthorizationAPIKeyParams{
		ID:       id,
		ApiKeyID: uuid.NullUUID{UUID: apiKeyID, Valid: true},
	})
}

// DeleteExpiredDeviceAuthorizations removes rows an hour past expiry.
func (q *Queries) DeleteExpiredDeviceAuthorizations(ctx context.Context) (int64, error) {
	return q.db.DeleteExpiredDeviceAuthorizations(ctx)
}

// DeleteAPIKeyByID deletes a user-owned key by id alone: a token revoking
// itself. Returns nil when there was no such user-owned key.
func (q *Queries) DeleteAPIKeyByID(ctx context.Context, id uuid.UUID) (*APIKey, error) {
	row, err := q.db.DeleteAPIKeyByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return apiKeyFromRow(row), nil
}

func deviceAuthorizationFromRow(row dbgen.DeviceAuthorization) *DeviceAuthorization {
	auth := &DeviceAuthorization{
		ID:                 row.ID,
		ClientID:           row.ClientID,
		ClientName:         row.ClientName,
		RequestedPreset:    row.RequestedPreset,
		RequesterIP:        row.RequesterIp,
		RequesterUserAgent: row.RequesterUserAgent,
		Status:             row.Status,
		PollInterval:       time.Duration(row.PollIntervalSeconds) * time.Second,
		ApprovedBy:         uuidPtrFromNull(row.ApprovedBy),
		TokenExpiresAt:     timePtrFromNull(row.TokenExpiresAt),
		APIKeyID:           uuidPtrFromNull(row.ApiKeyID),
		CreatedAt:          row.CreatedAt,
		ExpiresAt:          row.ExpiresAt,
		DecidedAt:          timePtrFromNull(row.DecidedAt),
	}
	if row.ApprovedPreset.Valid {
		auth.ApprovedPreset = row.ApprovedPreset.String
	}
	return auth
}
