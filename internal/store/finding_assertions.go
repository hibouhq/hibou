package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// Assertion decisions (ADR-034 §4).
const (
	AssertionResolved  = "resolved"
	AssertionRetracted = "retracted"
)

// FindingAssertion is the lifecycle of a manual or agent-filed finding: when
// it was last confirmed, and whether a decision closed it.
type FindingAssertion struct {
	RepoID                uuid.UUID  `json:"repo_id"`
	Fingerprint           string     `json:"fingerprint"`
	LastConfirmedAt       *time.Time `json:"last_confirmed_at,omitempty"`
	LastConfirmedBy       *uuid.UUID `json:"last_confirmed_by,omitempty"`
	LastConfirmedAPIKeyID *uuid.UUID `json:"last_confirmed_api_key_id,omitempty"`
	ClosedKind            string     `json:"closed_kind,omitempty"`
	ClosedAt              *time.Time `json:"closed_at,omitempty"`
	ClosedBy              *uuid.UUID `json:"closed_by,omitempty"`
	ClosedAPIKeyID        *uuid.UUID `json:"closed_api_key_id,omitempty"`
	ClosedReason          string     `json:"closed_reason,omitempty"`
	UpdatedAt             time.Time  `json:"updated_at"`
}

func findingAssertionFromRow(row dbgen.FindingAssertion) FindingAssertion {
	return FindingAssertion{
		RepoID:                row.RepoID,
		Fingerprint:           row.Fingerprint,
		LastConfirmedAt:       timePtrFromNull(row.LastConfirmedAt),
		LastConfirmedBy:       uuidPtrFromNull(row.LastConfirmedBy),
		LastConfirmedAPIKeyID: uuidPtrFromNull(row.LastConfirmedApiKeyID),
		ClosedKind:            row.ClosedKind.String,
		ClosedAt:              timePtrFromNull(row.ClosedAt),
		ClosedBy:              uuidPtrFromNull(row.ClosedBy),
		ClosedAPIKeyID:        uuidPtrFromNull(row.ClosedApiKeyID),
		ClosedReason:          row.ClosedReason.String,
		UpdatedAt:             row.UpdatedAt,
	}
}

// ConfirmFindingAssertion records a re-assert and reopens a closed assertion.
func (q *Queries) ConfirmFindingAssertion(ctx context.Context, repoID uuid.UUID, fingerprint string, userID, apiKeyID *uuid.UUID) (FindingAssertion, error) {
	row, err := q.db.ConfirmFindingAssertion(ctx, dbgen.ConfirmFindingAssertionParams{
		RepoID:            repoID,
		Fingerprint:       fingerprint,
		ConfirmedBy:       nullUUIDFromPtr(userID),
		ConfirmedApiKeyID: nullUUIDFromPtr(apiKeyID),
	})
	if err != nil {
		return FindingAssertion{}, err
	}
	return findingAssertionFromRow(row), nil
}

// CloseFindingAssertion records a resolve or a retract.
func (q *Queries) CloseFindingAssertion(ctx context.Context, repoID uuid.UUID, fingerprint, kind, reason string, userID, apiKeyID *uuid.UUID) (FindingAssertion, error) {
	row, err := q.db.CloseFindingAssertion(ctx, dbgen.CloseFindingAssertionParams{
		RepoID:         repoID,
		Fingerprint:    fingerprint,
		Kind:           sql.NullString{String: kind, Valid: true},
		ClosedBy:       nullUUIDFromPtr(userID),
		ClosedApiKeyID: nullUUIDFromPtr(apiKeyID),
		Reason:         sql.NullString{String: reason, Valid: reason != ""},
	})
	if err != nil {
		return FindingAssertion{}, err
	}
	return findingAssertionFromRow(row), nil
}

// GetFindingAssertion returns the lifecycle row, or nil when the assertion
// was never confirmed nor decided.
func (q *Queries) GetFindingAssertion(ctx context.Context, repoID uuid.UUID, fingerprint string) (*FindingAssertion, error) {
	row, err := q.db.GetFindingAssertion(ctx, dbgen.GetFindingAssertionParams{RepoID: repoID, Fingerprint: fingerprint})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	assertion := findingAssertionFromRow(row)
	return &assertion, nil
}

// ClosedAssertionFingerprints returns the repo's resolved or retracted
// assertions as a set: carry-forward skips them.
func (q *Queries) ClosedAssertionFingerprints(ctx context.Context, repoID uuid.UUID) (map[string]bool, error) {
	fingerprints, err := q.db.ListClosedAssertionFingerprints(ctx, repoID)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(fingerprints))
	for _, fingerprint := range fingerprints {
		out[fingerprint] = true
	}
	return out, nil
}

// SetAssertionRowsStatus applies a decision to the assertion's rows in the
// latest snapshot of each ref; returns rows updated.
func (q *Queries) SetAssertionRowsStatus(ctx context.Context, repoID uuid.UUID, fingerprint, status string, resolvedBy *uuid.UUID) (int64, error) {
	return q.db.SetAssertionRowsStatus(ctx, dbgen.SetAssertionRowsStatusParams{
		RepoID:      repoID,
		Fingerprint: fingerprint,
		Status:      status,
		ResolvedBy:  nullUUIDFromPtr(resolvedBy),
	})
}
