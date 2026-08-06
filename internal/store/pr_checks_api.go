package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// PrCheck is the persisted quality-gate outcome published to a forge as a commit
// status / check run. See ADR-018.
type PrCheck = dbgen.PrCheck

const defaultGateContext = "hibou/security"

// UpsertPRCheckInput is the domain-friendly input for persisting a gate outcome.
// Reasons is stored as a JSON array; DeltaSummary as a JSON object.
type UpsertPRCheckInput struct {
	RepoID        uuid.UUID
	RefID         *uuid.UUID
	HeadSha       string
	Context       string
	State         string
	Conclusion    string
	Enforcement   string
	Passed        bool
	Reasons       []string
	DeltaSummary  json.RawMessage
	ExternalID    string
	TargetURL     string
	ForgeSyncedAt *time.Time
	LastError     string
}

// UpsertPRCheck inserts or updates the gate outcome for (repo, head SHA, context).
// It is idempotent so re-evaluations refresh the same row rather than duplicating.
func (q *Queries) UpsertPRCheck(ctx context.Context, in UpsertPRCheckInput) (*PrCheck, error) {
	reasons, err := json.Marshal(in.Reasons)
	if err != nil || len(reasons) == 0 {
		reasons = []byte("[]")
	}
	summary := in.DeltaSummary
	if len(summary) == 0 {
		summary = json.RawMessage("{}")
	}
	context := in.Context
	if context == "" {
		context = defaultGateContext
	}
	enforcement := in.Enforcement
	if enforcement == "" {
		enforcement = "advisory"
	}

	row, err := q.db.UpsertPRCheck(ctx, dbgen.UpsertPRCheckParams{
		RepoID:        in.RepoID,
		RefID:         nullUUIDFromPtr(in.RefID),
		HeadSha:       in.HeadSha,
		Context:       context,
		State:         in.State,
		Conclusion:    in.Conclusion,
		Enforcement:   enforcement,
		Passed:        in.Passed,
		Reasons:       reasons,
		DeltaSummary:  summary,
		ExternalID:    in.ExternalID,
		TargetUrl:     in.TargetURL,
		ForgeSyncedAt: nullTimeFromPtr(in.ForgeSyncedAt),
		LastError:     in.LastError,
	})
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// GetPRCheck returns the persisted gate outcome for (repo, head SHA, context), or
// nil when none exists.
func (q *Queries) GetPRCheck(ctx context.Context, repoID uuid.UUID, headSha, context string) (*PrCheck, error) {
	if context == "" {
		context = defaultGateContext
	}
	row, err := q.db.GetPRCheck(ctx, dbgen.GetPRCheckParams{RepoID: repoID, HeadSha: headSha, Context: context})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// ListUnsyncedPRChecks returns gate outcomes whose forge post has not succeeded
// yet, for the reconcile/retry loop.
func (q *Queries) ListUnsyncedPRChecks(ctx context.Context, limit int32) ([]PrCheck, error) {
	if limit <= 0 {
		limit = 100
	}
	return q.db.ListUnsyncedPRChecks(ctx, limit)
}
