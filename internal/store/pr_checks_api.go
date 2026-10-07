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
	// ClaimsBaseSha is the base commit the resolved-fingerprint claims were
	// verified against; empty when no claims were recorded (PLAN §5).
	ClaimsBaseSha string
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
		ClaimsBaseSha: in.ClaimsBaseSha,
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

// ReplacePRCheckResolvedFingerprints records which findings this PR's latest
// gate run resolves versus its base.
func (q *Queries) ReplacePRCheckResolvedFingerprints(ctx context.Context, prCheckID uuid.UUID, fingerprints []string) error {
	return q.db.ReplacePRCheckResolvedFingerprints(ctx, dbgen.ReplacePRCheckResolvedFingerprintsParams{
		PrCheckID:    prCheckID,
		Fingerprints: fingerprints,
	})
}

// FixingPullRequest is an open PR whose gate run resolves a fingerprint —
// "don't accept this, #12 already fixes it".
type FixingPullRequest struct {
	Fingerprint string `json:"fingerprint"`
	RefName     string `json:"ref_name"`
	Number      string `json:"number,omitempty"`
	Title       string `json:"title,omitempty"`
	// VerifiedBaseSha is the base commit the claim was verified against
	// (PLAN §5) — what the UI's "resolved when merged" hover cites.
	VerifiedBaseSha string `json:"verified_base_sha,omitempty"`
}

func (q *Queries) ListFixingPullRequests(ctx context.Context, repoID uuid.UUID, fingerprints []string) ([]FixingPullRequest, error) {
	if len(fingerprints) == 0 {
		return nil, nil
	}
	rows, err := q.db.ListFixingPullRequests(ctx, dbgen.ListFixingPullRequestsParams{
		RepoID:       repoID,
		Fingerprints: fingerprints,
	})
	if err != nil {
		return nil, err
	}
	out := make([]FixingPullRequest, len(rows))
	for i, row := range rows {
		out[i] = FixingPullRequest{
			Fingerprint:     row.Fingerprint,
			RefName:         row.RefName,
			Number:          row.PrNumber.String,
			Title:           row.PrTitle,
			VerifiedBaseSha: row.ClaimsBaseSha,
		}
	}
	return out, nil
}

// ListUnsyncedPRChecks returns gate outcomes whose forge post has not succeeded
// yet, for the reconcile/retry loop.
func (q *Queries) ListUnsyncedPRChecks(ctx context.Context, limit int32) ([]PrCheck, error) {
	if limit <= 0 {
		limit = 100
	}
	return q.db.ListUnsyncedPRChecks(ctx, limit)
}
