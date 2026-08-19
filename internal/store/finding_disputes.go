package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// FindingDispute is the human-axis override for an in-source suppression
// (ADR-026): the scanner keeps reporting the finding as suppressed because the
// directive is in the code, but a human contests that call, so the finding
// stays visible and gating until the directive is removed or the dispute
// withdrawn. Deliberately NOT a finding_acceptances reason kind — an
// acceptance row means "not gating", a dispute means the opposite, and a
// consumer that forgets the dispute join must degrade to "dispute not
// surfaced", never to "gate wrongly passes".
type FindingDispute struct {
	ID          uuid.UUID  `json:"id"`
	RepoID      uuid.UUID  `json:"repo_id"`
	Fingerprint string     `json:"fingerprint"`
	Reason      string     `json:"reason"`
	DisputedBy  *uuid.UUID `json:"disputed_by,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

func findingDisputeFromRow(row dbgen.FindingDispute) FindingDispute {
	out := FindingDispute{
		ID:          row.ID,
		RepoID:      row.RepoID,
		Fingerprint: row.Fingerprint,
		Reason:      row.Reason,
		CreatedAt:   row.CreatedAt,
	}
	if row.DisputedBy.Valid {
		id := row.DisputedBy.UUID
		out.DisputedBy = &id
	}
	return out
}

func (q *Queries) UpsertFindingDispute(ctx context.Context, repoID uuid.UUID, fingerprint, reason string, disputedBy *uuid.UUID) (FindingDispute, error) {
	row, err := q.db.UpsertFindingDispute(ctx, dbgen.UpsertFindingDisputeParams{
		RepoID:      repoID,
		Fingerprint: fingerprint,
		Reason:      reason,
		DisputedBy:  nullUUIDFromPtr(disputedBy),
	})
	if err != nil {
		return FindingDispute{}, err
	}
	return findingDisputeFromRow(row), nil
}

func (q *Queries) DeleteFindingDispute(ctx context.Context, repoID uuid.UUID, fingerprint string) (bool, error) {
	affected, err := q.db.DeleteFindingDispute(ctx, dbgen.DeleteFindingDisputeParams{RepoID: repoID, Fingerprint: fingerprint})
	if err != nil {
		return false, err
	}
	return affected > 0, nil
}

// GetFindingDispute returns the dispute on one fingerprint, or nil when the
// suppression is uncontested.
func (q *Queries) GetFindingDispute(ctx context.Context, repoID uuid.UUID, fingerprint string) (*FindingDispute, error) {
	row, err := q.db.GetFindingDispute(ctx, dbgen.GetFindingDisputeParams{RepoID: repoID, Fingerprint: fingerprint})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	dispute := findingDisputeFromRow(row)
	return &dispute, nil
}

func (q *Queries) ListFindingDisputesByRepo(ctx context.Context, repoID uuid.UUID) ([]FindingDispute, error) {
	rows, err := q.db.ListFindingDisputesByRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}
	out := make([]FindingDispute, len(rows))
	for i, row := range rows {
		out[i] = findingDisputeFromRow(row)
	}
	return out, nil
}

// DisputedFingerprints returns the repo's disputed fingerprints as a set, the
// shape every "does this suppressed finding still count" consumer needs.
func (q *Queries) DisputedFingerprints(ctx context.Context, repoID uuid.UUID) (map[string]struct{}, error) {
	disputes, err := q.ListFindingDisputesByRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}
	set := make(map[string]struct{}, len(disputes))
	for _, dispute := range disputes {
		set[dispute.Fingerprint] = struct{}{}
	}
	return set, nil
}
