package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// ResolutionInput is one finding a snapshot resolved (ADR-034 §3).
type ResolutionInput struct {
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
	Producer    string `json:"producer"`
	Reason      string `json:"reason"`
}

// ReplaceFindingResolutions rewrites the resolutions a snapshot recorded.
func (q *Queries) ReplaceFindingResolutions(ctx context.Context, snapshotID uuid.UUID, resolutions []ResolutionInput) error {
	if err := q.db.DeleteFindingResolutionsBySnapshot(ctx, snapshotID); err != nil {
		return err
	}
	if len(resolutions) == 0 {
		return nil
	}
	encoded, err := json.Marshal(resolutions)
	if err != nil {
		return err
	}
	_, err = q.db.InsertFindingResolutions(ctx, dbgen.InsertFindingResolutionsParams{SnapshotID: snapshotID, Resolutions: encoded})
	return err
}

// FindingResolution is a resolution event for the timeline.
type FindingResolution struct {
	Reason          string    `json:"reason"`
	Producer        string    `json:"producer"`
	ProducerVersion string    `json:"producer_version,omitempty"`
	CommitSHA       string    `json:"commit_sha"`
	RefName         string    `json:"ref_name"`
	RefType         string    `json:"ref_type"`
	CreatedAt       time.Time `json:"created_at"`
}

func (q *Queries) ListFindingResolutions(ctx context.Context, repoID uuid.UUID, fingerprint string, limit int) ([]FindingResolution, error) {
	rows, err := q.db.ListFindingResolutions(ctx, dbgen.ListFindingResolutionsParams{
		RepoID:      repoID,
		Fingerprint: fingerprint,
		RowLimit:    int32(limit), // #nosec G115 -- limit is a small server-side constant.
	})
	if err != nil {
		return nil, err
	}
	out := make([]FindingResolution, len(rows))
	for i, row := range rows {
		out[i] = FindingResolution{
			Reason:          row.Reason,
			Producer:        row.Producer,
			ProducerVersion: row.ProducerVersion,
			CommitSHA:       row.CommitSha,
			RefName:         row.RefName,
			RefType:         row.RefType,
			CreatedAt:       row.CreatedAt,
		}
	}
	return out, nil
}

// ProducerPolicy is an org's resolution policy for one producer (ADR-034 §5).
type ProducerPolicy struct {
	Producer  string     `json:"producer"`
	Policy    string     `json:"policy"`
	Threshold int        `json:"threshold"`
	UpdatedBy *uuid.UUID `json:"updated_by,omitempty"`
	UpdatedAt time.Time  `json:"updated_at"`
}

func producerPolicyFromRow(row dbgen.ProducerPolicy) ProducerPolicy {
	return ProducerPolicy{
		Producer:  row.Producer,
		Policy:    row.Policy,
		Threshold: int(row.Threshold),
		UpdatedBy: uuidPtrFromNull(row.UpdatedBy),
		UpdatedAt: row.UpdatedAt,
	}
}

func (q *Queries) ListProducerPolicies(ctx context.Context, orgID uuid.UUID) ([]ProducerPolicy, error) {
	rows, err := q.db.ListProducerPolicies(ctx, orgID)
	if err != nil {
		return nil, err
	}
	out := make([]ProducerPolicy, len(rows))
	for i, row := range rows {
		out[i] = producerPolicyFromRow(row)
	}
	return out, nil
}

func (q *Queries) UpsertProducerPolicy(ctx context.Context, orgID uuid.UUID, policy ProducerPolicy) (ProducerPolicy, error) {
	row, err := q.db.UpsertProducerPolicy(ctx, dbgen.UpsertProducerPolicyParams{
		OrgID:     orgID,
		Producer:  policy.Producer,
		Policy:    policy.Policy,
		Threshold: int32(policy.Threshold), // #nosec G115 -- validated 1..100
		UpdatedBy: nullUUIDFromPtr(policy.UpdatedBy),
	})
	if err != nil {
		return ProducerPolicy{}, err
	}
	return producerPolicyFromRow(row), nil
}

func (q *Queries) DeleteProducerPolicy(ctx context.Context, orgID uuid.UUID, producer string) (bool, error) {
	affected, err := q.db.DeleteProducerPolicy(ctx, dbgen.DeleteProducerPolicyParams{OrgID: orgID, Producer: producer})
	return affected > 0, err
}
