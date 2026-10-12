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

// ScanPlan is a stored scan plan (ADR-035 §4). Plan holds the
// scanplan.Plan document as JSON so the store does not import the planner.
type ScanPlan struct {
	ID                uuid.UUID       `json:"id"`
	RepoID            uuid.UUID       `json:"repo_id"`
	RefName           string          `json:"ref_name"`
	CommitSHA         string          `json:"commit_sha"`
	BaseCommitSHA     *string         `json:"base_commit_sha,omitempty"`
	Mode              string          `json:"mode"`
	Digest            string          `json:"digest"`
	DetectionRevision string          `json:"detection_revision"`
	CatalogRevision   string          `json:"catalog_revision"`
	Plan              json.RawMessage `json:"plan"`
	CreatedAt         time.Time       `json:"created_at"`
}

func scanPlanFromRow(row dbgen.ScanPlan) ScanPlan {
	return ScanPlan{
		ID: row.ID, RepoID: row.RepoID, RefName: row.RefName, CommitSHA: row.CommitSha,
		BaseCommitSHA: stringPtrFromNull(row.BaseCommitSha), Mode: row.Mode, Digest: row.Digest,
		DetectionRevision: row.DetectionRevision, CatalogRevision: row.CatalogRevision,
		Plan: row.Plan, CreatedAt: row.CreatedAt,
	}
}

// CreateScanPlan stores a plan; apiKeyID names the CI token that asked.
func (q *Queries) CreateScanPlan(ctx context.Context, plan ScanPlan, apiKeyID *uuid.UUID) (ScanPlan, error) {
	row, err := q.db.CreateScanPlan(ctx, dbgen.CreateScanPlanParams{
		RepoID: plan.RepoID, RefName: plan.RefName, CommitSha: plan.CommitSHA,
		BaseCommitSha: nullStringFromPtr(plan.BaseCommitSHA), Mode: plan.Mode, Digest: plan.Digest,
		DetectionRevision: plan.DetectionRevision, CatalogRevision: plan.CatalogRevision,
		Plan: plan.Plan, CreatedByApiKeyID: nullUUIDFromPtr(apiKeyID),
	})
	if err != nil {
		return ScanPlan{}, err
	}
	return scanPlanFromRow(row), nil
}

// GetScanPlan returns a repo's plan by id, or nil.
func (q *Queries) GetScanPlan(ctx context.Context, repoID, planID uuid.UUID) (*ScanPlan, error) {
	row, err := q.db.GetScanPlan(ctx, dbgen.GetScanPlanParams{ID: planID, RepoID: repoID})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	plan := scanPlanFromRow(row)
	return &plan, nil
}

// GetLatestScanPlan returns the repo's newest plan, or nil.
func (q *Queries) GetLatestScanPlan(ctx context.Context, repoID uuid.UUID) (*ScanPlan, error) {
	row, err := q.db.GetLatestScanPlan(ctx, repoID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	plan := scanPlanFromRow(row)
	return &plan, nil
}

// BindArtifactToPlanJob records which plan job produced an artifact, on the
// artifact and on the producer runs ingested from it.
func (q *Queries) BindArtifactToPlanJob(ctx context.Context, artifactID, planID uuid.UUID, jobID string) error {
	plan := uuid.NullUUID{UUID: planID, Valid: true}
	job := sql.NullString{String: jobID, Valid: true}
	if err := q.db.SetSnapshotArtifactPlanJob(ctx, dbgen.SetSnapshotArtifactPlanJobParams{ID: artifactID, PlanID: plan, PlanJobID: job}); err != nil {
		return err
	}
	return q.db.SetProducerRunsPlanJob(ctx, dbgen.SetProducerRunsPlanJobParams{ArtifactID: uuid.NullUUID{UUID: artifactID, Valid: true}, PlanID: plan, PlanJobID: job})
}
