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

// RepoApplicability is a stored detection result (ADR-035 §3). Result is the
// applicability.Result document, kept as JSON so the store does not depend
// on the detector.
type RepoApplicability struct {
	ID                uuid.UUID       `json:"id"`
	RepoID            uuid.UUID       `json:"repo_id"`
	RefName           string          `json:"ref_name"`
	CommitSHA         string          `json:"commit_sha"`
	DetectionRevision string          `json:"detection_revision"`
	CatalogRevision   string          `json:"catalog_revision"`
	Status            string          `json:"status"`
	Result            json.RawMessage `json:"result"`
	CreatedAt         time.Time       `json:"created_at"`
}

func repoApplicabilityFromRow(row dbgen.RepoApplicability) RepoApplicability {
	return RepoApplicability{
		ID: row.ID, RepoID: row.RepoID, RefName: row.RefName, CommitSHA: row.CommitSha,
		DetectionRevision: row.DetectionRevision, CatalogRevision: row.CatalogRevision,
		Status: row.Status, Result: row.Result, CreatedAt: row.CreatedAt,
	}
}

func (q *Queries) UpsertRepoApplicability(ctx context.Context, input RepoApplicability) (RepoApplicability, error) {
	row, err := q.db.UpsertRepoApplicability(ctx, dbgen.UpsertRepoApplicabilityParams{
		RepoID: input.RepoID, RefName: input.RefName, CommitSha: input.CommitSHA,
		DetectionRevision: input.DetectionRevision, CatalogRevision: input.CatalogRevision,
		Status: input.Status, Result: input.Result,
	})
	if err != nil {
		return RepoApplicability{}, err
	}
	return repoApplicabilityFromRow(row), nil
}

// GetLatestRepoApplicability returns the newest detection, or nil.
func (q *Queries) GetLatestRepoApplicability(ctx context.Context, repoID uuid.UUID) (*RepoApplicability, error) {
	row, err := q.db.GetLatestRepoApplicability(ctx, repoID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := repoApplicabilityFromRow(row)
	return &out, nil
}
