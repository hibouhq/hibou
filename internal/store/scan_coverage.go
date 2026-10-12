package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// ScanCoverageCell is one persisted repository × scanner coverage state
// (ADR-035 §6).
type ScanCoverageCell struct {
	RepoID      uuid.UUID  `json:"repo_id"`
	RepoSlug    string     `json:"repo_slug,omitempty"`
	RepoName    string     `json:"repo_name,omitempty"`
	ScannerID   string     `json:"scanner_id"`
	State       string     `json:"state"`
	Reason      string     `json:"reason"`
	Configured  string     `json:"configured"`
	Required    bool       `json:"required"`
	Enforcement string     `json:"enforcement,omitempty"`
	LastRunAt   *time.Time `json:"last_run_at,omitempty"`
	LastCommit  string     `json:"last_commit,omitempty"`
	ComputedAt  time.Time  `json:"computed_at"`
}

// ReplaceRepoScanCoverage swaps a repository's cells (call in a transaction).
func (q *Queries) ReplaceRepoScanCoverage(ctx context.Context, repoID uuid.UUID, cells []ScanCoverageCell) error {
	if err := q.db.DeleteRepoScanCoverage(ctx, repoID); err != nil {
		return err
	}
	if len(cells) == 0 {
		return nil
	}
	encoded, err := json.Marshal(cells)
	if err != nil {
		return err
	}
	return q.db.InsertRepoScanCoverage(ctx, dbgen.InsertRepoScanCoverageParams{RepoID: repoID, Cells: encoded})
}

// OrgScanCoverageFilter narrows the org matrix.
type OrgScanCoverageFilter struct {
	State        string
	ScannerID    string
	RequiredOnly bool
	Limit        int
	Offset       int
}

func (q *Queries) ListOrgScanCoverage(ctx context.Context, orgID uuid.UUID, filter OrgScanCoverageFilter) ([]ScanCoverageCell, error) {
	rows, err := q.db.ListOrgScanCoverage(ctx, dbgen.ListOrgScanCoverageParams{
		OrgID: orgID, State: filter.State, ScannerID: filter.ScannerID, RequiredOnly: filter.RequiredOnly,
		RowLimit:  int32(filter.Limit),  // #nosec G115 -- bounded page size
		RowOffset: int32(filter.Offset), // #nosec G115 -- bounded page offset
	})
	if err != nil {
		return nil, err
	}
	out := make([]ScanCoverageCell, len(rows))
	for i, row := range rows {
		out[i] = ScanCoverageCell{
			RepoID: row.RepoID, RepoSlug: row.RepoSlug, RepoName: row.RepoName, ScannerID: row.ScannerID,
			State: row.State, Reason: row.Reason, Configured: row.Configured, Required: row.Required,
			Enforcement: row.Enforcement, LastRunAt: timePtrFromNull(row.LastRunAt), LastCommit: row.LastCommit, ComputedAt: row.ComputedAt,
		}
	}
	return out, nil
}

// ScanCoverageSummary counts cells per state.
type ScanCoverageSummary struct {
	State    string `json:"state"`
	Required bool   `json:"required"`
	Cells    int64  `json:"cells"`
}

func (q *Queries) SummarizeOrgScanCoverage(ctx context.Context, orgID uuid.UUID) ([]ScanCoverageSummary, error) {
	rows, err := q.db.SummarizeOrgScanCoverage(ctx, orgID)
	if err != nil {
		return nil, err
	}
	out := make([]ScanCoverageSummary, len(rows))
	for i, row := range rows {
		out[i] = ScanCoverageSummary{State: row.State, Required: row.Required, Cells: row.Cells}
	}
	return out, nil
}

// RefProducerRun is a producer run with its snapshot's commit.
type RefProducerRun struct {
	ProducerRun
	CommitSHA string `json:"commit_sha"`
}

// ListProducerRunsForRef returns recent runs on a ref, newest first.
func (q *Queries) ListProducerRunsForRef(ctx context.Context, refID uuid.UUID) ([]RefProducerRun, error) {
	rows, err := q.db.ListProducerRunsForRef(ctx, refID)
	if err != nil {
		return nil, err
	}
	out := make([]RefProducerRun, len(rows))
	for i, row := range rows {
		out[i] = RefProducerRun{
			ProducerRun: producerRunFromRow(dbgen.ProducerRun{
				ID: row.ID, SnapshotID: row.SnapshotID, ArtifactID: row.ArtifactID, RunIndex: row.RunIndex, Producer: row.Producer,
				Version: row.Version, ConfigDigest: row.ConfigDigest, Scope: row.Scope, ScopeDeclared: row.ScopeDeclared,
				ScopePaths: row.ScopePaths, Outcome: row.Outcome, SkippedFiles: row.SkippedFiles, FindingCount: row.FindingCount,
				Detail: row.Detail, CreatedAt: row.CreatedAt, PlanID: row.PlanID, PlanJobID: row.PlanJobID,
			}),
			CommitSHA: row.CommitSha,
		}
	}
	return out, nil
}
