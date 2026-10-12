package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// RepoScannerSetting is a repository's own choice for one scanner (ADR-035 §5).
type RepoScannerSetting struct {
	ScannerID string     `json:"scanner_id"`
	Mode      string     `json:"mode"`
	UpdatedBy *uuid.UUID `json:"updated_by,omitempty"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// ScannerRequirement is an org requirement: a capability for a language.
type ScannerRequirement struct {
	ID            uuid.UUID `json:"id"`
	Language      string    `json:"language"`
	Capability    string    `json:"capability"`
	ScannerIDs    []string  `json:"scanner_ids"`
	FreshnessDays int       `json:"freshness_days"`
	Enforcement   string    `json:"enforcement"`
	CreatedAt     time.Time `json:"created_at"`
}

// CoverageException waives a requirement for a repository scope.
type CoverageException struct {
	ID            uuid.UUID  `json:"id"`
	RepoID        uuid.UUID  `json:"repo_id"`
	RepoSlug      string     `json:"repo_slug,omitempty"`
	RequirementID uuid.UUID  `json:"requirement_id"`
	Scope         string     `json:"scope"`
	Reason        string     `json:"reason"`
	Status        string     `json:"status"`
	RequestedBy   *uuid.UUID `json:"requested_by,omitempty"`
	DecidedBy     *uuid.UUID `json:"decided_by,omitempty"`
	DecidedAt     *time.Time `json:"decided_at,omitempty"`
	ExpiresAt     time.Time  `json:"expires_at"`
	CreatedAt     time.Time  `json:"created_at"`
}

func coverageExceptionFromRow(row dbgen.CoverageException) CoverageException {
	return CoverageException{
		ID: row.ID, RepoID: row.RepoID, RequirementID: row.RequirementID, Scope: row.Scope, Reason: row.Reason,
		Status: row.Status, RequestedBy: uuidPtrFromNull(row.RequestedBy), DecidedBy: uuidPtrFromNull(row.DecidedBy),
		DecidedAt: timePtrFromNull(row.DecidedAt), ExpiresAt: row.ExpiresAt, CreatedAt: row.CreatedAt,
	}
}

func (q *Queries) ListRepoScannerSettings(ctx context.Context, repoID uuid.UUID) ([]RepoScannerSetting, error) {
	rows, err := q.db.ListRepoScannerSettings(ctx, repoID)
	if err != nil {
		return nil, err
	}
	out := make([]RepoScannerSetting, len(rows))
	for i, row := range rows {
		out[i] = RepoScannerSetting{ScannerID: row.ScannerID, Mode: row.Mode, UpdatedBy: uuidPtrFromNull(row.UpdatedBy), UpdatedAt: row.UpdatedAt}
	}
	return out, nil
}

func (q *Queries) UpsertRepoScannerSetting(ctx context.Context, repoID uuid.UUID, scannerID, mode string, updatedBy *uuid.UUID) error {
	_, err := q.db.UpsertRepoScannerSetting(ctx, dbgen.UpsertRepoScannerSettingParams{
		RepoID: repoID, ScannerID: scannerID, Mode: mode, UpdatedBy: nullUUIDFromPtr(updatedBy),
	})
	return err
}

func (q *Queries) ListScannerRequirements(ctx context.Context, orgID uuid.UUID) ([]ScannerRequirement, error) {
	rows, err := q.db.ListScannerRequirements(ctx, orgID)
	if err != nil {
		return nil, err
	}
	out := make([]ScannerRequirement, len(rows))
	for i, row := range rows {
		out[i] = scannerRequirementFromRow(row)
	}
	return out, nil
}

func scannerRequirementFromRow(row dbgen.ScannerRequirement) ScannerRequirement {
	ids := row.ScannerIds
	if ids == nil {
		ids = []string{}
	}
	return ScannerRequirement{
		ID: row.ID, Language: row.Language, Capability: row.Capability, ScannerIDs: ids,
		FreshnessDays: int(row.FreshnessDays), Enforcement: row.Enforcement, CreatedAt: row.CreatedAt,
	}
}

func (q *Queries) UpsertScannerRequirement(ctx context.Context, orgID uuid.UUID, requirement ScannerRequirement, createdBy *uuid.UUID) (ScannerRequirement, error) {
	ids := requirement.ScannerIDs
	if ids == nil {
		ids = []string{}
	}
	row, err := q.db.UpsertScannerRequirement(ctx, dbgen.UpsertScannerRequirementParams{
		OrgID: orgID, Language: requirement.Language, Capability: requirement.Capability, ScannerIds: ids,
		FreshnessDays: int32(requirement.FreshnessDays), // #nosec G115 -- validated small
		Enforcement:   requirement.Enforcement, CreatedBy: nullUUIDFromPtr(createdBy),
	})
	if err != nil {
		return ScannerRequirement{}, err
	}
	return scannerRequirementFromRow(row), nil
}

func (q *Queries) DeleteScannerRequirement(ctx context.Context, orgID, id uuid.UUID) (bool, error) {
	affected, err := q.db.DeleteScannerRequirement(ctx, dbgen.DeleteScannerRequirementParams{ID: id, OrgID: orgID})
	return affected > 0, err
}

func (q *Queries) ListCoverageExceptionsByRepo(ctx context.Context, repoID uuid.UUID) ([]CoverageException, error) {
	rows, err := q.db.ListCoverageExceptionsByRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}
	out := make([]CoverageException, len(rows))
	for i, row := range rows {
		out[i] = coverageExceptionFromRow(row)
	}
	return out, nil
}

func (q *Queries) ListPendingCoverageExceptionsByOrg(ctx context.Context, orgID uuid.UUID) ([]CoverageException, error) {
	rows, err := q.db.ListPendingCoverageExceptionsByOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	out := make([]CoverageException, len(rows))
	for i, row := range rows {
		exception := coverageExceptionFromRow(dbgen.CoverageException{
			ID: row.ID, RepoID: row.RepoID, RequirementID: row.RequirementID, Scope: row.Scope, Reason: row.Reason,
			Status: row.Status, RequestedBy: row.RequestedBy, DecidedBy: row.DecidedBy, DecidedAt: row.DecidedAt,
			ExpiresAt: row.ExpiresAt, CreatedAt: row.CreatedAt,
		})
		exception.RepoSlug = row.RepoSlug
		out[i] = exception
	}
	return out, nil
}

func (q *Queries) CreateCoverageException(ctx context.Context, exception CoverageException) (CoverageException, error) {
	row, err := q.db.CreateCoverageException(ctx, dbgen.CreateCoverageExceptionParams{
		RepoID: exception.RepoID, RequirementID: exception.RequirementID, Scope: exception.Scope,
		Reason: exception.Reason, RequestedBy: nullUUIDFromPtr(exception.RequestedBy), ExpiresAt: exception.ExpiresAt,
	})
	if err != nil {
		return CoverageException{}, err
	}
	return coverageExceptionFromRow(row), nil
}

// DecideCoverageException approves or rejects a pending exception of the
// org; nil when there is no such pending exception.
func (q *Queries) DecideCoverageException(ctx context.Context, orgID, id uuid.UUID, status string, decidedBy *uuid.UUID) (*CoverageException, error) {
	row, err := q.db.DecideCoverageException(ctx, dbgen.DecideCoverageExceptionParams{
		ID: id, OrgID: orgID, Status: status, DecidedBy: nullUUIDFromPtr(decidedBy),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	exception := coverageExceptionFromRow(row)
	return &exception, nil
}

// RepoScopeOverride is an owner's refinement of detection: an excluded path
// or a declared module root (ADR-035 §3).
type RepoScopeOverride struct {
	ID        uuid.UUID  `json:"id"`
	Kind      string     `json:"kind"`
	Path      string     `json:"path"`
	Reason    string     `json:"reason"`
	CreatedBy *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

func repoScopeOverrideFromRow(row dbgen.RepoScopeOverride) RepoScopeOverride {
	return RepoScopeOverride{ID: row.ID, Kind: row.Kind, Path: row.Path, Reason: row.Reason, CreatedBy: uuidPtrFromNull(row.CreatedBy), CreatedAt: row.CreatedAt}
}

func (q *Queries) ListRepoScopeOverrides(ctx context.Context, repoID uuid.UUID) ([]RepoScopeOverride, error) {
	rows, err := q.db.ListRepoScopeOverrides(ctx, repoID)
	if err != nil {
		return nil, err
	}
	out := make([]RepoScopeOverride, len(rows))
	for i, row := range rows {
		out[i] = repoScopeOverrideFromRow(row)
	}
	return out, nil
}

func (q *Queries) CreateRepoScopeOverride(ctx context.Context, repoID uuid.UUID, override RepoScopeOverride) (RepoScopeOverride, error) {
	row, err := q.db.CreateRepoScopeOverride(ctx, dbgen.CreateRepoScopeOverrideParams{
		RepoID: repoID, Kind: override.Kind, Path: override.Path, Reason: override.Reason, CreatedBy: nullUUIDFromPtr(override.CreatedBy),
	})
	if err != nil {
		return RepoScopeOverride{}, err
	}
	return repoScopeOverrideFromRow(row), nil
}

func (q *Queries) DeleteRepoScopeOverride(ctx context.Context, repoID, id uuid.UUID) (bool, error) {
	affected, err := q.db.DeleteRepoScopeOverride(ctx, dbgen.DeleteRepoScopeOverrideParams{ID: id, RepoID: repoID})
	return affected > 0, err
}
