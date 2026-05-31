package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/lehibou/internal/store/dbgen"
)

type RefType = dbgen.RefType

const (
	RefTypeBranch      = dbgen.RefTypeBranch
	RefTypeTag         = dbgen.RefTypeTag
	RefTypePullRequest = dbgen.RefTypePullRequest
)

type Ref struct {
	ID               uuid.UUID  `json:"id"`
	RepoID           uuid.UUID  `json:"repo_id"`
	Name             string     `json:"name"`
	RefType          RefType    `json:"ref_type"`
	ProviderID       *string    `json:"provider_id,omitempty"`
	MergeTargetRefID *uuid.UUID `json:"merge_target_ref_id,omitempty"`
	LatestCommitSHA  *string    `json:"latest_commit_sha,omitempty"`
	PrState          *string    `json:"pr_state,omitempty"`
	PrTitle          string     `json:"pr_title,omitempty"`
	PrSourceBranch   string     `json:"pr_source_branch,omitempty"`
	PrMergedAt       *time.Time `json:"pr_merged_at,omitempty"`
	PrClosedAt       *time.Time `json:"pr_closed_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

type EnhancedRef struct {
	ID                   uuid.UUID  `json:"id"`
	RepoID               uuid.UUID  `json:"repo_id"`
	Name                 string     `json:"name"`
	RefType              RefType    `json:"ref_type"`
	ProviderID           *string    `json:"provider_id,omitempty"`
	MergeTargetRefID     *uuid.UUID `json:"merge_target_ref_id,omitempty"`
	MergeTargetRefName   *string    `json:"merge_target_ref_name,omitempty"`
	LatestCommitSHA      *string    `json:"latest_commit_sha,omitempty"`
	PrState              *string    `json:"pr_state,omitempty"`
	PrTitle              string     `json:"pr_title,omitempty"`
	PrSourceBranch       string     `json:"pr_source_branch,omitempty"`
	PrMergedAt           *time.Time `json:"pr_merged_at,omitempty"`
	PrClosedAt           *time.Time `json:"pr_closed_at,omitempty"`
	LatestSnapshotID     *uuid.UUID `json:"latest_snapshot_id,omitempty"`
	LatestSnapshotStatus *string    `json:"latest_snapshot_status,omitempty"`
	LatestSnapshotDate   *time.Time `json:"latest_snapshot_date,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

func (q *Queries) CreateRef(ctx context.Context, repoID uuid.UUID, name string, refType RefType, providerID *string, mergeTargetRefID *uuid.UUID, latestCommitSHA *string) (*Ref, error) {
	row, err := q.db.CreateRef(ctx, dbgen.CreateRefParams{
		RepoID:           repoID,
		Name:             name,
		RefType:          refType,
		ProviderID:       nullStringFromPtr(providerID),
		MergeTargetRefID: nullUUIDFromPtr(mergeTargetRefID),
		LatestCommitSha:  nullStringFromPtr(latestCommitSHA),
	})
	if err != nil {
		return nil, err
	}

	return refFromRow(row), nil
}

func (q *Queries) GetRefByID(ctx context.Context, id uuid.UUID) (*Ref, error) {
	row, err := q.db.GetRefByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return refFromRow(row), nil
}

func (q *Queries) GetRefByRepoAndName(ctx context.Context, repoID uuid.UUID, name string, refType RefType) (*Ref, error) {
	row, err := q.db.GetRefByRepoAndName(ctx, dbgen.GetRefByRepoAndNameParams{
		RepoID:  repoID,
		Name:    name,
		RefType: refType,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return refFromRow(row), nil
}

func (q *Queries) ListRefsByRepo(ctx context.Context, repoID uuid.UUID, limit, offset int) ([]Ref, int, error) {
	rows, err := q.db.ListRefsByRepo(ctx, dbgen.ListRefsByRepoParams{
		RepoID: repoID,
		Limit:  int32(limit),  //nolint:gosec // G115: pagination values are bounded by API parsing.
		Offset: int32(offset), //nolint:gosec // G115: pagination values are bounded by API parsing.
	})
	if err != nil {
		return nil, 0, err
	}

	refs := make([]Ref, len(rows))
	for i, row := range rows {
		refs[i] = *refFromRow(row)
	}

	total, err := q.db.CountRefsByRepo(ctx, repoID)
	if err != nil {
		return nil, 0, err
	}

	return refs, int(total), nil
}

func (q *Queries) UpdateRefLatestCommit(ctx context.Context, id uuid.UUID, latestCommitSHA *string) (*Ref, error) {
	row, err := q.db.UpdateRefLatestCommit(ctx, dbgen.UpdateRefLatestCommitParams{
		ID:              id,
		LatestCommitSha: nullStringFromPtr(latestCommitSHA),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return refFromRow(row), nil
}

func (q *Queries) UpsertRef(ctx context.Context, repoID uuid.UUID, name string, refType RefType, providerID *string, mergeTargetRefID *uuid.UUID, latestCommitSHA *string) (*Ref, error) {
	row, err := q.db.UpsertRef(ctx, dbgen.UpsertRefParams{
		RepoID:           repoID,
		Name:             name,
		RefType:          refType,
		ProviderID:       nullStringFromPtr(providerID),
		MergeTargetRefID: nullUUIDFromPtr(mergeTargetRefID),
		LatestCommitSha:  nullStringFromPtr(latestCommitSHA),
		PrTitle:          "",
		PrSourceBranch:   "",
	})
	if err != nil {
		return nil, err
	}

	return refFromRow(row), nil
}

func (q *Queries) UpdateRefPRState(ctx context.Context, id uuid.UUID, prState *string, prTitle, prSourceBranch string, prMergedAt, prClosedAt *time.Time) (*Ref, error) {
	row, err := q.db.UpdateRefPRState(ctx, dbgen.UpdateRefPRStateParams{
		ID:             id,
		PrState:        nullStringFromPtr(prState),
		PrTitle:        prTitle,
		PrSourceBranch: prSourceBranch,
		PrMergedAt:     nullTimeFromPtr(prMergedAt),
		PrClosedAt:     nullTimeFromPtr(prClosedAt),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return refFromRow(row), nil
}

func (q *Queries) ListRefsEnhanced(ctx context.Context, repoID uuid.UUID, limit, offset int) ([]EnhancedRef, int, error) {
	rows, err := q.db.ListRefsEnhanced(ctx, dbgen.ListRefsEnhancedParams{
		RepoID: repoID,
		Limit:  int32(limit),  //nolint:gosec // G115: pagination values are bounded by API parsing.
		Offset: int32(offset), //nolint:gosec // G115: pagination values are bounded by API parsing.
	})
	if err != nil {
		return nil, 0, err
	}

	refs := make([]EnhancedRef, len(rows))
	for i, row := range rows {
		refs[i] = enhancedRefFromListRefsEnhancedRow(row)
	}

	total, err := q.db.CountRefsByRepo(ctx, repoID)
	if err != nil {
		return nil, 0, err
	}

	return refs, int(total), nil
}

func (q *Queries) ListPullRequestRefs(ctx context.Context, repoID uuid.UUID, limit, offset int) ([]EnhancedRef, error) {
	rows, err := q.db.ListPullRequestRefs(ctx, dbgen.ListPullRequestRefsParams{
		RepoID: repoID,
		Limit:  int32(limit),  //nolint:gosec // G115: pagination values are bounded by API parsing.
		Offset: int32(offset), //nolint:gosec // G115: pagination values are bounded by API parsing.
	})
	if err != nil {
		return nil, err
	}

	refs := make([]EnhancedRef, len(rows))
	for i, row := range rows {
		refs[i] = enhancedRefFromListPullRequestRefsRow(row)
	}

	return refs, nil
}

func (q *Queries) DeleteRef(ctx context.Context, id uuid.UUID) error {
	return q.db.DeleteRef(ctx, id)
}

func refFromRow(row dbgen.Ref) *Ref {
	return &Ref{
		ID:               row.ID,
		RepoID:           row.RepoID,
		Name:             row.Name,
		RefType:          row.RefType,
		ProviderID:       stringPtrFromNull(row.ProviderID),
		MergeTargetRefID: uuidPtrFromNull(row.MergeTargetRefID),
		LatestCommitSHA:  stringPtrFromNull(row.LatestCommitSha),
		PrState:          stringPtrFromNull(row.PrState),
		PrTitle:          row.PrTitle,
		PrSourceBranch:   row.PrSourceBranch,
		PrMergedAt:       timePtrFromNull(row.PrMergedAt),
		PrClosedAt:       timePtrFromNull(row.PrClosedAt),
		CreatedAt:        row.CreatedAt,
		UpdatedAt:        row.UpdatedAt,
	}
}

func enhancedRefFromListRefsEnhancedRow(row dbgen.ListRefsEnhancedRow) EnhancedRef {
	return enhancedRefFromFields(
		row.ID,
		row.RepoID,
		row.Name,
		row.RefType,
		row.ProviderID,
		row.MergeTargetRefID,
		row.MergeTargetRefName,
		row.LatestCommitSha,
		row.PrState,
		row.PrTitle,
		row.PrSourceBranch,
		row.PrMergedAt,
		row.PrClosedAt,
		row.LatestSnapshotID,
		row.LatestSnapshotStatus,
		row.LatestSnapshotDate,
		row.CreatedAt,
		row.UpdatedAt,
	)
}

func enhancedRefFromListPullRequestRefsRow(row dbgen.ListPullRequestRefsRow) EnhancedRef {
	return enhancedRefFromFields(
		row.ID,
		row.RepoID,
		row.Name,
		row.RefType,
		row.ProviderID,
		row.MergeTargetRefID,
		row.MergeTargetRefName,
		row.LatestCommitSha,
		row.PrState,
		row.PrTitle,
		row.PrSourceBranch,
		row.PrMergedAt,
		row.PrClosedAt,
		row.LatestSnapshotID,
		row.LatestSnapshotStatus,
		row.LatestSnapshotDate,
		row.CreatedAt,
		row.UpdatedAt,
	)
}

func enhancedRefFromFields(
	id uuid.UUID,
	repoID uuid.UUID,
	name string,
	refType RefType,
	providerID sql.NullString,
	mergeTargetRefID uuid.NullUUID,
	mergeTargetRefName string,
	latestCommitSHA sql.NullString,
	prState sql.NullString,
	prTitle string,
	prSourceBranch string,
	prMergedAt sql.NullTime,
	prClosedAt sql.NullTime,
	latestSnapshotID any,
	latestSnapshotStatus any,
	latestSnapshotDate any,
	createdAt time.Time,
	updatedAt time.Time,
) EnhancedRef {
	return EnhancedRef{
		ID:                   id,
		RepoID:               repoID,
		Name:                 name,
		RefType:              refType,
		ProviderID:           stringPtrFromNull(providerID),
		MergeTargetRefID:     uuidPtrFromNull(mergeTargetRefID),
		MergeTargetRefName:   stringPtrIfNotEmpty(mergeTargetRefName),
		LatestCommitSHA:      stringPtrFromNull(latestCommitSHA),
		PrState:              stringPtrFromNull(prState),
		PrTitle:              prTitle,
		PrSourceBranch:       prSourceBranch,
		PrMergedAt:           timePtrFromNull(prMergedAt),
		PrClosedAt:           timePtrFromNull(prClosedAt),
		LatestSnapshotID:     uuidPtrFromAny(latestSnapshotID),
		LatestSnapshotStatus: stringPtrFromAny(latestSnapshotStatus),
		LatestSnapshotDate:   timePtrFromAny(latestSnapshotDate),
		CreatedAt:            createdAt,
		UpdatedAt:            updatedAt,
	}
}

func stringPtrIfNotEmpty(value string) *string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return &value
}

func uuidPtrFromAny(value any) *uuid.UUID {
	switch typed := value.(type) {
	case nil:
		return nil
	case uuid.UUID:
		if typed == uuid.Nil {
			return nil
		}
		result := typed
		return &result
	case string:
		parsed, err := uuid.Parse(strings.TrimSpace(typed))
		if err != nil {
			return nil
		}
		return &parsed
	case []byte:
		return uuidPtrFromAny(string(typed))
	default:
		return uuidPtrFromAny(fmt.Sprint(typed))
	}
}

func stringPtrFromAny(value any) *string {
	switch typed := value.(type) {
	case nil:
		return nil
	case string:
		return stringPtrIfNotEmpty(typed)
	case []byte:
		return stringPtrIfNotEmpty(string(typed))
	default:
		return stringPtrIfNotEmpty(fmt.Sprint(typed))
	}
}

func timePtrFromAny(value any) *time.Time {
	switch typed := value.(type) {
	case nil:
		return nil
	case time.Time:
		result := typed
		return &result
	case string:
		parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(typed))
		if err != nil {
			return nil
		}
		return &parsed
	case []byte:
		return timePtrFromAny(string(typed))
	default:
		return nil
	}
}
