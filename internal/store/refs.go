package store

import (
	"context"
	"database/sql"
	"errors"
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
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
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
		Limit:  int32(limit),
		Offset: int32(offset),
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

func (q *Queries) UpsertRef(ctx context.Context, repoID uuid.UUID, name string, refType RefType, providerID *string, latestCommitSHA *string) (*Ref, error) {
	row, err := q.db.UpsertRef(ctx, dbgen.UpsertRefParams{
		RepoID:          repoID,
		Name:            name,
		RefType:         refType,
		ProviderID:      nullStringFromPtr(providerID),
		LatestCommitSha: nullStringFromPtr(latestCommitSHA),
	})
	if err != nil {
		return nil, err
	}

	return refFromRow(row), nil
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
		CreatedAt:        row.CreatedAt,
		UpdatedAt:        row.UpdatedAt,
	}
}
