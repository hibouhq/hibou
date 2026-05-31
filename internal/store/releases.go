package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/lehibou/internal/store/dbgen"
)

type Release struct {
	ID            uuid.UUID       `json:"id"`
	RepoID        uuid.UUID       `json:"repo_id"`
	RefID         uuid.UUID       `json:"ref_id"`
	SnapshotID    *uuid.UUID      `json:"snapshot_id,omitempty"`
	Version       string          `json:"version"`
	BuildMetadata json.RawMessage `json:"build_metadata,omitempty"`
	ArtifactIDs   json.RawMessage `json:"artifact_ids,omitempty"`
	Provenance    json.RawMessage `json:"provenance,omitempty"`
	PublishedAt   *time.Time      `json:"published_at,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

func (q *Queries) CreateRelease(ctx context.Context, repoID, refID uuid.UUID, snapshotID *uuid.UUID, version string, buildMetadata, artifactIDs, provenance json.RawMessage, publishedAt *time.Time) (*Release, error) {
	row, err := q.db.CreateRelease(ctx, dbgen.CreateReleaseParams{
		RepoID:        repoID,
		RefID:         refID,
		SnapshotID:    nullUUIDFromPtr(snapshotID),
		Version:       version,
		BuildMetadata: defaultJSON(buildMetadata, []byte("{}")),
		ArtifactIds:   defaultJSON(artifactIDs, []byte("[]")),
		Provenance:    defaultJSON(provenance, []byte("{}")),
		PublishedAt:   nullTimeFromPtr(publishedAt),
	})
	if err != nil {
		return nil, err
	}

	return releaseFromRow(row), nil
}

func (q *Queries) GetReleaseByID(ctx context.Context, id uuid.UUID) (*Release, error) {
	row, err := q.db.GetReleaseByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return releaseFromRow(row), nil
}

func (q *Queries) ListReleasesByRepo(ctx context.Context, repoID uuid.UUID, limit, offset int) ([]Release, int, error) {
	rows, err := q.db.ListReleasesByRepo(ctx, dbgen.ListReleasesByRepoParams{RepoID: repoID, Limit: int32(limit), Offset: int32(offset)}) //nolint:gosec // G115: pagination values are bounded by API parsing.
	if err != nil {
		return nil, 0, err
	}

	releases := make([]Release, len(rows))
	for i, row := range rows {
		releases[i] = *releaseFromRow(row)
	}

	total, err := q.db.CountReleasesByRepo(ctx, repoID)
	if err != nil {
		return nil, 0, err
	}

	return releases, int(total), nil
}

func (q *Queries) ListReleasesByOrg(ctx context.Context, orgID uuid.UUID, limit, offset int) ([]Release, int, error) {
	rows, err := q.db.ListReleasesByOrg(ctx, dbgen.ListReleasesByOrgParams{OrgID: orgID, Limit: int32(limit), Offset: int32(offset)}) //nolint:gosec // G115: pagination values are bounded by API parsing.
	if err != nil {
		return nil, 0, err
	}

	releases := make([]Release, len(rows))
	for i, row := range rows {
		releases[i] = *releaseFromRow(row)
	}

	total, err := q.db.CountReleasesByOrg(ctx, orgID)
	if err != nil {
		return nil, 0, err
	}

	return releases, int(total), nil
}

func (q *Queries) DeleteRelease(ctx context.Context, id uuid.UUID) error {
	return q.db.DeleteRelease(ctx, id)
}

func releaseFromRow(row dbgen.Release) *Release {
	return &Release{
		ID:            row.ID,
		RepoID:        row.RepoID,
		RefID:         row.RefID,
		SnapshotID:    uuidPtrFromNull(row.SnapshotID),
		Version:       row.Version,
		BuildMetadata: row.BuildMetadata,
		ArtifactIDs:   row.ArtifactIds,
		Provenance:    row.Provenance,
		PublishedAt:   timePtrFromNull(row.PublishedAt),
		CreatedAt:     row.CreatedAt,
		UpdatedAt:     row.UpdatedAt,
	}
}
