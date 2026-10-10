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

// Release sources: what derived the row (ADR-024 §5) — a version tag with an
// analysis snapshot, or a forge release event. Releases are never hand-created.
const (
	ReleaseSourceTag   = "tag"
	ReleaseSourceForge = "forge"
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
	HTMLURL       *string         `json:"html_url,omitempty"`
	Source        string          `json:"source"`
	PublishedAt   *time.Time      `json:"published_at,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
	// Re-tag divergence (ADR-024 §5): the tag now points at a different commit
	// than the analyzed build clients run. Nil = aligned.
	PendingSnapshotID *uuid.UUID `json:"pending_snapshot_id,omitempty"`
	DivergedAt        *time.Time `json:"diverged_at,omitempty"`
	// Commit a manager chose to ignore ("keep old build"); derivation-internal.
	DismissedCommitSHA string `json:"-"`
}

// ReleaseClient is one client currently on a release (an active deployment),
// as aggregated by the enriched listing query.
type ReleaseClient struct {
	DeploymentID uuid.UUID `json:"deployment_id"`
	ClientID     uuid.UUID `json:"client_id"`
	Slug         string    `json:"slug"`
	Name         string    `json:"name"`
	Environment  string    `json:"environment"`
	DeployedAt   time.Time `json:"deployed_at"`
}

// ReleaseWithRisk is a release plus the open-risk posture of its pinned
// snapshot and the clients currently running it (ADR-024 §3).
type ReleaseWithRisk struct {
	Release
	RefName          string          `json:"ref_name"`
	CommitSHA        string          `json:"commit_sha,omitempty"`
	PendingCommitSHA string          `json:"pending_commit_sha,omitempty"`
	CriticalCount    int64           `json:"critical_count"`
	HighCount        int64           `json:"high_count"`
	MediumCount      int64           `json:"medium_count"`
	LowCount         int64           `json:"low_count"`
	KEVOpen          *int64          `json:"kev_open"`
	MalwareOpen      int64           `json:"malware_open"`
	OpenFindingCount int64           `json:"open_finding_count"`
	LastScannedAt    *time.Time      `json:"last_scanned_at,omitempty"`
	Clients          []ReleaseClient `json:"clients"`
}

// ReleaseListFilters narrows the enriched release listing. Zero values mean
// "no filter".
type ReleaseListFilters struct {
	VersionQuery   string
	ClientSlug     string
	VulnerableOnly bool
}

type UpsertReleaseParams struct {
	RepoID        uuid.UUID
	RefID         uuid.UUID
	SnapshotID    *uuid.UUID
	Version       string
	BuildMetadata json.RawMessage
	ArtifactIDs   json.RawMessage
	Provenance    json.RawMessage
	HTMLURL       *string
	Source        string
	PublishedAt   *time.Time
}

// UpsertRelease creates or converges a release row on its (repo, version)
// identity: NULLs and empty JSON payloads keep the stored value (ADR-024 §5).
func (q *Queries) UpsertRelease(ctx context.Context, params UpsertReleaseParams) (*Release, error) {
	source := params.Source
	if source == "" {
		source = ReleaseSourceTag
	}
	row, err := q.db.UpsertRelease(ctx, dbgen.UpsertReleaseParams{
		RepoID:        params.RepoID,
		RefID:         params.RefID,
		SnapshotID:    nullUUIDFromPtr(params.SnapshotID),
		Version:       params.Version,
		BuildMetadata: defaultJSON(params.BuildMetadata, []byte("{}")),
		ArtifactIds:   defaultJSON(params.ArtifactIDs, []byte("[]")),
		Provenance:    defaultJSON(params.Provenance, []byte("{}")),
		PublishedAt:   nullTimeFromPtr(params.PublishedAt),
		HtmlUrl:       nullStringFromPtr(params.HTMLURL),
		Source:        source,
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

func (q *Queries) GetReleaseByRepoAndID(ctx context.Context, repoID, id uuid.UUID) (*Release, error) {
	row, err := q.db.GetReleaseByRepoAndID(ctx, dbgen.GetReleaseByRepoAndIDParams{RepoID: repoID, ID: id})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return releaseFromRow(row), nil
}

func (q *Queries) ListReleasesByRepo(ctx context.Context, repoID uuid.UUID, limit, offset int) ([]Release, int, error) {
	rows, err := q.db.ListReleasesByRepo(ctx, dbgen.ListReleasesByRepoParams{RepoID: repoID, Limit: int32(limit), Offset: int32(offset)}) // #nosec G115 -- pagination values are bounded by API parsing.
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

// ListReleasesWithRiskByRepo returns the enriched release listing for the
// Releases tab, newest first.
func (q *Queries) ListReleasesWithRiskByRepo(ctx context.Context, repoID uuid.UUID, filters ReleaseListFilters, limit, offset int) ([]ReleaseWithRisk, int, error) {
	rows, err := q.db.ListReleasesWithRiskByRepo(ctx, dbgen.ListReleasesWithRiskByRepoParams{
		RepoID:         repoID,
		VersionQuery:   filters.VersionQuery,
		ClientSlug:     filters.ClientSlug,
		VulnerableOnly: filters.VulnerableOnly,
		RowLimit:       int32(limit),  // #nosec G115 -- pagination values are bounded by API parsing.
		RowOffset:      int32(offset), // #nosec G115 -- pagination values are bounded by API parsing.
	})
	if err != nil {
		return nil, 0, err
	}

	releases := make([]ReleaseWithRisk, len(rows))
	for i, row := range rows {
		kevOpen := row.KevOpen
		enriched := ReleaseWithRisk{
			Release: Release{
				ID:                row.ID,
				RepoID:            row.RepoID,
				RefID:             row.RefID,
				SnapshotID:        uuidPtrFromNull(row.SnapshotID),
				Version:           row.Version,
				BuildMetadata:     row.BuildMetadata,
				ArtifactIDs:       row.ArtifactIds,
				Provenance:        row.Provenance,
				HTMLURL:           stringPtrFromNull(row.HtmlUrl),
				Source:            row.Source,
				PublishedAt:       timePtrFromNull(row.PublishedAt),
				CreatedAt:         row.CreatedAt,
				UpdatedAt:         row.UpdatedAt,
				PendingSnapshotID: uuidPtrFromNull(row.PendingSnapshotID),
				DivergedAt:        timePtrFromNull(row.DivergedAt),
			},
			RefName:          row.RefName,
			CommitSHA:        row.CommitSha.String,
			PendingCommitSHA: row.PendingCommitSha.String,
			CriticalCount:    row.CriticalCount,
			HighCount:        row.HighCount,
			MediumCount:      row.MediumCount,
			LowCount:         row.LowCount,
			KEVOpen:          &kevOpen,
			MalwareOpen:      row.MalwareOpen,
			OpenFindingCount: row.OpenFindingCount,
			Clients:          []ReleaseClient{},
		}
		// The query COALESCEs "never scanned" to the epoch (nullable MAX).
		if row.LastScannedAt.Unix() > 0 {
			scannedAt := row.LastScannedAt
			enriched.LastScannedAt = &scannedAt
		}
		if len(row.Clients) > 0 {
			if err := json.Unmarshal(row.Clients, &enriched.Clients); err != nil {
				return nil, 0, err
			}
		}
		releases[i] = enriched
	}

	total, err := q.db.CountReleasesWithRiskByRepo(ctx, dbgen.CountReleasesWithRiskByRepoParams{
		RepoID:         repoID,
		VersionQuery:   filters.VersionQuery,
		ClientSlug:     filters.ClientSlug,
		VulnerableOnly: filters.VulnerableOnly,
	})
	if err != nil {
		return nil, 0, err
	}

	return releases, int(total), nil
}

func (q *Queries) ListReleasesByOrg(ctx context.Context, orgID uuid.UUID, limit, offset int) ([]Release, int, error) {
	rows, err := q.db.ListReleasesByOrg(ctx, dbgen.ListReleasesByOrgParams{OrgID: orgID, Limit: int32(limit), Offset: int32(offset)}) // #nosec G115 -- pagination values are bounded by API parsing.
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

// CountReleasesBySnapshotExcluding reports how many releases other than the
// given one still pin a snapshot — the unpin guard for release deletion.
func (q *Queries) CountReleasesBySnapshotExcluding(ctx context.Context, snapshotID, excludedReleaseID uuid.UUID) (int64, error) {
	return q.db.CountReleasesBySnapshotExcluding(ctx, dbgen.CountReleasesBySnapshotExcludingParams{
		SnapshotID: uuid.NullUUID{UUID: snapshotID, Valid: true},
		ID:         excludedReleaseID,
	})
}

// ListReleasePinnedSnapshotIDs returns the distinct snapshots referenced by
// any release, for the advisory refresh worker (ADR-024 §6).
func (q *Queries) ListReleasePinnedSnapshotIDs(ctx context.Context) ([]uuid.UUID, error) {
	rows, err := q.db.ListReleasePinnedSnapshotIDs(ctx)
	if err != nil {
		return nil, err
	}
	ids := make([]uuid.UUID, 0, len(rows))
	for _, row := range rows {
		if row.Valid {
			ids = append(ids, row.UUID)
		}
	}
	return ids, nil
}

func (q *Queries) GetReleaseByRepoVersion(ctx context.Context, repoID uuid.UUID, version string) (*Release, error) {
	row, err := q.db.GetReleaseByRepoVersion(ctx, dbgen.GetReleaseByRepoVersionParams{RepoID: repoID, Version: version})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return releaseFromRow(row), nil
}

// SetReleaseSnapshot repoints a release to a snapshot and clears any pending
// divergence (initial derivation refresh, or adopting a re-tagged build).
func (q *Queries) SetReleaseSnapshot(ctx context.Context, id, snapshotID uuid.UUID) (*Release, error) {
	row, err := q.db.SetReleaseSnapshot(ctx, dbgen.SetReleaseSnapshotParams{
		ID:         id,
		SnapshotID: uuid.NullUUID{UUID: snapshotID, Valid: true},
	})
	if err != nil {
		return nil, err
	}
	return releaseFromRow(row), nil
}

// SetReleaseDivergence records a re-tag candidate instead of silently
// repointing a release clients are running (ADR-024 §5).
func (q *Queries) SetReleaseDivergence(ctx context.Context, id, pendingSnapshotID uuid.UUID) (*Release, error) {
	row, err := q.db.SetReleaseDivergence(ctx, dbgen.SetReleaseDivergenceParams{
		ID:                id,
		PendingSnapshotID: uuid.NullUUID{UUID: pendingSnapshotID, Valid: true},
	})
	if err != nil {
		return nil, err
	}
	return releaseFromRow(row), nil
}

// DismissReleaseDivergence keeps the old build and remembers the dismissed
// commit so the same candidate does not re-flag.
func (q *Queries) DismissReleaseDivergence(ctx context.Context, id uuid.UUID, dismissedCommitSHA string) (*Release, error) {
	row, err := q.db.DismissReleaseDivergence(ctx, dbgen.DismissReleaseDivergenceParams{
		ID:                 id,
		DismissedCommitSha: sql.NullString{String: dismissedCommitSHA, Valid: dismissedCommitSHA != ""},
	})
	if err != nil {
		return nil, err
	}
	return releaseFromRow(row), nil
}

func (q *Queries) DeleteRelease(ctx context.Context, id uuid.UUID) error {
	return q.db.DeleteRelease(ctx, id)
}

func releaseFromRow(row dbgen.Release) *Release {
	return &Release{
		ID:                 row.ID,
		RepoID:             row.RepoID,
		RefID:              row.RefID,
		SnapshotID:         uuidPtrFromNull(row.SnapshotID),
		Version:            row.Version,
		BuildMetadata:      row.BuildMetadata,
		ArtifactIDs:        row.ArtifactIds,
		Provenance:         row.Provenance,
		HTMLURL:            stringPtrFromNull(row.HtmlUrl),
		Source:             row.Source,
		PublishedAt:        timePtrFromNull(row.PublishedAt),
		CreatedAt:          row.CreatedAt,
		UpdatedAt:          row.UpdatedAt,
		PendingSnapshotID:  uuidPtrFromNull(row.PendingSnapshotID),
		DivergedAt:         timePtrFromNull(row.DivergedAt),
		DismissedCommitSHA: row.DismissedCommitSha.String,
	}
}

// AttachSnapshotToReleasesByRef adopts a newly completed snapshot on the
// snapshot-less releases of its ref (webhook-before-upload race, ADR-024 §5).
// Returns the number of releases attached.
func (q *Queries) AttachSnapshotToReleasesByRef(ctx context.Context, refID, snapshotID uuid.UUID) (int64, error) {
	return q.db.AttachSnapshotToReleasesByRef(ctx, dbgen.AttachSnapshotToReleasesByRefParams{
		RefID:      refID,
		SnapshotID: uuid.NullUUID{UUID: snapshotID, Valid: true},
	})
}
