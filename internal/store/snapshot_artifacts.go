package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type SnapshotArtifact struct {
	ID          uuid.UUID `json:"id"`
	SnapshotID  uuid.UUID `json:"snapshot_id"`
	Kind        string    `json:"kind"`
	Format      *string   `json:"format,omitempty"`
	ToolName    *string   `json:"tool_name,omitempty"`
	ObjectKey   string    `json:"object_key"`
	SHA256      *string   `json:"sha256,omitempty"`
	SizeBytes   int64     `json:"size_bytes"`
	ContentType *string   `json:"content_type,omitempty"`
	Filename    string    `json:"filename,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	// What the uploader declared about the run (ADR-034 §2); SARIF values
	// win when both are present.
	Scope        *string  `json:"scope,omitempty"`
	ScopePaths   []string `json:"scope_paths,omitempty"`
	ToolVersion  *string  `json:"tool_version,omitempty"`
	ConfigDigest *string  `json:"config_digest,omitempty"`
	// PlanID / PlanJobID bind the artifact to the scan plan job that
	// produced it (ADR-035 §4); nil for unplanned reports.
	PlanID    *uuid.UUID `json:"plan_id,omitempty"`
	PlanJobID *string    `json:"plan_job_id,omitempty"`
}

type CreateSnapshotArtifactParams struct {
	SnapshotID  uuid.UUID
	Kind        string
	Format      *string
	ToolName    *string
	ObjectKey   string
	SHA256      *string
	SizeBytes   int64
	ContentType *string
	Filename    string
}

func (q *Queries) CreateSnapshotArtifact(ctx context.Context, params CreateSnapshotArtifactParams) (*SnapshotArtifact, error) {
	row, err := q.db.CreateSnapshotArtifact(ctx, dbgen.CreateSnapshotArtifactParams{
		SnapshotID:  params.SnapshotID,
		Kind:        params.Kind,
		Format:      nullStringFromPtr(params.Format),
		ToolName:    nullStringFromPtr(params.ToolName),
		ObjectKey:   params.ObjectKey,
		Sha256:      nullStringFromPtr(params.SHA256),
		SizeBytes:   params.SizeBytes,
		ContentType: nullStringFromPtr(params.ContentType),
		Filename:    params.Filename,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return snapshotArtifactFromRow(row), nil
}

func (q *Queries) ListSnapshotArtifactsBySnapshot(ctx context.Context, snapshotID uuid.UUID) ([]SnapshotArtifact, error) {
	rows, err := q.db.ListSnapshotArtifactsBySnapshot(ctx, snapshotID)
	if err != nil {
		return nil, err
	}

	artifacts := make([]SnapshotArtifact, len(rows))
	for i, row := range rows {
		artifacts[i] = *snapshotArtifactFromRow(row)
	}

	return artifacts, nil
}

func (q *Queries) GetSnapshotArtifactByID(ctx context.Context, id uuid.UUID) (*SnapshotArtifact, error) {
	row, err := q.db.GetSnapshotArtifactByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return snapshotArtifactFromRow(row), nil
}

func (q *Queries) ListSnapshotArtifactObjectKeys(ctx context.Context, snapshotID uuid.UUID) ([]string, error) {
	return q.db.ListSnapshotArtifactObjectKeys(ctx, snapshotID)
}

// ListSnapshotArtifactObjectKeysByRepo returns every object-store key for all
// snapshots under a repository, for cleanup before a repository hard delete.
func (q *Queries) ListSnapshotArtifactObjectKeysByRepo(ctx context.Context, repoID uuid.UUID) ([]string, error) {
	return q.db.ListSnapshotArtifactObjectKeysByRepo(ctx, repoID)
}

// ListSnapshotArtifactObjectKeysByOrg returns every object-store key for all
// snapshots under an organization, for cleanup before an org hard delete.
func (q *Queries) ListSnapshotArtifactObjectKeysByOrg(ctx context.Context, orgID uuid.UUID) ([]string, error) {
	return q.db.ListSnapshotArtifactObjectKeysByOrg(ctx, orgID)
}

func snapshotArtifactFromRow(row dbgen.SnapshotArtifact) *SnapshotArtifact {
	return &SnapshotArtifact{
		ID:           row.ID,
		SnapshotID:   row.SnapshotID,
		Kind:         row.Kind,
		Format:       stringPtrFromNull(row.Format),
		ToolName:     stringPtrFromNull(row.ToolName),
		ObjectKey:    row.ObjectKey,
		SHA256:       stringPtrFromNull(row.Sha256),
		SizeBytes:    row.SizeBytes,
		ContentType:  stringPtrFromNull(row.ContentType),
		Filename:     row.Filename,
		CreatedAt:    row.CreatedAt,
		Scope:        stringPtrFromNull(row.Scope),
		ScopePaths:   row.ScopePaths,
		ToolVersion:  stringPtrFromNull(row.ToolVersion),
		ConfigDigest: stringPtrFromNull(row.ConfigDigest),
		PlanID:       uuidPtrFromNull(row.PlanID),
		PlanJobID:    stringPtrFromNull(row.PlanJobID),
	}
}

// ArtifactRunDeclaration is the run metadata an uploader may send with an
// artifact: scope, the paths a partial scan covered, and the tool's version
// and configuration digest.
type ArtifactRunDeclaration struct {
	Scope        *string
	ScopePaths   []string
	ToolVersion  *string
	ConfigDigest *string
}

// Empty reports whether nothing was declared.
func (d ArtifactRunDeclaration) Empty() bool {
	return d.Scope == nil && len(d.ScopePaths) == 0 && d.ToolVersion == nil && d.ConfigDigest == nil
}

func (q *Queries) SetSnapshotArtifactRunDeclaration(ctx context.Context, artifactID uuid.UUID, declaration ArtifactRunDeclaration) error {
	paths := declaration.ScopePaths
	if paths == nil {
		paths = []string{}
	}
	return q.db.SetSnapshotArtifactRunDeclaration(ctx, dbgen.SetSnapshotArtifactRunDeclarationParams{
		ID:           artifactID,
		Scope:        nullStringFromPtr(declaration.Scope),
		ScopePaths:   paths,
		ToolVersion:  nullStringFromPtr(declaration.ToolVersion),
		ConfigDigest: nullStringFromPtr(declaration.ConfigDigest),
	})
}
