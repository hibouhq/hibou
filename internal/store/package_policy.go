package store

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// PackagePolicyAcceptance is one accepted package version (ADR-048 §3).
type PackagePolicyAcceptance struct {
	ID         uuid.UUID  `json:"id"`
	OrgID      uuid.UUID  `json:"org_id"`
	RepoID     *uuid.UUID `json:"repo_id,omitempty"`
	Purl       string     `json:"purl"`
	Reason     string     `json:"reason"`
	AcceptedBy *uuid.UUID `json:"accepted_by,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

type UpsertPackagePolicyAcceptanceParams struct {
	OrgID      uuid.UUID
	RepoID     *uuid.UUID
	Purl       string
	Reason     string
	AcceptedBy *uuid.UUID
	ExpiresAt  *time.Time
}

func (q *Queries) UpsertPackagePolicyAcceptance(ctx context.Context, params UpsertPackagePolicyAcceptanceParams) (*PackagePolicyAcceptance, error) {
	row, err := q.db.UpsertPackagePolicyAcceptance(ctx, dbgen.UpsertPackagePolicyAcceptanceParams{
		OrgID:      params.OrgID,
		RepoID:     nullUUIDFromPtr(params.RepoID),
		Purl:       params.Purl,
		Reason:     params.Reason,
		AcceptedBy: nullUUIDFromPtr(params.AcceptedBy),
		ExpiresAt:  nullTimeFromPtr(params.ExpiresAt),
	})
	if err != nil {
		return nil, err
	}
	return packagePolicyAcceptanceFromRow(row), nil
}

func (q *Queries) DeletePackagePolicyAcceptance(ctx context.Context, orgID uuid.UUID, repoID *uuid.UUID, purl string) (bool, error) {
	rows, err := q.db.DeletePackagePolicyAcceptance(ctx, dbgen.DeletePackagePolicyAcceptanceParams{
		OrgID:  orgID,
		Purl:   purl,
		RepoID: nullUUIDFromPtr(repoID),
	})
	if err != nil {
		return false, err
	}
	return rows > 0, nil
}

// ListPackagePolicyAcceptancesForPurls returns the unexpired acceptances
// that apply to the purls in the org, org-wide ones and the repository's.
func (q *Queries) ListPackagePolicyAcceptancesForPurls(ctx context.Context, orgID uuid.UUID, repoID *uuid.UUID, purls []string) ([]PackagePolicyAcceptance, error) {
	if len(purls) == 0 {
		return []PackagePolicyAcceptance{}, nil
	}
	rows, err := q.db.ListPackagePolicyAcceptancesForPurls(ctx, dbgen.ListPackagePolicyAcceptancesForPurlsParams{
		OrgID:  orgID,
		Purls:  purls,
		RepoID: nullUUIDFromPtr(repoID),
	})
	if err != nil {
		return nil, err
	}
	out := make([]PackagePolicyAcceptance, 0, len(rows))
	for _, row := range rows {
		out = append(out, *packagePolicyAcceptanceFromRow(row))
	}
	return out, nil
}

func (q *Queries) ListPackagePolicyAcceptancesByOrg(ctx context.Context, orgID uuid.UUID, limit int32) ([]PackagePolicyAcceptance, error) {
	rows, err := q.db.ListPackagePolicyAcceptancesByOrg(ctx, dbgen.ListPackagePolicyAcceptancesByOrgParams{OrgID: orgID, RowLimit: limit})
	if err != nil {
		return nil, err
	}
	out := make([]PackagePolicyAcceptance, 0, len(rows))
	for _, row := range rows {
		out = append(out, *packagePolicyAcceptanceFromRow(row))
	}
	return out, nil
}

func packagePolicyAcceptanceFromRow(row dbgen.PackagePolicyAcceptance) *PackagePolicyAcceptance {
	out := &PackagePolicyAcceptance{
		ID:        row.ID,
		OrgID:     row.OrgID,
		Purl:      row.Purl,
		Reason:    row.Reason,
		CreatedAt: row.CreatedAt,
	}
	if row.RepoID.Valid {
		id := row.RepoID.UUID
		out.RepoID = &id
	}
	if row.AcceptedBy.Valid {
		id := row.AcceptedBy.UUID
		out.AcceptedBy = &id
	}
	if row.ExpiresAt.Valid {
		at := row.ExpiresAt.Time
		out.ExpiresAt = &at
	}
	return out
}
