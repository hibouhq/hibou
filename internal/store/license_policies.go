package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/license"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// GetOrgLicensePolicy returns the org's active license policy, or nil when none
// is set. Nil means "no policy", which is different from an empty policy: the
// caller must not invent a fail-closed default the org never chose.
func (q *Queries) GetOrgLicensePolicy(ctx context.Context, orgID uuid.UUID) (*license.Spec, error) {
	row, err := q.db.GetOrgLicensePolicy(ctx, orgID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	spec := licenseSpecFromRow(row)
	return &spec, nil
}

// UpsertOrgLicensePolicy writes the org's single active policy.
func (q *Queries) UpsertOrgLicensePolicy(ctx context.Context, orgID uuid.UUID, name string, spec license.Spec, updatedBy *uuid.UUID) (*license.Spec, error) {
	row, err := q.db.UpsertOrgLicensePolicy(ctx, dbgen.UpsertOrgLicensePolicyParams{
		OrgID:            orgID,
		Name:             name,
		AllowedLicenses:  nonNilStrings(spec.Allow),
		DeniedLicenses:   nonNilStrings(spec.Deny),
		DeniedCategories: nonNilStrings(spec.DenyCategories),
		ExemptPurls:      nonNilStrings(spec.ExemptPurls),
		DenyUnknown:      spec.DenyUnknown,
		Evaluate:         spec.EvaluateValue(),
		UpdatedBy:        nullableUUID(updatedBy),
	})
	if err != nil {
		return nil, err
	}
	written := licenseSpecFromRow(row)
	return &written, nil
}

// DisableOrgLicensePolicy retires the policy without deleting it, so the last
// enforced policy stays inspectable and re-enabling revives the same row.
func (q *Queries) DisableOrgLicensePolicy(ctx context.Context, orgID uuid.UUID, updatedBy *uuid.UUID) error {
	return q.db.DisableOrgLicensePolicy(ctx, dbgen.DisableOrgLicensePolicyParams{
		OrgID:     orgID,
		UpdatedBy: nullableUUID(updatedBy),
	})
}

// licenseSpecFromRow maps the stored row onto the shared declarative type. The
// column names predate the current model: allowed_licenses/denied_licenses are
// the id-glob allow and deny lists.
func licenseSpecFromRow(row dbgen.LicensePolicy) license.Spec {
	return license.Spec{
		DenyCategories: row.DeniedCategories,
		Deny:           row.DeniedLicenses,
		Allow:          row.AllowedLicenses,
		ExemptPurls:    row.ExemptPurls,
		DenyUnknown:    row.DenyUnknown,
		Evaluate:       row.Evaluate,
	}
}

func nullableUUID(value *uuid.UUID) uuid.NullUUID {
	if value == nil {
		return uuid.NullUUID{}
	}
	return uuid.NullUUID{UUID: *value, Valid: true}
}
