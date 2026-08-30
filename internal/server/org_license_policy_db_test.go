package server

import (
	"context"
	"testing"

	"github.com/hibouhq/hibou/internal/license"
)

// The upsert relies on a PARTIAL unique index (one enabled policy per org) and
// an ON CONFLICT targeting that predicate. Both are easy to get wrong in a way
// no unit test would catch, so this exercises the real schema.
func TestOrgLicensePolicyUpsertAndSingleActiveConstraint(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	srv, org, _, _ := newDiscoveryTestServer(t)

	// No policy yet: nil, not an empty policy. The distinction matters — the
	// gate must not invent a fail-closed default the org never chose.
	existing, err := srv.queries.GetOrgLicensePolicy(ctx, org.ID)
	if err != nil {
		t.Fatalf("GetOrgLicensePolicy: %v", err)
	}
	if existing != nil {
		t.Fatalf("expected no policy, got %+v", existing)
	}

	spec := license.Spec{
		DenyCategories: []string{"copyleft", "network-copyleft"},
		Deny:           []string{"BUSL-1.1"},
		Allow:          []string{"GPL-2.0-only"},
		ExemptPurls:    []string{"pkg:npm/eslint-*"},
		DenyUnknown:    true,
		Evaluate:       license.EvaluateAll,
	}
	written, err := srv.queries.UpsertOrgLicensePolicy(ctx, org.ID, "default", spec, nil)
	if err != nil {
		t.Fatalf("UpsertOrgLicensePolicy: %v", err)
	}
	if len(written.DenyCategories) != 2 || written.Evaluate != license.EvaluateAll || !written.DenyUnknown {
		t.Fatalf("round-trip lost data: %+v", written)
	}
	if len(written.ExemptPurls) != 1 || written.ExemptPurls[0] != "pkg:npm/eslint-*" {
		t.Errorf("exempt_purls = %+v", written.ExemptPurls)
	}

	// A second write must UPDATE the same row rather than inserting a rival
	// policy — otherwise "the org policy" becomes ambiguous.
	updated, err := srv.queries.UpsertOrgLicensePolicy(ctx, org.ID, "default", license.Spec{
		DenyCategories: []string{"copyleft"},
		DenyUnknown:    false,
		Evaluate:       license.EvaluateNew,
	}, nil)
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	if len(updated.DenyCategories) != 1 || updated.DenyUnknown {
		t.Fatalf("update did not take: %+v", updated)
	}

	var enabledCount int
	if err := srv.db.QueryRowContext(ctx,
		`SELECT count(*) FROM license_policies WHERE org_id = $1 AND enabled`, org.ID,
	).Scan(&enabledCount); err != nil {
		t.Fatalf("count enabled: %v", err)
	}
	if enabledCount != 1 {
		t.Fatalf("enabled policies = %d, want exactly 1", enabledCount)
	}

	// Reading it back must produce the same spec the gate would apply.
	reread, err := srv.queries.GetOrgLicensePolicy(ctx, org.ID)
	if err != nil || reread == nil {
		t.Fatalf("re-read: %v (%+v)", err, reread)
	}
	if relation, differences := license.Compare(*updated, *reread); relation != license.RelationEquivalent {
		t.Errorf("re-read differs from what was written: %s %+v", relation, differences)
	}

	// Disabling retires the policy rather than deleting it.
	if err := srv.queries.DisableOrgLicensePolicy(ctx, org.ID, nil); err != nil {
		t.Fatalf("DisableOrgLicensePolicy: %v", err)
	}
	after, err := srv.queries.GetOrgLicensePolicy(ctx, org.ID)
	if err != nil {
		t.Fatalf("get after disable: %v", err)
	}
	if after != nil {
		t.Errorf("a disabled policy must not be returned, got %+v", after)
	}

	var rowCount int
	if err := srv.db.QueryRowContext(ctx,
		`SELECT count(*) FROM license_policies WHERE org_id = $1`, org.ID,
	).Scan(&rowCount); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if rowCount == 0 {
		t.Error("disabling must retire the row, not delete it")
	}

	// And a fresh policy can be enabled afterwards — the partial index must not
	// collide with the retired row.
	if _, err := srv.queries.UpsertOrgLicensePolicy(ctx, org.ID, "default", spec, nil); err != nil {
		t.Fatalf("re-enable after disable: %v", err)
	}
}
