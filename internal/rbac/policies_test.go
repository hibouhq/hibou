package rbac

import (
	"sort"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/google/uuid"
)

func newTestEnforcer(t *testing.T) *Enforcer {
	t.Helper()
	m, err := model.NewModelFromString(ModelText)
	if err != nil {
		t.Fatalf("model: %v", err)
	}
	e, err := casbin.NewEnforcer(m)
	if err != nil {
		t.Fatalf("enforcer: %v", err)
	}
	return &Enforcer{e: e}
}

func grantsFor(t *testing.T, enf *Enforcer, user uuid.UUID, orgID uuid.UUID) []string {
	t.Helper()
	granted := []string{}
	for _, action := range []string{ActionRead, ActionWrite, ActionAdmin, ActionUpload, ActionExport, ActionTriage} {
		ok, err := enf.CheckPermission(user.String(), OrgObject(orgID), action)
		if err != nil {
			t.Fatalf("enforce %s: %v", action, err)
		}
		if ok {
			granted = append(granted, action)
		}
	}
	sort.Strings(granted)
	return granted
}

// The hierarchy replaced five copied-out action lists. It must not have moved
// a single grant: this pins each base role's effective permissions to exactly
// what the flat form produced.
func TestRoleGrantsUnchangedByHierarchy(t *testing.T) {
	want := map[string][]string{
		RoleAdmin:          {"admin", "export", "read", "upload", "write"},
		RoleDeveloper:      {"read", "upload"},
		RoleReleaseManager: {"export", "read", "write"},
		RoleAuditor:        {"export", "read"},
		RoleViewer:         {"read"},
	}

	for role, expected := range want {
		enf := newTestEnforcer(t)
		orgID := uuid.New()
		if err := enf.SeedOrgPolicies(orgID); err != nil {
			t.Fatalf("seed: %v", err)
		}
		user := uuid.New()
		if err := enf.AddRoleForUserInOrg(user, role, orgID); err != nil {
			t.Fatalf("grant %s: %v", role, err)
		}
		got := grantsFor(t, enf, user, orgID)
		if len(got) != len(expected) {
			t.Fatalf("%s granted %v, want %v", role, got, expected)
		}
		for i := range got {
			if got[i] != expected[i] {
				t.Fatalf("%s granted %v, want %v", role, got, expected)
			}
		}
	}
}

// Authoring advisory data creates findings across every repo using a package.
// No forge-derived role may confer it, admin included.
func TestNoBaseRoleGrantsTriage(t *testing.T) {
	for _, role := range []string{RoleAdmin, RoleDeveloper, RoleReleaseManager, RoleAuditor, RoleViewer} {
		enf := newTestEnforcer(t)
		orgID := uuid.New()
		if err := enf.SeedOrgPolicies(orgID); err != nil {
			t.Fatalf("seed: %v", err)
		}
		user := uuid.New()
		if err := enf.AddRoleForUserInOrg(user, role, orgID); err != nil {
			t.Fatalf("grant: %v", err)
		}
		ok, err := enf.CanTriage(user, orgID)
		if err != nil {
			t.Fatalf("CanTriage: %v", err)
		}
		if ok {
			t.Errorf("base role %q conferred triage", role)
		}
	}
}

// A developer keeps their synced base role and is additionally granted triage:
// the multi-role case the members dropdown implies is impossible.
func TestLocalGrantIsAdditiveToBaseRole(t *testing.T) {
	enf := newTestEnforcer(t)
	orgID := uuid.New()
	if err := enf.SeedOrgPolicies(orgID); err != nil {
		t.Fatalf("seed: %v", err)
	}
	user := uuid.New()
	if err := enf.AddRoleForUserInOrg(user, RoleDeveloper, orgID); err != nil {
		t.Fatalf("base: %v", err)
	}
	if err := enf.AddLocalRoleForUserInOrg(user, RoleCVETriager, orgID); err != nil {
		t.Fatalf("local: %v", err)
	}

	if ok, _ := enf.CanTriage(user, orgID); !ok {
		t.Error("granted cve-triager but CanTriage is false")
	}
	// The base role is intact, and unchanged.
	base := enf.GetRolesForUserInOrg(user, orgID)
	if len(base) != 1 || base[0] != RoleDeveloper {
		t.Errorf("forge roles = %v, want [developer]", base)
	}
}

// The sync replaces the base role it wrote last time. That must never be able
// to name — and so revoke — an operator's local grant.
func TestSyncCannotTouchLocalRoles(t *testing.T) {
	enf := newTestEnforcer(t)
	orgID := uuid.New()
	if err := enf.SeedOrgPolicies(orgID); err != nil {
		t.Fatalf("seed: %v", err)
	}
	user := uuid.New()
	if err := enf.AddLocalRoleForUserInOrg(user, RoleCVETriager, orgID); err != nil {
		t.Fatalf("local: %v", err)
	}

	// A namespaced role name is refused outright on the sync path.
	for _, attempt := range []string{"local:cve-triager", "local:" + RoleCVETriager, ""} {
		if err := enf.AddRoleForUserInOrg(user, attempt, orgID); err == nil {
			t.Errorf("sync accepted role name %q", attempt)
		}
		if err := enf.RemoveRoleForUserInOrg(user, attempt, orgID); err == nil {
			t.Errorf("sync removed role name %q", attempt)
		}
	}

	// A full sync cycle — grant a base role, then replace it — leaves the
	// local grant standing.
	if err := enf.AddRoleForUserInOrg(user, RoleAdmin, orgID); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if err := enf.RemoveRoleForUserInOrg(user, RoleAdmin, orgID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := enf.AddRoleForUserInOrg(user, RoleViewer, orgID); err != nil {
		t.Fatalf("downgrade: %v", err)
	}
	if ok, _ := enf.CanTriage(user, orgID); !ok {
		t.Error("a forge downgrade revoked a local grant")
	}
}

// An instance grant covers every org, including ones created later.
func TestInstanceGrantSpansOrgs(t *testing.T) {
	enf := newTestEnforcer(t)
	if err := enf.SeedInstancePolicies(); err != nil {
		t.Fatalf("seed instance: %v", err)
	}
	orgA, orgB := uuid.New(), uuid.New()
	for _, orgID := range []uuid.UUID{orgA, orgB} {
		if err := enf.SeedOrgPolicies(orgID); err != nil {
			t.Fatalf("seed org: %v", err)
		}
	}
	user := uuid.New()
	if err := enf.AddLocalRoleForUserOnInstance(user, RoleCVETriager); err != nil {
		t.Fatalf("instance grant: %v", err)
	}

	for _, orgID := range []uuid.UUID{orgA, orgB} {
		if ok, _ := enf.CanTriage(user, orgID); !ok {
			t.Errorf("instance triager cannot triage org %s", orgID)
		}
	}
	// An org-scoped triager does not leak into another org.
	scoped := uuid.New()
	if err := enf.AddLocalRoleForUserInOrg(scoped, RoleCVETriager, orgA); err != nil {
		t.Fatalf("scoped grant: %v", err)
	}
	if ok, _ := enf.CanTriage(scoped, orgB); ok {
		t.Error("an org-scoped triager reached another org")
	}
}

// The cross-org question an operator must be able to answer before granting a
// role whose blast radius crosses orgs.
func TestGetLocalRolesForUser(t *testing.T) {
	enf := newTestEnforcer(t)
	orgA, orgB := uuid.New(), uuid.New()
	user := uuid.New()
	if err := enf.AddLocalRoleForUserInOrg(user, RoleCVETriager, orgA); err != nil {
		t.Fatal(err)
	}
	if err := enf.AddLocalRoleForUserInOrg(user, RoleSubscriptionWriter, orgB); err != nil {
		t.Fatal(err)
	}
	if err := enf.AddLocalRoleForUserOnInstance(user, RoleAdvisoryPromoter); err != nil {
		t.Fatal(err)
	}
	if err := enf.AddRoleForUserInOrg(user, RoleDeveloper, orgA); err != nil {
		t.Fatal(err)
	}

	orgScoped, instanceScoped := enf.GetLocalRolesForUser(user)
	if len(instanceScoped) != 1 || instanceScoped[0] != RoleAdvisoryPromoter {
		t.Errorf("instance roles = %v", instanceScoped)
	}
	if len(orgScoped) != 2 {
		t.Fatalf("org-scoped roles = %v", orgScoped)
	}
	if got := orgScoped[orgA]; len(got) != 1 || got[0] != RoleCVETriager {
		t.Errorf("orgA local roles = %v, want [cve-triager] (the forge role must not appear)", got)
	}
}

// Regression test for a cross-tenant authorization bug.
//
// The model matched objects with keyMatch2, which reads ":name" as a named
// parameter and rewrites it to a wildcard. The policy object "org:<uuid>/*"
// therefore compiled to "^org[^/]+/.*$" and matched EVERY organization: a role
// held in one org authorized the same actions in all the others. The matcher is
// keyMatch, which is literal up to the "*"; this pins that.
func TestOrgPoliciesDoNotCrossOrgs(t *testing.T) {
	enf := newTestEnforcer(t)
	orgA, orgB := uuid.New(), uuid.New()
	for _, orgID := range []uuid.UUID{orgA, orgB} {
		if err := enf.SeedOrgPolicies(orgID); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	admin := uuid.New()
	if err := enf.AddRoleForUserInOrg(admin, RoleAdmin, orgA); err != nil {
		t.Fatalf("grant: %v", err)
	}

	for _, action := range []string{ActionRead, ActionWrite, ActionAdmin, ActionUpload, ActionExport} {
		ok, err := enf.CheckPermission(admin.String(), OrgObject(orgA), action)
		if err != nil {
			t.Fatalf("enforce own org: %v", err)
		}
		if !ok {
			t.Errorf("admin of org A denied %q in org A", action)
		}

		leaked, err := enf.CheckPermission(admin.String(), OrgObject(orgB), action)
		if err != nil {
			t.Fatalf("enforce other org: %v", err)
		}
		if leaked {
			t.Errorf("admin of org A was granted %q in org B", action)
		}
	}

	// A concrete resource, not just the org-wide pattern.
	if leaked, _ := enf.CheckPermission(admin.String(), "org:"+orgB.String()+"/repo:x", ActionAdmin); leaked {
		t.Error("admin of org A reached a repository in org B")
	}
}

// Instance-scoped objects must not be reachable from an org-scoped role either.
func TestOrgRoleDoesNotReachInstanceObjects(t *testing.T) {
	enf := newTestEnforcer(t)
	orgID := uuid.New()
	if err := enf.SeedOrgPolicies(orgID); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	if err := enf.SeedInstancePolicies(); err != nil {
		t.Fatalf("seed instance: %v", err)
	}
	admin := uuid.New()
	if err := enf.AddRoleForUserInOrg(admin, RoleAdmin, orgID); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if leaked, _ := enf.CheckPermission(admin.String(), InstanceObject, ActionAdmin); leaked {
		t.Error("an org admin reached instance-scoped objects")
	}
}
