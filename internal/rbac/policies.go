package rbac

import (
	"fmt"

	"github.com/google/uuid"
)

// Org roles derived from a forge. These are owned by the permission sync: it
// computes one per (user, org) from forge membership and replaces the previous
// one on every run, so nothing set by hand in hibou survives here.
const (
	RoleAdmin          = "admin"
	RoleDeveloper      = "developer"
	RoleReleaseManager = "release_manager"
	RoleAuditor        = "auditor"
	RoleViewer         = "viewer"
)

// Local roles, granted in hibou and never touched by the permission sync.
//
// They exist because no forge has an opinion about them. A forge knows who can
// push to a repository; it has no concept of who may author advisory data for
// an organisation. Two of the roles the members UI already offers —
// release_manager and auditor — are in the same position: `roleRank` in the
// permission sync scores only admin/developer/viewer, so a forge sweep can
// never produce them. This namespace makes that existing reality explicit
// rather than inventing a new concept.
const (
	// RoleCVETriager may map a CVE to package coordinates. That authors
	// advisory data, which creates findings on every repository using the
	// package — so it is granted explicitly and never inherited from a base
	// role.
	RoleCVETriager = "cve-triager"
	// RoleSubscriptionWriter may create and edit watched-product subscriptions.
	RoleSubscriptionWriter = "subscription-writer"
	// RoleAdvisoryPromoter may propose an org-scoped mapping for instance-wide
	// use. Instance scope only.
	RoleAdvisoryPromoter = "advisory-promoter"
)

// Actions. `triage` is new: authoring advisory data is not "write" on an
// organisation's ordinary resources, and collapsing the two would hand it to
// every developer.
const (
	ActionRead   = "read"
	ActionWrite  = "write"
	ActionAdmin  = "admin"
	ActionUpload = "upload"
	ActionExport = "export"
	ActionTriage = "triage"
)

// SeedOrgPolicies creates the default RBAC policies for an org.
//
// Roles are expressed as increments over one another rather than as five
// copied-out action lists: Casbin's `g` relation chains, so a role grouped
// under another inherits its policies with no model change. The effective
// permission set is identical to the flat form it replaces — TestRoleGrants
// pins every role's grants so that stays true.
func (enf *Enforcer) SeedOrgPolicies(orgID uuid.UUID) error {
	org := fmt.Sprintf("org:%s", orgID)
	all := org + "/*"

	policies := [][]string{
		// viewer is the floor everything else builds on.
		{orgRoleKey(RoleViewer, orgID), all, ActionRead},

		{orgRoleKey(RoleDeveloper, orgID), all, ActionUpload},

		{orgRoleKey(RoleReleaseManager, orgID), all, ActionWrite},
		{orgRoleKey(RoleReleaseManager, orgID), all, ActionExport},

		{orgRoleKey(RoleAuditor, orgID), all, ActionExport},

		{orgRoleKey(RoleAdmin, orgID), all, ActionAdmin},

		// Local roles: granted in hibou, never synced. Triage is deliberately
		// absent from every base role above.
		{localOrgRoleKey(RoleCVETriager, orgID), all, ActionTriage},
		{localOrgRoleKey(RoleSubscriptionWriter, orgID), all, ActionWrite},
	}
	for _, policy := range policies {
		if _, err := enf.e.AddPolicy(policy[0], policy[1], policy[2]); err != nil {
			return fmt.Errorf("adding policy %q %q %q: %w", policy[0], policy[1], policy[2], err)
		}
	}

	// Role hierarchy. admin inherits every other base role; the rest inherit
	// viewer. Nothing inherits a local role — that is the whole point of them.
	hierarchy := [][2]string{
		{RoleDeveloper, RoleViewer},
		{RoleReleaseManager, RoleViewer},
		{RoleAuditor, RoleViewer},
		{RoleAdmin, RoleDeveloper},
		{RoleAdmin, RoleReleaseManager},
		{RoleAdmin, RoleAuditor},
	}
	for _, pair := range hierarchy {
		if _, err := enf.e.AddGroupingPolicy(orgRoleKey(pair[0], orgID), orgRoleKey(pair[1], orgID)); err != nil {
			return fmt.Errorf("adding role hierarchy %s -> %s: %w", pair[0], pair[1], err)
		}
	}
	return nil
}

// SeedInstancePolicies creates the instance-scoped policies.
//
// Nothing instance-scoped existed before: every key was `…:org:<uuid>` and every
// object `org:<uuid>/*`, so a decision that applies to every org on the instance
// had nowhere to live. The existing instance-admin list is not a substitute —
// it is a static, email-keyed config list scoped to banners and the instance
// audit log, and widening its meaning would make anyone who can edit an
// announcement able to author findings for every tenant.
func (enf *Enforcer) SeedInstancePolicies() error {
	policies := [][]string{
		{instanceRoleKey(RoleCVETriager), InstanceObject, ActionTriage},
		{instanceRoleKey(RoleSubscriptionWriter), InstanceObject, ActionWrite},
		{instanceRoleKey(RoleAdvisoryPromoter), InstanceObject, ActionAdmin},
	}
	for _, policy := range policies {
		if _, err := enf.e.AddPolicy(policy[0], policy[1], policy[2]); err != nil {
			return fmt.Errorf("adding instance policy %q %q %q: %w", policy[0], policy[1], policy[2], err)
		}
	}
	return nil
}
