package rbac

import (
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// Role keys carry their own ownership, so a caller cannot accidentally write
// into the wrong namespace:
//
//	role:<name>:org:<uuid>          forge-derived, owned by the permission sync
//	role:local:<name>:org:<uuid>    granted in hibou, sync must never touch it
//	role:local:<name>:instance      granted in hibou, applies to every org
//
// The forge form is unchanged from before this split, so existing grouping
// policies keep working with no migration.
const (
	rolePrefix      = "role:"
	localPrefix     = "role:local:"
	instanceSuffix  = ":instance"
	orgSuffixFormat = ":org:%s"

	// InstanceObject is the object pattern for instance-scoped permissions.
	InstanceObject = "instance/*"
)

func orgRoleKey(role string, orgID uuid.UUID) string {
	return fmt.Sprintf("role:%s:org:%s", role, orgID)
}

func localOrgRoleKey(role string, orgID uuid.UUID) string {
	return fmt.Sprintf("role:local:%s:org:%s", role, orgID)
}

func instanceRoleKey(role string) string {
	return "role:local:" + role + instanceSuffix
}

// OrgObject is the object pattern covering everything in one org.
func OrgObject(orgID uuid.UUID) string {
	return fmt.Sprintf("org:%s/*", orgID)
}

// isLocalRoleKey reports whether a key belongs to the operator-owned namespace.
func isLocalRoleKey(key string) bool {
	return strings.HasPrefix(key, localPrefix)
}

// validateSyncRole rejects a role name that would let the permission sync write
// into the local namespace.
//
// The sync computes a role from forge membership and replaces the one it set
// last time. If a local grant could be produced by that path, a forge sweep
// could silently revoke a capability an operator granted deliberately — the
// grant survives today only because the sync happens to remove just the role it
// previously wrote, which is an accident rather than a guarantee.
func validateSyncRole(role string) error {
	if strings.TrimSpace(role) == "" {
		return errors.New("rbac: empty role name")
	}
	if strings.Contains(role, ":") {
		return fmt.Errorf("rbac: %q is not a forge-derived role name", role)
	}
	return nil
}
