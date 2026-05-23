package rbac

import (
	"fmt"

	"github.com/google/uuid"
)

// SeedOrgPolicies creates the default RBAC policies for an org.
func (enf *Enforcer) SeedOrgPolicies(orgID uuid.UUID) error {
	org := fmt.Sprintf("org:%s", orgID)
	policies := [][]string{
		{fmt.Sprintf("role:admin:org:%s", orgID), org + "/*", "read"},
		{fmt.Sprintf("role:admin:org:%s", orgID), org + "/*", "write"},
		{fmt.Sprintf("role:admin:org:%s", orgID), org + "/*", "admin"},
		{fmt.Sprintf("role:admin:org:%s", orgID), org + "/*", "upload"},
		{fmt.Sprintf("role:admin:org:%s", orgID), org + "/*", "export"},
		{fmt.Sprintf("role:developer:org:%s", orgID), org + "/*", "read"},
		{fmt.Sprintf("role:developer:org:%s", orgID), org + "/*", "upload"},
		{fmt.Sprintf("role:release_manager:org:%s", orgID), org + "/*", "read"},
		{fmt.Sprintf("role:release_manager:org:%s", orgID), org + "/*", "write"},
		{fmt.Sprintf("role:release_manager:org:%s", orgID), org + "/*", "export"},
		{fmt.Sprintf("role:auditor:org:%s", orgID), org + "/*", "read"},
		{fmt.Sprintf("role:auditor:org:%s", orgID), org + "/*", "export"},
		{fmt.Sprintf("role:viewer:org:%s", orgID), org + "/*", "read"},
	}

	for _, policy := range policies {
		_, err := enf.e.AddPolicy(policy[0], policy[1], policy[2])
		if err != nil {
			return fmt.Errorf("adding policy %q %q %q: %w", policy[0], policy[1], policy[2], err)
		}
	}

	return nil
}
