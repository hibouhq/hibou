package rbac

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/google/uuid"
)

// Enforcer wraps Casbin with project-specific helper methods.
type Enforcer struct {
	e *casbin.Enforcer
}

// New creates a new RBAC enforcer backed by the given database.
func New(db *sql.DB) (*Enforcer, error) {
	m, err := model.NewModelFromString(ModelText)
	if err != nil {
		return nil, fmt.Errorf("loading rbac model: %w", err)
	}

	adapter := NewAdapter(db)
	e, err := casbin.NewEnforcer(m, adapter)
	if err != nil {
		return nil, fmt.Errorf("creating enforcer: %w", err)
	}

	if err := e.LoadPolicy(); err != nil {
		return nil, fmt.Errorf("loading policies: %w", err)
	}

	return &Enforcer{e: e}, nil
}

func (enf *Enforcer) CheckPermission(sub, obj, act string) (bool, error) {
	return enf.e.Enforce(sub, obj, act)
}

// AddRoleForUserInOrg grants a forge-derived base role.
//
// Owned by the permission sync. The role name must be a bare name — anything
// namespaced is refused, so this path can never reach an operator's local
// grant.
func (enf *Enforcer) AddRoleForUserInOrg(userID uuid.UUID, role string, orgID uuid.UUID) error {
	if err := validateSyncRole(role); err != nil {
		return err
	}
	if _, err := enf.e.AddGroupingPolicy(userID.String(), orgRoleKey(role, orgID)); err != nil {
		return fmt.Errorf("adding grouping policy: %w", err)
	}
	return nil
}

// RemoveRoleForUserInOrg revokes a forge-derived base role. Local grants are
// out of reach here by construction; see AddRoleForUserInOrg.
func (enf *Enforcer) RemoveRoleForUserInOrg(userID uuid.UUID, role string, orgID uuid.UUID) error {
	if err := validateSyncRole(role); err != nil {
		return err
	}
	if _, err := enf.e.RemoveGroupingPolicy(userID.String(), orgRoleKey(role, orgID)); err != nil {
		return fmt.Errorf("removing grouping policy: %w", err)
	}
	return nil
}

// GetRolesForUserInOrg lists the user's forge-derived roles in an org.
//
// Local grants are excluded: callers of this function are asking what the forge
// says about a user, and folding an operator's deliberate grant into that answer
// would make the sync's "replace what I set last time" logic revoke it.
func (enf *Enforcer) GetRolesForUserInOrg(userID uuid.UUID, orgID uuid.UUID) []string {
	roles, err := enf.e.GetRolesForUser(userID.String())
	if err != nil {
		return nil
	}

	suffix := fmt.Sprintf(orgSuffixFormat, orgID)
	result := make([]string, 0, len(roles))
	for _, role := range roles {
		if isLocalRoleKey(role) {
			continue
		}
		if !strings.HasPrefix(role, rolePrefix) || !strings.HasSuffix(role, suffix) {
			continue
		}
		result = append(result, strings.TrimSuffix(strings.TrimPrefix(role, rolePrefix), suffix))
	}

	return result
}

// AddLocalRoleForUserInOrg grants an operator-owned role scoped to one org.
func (enf *Enforcer) AddLocalRoleForUserInOrg(userID uuid.UUID, role string, orgID uuid.UUID) error {
	if _, err := enf.e.AddGroupingPolicy(userID.String(), localOrgRoleKey(role, orgID)); err != nil {
		return fmt.Errorf("adding local grouping policy: %w", err)
	}
	return nil
}

// RemoveLocalRoleForUserInOrg revokes an operator-owned org-scoped role.
func (enf *Enforcer) RemoveLocalRoleForUserInOrg(userID uuid.UUID, role string, orgID uuid.UUID) error {
	if _, err := enf.e.RemoveGroupingPolicy(userID.String(), localOrgRoleKey(role, orgID)); err != nil {
		return fmt.Errorf("removing local grouping policy: %w", err)
	}
	return nil
}

// AddLocalRoleForUserOnInstance grants an operator-owned role across every org
// on the instance.
func (enf *Enforcer) AddLocalRoleForUserOnInstance(userID uuid.UUID, role string) error {
	if _, err := enf.e.AddGroupingPolicy(userID.String(), instanceRoleKey(role)); err != nil {
		return fmt.Errorf("adding instance grouping policy: %w", err)
	}
	return nil
}

// RemoveLocalRoleForUserOnInstance revokes an instance-scoped role.
func (enf *Enforcer) RemoveLocalRoleForUserOnInstance(userID uuid.UUID, role string) error {
	if _, err := enf.e.RemoveGroupingPolicy(userID.String(), instanceRoleKey(role)); err != nil {
		return fmt.Errorf("removing instance grouping policy: %w", err)
	}
	return nil
}

// GetLocalRolesForUser lists a user's operator-granted roles, org-scoped and
// instance-scoped alike.
//
// This is the answer to "what can this person do here that no forge decided",
// which is the question an operator must be able to ask before granting a role
// whose blast radius crosses orgs.
func (enf *Enforcer) GetLocalRolesForUser(userID uuid.UUID) (orgScoped map[uuid.UUID][]string, instanceScoped []string) {
	roles, err := enf.e.GetRolesForUser(userID.String())
	if err != nil {
		return nil, nil
	}
	orgScoped = map[uuid.UUID][]string{}
	instanceScoped = []string{}

	for _, key := range roles {
		if !isLocalRoleKey(key) {
			continue
		}
		body := strings.TrimPrefix(key, localPrefix)
		if name, ok := strings.CutSuffix(body, instanceSuffix); ok {
			instanceScoped = append(instanceScoped, name)
			continue
		}
		name, rawOrg, found := strings.Cut(body, ":org:")
		if !found {
			continue
		}
		orgID, parseErr := uuid.Parse(rawOrg)
		if parseErr != nil {
			continue
		}
		orgScoped[orgID] = append(orgScoped[orgID], name)
	}
	return orgScoped, instanceScoped
}

// CanTriage reports whether a user may author advisory data for an org, by
// either an org-scoped or an instance-scoped grant.
func (enf *Enforcer) CanTriage(userID uuid.UUID, orgID uuid.UUID) (bool, error) {
	if allowed, err := enf.CheckPermission(userID.String(), InstanceObject, ActionTriage); err != nil {
		return false, err
	} else if allowed {
		return true, nil
	}
	return enf.CheckPermission(userID.String(), OrgObject(orgID), ActionTriage)
}

func (enf *Enforcer) LoadPolicy() error {
	return enf.e.LoadPolicy()
}
