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

func (enf *Enforcer) AddRoleForUserInOrg(userID uuid.UUID, role string, orgID uuid.UUID) error {
	roleKey := fmt.Sprintf("role:%s:org:%s", role, orgID)
	_, err := enf.e.AddGroupingPolicy(userID.String(), roleKey)
	if err != nil {
		return fmt.Errorf("adding grouping policy: %w", err)
	}

	return nil
}

func (enf *Enforcer) RemoveRoleForUserInOrg(userID uuid.UUID, role string, orgID uuid.UUID) error {
	roleKey := fmt.Sprintf("role:%s:org:%s", role, orgID)
	_, err := enf.e.RemoveGroupingPolicy(userID.String(), roleKey)
	if err != nil {
		return fmt.Errorf("removing grouping policy: %w", err)
	}

	return nil
}

func (enf *Enforcer) GetRolesForUserInOrg(userID uuid.UUID, orgID uuid.UUID) []string {
	roles, err := enf.e.GetRolesForUser(userID.String())
	if err != nil {
		return nil
	}

	prefix := "role:"
	suffix := fmt.Sprintf(":org:%s", orgID)
	result := make([]string, 0, len(roles))
	for _, role := range roles {
		if !strings.HasPrefix(role, prefix) || !strings.HasSuffix(role, suffix) {
			continue
		}

		result = append(result, strings.TrimSuffix(strings.TrimPrefix(role, prefix), suffix))
	}

	return result
}

func (enf *Enforcer) LoadPolicy() error {
	return enf.e.LoadPolicy()
}
