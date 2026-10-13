// Package repoaccess resolves which repositories of an org a principal may
// see. The HTTP API and the MCP server share it so the two cannot drift: a
// repository collaborator sees the repositories the forge granted them, over
// every transport, and nothing org-wide.
package repoaccess

import (
	"context"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/rbac"
)

// Store is the subset of store.Queries the resolution reads.
type Store interface {
	IsRepoScopedOrgMember(ctx context.Context, orgID, userID uuid.UUID) (bool, error)
	ListUserRepoAccessInOrg(ctx context.Context, orgID, userID uuid.UUID) (map[uuid.UUID]string, error)
}

// Access is how a principal reaches the repositories of one org.
type Access struct {
	// Scoped is true when the principal may see only the repositories in
	// Repos: a forge collaborator with no org-wide standing.
	Scoped bool
	// Repos maps each visible repository to the role its grant carries.
	// Populated only when Scoped; empty means nothing is visible.
	Repos map[uuid.UUID]string
}

// Allows reports whether the repository is visible.
func (a Access) Allows(repoID uuid.UUID) bool {
	if !a.Scoped {
		return true
	}
	_, ok := a.Repos[repoID]
	return ok
}

// Resolve answers for a user principal holding orgRole in the org. Service
// principals are bounded by their token scope instead, and only forge-synced
// viewer/developer memberships can be scoped, so other roles skip the lookup.
// A nil user (service principal) is never scoped.
func Resolve(ctx context.Context, st Store, orgID, userID uuid.UUID, servicePrincipal bool, orgRole string) (Access, error) {
	if servicePrincipal || userID == uuid.Nil || st == nil {
		return Access{}, nil
	}
	if orgRole != rbac.RoleViewer && orgRole != rbac.RoleDeveloper {
		return Access{}, nil
	}
	scoped, err := st.IsRepoScopedOrgMember(ctx, orgID, userID)
	if err != nil || !scoped {
		return Access{}, err
	}
	repos, err := st.ListUserRepoAccessInOrg(ctx, orgID, userID)
	if err != nil {
		return Access{}, err
	}
	if repos == nil {
		repos = map[uuid.UUID]string{}
	}
	return Access{Scoped: true, Repos: repos}, nil
}
