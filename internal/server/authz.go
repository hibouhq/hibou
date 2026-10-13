package server

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/rbac"
	"github.com/hibouhq/hibou/internal/repoaccess"
	"github.com/hibouhq/hibou/internal/store"
)

// Shared authorization helpers for org and repository routes.
//
// SessionAuth never rejects, so every check below runs inside a handler (or a
// load* helper the handler calls). They are kept together so that the three
// questions a handler asks — is there a principal, may it see this, may it
// change this — get the same answer everywhere.

// readOnlyMessage is the 403 body for a read-only role attempting a write.
const readOnlyMessage = "this action requires the developer role or higher; viewer and auditor roles are read-only"

// repoScopedOrgWideMessage is the 403 body for a repository collaborator
// reaching for an organization-wide view.
const repoScopedOrgWideMessage = "organization-wide views require organization membership; your access covers specific repositories only"

// readOnlyUnsafeRouteSuffixes are routes that use POST to carry a request body
// but compute an answer and change nothing, so a read-only role may call them.
// Matched against the chi route pattern, which is fixed by the router and not
// by the client.
var readOnlyUnsafeRouteSuffixes = []string{
	"/repos/{repoSlug}/sbom/compare",
	"/licenses/simulate",
}

// requireAuthenticated rejects a request with no principal. Routes that serve
// instance-wide data to any signed-in caller use it; SessionAuth alone lets an
// anonymous request through.
func (s *Server) requireAuthenticated(w http.ResponseWriter, r *http.Request) bool {
	if !s.hasPrincipal(r) {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return false
	}
	return true
}

// roleCanWrite reports whether an org role may change org or repository
// state. viewer and auditor are read-only; every other base role writes.
func roleCanWrite(role string) bool {
	switch role {
	case rbac.RoleAdmin, rbac.RoleDeveloper, rbac.RoleReleaseManager:
		return true
	default:
		return false
	}
}

func orgRoleRank(role string) int {
	switch role {
	case rbac.RoleAdmin:
		return 3
	case rbac.RoleDeveloper, rbac.RoleReleaseManager:
		return 2
	case rbac.RoleViewer, rbac.RoleAuditor:
		return 1
	default:
		return 0
	}
}

// weakerRole returns the less privileged of two roles.
func weakerRole(a, b string) string {
	if orgRoleRank(b) < orgRoleRank(a) {
		return b
	}
	return a
}

// requestChangesState reports whether the request is a write. Safe methods and
// the read-only POST routes above are not.
func requestChangesState(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	if rctx := chi.RouteContext(r.Context()); rctx != nil {
		pattern := rctx.RoutePattern()
		for _, suffix := range readOnlyUnsafeRouteSuffixes {
			if strings.HasSuffix(pattern, suffix) {
				return false
			}
		}
	}
	return true
}

// requireWriteRole refuses a state-changing request from a read-only role.
// Service principals resolve to developer or admin in principalOrgRole, so
// their writes stay governed by token scope alone.
func requireWriteRole(w http.ResponseWriter, r *http.Request, role string) bool {
	if requestChangesState(r) && !roleCanWrite(role) {
		api.JSONError(w, http.StatusForbidden, readOnlyMessage)
		return false
	}
	return true
}

// repoAccess is how the request principal reaches the repositories of one org.
type repoAccess struct {
	// scoped is true when the principal may see only the repositories in
	// repos: a forge collaborator with no org-wide standing (§4.3).
	scoped bool
	// repos maps each visible repository to the forge role the grant carries.
	// Populated only when scoped.
	repos map[uuid.UUID]string
}

func (a repoAccess) allows(repoID uuid.UUID) bool {
	if !a.scoped {
		return true
	}
	_, ok := a.repos[repoID]
	return ok
}

// repoRole is the principal's effective role on one repository: the org role,
// lowered to the repository grant for a scoped principal. A collaborator with
// push on one repository is synced as an org developer, and must not write to
// a repository where the forge gave them only read.
func (a repoAccess) repoRole(orgRole string, repoID uuid.UUID) string {
	if !a.scoped {
		return orgRole
	}
	return weakerRole(orgRole, a.repos[repoID])
}

// principalRepoAccess resolves repository visibility for the request principal
// in an org (repoaccess.Resolve, shared with the MCP server). Service
// principals are bounded by their token scope instead.
func (s *Server) principalRepoAccess(r *http.Request, orgID uuid.UUID, orgRole string) (repoAccess, error) {
	if s.queries == nil {
		return repoAccess{}, nil
	}
	var userID uuid.UUID
	if user := UserFromContext(r.Context()); user != nil {
		userID = user.ID
	}
	access, err := repoaccess.Resolve(r.Context(), s.queries, orgID, userID,
		auth.TokenAuthFromContext(r.Context()).IsServicePrincipal(), orgRole)
	if err != nil {
		return repoAccess{}, err
	}
	return repoAccess{scoped: access.Scoped, repos: access.Repos}, nil
}

// loadOrgMembership resolves the org in the URL and the principal's role in
// it. A non-member gets a 404, never a 403, so org existence does not leak.
func (s *Server) loadOrgMembership(r *http.Request, w http.ResponseWriter) (*store.Organization, string, bool) {
	if !s.hasPrincipal(r) {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return nil, "", false
	}

	org, err := s.resolveOrg(r)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load organization")
		return nil, "", false
	}
	if org == nil {
		api.JSONError(w, http.StatusNotFound, "organization not found")
		return nil, "", false
	}

	role, err := s.principalOrgRole(r, org.ID)
	if err != nil || role == "" {
		api.JSONError(w, http.StatusNotFound, "organization not found")
		return nil, "", false
	}
	return org, role, true
}

// requireOrgWideAccess refuses org-wide views to a repository-scoped
// principal. Org aggregates (dashboard, search, vulnerabilities, components,
// licenses…) enumerate every repository; denying them outright is the only
// answer that cannot leak through an aggregate someone forgets to filter.
func (s *Server) requireOrgWideAccess(w http.ResponseWriter, r *http.Request, orgID uuid.UUID, orgRole string) bool {
	access, err := s.principalRepoAccess(r, orgID, orgRole)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load organization")
		return false
	}
	if access.scoped {
		api.JSONError(w, http.StatusForbidden, repoScopedOrgWideMessage)
		return false
	}
	return true
}

// authorizeRepoRequest is the shared tail of every repository loader: the
// repository must be visible to the principal (404 otherwise, like a missing
// repository) and a write needs a writing role on it.
func (s *Server) authorizeRepoRequest(w http.ResponseWriter, r *http.Request, orgID uuid.UUID, orgRole string, repo *store.Repository) bool {
	access, err := s.principalRepoAccess(r, orgID, orgRole)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load repository")
		return false
	}
	if !access.allows(repo.ID) {
		api.JSONError(w, http.StatusNotFound, "repository not found")
		return false
	}
	return requireWriteRole(w, r, access.repoRole(orgRole, repo.ID))
}

// visibleInventory drops the repositories a scoped principal may not see,
// including forge inventory rows not enrolled here: their names are the
// organization's, not the collaborator's.
func (a repoAccess) visibleInventory(entries []repositoryInventoryEntry) []repositoryInventoryEntry {
	if !a.scoped {
		return entries
	}
	out := make([]repositoryInventoryEntry, 0, len(a.repos))
	for _, entry := range entries {
		if entry.ID != nil && a.allows(*entry.ID) {
			out = append(out, entry)
		}
	}
	return out
}

// canSeeInstanceInventory reports whether the caller may see component
// inventory aggregated across every org: an instance admin or a holder of an
// instance-scoped triage grant. Everyone else sees one org at a time.
func (s *Server) canSeeInstanceInventory(r *http.Request) bool {
	user := UserFromContext(r.Context())
	if user == nil {
		return false
	}
	if s.isInstanceAdmin(r) {
		return true
	}
	if s.enforcer == nil {
		return false
	}
	allowed, err := s.enforcer.CheckPermission(user.ID.String(), rbac.InstanceObject, rbac.ActionTriage)
	return err == nil && allowed
}

// tokenScopeAllows reports whether the request's token scope (if any) grants a
// capability on an org/repository resolved inside the handler, for routes whose
// URL carries neither and so passed the route guard unqualified.
func tokenScopeAllows(r *http.Request, capability apitoken.Capability, need apitoken.AccessLevel, org, repoSlug string) bool {
	return auth.RequireCapability(r.Context(), capability, need, org, repoSlug) == nil
}

// requirePrincipal is the structural form of requireAuthenticated, meant for
// the SessionAuth route group: SessionAuth never rejects, so any handler that
// forgets its own check serves anonymous callers. Public routes are registered
// outside that group and stay reachable.
func (s *Server) requirePrincipal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.requireAuthenticated(w, r) {
			return
		}
		next.ServeHTTP(w, r)
	})
}
