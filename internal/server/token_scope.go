package server

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/rbac"
)

// scopeDenied writes the 403 for a token-scope denial, naming the missing
// grant (ADR-020: "Denials return 403 with which permission was missing").
// Capability names are public API vocabulary, and the caller already knows the
// org/repo they asked for — this leaks nothing while turning a dead end into a
// fixable error, for humans and agents alike.
func scopeDenied(w http.ResponseWriter, cap apitoken.Capability, need apitoken.AccessLevel, target string) {
	api.JSONError(w, http.StatusForbidden, deniedMessage(cap, need, target))
}

func deniedMessage(cap apitoken.Capability, need apitoken.AccessLevel, target string) string {
	message := fmt.Sprintf("token scope does not permit this action (requires %s:%s", cap, need)
	if target != "" {
		message += " on " + target
	}
	return message + ")"
}

func requestTarget(org, repoSlug string) string {
	if org == "" {
		return ""
	}
	if repoSlug == "" {
		return org
	}
	return org + "/" + repoSlug
}

// principalOrgRole resolves the requesting principal's effective role in an
// org. A service principal (org-owned token, ADR-022) acting for THIS org is
// an "admin" when its scope grants admin:write, otherwise a member-equivalent
// "developer"; it has no role in any other org. Users resolve to their stored
// membership role, capped by the org's login-token policy when the request
// carries a membership-wide device-login token (ADR-043 §4). Empty string =
// no access. The token scope is enforced separately (route guard + capability
// checks) — this answers only the membership/RBAC question the handlers ask.
func (s *Server) principalOrgRole(r *http.Request, orgID uuid.UUID) (string, error) {
	if tokenAuth := auth.TokenAuthFromContext(r.Context()); tokenAuth.IsServicePrincipal() {
		if !tokenAuth.ActsForOrg(orgID) {
			return "", nil
		}
		if tokenAuth.Scope.Allows(apitoken.CapAdmin, apitoken.AccessWrite, "", "") {
			return "admin", nil
		}
		return "developer", nil
	}

	user := UserFromContext(r.Context())
	if user == nil {
		return "", nil
	}
	role, err := s.queries.GetOrgMemberRole(r.Context(), orgID, user.ID)
	if err != nil || role == "" {
		return role, err
	}
	if tokenAuth := auth.TokenAuthFromContext(r.Context()); tokenAuth.IsMembershipWide() {
		org, err := s.queries.GetOrganizationByID(r.Context(), orgID)
		if err != nil {
			return "", err
		}
		if org == nil {
			return "", nil
		}
		return rbac.CapRoleForLoginToken(role, rbac.LoginTokensPolicy(org.Settings)), nil
	}
	return role, nil
}

// hasPrincipal reports whether the request carries any authenticated
// principal — a user (session or user-owned token) or an org service
// principal. The unauthenticated 401 keeps its meaning under ADR-022.
func (s *Server) hasPrincipal(r *http.Request) bool {
	return UserFromContext(r.Context()) != nil || auth.TokenAuthFromContext(r.Context()).IsServicePrincipal()
}

func (s *Server) enforceTokenCapability(w http.ResponseWriter, r *http.Request, cap apitoken.Capability, need apitoken.AccessLevel, org, repoSlug string) bool {
	if err := auth.RequireCapability(r.Context(), cap, need, org, repoSlug); err != nil {
		if errors.Is(err, auth.ErrTokenScopeDenied) {
			scopeDenied(w, cap, need, requestTarget(org, repoSlug))
			return false
		}
	}
	return true
}

func (s *Server) enforceOrgWideCapability(w http.ResponseWriter, r *http.Request, cap apitoken.Capability, need apitoken.AccessLevel, orgSlug string) bool {
	if err := auth.RequireOrgWideCapability(r.Context(), cap, need, orgSlug); err != nil {
		if errors.Is(err, auth.ErrTokenScopeDenied) {
			api.JSONError(w, http.StatusForbidden, fmt.Sprintf(
				"token scope does not permit organization-wide access (requires %s:%s across every repository in %s; this token is limited to specific repositories)",
				cap, need, orgSlug,
			))
			return false
		}
	}
	return true
}
