package server

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/auth"
)

// routeScope declares what a scoped API token must hold to reach one route.
// Exactly one of the modes applies; the zero value is a capability requirement.
type routeScope struct {
	// sessionOnly rejects every scoped token: the route is reachable from a
	// browser session (or a legacy unscoped token) only.
	sessionOnly bool
	// self is the token's own identity — reachable with any scope.
	self bool
	// anyGrant requires at least one granted capability rather than a specific
	// one: org/repo metadata a token needs to address the resources it can use.
	anyGrant bool
	// orgWide requires `repos.mode=all`: the route reads or writes across every
	// repository in the org, so a repo-restricted token can never satisfy it.
	orgWide    bool
	capability apitoken.Capability
	level      apitoken.AccessLevel
}

func sessionOnlyRoute() routeScope { return routeScope{sessionOnly: true} }
func selfRoute() routeScope        { return routeScope{self: true} }
func anyGrantRoute() routeScope    { return routeScope{anyGrant: true} }
func orgWideAnyRoute() routeScope  { return routeScope{anyGrant: true, orgWide: true} }

func needs(capability apitoken.Capability, level apitoken.AccessLevel) routeScope {
	return routeScope{capability: capability, level: level}
}

func needsOrgWide(capability apitoken.Capability, level apitoken.AccessLevel) routeScope {
	return routeScope{capability: capability, level: level, orgWide: true}
}

func (rs routeScope) allows(scope apitoken.Scope, org, repoSlug string) bool {
	switch {
	case rs.sessionOnly:
		return false
	case rs.self:
		return true
	case rs.anyGrant:
		return scope.HasPermissions() && rs.matchesResources(scope, org, repoSlug)
	case rs.orgWide:
		return scope.AllowsOrgWide(rs.capability, rs.level, org)
	default:
		return scope.Allows(rs.capability, rs.level, org, repoSlug)
	}
}

func (rs routeScope) matchesResources(scope apitoken.Scope, org, repoSlug string) bool {
	if org != "" && scope.Org != org {
		return false
	}
	if rs.orgWide {
		return scope.Repos.Mode == apitoken.RepoAll
	}
	return repoSlug == "" || scope.Repos.Includes(repoSlug)
}

const (
	orgRoute  = "/api/v1/orgs/{provider}/{slug}"
	repoRoute = orgRoute + "/repos/{repoSlug}"
)

// routeScopes is the deny-by-default capability declaration for every route
// behind auth.SessionAuth. A scoped token is rejected on any route absent from
// this table; TestEveryAuthenticatedRouteDeclaresScope keeps it exhaustive.
//
// Org and repo slugs are matched from the URL because both lookups are exact
// (`WHERE provider = $1 AND slug = $2`, `WHERE org_id = $1 AND slug = $2`), so
// the path segment is the canonical slug for any request that resolves.
var routeScopes = map[string]routeScope{
	"GET /api/v1/users/me": selfRoute(),

	"GET /api/v1/notifications":              sessionOnlyRoute(),
	"GET /api/v1/notifications/unread-count": sessionOnlyRoute(),
	"POST /api/v1/notifications/{id}/read":   sessionOnlyRoute(),
	"POST /api/v1/notifications/read-all":    sessionOnlyRoute(),

	"POST /api/v1/users/me/api-keys/":               sessionOnlyRoute(),
	"GET /api/v1/users/me/api-keys/":                sessionOnlyRoute(),
	"PATCH /api/v1/users/me/api-keys/{keyID}":       sessionOnlyRoute(),
	"DELETE /api/v1/users/me/api-keys/{keyID}":      sessionOnlyRoute(),
	"POST /api/v1/users/me/api-keys/{keyID}/rotate": sessionOnlyRoute(),

	"GET /api/v1/orgs/onboardable": sessionOnlyRoute(),
	"POST /api/v1/orgs/":           sessionOnlyRoute(),
	"GET /api/v1/orgs/":            sessionOnlyRoute(),

	"POST /api/v1/secret-scan/check":  needs(apitoken.CapSecrets, apitoken.AccessRead),
	"POST /api/v1/upload":             needs(apitoken.CapUploads, apitoken.AccessWrite),
	"GET /api/v1/uploads/{id}/status": needs(apitoken.CapUploads, apitoken.AccessRead),

	"GET " + orgRoute + "/":    anyGrantRoute(),
	"PUT " + orgRoute + "/":    needsOrgWide(apitoken.CapAdmin, apitoken.AccessWrite),
	"DELETE " + orgRoute + "/": sessionOnlyRoute(),

	"GET " + orgRoute + "/dashboard":           needsOrgWide(apitoken.CapVulnerabilities, apitoken.AccessRead),
	"GET " + orgRoute + "/vulnerabilities":     needsOrgWide(apitoken.CapVulnerabilities, apitoken.AccessRead),
	"GET " + orgRoute + "/search":              needsOrgWide(apitoken.CapVulnerabilities, apitoken.AccessRead),
	"GET " + orgRoute + "/compliance/export":   needsOrgWide(apitoken.CapVulnerabilities, apitoken.AccessRead),
	"GET " + orgRoute + "/compliance/iso27001": needsOrgWide(apitoken.CapVulnerabilities, apitoken.AccessRead),
	"GET " + orgRoute + "/compliance/soa":      needsOrgWide(apitoken.CapVulnerabilities, apitoken.AccessRead),
	"GET " + orgRoute + "/components":          needsOrgWide(apitoken.CapComponents, apitoken.AccessRead),
	"POST " + orgRoute + "/components/scan":    needsOrgWide(apitoken.CapComponents, apitoken.AccessWrite),
	"GET " + orgRoute + "/tool-catalog":        orgWideAnyRoute(),
	"GET " + orgRoute + "/settings":            needsOrgWide(apitoken.CapAdmin, apitoken.AccessRead),
	"PUT " + orgRoute + "/settings":            needsOrgWide(apitoken.CapAdmin, apitoken.AccessWrite),
	"GET " + orgRoute + "/audit-logs":          needsOrgWide(apitoken.CapAdmin, apitoken.AccessRead),

	"GET " + orgRoute + "/api-keys/":                 sessionOnlyRoute(),
	"GET " + orgRoute + "/api-keys/exposure":         sessionOnlyRoute(),
	"POST " + orgRoute + "/api-keys/":                sessionOnlyRoute(),
	"PATCH " + orgRoute + "/api-keys/{keyID}":        sessionOnlyRoute(),
	"DELETE " + orgRoute + "/api-keys/{keyID}":       sessionOnlyRoute(),
	"POST " + orgRoute + "/api-keys/{keyID}/rotate":  sessionOnlyRoute(),
	"POST " + orgRoute + "/api-keys/{keyID}/approve": sessionOnlyRoute(),
	"POST " + orgRoute + "/api-keys/{keyID}/reject":  sessionOnlyRoute(),

	"GET " + orgRoute + "/members/":              needsOrgWide(apitoken.CapAdmin, apitoken.AccessRead),
	"POST " + orgRoute + "/members/":             needsOrgWide(apitoken.CapAdmin, apitoken.AccessWrite),
	"PUT " + orgRoute + "/members/{userID}/role": needsOrgWide(apitoken.CapAdmin, apitoken.AccessWrite),
	"DELETE " + orgRoute + "/members/{userID}":   needsOrgWide(apitoken.CapAdmin, apitoken.AccessWrite),

	"GET " + orgRoute + "/integrations/":                        needsOrgWide(apitoken.CapAdmin, apitoken.AccessRead),
	"POST " + orgRoute + "/integrations/":                       needsOrgWide(apitoken.CapAdmin, apitoken.AccessWrite),
	"GET " + orgRoute + "/integrations/{integrationID}/":        needsOrgWide(apitoken.CapAdmin, apitoken.AccessRead),
	"GET " + orgRoute + "/integrations/{integrationID}/health":  needsOrgWide(apitoken.CapAdmin, apitoken.AccessRead),
	"POST " + orgRoute + "/integrations/{integrationID}/replay": needsOrgWide(apitoken.CapAdmin, apitoken.AccessWrite),
	"PUT " + orgRoute + "/integrations/{integrationID}/":        needsOrgWide(apitoken.CapAdmin, apitoken.AccessWrite),
	"DELETE " + orgRoute + "/integrations/{integrationID}/":     needsOrgWide(apitoken.CapAdmin, apitoken.AccessWrite),

	"GET " + orgRoute + "/notification-rules/":             needsOrgWide(apitoken.CapAdmin, apitoken.AccessRead),
	"POST " + orgRoute + "/notification-rules/":            needsOrgWide(apitoken.CapAdmin, apitoken.AccessWrite),
	"POST " + orgRoute + "/notification-rules/dry-run":     needsOrgWide(apitoken.CapAdmin, apitoken.AccessWrite),
	"GET " + orgRoute + "/notification-rules/{ruleID}/":    needsOrgWide(apitoken.CapAdmin, apitoken.AccessRead),
	"PUT " + orgRoute + "/notification-rules/{ruleID}/":    needsOrgWide(apitoken.CapAdmin, apitoken.AccessWrite),
	"DELETE " + orgRoute + "/notification-rules/{ruleID}/": needsOrgWide(apitoken.CapAdmin, apitoken.AccessWrite),

	"GET " + orgRoute + "/quality-gates/":             needsOrgWide(apitoken.CapQualityGates, apitoken.AccessRead),
	"POST " + orgRoute + "/quality-gates/":            needsOrgWide(apitoken.CapQualityGates, apitoken.AccessWrite),
	"GET " + orgRoute + "/quality-gates/{gateID}/":    needsOrgWide(apitoken.CapQualityGates, apitoken.AccessRead),
	"PUT " + orgRoute + "/quality-gates/{gateID}/":    needsOrgWide(apitoken.CapQualityGates, apitoken.AccessWrite),
	"DELETE " + orgRoute + "/quality-gates/{gateID}/": needsOrgWide(apitoken.CapQualityGates, apitoken.AccessWrite),

	"GET " + orgRoute + "/clients/":                          needsOrgWide(apitoken.CapComponents, apitoken.AccessRead),
	"POST " + orgRoute + "/clients/":                         needsOrgWide(apitoken.CapComponents, apitoken.AccessWrite),
	"GET " + orgRoute + "/clients/label-keys":                needsOrgWide(apitoken.CapComponents, apitoken.AccessRead),
	"GET " + orgRoute + "/clients/{clientSlug}/":             needsOrgWide(apitoken.CapComponents, apitoken.AccessRead),
	"PUT " + orgRoute + "/clients/{clientSlug}/":             needsOrgWide(apitoken.CapComponents, apitoken.AccessWrite),
	"DELETE " + orgRoute + "/clients/{clientSlug}/":          needsOrgWide(apitoken.CapComponents, apitoken.AccessWrite),
	"GET " + orgRoute + "/clients/{clientSlug}/deployments":  needsOrgWide(apitoken.CapComponents, apitoken.AccessRead),
	"POST " + orgRoute + "/clients/{clientSlug}/deployments": needsOrgWide(apitoken.CapComponents, apitoken.AccessWrite),
	"GET " + orgRoute + "/clients/{clientSlug}/impact":       needsOrgWide(apitoken.CapComponents, apitoken.AccessRead),

	"GET " + orgRoute + "/teams/":                                 needsOrgWide(apitoken.CapAdmin, apitoken.AccessRead),
	"POST " + orgRoute + "/teams/":                                needsOrgWide(apitoken.CapAdmin, apitoken.AccessWrite),
	"GET " + orgRoute + "/teams/{teamSlug}/":                      needsOrgWide(apitoken.CapAdmin, apitoken.AccessRead),
	"PUT " + orgRoute + "/teams/{teamSlug}/":                      needsOrgWide(apitoken.CapAdmin, apitoken.AccessWrite),
	"DELETE " + orgRoute + "/teams/{teamSlug}/":                   needsOrgWide(apitoken.CapAdmin, apitoken.AccessWrite),
	"GET " + orgRoute + "/teams/{teamSlug}/members/":              needsOrgWide(apitoken.CapAdmin, apitoken.AccessRead),
	"POST " + orgRoute + "/teams/{teamSlug}/members/":             needsOrgWide(apitoken.CapAdmin, apitoken.AccessWrite),
	"PUT " + orgRoute + "/teams/{teamSlug}/members/{userID}/role": needsOrgWide(apitoken.CapAdmin, apitoken.AccessWrite),
	"DELETE " + orgRoute + "/teams/{teamSlug}/members/{userID}":   needsOrgWide(apitoken.CapAdmin, apitoken.AccessWrite),

	"GET " + orgRoute + "/repos/":      orgWideAnyRoute(),
	"POST " + orgRoute + "/repos/":     needsOrgWide(apitoken.CapAdmin, apitoken.AccessWrite),
	"POST " + orgRoute + "/repos/sync": needsOrgWide(apitoken.CapAdmin, apitoken.AccessWrite),

	"GET " + repoRoute:               anyGrantRoute(),
	"PUT " + repoRoute:               needs(apitoken.CapAdmin, apitoken.AccessWrite),
	"DELETE " + repoRoute:            needs(apitoken.CapAdmin, apitoken.AccessWrite),
	"GET " + repoRoute + "/onboard":  needs(apitoken.CapAdmin, apitoken.AccessRead),
	"POST " + repoRoute + "/onboard": needs(apitoken.CapAdmin, apitoken.AccessWrite),
	"GET " + repoRoute + "/config":   anyGrantRoute(),

	"GET " + repoRoute + "/refs":          anyGrantRoute(),
	"GET " + repoRoute + "/refs/enhanced": anyGrantRoute(),
	"GET " + repoRoute + "/snapshots":     anyGrantRoute(),
	"GET " + repoRoute + "/releases":      anyGrantRoute(),

	"POST " + repoRoute + "/releases/{releaseID}/divergence":               needs(apitoken.CapUploads, apitoken.AccessWrite),
	"POST " + repoRoute + "/releases/{releaseID}/clients":                  needs(apitoken.CapUploads, apitoken.AccessWrite),
	"DELETE " + repoRoute + "/releases/{releaseID}/clients/{deploymentID}": needs(apitoken.CapUploads, apitoken.AccessWrite),

	"GET " + repoRoute + "/snapshots/{snapshotID}/files":              needs(apitoken.CapUploads, apitoken.AccessRead),
	"GET " + repoRoute + "/snapshots/{snapshotID}/files.zip":          needs(apitoken.CapUploads, apitoken.AccessRead),
	"GET " + repoRoute + "/snapshots/{snapshotID}/files/{artifactID}": needs(apitoken.CapUploads, apitoken.AccessRead),
	"GET " + repoRoute + "/snapshots/{snapshotID}/coverage-source":    needs(apitoken.CapCoverage, apitoken.AccessRead),

	"GET " + repoRoute + "/coverage": needs(apitoken.CapCoverage, apitoken.AccessRead),
	"GET " + repoRoute + "/tests":    needs(apitoken.CapCoverage, apitoken.AccessRead),

	"GET " + repoRoute + "/compare": needs(apitoken.CapVulnerabilities, apitoken.AccessRead),
	"GET " + repoRoute + "/trends":  needs(apitoken.CapVulnerabilities, apitoken.AccessRead),
	"GET " + repoRoute + "/summary": needs(apitoken.CapVulnerabilities, apitoken.AccessRead),
	"GET " + repoRoute + "/delta/":  needs(apitoken.CapVulnerabilities, apitoken.AccessRead),

	"GET " + repoRoute + "/findings":               needs(apitoken.CapVulnerabilities, apitoken.AccessRead),
	"POST " + repoRoute + "/findings":              needs(apitoken.CapVulnerabilities, apitoken.AccessWrite),
	"GET " + repoRoute + "/findings/facets":        needs(apitoken.CapVulnerabilities, apitoken.AccessRead),
	"GET " + repoRoute + "/vulnerabilities":        needs(apitoken.CapVulnerabilities, apitoken.AccessRead),
	"GET " + repoRoute + "/vulnerabilities/facets": needs(apitoken.CapVulnerabilities, apitoken.AccessRead),
	"GET " + repoRoute + "/vulnerabilities/rules":  needs(apitoken.CapVulnerabilities, apitoken.AccessRead),
	"GET " + repoRoute + "/findings/{fingerprint}": needs(apitoken.CapVulnerabilities, apitoken.AccessRead),
	// Same capability as the detail it belongs to: the history says what
	// happened to this one finding, which is what reading the finding means.
	"GET " + repoRoute + "/findings/{fingerprint}/history": needs(apitoken.CapVulnerabilities, apitoken.AccessRead),
	"POST " + repoRoute + "/reachability":                  needs(apitoken.CapUploads, apitoken.AccessWrite),
	"GET " + repoRoute + "/vulnerabilities/fingerprints":   needs(apitoken.CapVulnerabilities, apitoken.AccessRead),

	"PUT " + repoRoute + "/vulnerabilities/acceptance":           needs(apitoken.CapTriage, apitoken.AccessWrite),
	"PUT " + repoRoute + "/vulnerabilities/{vulnID}/acceptance":  needs(apitoken.CapTriage, apitoken.AccessWrite),
	"POST " + repoRoute + "/vulnerabilities/{vulnID}/revocation": needs(apitoken.CapTriage, apitoken.AccessWrite),
	"GET " + repoRoute + "/finding-acceptances":                  needs(apitoken.CapTriage, apitoken.AccessRead),

	"GET " + repoRoute + "/vex/":                 needs(apitoken.CapTriage, apitoken.AccessRead),
	"GET " + repoRoute + "/vex/export":           needs(apitoken.CapTriage, apitoken.AccessRead),
	"GET " + repoRoute + "/vex/{statementID}":    needs(apitoken.CapTriage, apitoken.AccessRead),
	"POST " + repoRoute + "/vex/":                needs(apitoken.CapTriage, apitoken.AccessWrite),
	"PUT " + repoRoute + "/vex/{statementID}":    needs(apitoken.CapTriage, apitoken.AccessWrite),
	"DELETE " + repoRoute + "/vex/{statementID}": needs(apitoken.CapTriage, apitoken.AccessWrite),

	"GET " + repoRoute + "/components":       needs(apitoken.CapComponents, apitoken.AccessRead),
	"GET " + repoRoute + "/components/graph": needs(apitoken.CapComponents, apitoken.AccessRead),
	"POST " + repoRoute + "/components/scan": needs(apitoken.CapComponents, apitoken.AccessWrite),
	"POST " + repoRoute + "/sbom/compare":    needs(apitoken.CapComponents, apitoken.AccessRead),

	"GET " + repoRoute + "/secrets/jobs":  needs(apitoken.CapSecrets, apitoken.AccessRead),
	"POST " + repoRoute + "/secrets/scan": needs(apitoken.CapSecrets, apitoken.AccessWrite),

	"GET " + repoRoute + "/pulls/{pr}/gate": needs(apitoken.CapQualityGates, apitoken.AccessRead),
}

// tokenScopeGuard is the deny-by-default gate for scoped API tokens (ADR-020).
// Sessions and legacy unscoped tokens pass straight through, keeping the check
// additive to RBAC. Every other request must match a declared route whose
// capability, org, and repository the token's scope satisfies; an undeclared or
// unmatched route is a denial, never a fallthrough.
func (s *Server) tokenScopeGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenAuth := auth.TokenAuthFromContext(r.Context())
		if tokenAuth == nil || !tokenAuth.Scoped {
			next.ServeHTTP(w, r)
			return
		}

		matchCtx := chi.NewRouteContext()
		pattern := s.router.Find(matchCtx, r.Method, routeMatchPath(r))
		if pattern == "" {
			api.JSONError(w, http.StatusForbidden, "token scope does not permit this action")
			return
		}

		rule, declared := lookupRouteScope(r.Method, pattern)
		if !declared {
			s.log.Warn().Str("method", r.Method).Str("route", pattern).Str("key_id", tokenAuth.KeyID.String()).Msg("scoped token denied on a route with no capability declaration")
			api.JSONError(w, http.StatusForbidden, "token scope does not permit this action")
			return
		}

		org, repoSlug := matchCtx.URLParam("slug"), matchCtx.URLParam("repoSlug")
		if !rule.allows(tokenAuth.Scope, org, repoSlug) {
			api.JSONError(w, http.StatusForbidden, rule.denialMessage(org, repoSlug))
			return
		}

		next.ServeHTTP(w, r)
	})
}

// lookupRouteScope resolves a matched chi pattern to its declaration. A mounted
// subrouter is reachable with and without its trailing slash, and chi reports
// the slashless stub pattern for the former, so both spellings resolve to the
// one declaration chi.Walk reports.
func lookupRouteScope(method, pattern string) (routeScope, bool) {
	if rule, ok := routeScopes[method+" "+pattern]; ok {
		return rule, true
	}
	if strings.HasSuffix(pattern, "/") {
		return routeScope{}, false
	}
	rule, ok := routeScopes[method+" "+pattern+"/"]
	return rule, ok
}

// denialMessage names what the route needed, per ADR-020's "denials return 403
// with which permission was missing". Session-only routes stay generic — the
// answer there is "no token works", not a grant to add.
func (rs routeScope) denialMessage(org, repoSlug string) string {
	switch {
	case rs.sessionOnly:
		return "this action is only available from a browser session, not with an API token"
	case rs.anyGrant && rs.orgWide:
		return fmt.Sprintf("token scope does not permit organization-wide access (requires repos.mode=all in %s)", org)
	case rs.anyGrant:
		return "token scope does not permit this action (requires at least one granted capability on " + requestTarget(org, repoSlug) + ")"
	case rs.orgWide:
		return fmt.Sprintf(
			"token scope does not permit organization-wide access (requires %s:%s across every repository in %s; this token is limited to specific repositories)",
			rs.capability, rs.level, org,
		)
	default:
		return deniedMessage(rs.capability, rs.level, requestTarget(org, repoSlug))
	}
}

// routeMatchPath mirrors how chi derives the path it routes on, so a dry-run
// match against the root router resolves the same pattern the request will hit.
func routeMatchPath(r *http.Request) string {
	if r.URL.RawPath != "" {
		return r.URL.RawPath
	}
	if r.URL.Path == "" {
		return "/"
	}
	return r.URL.Path
}
