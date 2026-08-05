package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/apitoken"
	internalauth "github.com/hibouhq/hibou/internal/auth"
)

func servicePrincipalRequest(t *testing.T, orgID uuid.UUID, permissions map[apitoken.Capability]apitoken.AccessLevel) *http.Request {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/orgs/github/acme", nil)
	return req.WithContext(internalauth.WithTokenAuth(req.Context(), &internalauth.TokenAuth{
		KeyID:     uuid.New(),
		Name:      "org-bot",
		OwnerType: "org",
		OwnerID:   orgID,
		Scoped:    true,
		Scope: apitoken.Scope{
			Org:         "acme",
			Repos:       apitoken.RepoSelector{Mode: apitoken.RepoAll},
			Permissions: permissions,
		},
	}))
}

func TestPrincipalOrgRoleServicePrincipal(t *testing.T) {
	t.Parallel()

	srv := &Server{}
	orgID := uuid.New()

	adminReq := servicePrincipalRequest(t, orgID, map[apitoken.Capability]apitoken.AccessLevel{apitoken.CapAdmin: apitoken.AccessWrite})
	role, err := srv.principalOrgRole(adminReq, orgID)
	if err != nil || role != "admin" {
		t.Fatalf("admin-scoped SP role = %q err=%v, want admin", role, err)
	}

	memberReq := servicePrincipalRequest(t, orgID, map[apitoken.Capability]apitoken.AccessLevel{apitoken.CapCoverage: apitoken.AccessRead})
	role, err = srv.principalOrgRole(memberReq, orgID)
	if err != nil || role != "developer" {
		t.Fatalf("member-scoped SP role = %q err=%v, want developer", role, err)
	}

	// The one rule that must never soften: an org token has no role anywhere
	// but its own org.
	role, err = srv.principalOrgRole(adminReq, uuid.New())
	if err != nil || role != "" {
		t.Fatalf("cross-org SP role = %q err=%v, want empty", role, err)
	}
}

func TestHasPrincipal(t *testing.T) {
	t.Parallel()

	srv := &Server{}
	bare := httptest.NewRequest(http.MethodGet, "/", nil)
	if srv.hasPrincipal(bare) {
		t.Fatal("unauthenticated request must have no principal")
	}
	if !srv.hasPrincipal(servicePrincipalRequest(t, uuid.New(), nil)) {
		t.Fatal("service principal must count as a principal")
	}

	// A user-owned token is a user principal, not a service principal.
	userTokenReq := httptest.NewRequest(http.MethodGet, "/", nil)
	userTokenReq = userTokenReq.WithContext(internalauth.WithTokenAuth(userTokenReq.Context(), &internalauth.TokenAuth{
		KeyID: uuid.New(), OwnerType: "user", OwnerID: uuid.New(),
	}))
	if srv.hasPrincipal(userTokenReq) {
		t.Fatal("a user token without a user in context is not a principal")
	}
}
