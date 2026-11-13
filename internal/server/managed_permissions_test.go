package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/auth"
)

func TestManagedCapabilityPermissions(t *testing.T) {
	repoID := uuid.New()
	for _, tt := range []struct {
		name, role                 string
		access                     repoAccess
		generate, publish, consent bool
	}{
		{name: "admin", role: "admin", generate: true, publish: true, consent: true},
		{name: "developer", role: "developer", generate: true},
		{name: "viewer", role: "viewer"},
		{name: "repo viewer cannot use organization write role", role: "developer", access: repoAccess{scoped: true, repos: map[uuid.UUID]string{repoID: "viewer"}}},
		{name: "scoped admin cannot consent for organization", role: "admin", access: repoAccess{scoped: true, repos: map[uuid.UUID]string{repoID: "admin"}}, generate: true, publish: true},
		{name: "scoped developer cannot publish", role: "admin", access: repoAccess{scoped: true, repos: map[uuid.UUID]string{repoID: "developer"}}, generate: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			g, p, c := managedPermissions(r, "acme", "app", repoID, tt.role, tt.access)
			if g != tt.generate || p != tt.publish || c != tt.consent {
				t.Fatalf("permissions %v %v %v", g, p, c)
			}
		})
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r = r.WithContext(auth.WithTokenAuth(r.Context(), &auth.TokenAuth{Scoped: true, Scope: apitoken.Scope{
		Org: "acme", Repos: apitoken.RepoSelector{Mode: apitoken.RepoList, Slugs: []string{"app"}},
		Permissions: map[apitoken.Capability]apitoken.AccessLevel{apitoken.CapAdmin: apitoken.AccessWrite, apitoken.CapVulnerabilities: apitoken.AccessRead},
	}}))
	g, p, c := managedPermissions(r, "acme", "app", repoID, "admin", repoAccess{})
	if g || p || c {
		t.Fatalf("read-only vulnerabilities/repo-scoped token gained mutation: %v %v %v", g, p, c)
	}
}
