package forge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/oauth2"
)

func TestGitHubListUserAccess(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		membershipStatus  int
		membershipBody    map[string]any
		wantOrgLevel      string
		wantRepoLevels    []string
		wantInstallations int
	}{
		{
			name:              "membership admin wins",
			membershipStatus:  http.StatusOK,
			membershipBody:    map[string]any{"role": "admin"},
			wantOrgLevel:      "admin",
			wantRepoLevels:    []string{"maintain", "pull"},
			wantInstallations: 1,
		},
		{
			name:              "membership member maps to read",
			membershipStatus:  http.StatusOK,
			membershipBody:    map[string]any{"role": "member"},
			wantOrgLevel:      "read",
			wantRepoLevels:    []string{"maintain", "pull"},
			wantInstallations: 1,
		},
		{
			name:              "membership fallback capped at write",
			membershipStatus:  http.StatusForbidden,
			membershipBody:    map[string]any{"message": "forbidden"},
			wantOrgLevel:      "push",
			wantRepoLevels:    []string{"maintain", "pull"},
			wantInstallations: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.Header.Get("Authorization"); got != "Bearer user-token" {
					t.Fatalf("Authorization header = %q, want Bearer user-token", got)
				}

				switch r.URL.RequestURI() {
				case "/user/installations?per_page=100":
					w.Header().Set("Link", serverLink(r, "/user/installations?page=2"))
					writeJSON(w, map[string]any{
						"installations": []map[string]any{{
							"id":      1,
							"account": map[string]any{"login": "Acme", "type": "Organization"},
						}},
					})
				case "/user/installations?page=2":
					writeJSON(w, map[string]any{"installations": []map[string]any{}})
				case "/user/installations/1/repositories?per_page=100":
					w.Header().Set("Link", serverLink(r, "/user/installations/1/repositories?page=2"))
					writeJSON(w, map[string]any{
						"repositories": []map[string]any{{
							"id":          10,
							"name":        "alpha",
							"full_name":   "Acme/alpha",
							"owner":       map[string]any{"login": "Acme"},
							"permissions": map[string]any{"maintain": true},
						}},
					})
				case "/user/installations/1/repositories?page=2":
					writeJSON(w, map[string]any{
						"repositories": []map[string]any{{
							"id":          11,
							"name":        "beta",
							"full_name":   "Acme/beta",
							"owner":       map[string]any{"login": "Acme"},
							"permissions": map[string]any{"pull": true},
						}},
					})
				case "/user/memberships/orgs/Acme":
					w.WriteHeader(tt.membershipStatus)
					writeJSON(w, tt.membershipBody)
				default:
					t.Fatalf("unexpected path %s", r.URL.RequestURI())
				}
			}))
			defer server.Close()

			provider := NewGitHub("client", "secret", "webhook", WithAPIURL(server.URL), WithAppCredentials(1, []byte("app-mode-enabled")))
			access, err := provider.ListUserAccess(context.Background(), &oauth2.Token{AccessToken: "user-token"})
			if err != nil {
				t.Fatalf("ListUserAccess() error = %v", err)
			}
			if len(access.Orgs) != tt.wantInstallations {
				t.Fatalf("org count = %d, want %d", len(access.Orgs), tt.wantInstallations)
			}
			if access.Orgs[0].AccountLogin != "Acme" || access.Orgs[0].Level != tt.wantOrgLevel {
				t.Fatalf("org access = %#v, want login Acme level %q", access.Orgs[0], tt.wantOrgLevel)
			}
			if len(access.Repos) != len(tt.wantRepoLevels) {
				t.Fatalf("repo count = %d, want %d", len(access.Repos), len(tt.wantRepoLevels))
			}
			for idx, wantLevel := range tt.wantRepoLevels {
				if access.Repos[idx].Level != wantLevel {
					t.Fatalf("repo[%d] level = %q, want %q", idx, access.Repos[idx].Level, wantLevel)
				}
			}
		})
	}
}

func TestGitHubListUserAccessReturnsEmptyOutsideAppMode(t *testing.T) {
	t.Parallel()

	provider := NewGitHub("client", "secret", "webhook")
	access, err := provider.ListUserAccess(context.Background(), &oauth2.Token{AccessToken: "user-token"})
	if err != nil {
		t.Fatalf("ListUserAccess() error = %v", err)
	}
	if len(access.Orgs) != 0 || len(access.Repos) != 0 {
		t.Fatalf("expected empty access, got %#v", access)
	}
}

func writeJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		panic(err)
	}
}

func serverLink(r *http.Request, path string) string {
	return "<" + "http://" + r.Host + path + ">; rel=\"next\""
}
