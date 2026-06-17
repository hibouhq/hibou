package forge

import "testing"

func TestMapForgeRole(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		providerID string
		level      string
		want       string
	}{
		{name: "github admin", providerID: "github", level: "admin", want: "admin"},
		{name: "github maintain", providerID: "github", level: "maintain", want: "admin"},
		{name: "github push", providerID: "github", level: "push", want: "write"},
		{name: "github triage", providerID: "github", level: "triage", want: "read"},
		{name: "github pull", providerID: "github", level: "pull", want: "read"},
		{name: "github member", providerID: "github", level: "member", want: "read"},
		{name: "github none", providerID: "github", level: "none", want: ""},
		{name: "github empty", providerID: "github", level: "", want: ""},
		{name: "gitlab owner numeric", providerID: "gitlab", level: "50", want: "admin"},
		{name: "gitlab maintainer numeric", providerID: "gitlab", level: "40", want: "admin"},
		{name: "gitlab developer numeric", providerID: "gitlab", level: "30", want: "write"},
		{name: "gitlab reporter numeric", providerID: "gitlab", level: "20", want: "read"},
		{name: "gitlab guest numeric", providerID: "gitlab", level: "10", want: "read"},
		{name: "gitlab no access numeric", providerID: "gitlab", level: "0", want: ""},
		{name: "gitlab owner text", providerID: "gitlab", level: "owner", want: "admin"},
		{name: "gitlab maintainer text", providerID: "gitlab", level: "maintainer", want: "admin"},
		{name: "gitlab developer text", providerID: "gitlab", level: "developer", want: "write"},
		{name: "gitlab reporter text", providerID: "gitlab", level: "reporter", want: "read"},
		{name: "gitlab guest text", providerID: "gitlab", level: "guest", want: "read"},
		{name: "gitea admin", providerID: "gitea", level: "admin", want: "admin"},
		{name: "gitea owner", providerID: "gitea", level: "owner", want: "admin"},
		{name: "gitea write", providerID: "gitea", level: "write", want: "write"},
		{name: "gitea read", providerID: "gitea", level: "read", want: "read"},
		{name: "gitea unknown", providerID: "gitea", level: "maintainer", want: ""},
		{name: "forgejo admin", providerID: "forgejo", level: "admin", want: "admin"},
		{name: "forgejo owner", providerID: "forgejo", level: "owner", want: "admin"},
		{name: "forgejo write", providerID: "forgejo", level: "write", want: "write"},
		{name: "forgejo read", providerID: "forgejo", level: "read", want: "read"},
		{name: "forgejo maintainer does not fall through", providerID: "forgejo", level: "maintainer", want: ""},
		{name: "forgejo developer does not fall through", providerID: "forgejo", level: "developer", want: ""},
		{name: "case insensitive and whitespace", providerID: " GitHub ", level: "  PuSh ", want: "write"},
		{name: "unknown level", providerID: "github", level: "banana", want: ""},
		{name: "unknown provider fallback admin", providerID: "bitbucket", level: "maintainer", want: "admin"},
		{name: "unknown provider fallback write", providerID: "bitbucket", level: "developer", want: "write"},
		{name: "unknown provider fallback read", providerID: "bitbucket", level: "guest", want: "read"},
		{name: "unknown provider fallback empty", providerID: "bitbucket", level: "none", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := MapForgeRole(tt.providerID, tt.level); got != tt.want {
				t.Fatalf("MapForgeRole(%q, %q) = %q, want %q", tt.providerID, tt.level, got, tt.want)
			}
		})
	}
}

func TestRoleForTier(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		tier string
		want string
	}{
		{name: "admin", tier: "admin", want: "admin"},
		{name: "write", tier: "write", want: "developer"},
		{name: "read", tier: "read", want: "viewer"},
		{name: "trim and case", tier: " Read ", want: "viewer"},
		{name: "unknown", tier: "owner", want: ""},
		{name: "empty", tier: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := RoleForTier(tt.tier); got != tt.want {
				t.Fatalf("RoleForTier(%q) = %q, want %q", tt.tier, got, tt.want)
			}
		})
	}
}
