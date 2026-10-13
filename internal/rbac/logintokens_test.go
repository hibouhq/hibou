package rbac

import "testing"

func TestLoginTokensPolicy(t *testing.T) {
	cases := map[string]string{
		``:                             LoginTokensAllow,
		`{}`:                           LoginTokensAllow,
		`{"login_tokens":""}`:          LoginTokensAllow,
		`{"login_tokens":"allow"}`:     LoginTokensAllow,
		`{"login_tokens":"READ_ONLY"}`: LoginTokensReadOnly,
		`{"login_tokens":"deny"}`:      LoginTokensDeny,
		`{"login_tokens":"maybe"}`:     LoginTokensDeny,
		`not json`:                     LoginTokensDeny,
	}
	for settings, want := range cases {
		if got := LoginTokensPolicy([]byte(settings)); got != want {
			t.Errorf("LoginTokensPolicy(%q) = %q, want %q", settings, got, want)
		}
	}
}

func TestCapRoleForLoginToken(t *testing.T) {
	cases := []struct{ role, policy, want string }{
		{RoleAdmin, LoginTokensAllow, RoleAdmin},
		{RoleAdmin, LoginTokensReadOnly, RoleViewer},
		{RoleDeveloper, LoginTokensReadOnly, RoleViewer},
		{RoleAuditor, LoginTokensReadOnly, RoleAuditor},
		{"", LoginTokensReadOnly, ""},
		{RoleAdmin, LoginTokensDeny, ""},
		{RoleAdmin, "unknown", ""},
	}
	for _, c := range cases {
		if got := CapRoleForLoginToken(c.role, c.policy); got != c.want {
			t.Errorf("CapRoleForLoginToken(%q, %q) = %q, want %q", c.role, c.policy, got, c.want)
		}
	}
}
