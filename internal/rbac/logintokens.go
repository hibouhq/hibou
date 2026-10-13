package rbac

import (
	"encoding/json"
	"strings"
)

// Org policy for membership-wide device-login tokens (ADR-043 §4), stored in
// organizations.settings as "login_tokens". Unset means allow.
const (
	LoginTokensAllow    = "allow"
	LoginTokensReadOnly = "read_only"
	LoginTokensDeny     = "deny"
)

// LoginTokensPolicy reads the policy from an org's settings document. An
// unreadable document or an unknown value fails closed (deny).
func LoginTokensPolicy(settings json.RawMessage) string {
	if len(settings) == 0 {
		return LoginTokensAllow
	}
	var doc struct {
		LoginTokens *string `json:"login_tokens"`
	}
	if err := json.Unmarshal(settings, &doc); err != nil {
		return LoginTokensDeny
	}
	if doc.LoginTokens == nil {
		return LoginTokensAllow
	}
	switch value := strings.ToLower(strings.TrimSpace(*doc.LoginTokens)); value {
	case "", LoginTokensAllow:
		return LoginTokensAllow
	case LoginTokensReadOnly, LoginTokensDeny:
		return value
	default:
		return LoginTokensDeny
	}
}

// CapRoleForLoginToken applies the policy to a user's stored org role when the
// request carries a membership-wide token: read_only caps the role at a
// read-only one, deny removes it (the org then answers like for a non-member).
func CapRoleForLoginToken(role, policy string) string {
	switch policy {
	case LoginTokensAllow:
		return role
	case LoginTokensReadOnly:
		if role == "" || role == RoleViewer || role == RoleAuditor {
			return role
		}
		return RoleViewer
	default:
		return ""
	}
}
