package forge

import "strings"

// MapForgeRole maps a forge-native permission level to a Hibou role
// ("admin", "write", "read"), or "" when the level grants no access.
// providerID is one of "github", "gitlab", "gitea", or "forgejo".
func MapForgeRole(providerID, level string) string {
	provider := strings.ToLower(strings.TrimSpace(providerID))
	normalizedLevel := strings.ToLower(strings.TrimSpace(level))
	if normalizedLevel == "" || normalizedLevel == "none" || normalizedLevel == "0" {
		return ""
	}

	switch provider {
	case "github":
		switch normalizedLevel {
		case "admin", "maintain":
			return "admin"
		case "push":
			return "write"
		case "triage", "pull", "member":
			return "read"
		default:
			return ""
		}
	case "gitlab":
		switch normalizedLevel {
		case "50", "40", "owner", "maintainer":
			return "admin"
		case "30", "developer":
			return "write"
		case "20", "10", "reporter", "guest":
			return "read"
		default:
			return ""
		}
	case "gitea", "forgejo":
		switch normalizedLevel {
		case "admin", "owner":
			return "admin"
		case "write":
			return "write"
		case "read":
			return "read"
		default:
			return ""
		}
	default:
		switch normalizedLevel {
		case "admin", "owner", "maintain", "maintainer":
			return "admin"
		case "write", "push", "developer":
			return "write"
		case "read", "pull", "triage", "reporter", "guest":
			return "read"
		default:
			return ""
		}
	}
}

func RoleForTier(tier string) string {
	switch strings.ToLower(strings.TrimSpace(tier)) {
	case "admin":
		return "admin"
	case "write":
		return "developer"
	case "read":
		return "viewer"
	default:
		return ""
	}
}
