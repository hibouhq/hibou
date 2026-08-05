package server

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/auth"
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
