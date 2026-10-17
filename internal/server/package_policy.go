package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/cooldown"
	"github.com/hibouhq/hibou/internal/packagepolicy"
	"github.com/hibouhq/hibou/internal/repoconfig"
	"github.com/hibouhq/hibou/internal/store"
)

// Package policy endpoint (ADR-048 §3.1, §7): what a registry proxy, a CI
// step or an agent asks before a package version is used. Read-only,
// org-wide: the answer never names anything the caller could not list.

const maxPolicyPurls = 500

type packagePolicyRequest struct {
	Purls []string `json:"purls"`
	// Repo scopes the answer to a repository: its .hibou.yaml window and
	// private namespaces, and its acceptances.
	Repo string `json:"repo,omitempty"`
}

type packagePolicyResponse struct {
	Decisions []packagepolicy.Decision `json:"decisions"`
	Policy    packagePolicySummary     `json:"policy"`
}

type packagePolicySummary struct {
	Window string `json:"window"`
	Repo   string `json:"repo,omitempty"`
}

// handlePackagePolicy answers GET ?purl=…&purl=… and POST {"purls": [...]}.
func (s *Server) handlePackagePolicy(w http.ResponseWriter, r *http.Request) {
	org, _, ok := s.loadOrgMembership(r, w)
	if !ok {
		return
	}
	if s.packagePolicy == nil {
		api.JSONError(w, http.StatusConflict, "package policy is not available on this instance")
		return
	}
	var req packagePolicyRequest
	if r.Method == http.MethodPost {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			api.JSONError(w, http.StatusBadRequest, "invalid request body")
			return
		}
	} else {
		req.Purls = r.URL.Query()["purl"]
		req.Repo = r.URL.Query().Get("repo")
	}
	if len(req.Purls) == 0 {
		api.JSONError(w, http.StatusBadRequest, "at least one purl is required")
		return
	}
	if len(req.Purls) > maxPolicyPurls {
		api.JSONError(w, http.StatusBadRequest, "at most 500 purls per request")
		return
	}

	var repoID *uuid.UUID
	var cfg *repoconfig.RepoConfig
	if slug := strings.TrimSpace(req.Repo); slug != "" {
		repo, err := s.queries.GetRepositoryBySlug(r.Context(), org.ID, slug)
		if err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to load repository")
			return
		}
		if repo == nil {
			api.JSONError(w, http.StatusNotFound, "repository not found")
			return
		}
		repoID = &repo.ID
		if loaded, _, err := s.loadBoundRepoConfig(r.Context(), repo); err == nil {
			cfg = loaded
		}
	}
	policy := s.policyFor(org, cfg)
	decisions, err := s.packagePolicy.Evaluate(r.Context(), packagepolicy.Request{OrgID: org.ID, RepoID: repoID, Purls: req.Purls, Policy: policy})
	if err != nil {
		s.log.Error().Err(err).Str("org_id", org.ID.String()).Msg("package policy evaluation failed")
		api.JSONError(w, http.StatusInternalServerError, "failed to evaluate package policy")
		return
	}
	holds, denies := 0, 0
	for _, d := range decisions {
		switch d.Decision {
		case packagepolicy.DecisionHold:
			holds++
		case packagepolicy.DecisionDeny:
			denies++
		}
	}
	// Who asked what, and what was refused: the audit trail that turns
	// "someone tried to install lodahs" into a question hibou can answer.
	clientIP, _ := audit.RequestContext(r)
	s.log.Info().Str("org_id", org.ID.String()).Str("repo", req.Repo).Int("purls", len(req.Purls)).Int("holds", holds).Int("denies", denies).Str("client", clientIP).Msg("package policy evaluated")
	api.JSON(w, http.StatusOK, packagePolicyResponse{
		Decisions: decisions,
		Policy:    packagePolicySummary{Window: windowLabel(policy), Repo: strings.TrimSpace(req.Repo)},
	})
}

// policyFor resolves the package policy for a repository: the instance
// default, the organization's settings on top, and the repository's
// dependencies section, which can only tighten (ADR-048 §3, ADR-035).
func (s *Server) policyFor(org *store.Organization, cfg *repoconfig.RepoConfig) packagepolicy.Policy {
	window := ""
	var namespaces []string
	if org != nil {
		defaults := cooldown.ParseOrgDefaults(org.Settings)
		window = defaults.Window
		namespaces = append(namespaces, defaults.PrivateNamespaces...)
	}
	if cfg != nil && cfg.Dependencies != nil {
		namespaces = append(namespaces, cfg.Dependencies.PrivateNamespaces...)
		if cfg.Dependencies.Cooldown != nil {
			window = cooldown.StricterWindow(window, cfg.Dependencies.Cooldown.Window)
		}
	}
	return s.packagePolicy.PolicyWith(window, namespaces)
}

func windowLabel(policy packagepolicy.Policy) string {
	if policy.WindowMode == cooldown.WindowDuration {
		return policy.WindowDuration.String()
	}
	return policy.WindowMode
}

type packagePolicyAcceptRequest struct {
	Purl      string     `json:"purl"`
	Reason    string     `json:"reason"`
	Repo      string     `json:"repo,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// handleAcceptPackagePolicy records an acceptance (ADR-048 §3): the
// designed exit from a hold, by an org admin, with a reason, audit-logged.
func (s *Server) handleAcceptPackagePolicy(w http.ResponseWriter, r *http.Request) {
	org, user, ok := s.loadOrgAdminUser(r, w)
	if !ok {
		return
	}
	var req packagePolicyAcceptRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	purl := strings.TrimSpace(req.Purl)
	reason := strings.TrimSpace(req.Reason)
	if !strings.HasPrefix(purl, "pkg:") || !strings.Contains(purl, "@") {
		api.JSONError(w, http.StatusBadRequest, "purl must name a package version (pkg:type/name@version)")
		return
	}
	if reason == "" {
		api.JSONError(w, http.StatusBadRequest, "a reason is required")
		return
	}
	var repoID *uuid.UUID
	if slug := strings.TrimSpace(req.Repo); slug != "" {
		repo, err := s.queries.GetRepositoryBySlug(r.Context(), org.ID, slug)
		if err != nil || repo == nil {
			api.JSONError(w, http.StatusNotFound, "repository not found")
			return
		}
		repoID = &repo.ID
	}
	var acceptedBy *uuid.UUID
	if user != nil {
		acceptedBy = &user.ID
	}
	acceptance, err := s.queries.UpsertPackagePolicyAcceptance(r.Context(), store.UpsertPackagePolicyAcceptanceParams{
		OrgID: org.ID, RepoID: repoID, Purl: purl, Reason: reason, AcceptedBy: acceptedBy, ExpiresAt: req.ExpiresAt,
	})
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to record acceptance")
		return
	}
	s.writeAuditLog(r, user, uuid.NullUUID{UUID: org.ID, Valid: true}, auditEntry{
		Action:       audit.ActionPackageAcceptance,
		ResourceType: "package_version",
		ResourceID:   purl,
		Context:      map[string]any{"purl": purl, "reason": reason, "repo": strings.TrimSpace(req.Repo), "expires_at": req.ExpiresAt},
	})
	api.JSON(w, http.StatusOK, acceptance)
}

// handleRevokePackagePolicyAcceptance removes an acceptance.
func (s *Server) handleRevokePackagePolicyAcceptance(w http.ResponseWriter, r *http.Request) {
	org, user, ok := s.loadOrgAdminUser(r, w)
	if !ok {
		return
	}
	purl := strings.TrimSpace(r.URL.Query().Get("purl"))
	if purl == "" {
		api.JSONError(w, http.StatusBadRequest, "purl is required")
		return
	}
	var repoID *uuid.UUID
	if slug := strings.TrimSpace(r.URL.Query().Get("repo")); slug != "" {
		repo, err := s.queries.GetRepositoryBySlug(r.Context(), org.ID, slug)
		if err != nil || repo == nil {
			api.JSONError(w, http.StatusNotFound, "repository not found")
			return
		}
		repoID = &repo.ID
	}
	deleted, err := s.queries.DeletePackagePolicyAcceptance(r.Context(), org.ID, repoID, purl)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to revoke acceptance")
		return
	}
	if !deleted {
		api.JSONError(w, http.StatusNotFound, "no such acceptance")
		return
	}
	s.writeAuditLog(r, user, uuid.NullUUID{UUID: org.ID, Valid: true}, auditEntry{
		Action:       audit.ActionPackageAcceptanceRevoked,
		ResourceType: "package_version",
		ResourceID:   purl,
		Context:      map[string]any{"purl": purl, "repo": strings.TrimSpace(r.URL.Query().Get("repo"))},
	})
	w.WriteHeader(http.StatusNoContent)
}

// handleListPackagePolicyAcceptances lists an org's acceptances.
func (s *Server) handleListPackagePolicyAcceptances(w http.ResponseWriter, r *http.Request) {
	org, _, ok := s.loadOrgMembership(r, w)
	if !ok {
		return
	}
	acceptances, err := s.queries.ListPackagePolicyAcceptancesByOrg(r.Context(), org.ID, 500)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list acceptances")
		return
	}
	api.JSON(w, http.StatusOK, acceptances)
}
