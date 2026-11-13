package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/config"
	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type managedReleaseSource struct {
	ReleaseID      uuid.UUID `json:"release_id"`
	ReleaseVersion string    `json:"release_version"`
	Tag            string    `json:"tag"`
	SHA            string    `json:"sha"`
}

type managedMaintenanceSuggestion struct {
	Mapping      managedMaintenanceMapping  `json:"mapping"`
	TargetBranch string                     `json:"target_branch,omitempty"`
	Evidence     *forge.MaintenanceEvidence `json:"evidence,omitempty"`
	CanCreate    bool                       `json:"can_create"`
	Reason       string                     `json:"reason,omitempty"`
}

func (s *Server) managedMaintenanceRoutes(r chi.Router) {
	r.Get("/{repoSlug}/remediation/maintenance-settings", s.handleManagedMaintenanceSettings)
	r.Put("/{repoSlug}/remediation/maintenance-settings", s.handleManagedMaintenanceSettingsUpdate)
	r.Get("/{repoSlug}/remediation/maintenance-targets", s.handleManagedMaintenanceSuggestions)
	r.Post("/{repoSlug}/remediation/maintenance-targets", s.handleManagedMaintenanceCreate)
}

func (s *Server) managedMaintenancePermissions(r *http.Request, org *store.Organization, repo *store.Repository) (publish, configure bool) {
	role, err := s.principalOrgRole(r, org.ID)
	if err != nil {
		return false, false
	}
	access, err := s.principalRepoAccess(r, org.ID, role)
	if err != nil {
		return false, false
	}
	_, publish, configure = managedPermissions(r, org.Slug, repo.Slug, repo.ID, role, access)
	return
}

func (s *Server) managedMaintenanceCreationReason(r *http.Request, org *store.Organization, repo *store.Repository, settings managedMaintenanceSettings) string {
	patterns := config.ManagedMaintenanceBranchAllowlist()
	if len(patterns) == 0 {
		return "Operator maintenance-branch creation allowlist is empty."
	}
	if err := forge.ValidateMaintenancePatterns(patterns); err != nil {
		return err.Error()
	}
	if !settings.AllowCreation {
		return "Organization maintenance-target creation consent is disabled."
	}
	if !managedOrgConsent(org) {
		return "Organization managed branch/PR consent is required."
	}
	publish, _ := s.managedMaintenancePermissions(r, org, repo)
	if !publish {
		return "Repository admin authorization and vulnerabilities:write capability are required."
	}
	provider, ok := s.forges[repo.Provider].(forge.MaintenanceProvider)
	if !ok {
		return "This forge does not implement create-only, release-confirmed maintenance targets."
	}
	binding, err := s.queries.VerifiedForgeRepositoryTarget(r.Context(), repo.ID)
	if err != nil {
		return "Immutable repository enrollment is unavailable."
	}
	ctx := forge.WithRepositoryIdentity(forge.WithInstallationOwner(r.Context(), binding.Owner), binding.AccountID, binding.RepositoryID)
	if err := provider.CheckMaintenanceCreation(ctx, binding.Owner, binding.Name); err != nil {
		return err.Error()
	}
	return ""
}

func (s *Server) managedMaintenanceRead(w http.ResponseWriter, r *http.Request) (*store.Organization, *store.Repository, bool) {
	org, repo, _, ok := s.loadAuthorizedRepoWithUser(w, r, false)
	if !ok {
		return nil, nil, false
	}
	if auth.RequireCapability(r.Context(), apitoken.CapVulnerabilities, apitoken.AccessRead, org.Slug, repo.Slug) != nil &&
		auth.RequireCapability(r.Context(), apitoken.CapAdmin, apitoken.AccessRead, org.Slug, repo.Slug) != nil {
		api.JSONError(w, http.StatusForbidden, "vulnerabilities:read or admin:read capability is required")
		return nil, nil, false
	}
	return org, repo, true
}

// handleManagedMaintenanceSettings reads explicit organization release mappings.
// @Summary      Get maintenance-target mapping settings
// @Description  Returns organization-owned tag patterns/target templates, current configuration authority, branch/PR consent and creation availability/reason. Requires repository visibility and vulnerabilities:read or admin:read. These mappings are distinct from dependency branch-inventory policy.
// @Tags         remediation
// @Produce      json
// @Security     BearerAuth
// @Param        provider path string true "Forge provider"
// @Param        slug path string true "Organization slug"
// @Param        repoSlug path string true "Repository authorization context"
// @Success      200 {object} api.Response{data=ManagedMaintenanceSettingsResponse}
// @Failure      401,403,404,500,503 {object} api.Response
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/remediation/maintenance-settings [get]
func (s *Server) handleManagedMaintenanceSettings(w http.ResponseWriter, r *http.Request) {
	org, repo, ok := s.managedMaintenanceRead(w, r)
	if !ok {
		return
	}
	settings, err := parseManagedMaintenanceSettings(org)
	if err != nil {
		api.JSONError(w, http.StatusServiceUnavailable, "organization maintenance mappings are invalid")
		return
	}
	_, configure := s.managedMaintenancePermissions(r, org, repo)
	reason := s.managedMaintenanceCreationReason(r, org, repo, settings)
	api.JSON(w, http.StatusOK, map[string]any{"settings": settings, "can_configure": configure, "branch_pr_consent": managedOrgConsent(org), "creation_available": reason == "", "creation_reason": reason})
}

func (s *Server) strictManagedMaintenanceAudit(r *http.Request, user *store.User, org uuid.UUID, resource, action string, details map[string]any) error {
	actor := requestAuditActor(r, user)
	ip, agent := audit.RequestContext(r)
	_, err := s.queries.CreateAuditLog(r.Context(), dbgen.CreateAuditLogParams{
		ActorID: actor.ID, ActorType: actor.Type, ActorDisplay: actor.Display,
		Action: action, ResourceType: "remediation_maintenance_target", ResourceID: resource,
		OrgID: orgAuditID(org), Context: auditContextJSON(details, actor.Extra), IpAddress: ip, UserAgent: agent,
	})
	return err
}

// handleManagedMaintenanceSettingsUpdate persists audited organization mappings.
// @Summary      Configure explicit release-line maintenance mappings
// @Description  Requires organization-wide admin authorization and admin:write; repository-scoped admin tokens are insufficient. Saves at most 50 explicit tag globs and safe target templates using major/minor/patch/tag placeholders. allow_creation requires separate organization branch/PR consent, an operator allowlist and caller/App permissions; saving settings never creates a branch. Response contains settings, can_configure and branch_pr_consent.
// @Tags         remediation
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        provider path string true "Forge provider"
// @Param        slug path string true "Organization slug"
// @Param        repoSlug path string true "Repository authorization context"
// @Param        payload body managedMaintenanceSettings true "Organization maintenance policy, separate from dependencies.branches"
// @Success      200 {object} api.Response{data=ManagedMaintenanceSettingsResponse}
// @Failure      400,401,403,404,500,503 {object} api.Response
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/remediation/maintenance-settings [put]
func (s *Server) handleManagedMaintenanceSettingsUpdate(w http.ResponseWriter, r *http.Request) {
	org, repo, user, ok := s.loadAuthorizedRepoWithUser(w, r, true)
	if !ok {
		return
	}
	if !s.enforceOrgWideCapability(w, r, apitoken.CapAdmin, apitoken.AccessWrite, org.Slug) {
		return
	}
	_, configure := s.managedMaintenancePermissions(r, org, repo)
	if !configure {
		api.JSONError(w, http.StatusForbidden, "organization-wide admin authorization is required")
		return
	}
	var settings managedMaintenanceSettings
	if !decodeManaged(w, r, &settings) {
		return
	}
	if settings.Mappings == nil {
		settings.Mappings = []managedMaintenanceMapping{}
	}
	if err := settings.validate(); err != nil {
		api.JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	data, err := json.Marshal(settings)
	if err != nil {
		api.JSONError(w, 500, "unable to encode maintenance settings")
		return
	}
	details := map[string]any{"settings": settings, "scope": "organization"}
	if err := s.strictManagedMaintenanceAudit(r, user, org.ID, org.ID.String(), "remediation.maintenance.settings_intent", details); err != nil {
		api.JSONError(w, 503, "durable configuration audit is unavailable")
		return
	}
	if err := s.queries.SetManagedMaintenanceSettings(r.Context(), org.ID, data); err != nil {
		api.JSONError(w, 500, "unable to persist maintenance mappings")
		return
	}
	if err := s.strictManagedMaintenanceAudit(r, user, org.ID, org.ID.String(), "remediation.maintenance.settings_saved", details); err != nil {
		api.JSONError(w, 503, "settings saved; audit completion failed, reload to reconcile")
		return
	}
	api.JSON(w, http.StatusOK, map[string]any{"settings": settings, "can_configure": true, "branch_pr_consent": managedOrgConsent(org)})
}

func (s *Server) managedReleaseSource(ctx context.Context, repo *store.Repository, id uuid.UUID) (*managedReleaseSource, error) {
	release, err := s.queries.GetReleaseByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if release == nil || release.RepoID != repo.ID || release.SnapshotID == nil {
		return nil, errors.New("release has no exact shipped source in this repository")
	}
	snapshot, err := s.queries.GetSnapshotByID(ctx, *release.SnapshotID)
	if err != nil {
		return nil, err
	}
	ref, err := s.queries.GetRefByID(ctx, release.RefID)
	if err != nil {
		return nil, err
	}
	if snapshot == nil || ref == nil || ref.RepoID != repo.ID || snapshot.RefID != release.RefID || ref.RefType != store.RefTypeTag ||
		!managedFullCommitSHA.MatchString(snapshot.CommitSHA) {
		return nil, errors.New("release source snapshot/tag binding is incomplete")
	}
	tag := strings.TrimPrefix(ref.Name, "refs/tags/")
	if err := forge.ValidateMaintenanceRef(tag); err != nil {
		return nil, err
	}
	return &managedReleaseSource{ReleaseID: release.ID, ReleaseVersion: release.Version, Tag: tag, SHA: strings.ToLower(snapshot.CommitSHA)}, nil
}

// handleManagedMaintenanceSuggestions provides declared, evidence-backed targets.
// @Summary      Suggest mapped maintenance targets for a shipped release
// @Description  Matches explicit organization tag patterns against the exact release snapshot/tag binding. Suggestions include live tag confirmation, existing branch head and tag-to-target ancestry evidence, with creation availability/reasons. Does not guess writes or create branches. Arbitrary manual existing-branch selection remains available.
// @Tags         remediation
// @Produce      json
// @Security     BearerAuth
// @Param        provider path string true "Forge provider"
// @Param        slug path string true "Organization slug"
// @Param        repoSlug path string true "Repository slug"
// @Param        release_id query string true "Release UUID with an exact shipped snapshot"
// @Success      200 {object} api.Response{data=ManagedMaintenanceSuggestionsResponse}
// @Failure      400,401,403,404,409,500,503 {object} api.Response
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/remediation/maintenance-targets [get]
func (s *Server) handleManagedMaintenanceSuggestions(w http.ResponseWriter, r *http.Request) {
	org, repo, ok := s.managedMaintenanceRead(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.URL.Query().Get("release_id"))
	if err != nil {
		api.JSONError(w, 400, "a release_id is required")
		return
	}
	source, err := s.managedReleaseSource(r.Context(), repo, id)
	if err != nil {
		api.JSONError(w, 409, err.Error())
		return
	}
	settings, err := parseManagedMaintenanceSettings(org)
	if err != nil {
		api.JSONError(w, 503, "organization maintenance mappings are invalid")
		return
	}
	ctx, provider, live, err := s.managedLiveTarget(r.Context(), repo)
	if err != nil {
		api.JSONError(w, 409, "immutable live repository identity is unavailable")
		return
	}
	maintenance, supported := provider.(forge.MaintenanceProvider)
	creationReason := s.managedMaintenanceCreationReason(r, org, repo, settings)
	patterns := config.ManagedMaintenanceBranchAllowlist()
	suggestions := []managedMaintenanceSuggestion{}
	for _, mapping := range settings.Mappings {
		target, matched, renderErr := mapping.target(source.Tag)
		if !matched {
			continue
		}
		candidate := managedMaintenanceSuggestion{Mapping: mapping, TargetBranch: target}
		switch {
		case renderErr != nil:
			candidate.Reason = renderErr.Error()
		case !supported:
			candidate.Reason = "Forge tag/ancestry evidence is unavailable; manual existing targets remain supported."
		default:
			candidate.Evidence, err = maintenance.InspectMaintenanceTarget(ctx, live.Owner, live.Name, source.Tag, source.SHA, target)
			if err != nil {
				candidate.Reason = err.Error()
			} else if candidate.Evidence.Exists {
				if candidate.Evidence.SourceAncestor {
					candidate.Reason = "Declared mapping; confirmed source tag is an ancestor of the existing target."
				} else {
					candidate.Reason = "Declared mapping, but the existing target does not contain the pinned release; inspect before choosing."
				}
			} else if creationReason != "" {
				candidate.Reason = creationReason
			} else if target == live.DefaultBranch {
				candidate.Reason = "Default branch creation is not supported."
			} else if err := forge.CheckMaintenanceBranch(target, patterns); err != nil {
				candidate.Reason = err.Error()
			} else {
				candidate.CanCreate = true
				candidate.Reason = "Explicit mapping and confirmed source tag; create only at this pinned SHA."
			}
		}
		suggestions = append(suggestions, candidate)
	}
	reason := ""
	if len(suggestions) == 0 {
		reason = "No explicit organization release-tag mapping matches this source. Manual existing branch selection remains available."
	}
	api.JSON(w, http.StatusOK, map[string]any{"source": source, "suggestions": suggestions, "reason": reason, "creation_reason": creationReason})
}

// handleManagedMaintenanceCreate creates only an explicitly confirmed target.
// @Summary      Create a mapped maintenance target at a confirmed release SHA
// @Description  Requires admin authorization, vulnerabilities:write, both organization consents, GitHub App propose/contents-write permission, and an operator creation allowlist (empty disables creation). Confirms the current mapping, release/snapshot/source tag/full SHA and live immutable repository/tag. Creates only a missing ref at the exact confirmed SHA; never updates, deletes, force-pushes or repoints an existing branch. Audited retries reconcile only the same source SHA with a prior durable intent. Does not generate a patch or publish a PR.
// @Tags         remediation
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        provider path string true "Forge provider"
// @Param        slug path string true "Organization slug"
// @Param        repoSlug path string true "Repository slug"
// @Param        payload body ManagedMaintenanceCreateRequest true "Confirmed mapped target and exact shipped source"
// @Success      200 {object} api.Response{data=forge.MaintenanceCreated}
// @Failure      400,401,403,404,409,500 {object} api.Response
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/remediation/maintenance-targets [post]
func (s *Server) handleManagedMaintenanceCreate(w http.ResponseWriter, r *http.Request) {
	org, repo, user, ok := s.loadAuthorizedRepoWithUser(w, r, true)
	if !ok {
		return
	}
	if !s.enforceTokenCapability(w, r, apitoken.CapVulnerabilities, apitoken.AccessWrite, org.Slug, repo.Slug) {
		return
	}
	var req ManagedMaintenanceCreateRequest
	if !decodeManaged(w, r, &req) {
		return
	}
	if req.ReleaseID == uuid.Nil || !managedFullCommitSHA.MatchString(req.SourceSHA) {
		api.JSONError(w, 400, "an exact release and full confirmed source SHA are required")
		return
	}
	if !managedMappingID.MatchString(req.MappingID) {
		api.JSONError(w, http.StatusBadRequest, "a declared mapping ID is required")
		return
	}
	if err := forge.ValidateMaintenanceRef(req.TargetBranch); err != nil {
		api.JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := forge.ValidateMaintenanceRef(req.SourceTag); err != nil {
		api.JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	r = r.WithContext(ctx)
	var created *forge.MaintenanceCreated
	err := s.queries.WithManagedMaintenanceLock(ctx, repo.ID, req.TargetBranch, func() error {
		current, err := s.queries.GetOrganizationByID(ctx, org.ID)
		if err != nil || current == nil {
			return errors.New("organization authorization is unavailable")
		}
		settings, err := parseManagedMaintenanceSettings(current)
		if err != nil {
			return err
		}
		if reason := s.managedMaintenanceCreationReason(r, current, repo, settings); reason != "" {
			return errors.New(reason)
		}
		source, err := s.managedReleaseSource(ctx, repo, req.ReleaseID)
		if err != nil {
			return err
		}
		if source.Tag != req.SourceTag || !strings.EqualFold(source.SHA, req.SourceSHA) {
			return errors.New("confirmed release tag/source changed; refresh the suggestion")
		}
		approved := false
		for _, mapping := range settings.Mappings {
			if mapping.ID != req.MappingID {
				continue
			}
			target, matched, err := mapping.target(source.Tag)
			if err != nil {
				return err
			}
			approved = matched && target == req.TargetBranch
		}
		if !approved {
			return errors.New("target no longer equals an explicit release mapping")
		}
		if err := forge.CheckMaintenanceBranch(req.TargetBranch, config.ManagedMaintenanceBranchAllowlist()); err != nil {
			return err
		}
		boundCtx, provider, live, err := s.managedLiveTarget(ctx, repo)
		if err != nil {
			return err
		}
		maintenance, ok := provider.(forge.MaintenanceProvider)
		if !ok {
			return errors.New("forge maintenance creation is unavailable")
		}
		if req.TargetBranch == live.DefaultBranch {
			return errors.New("default branch creation is not supported")
		}
		resourceHash := sha256.Sum256([]byte(repo.ID.String() + "\x00" + source.ReleaseID.String() + "\x00" + source.Tag + "\x00" + source.SHA + "\x00" + req.TargetBranch))
		resource := hex.EncodeToString(resourceHash[:])
		prior, err := s.queries.HasManagedMaintenanceIntent(ctx, org.ID, resource)
		if err != nil {
			return err
		}
		created, err = maintenance.CreateApprovedMaintenanceTarget(boundCtx, live.Owner, live.Name, forge.MaintenanceCreation{
			SourceTag: source.Tag, SourceSHA: source.SHA, TargetBranch: req.TargetBranch,
			ApprovedPatterns: config.ManagedMaintenanceBranchAllowlist(), ReconcileExisting: prior,
			Audit: func(step string, event any) error {
				action := "remediation.maintenance." + step
				if step == "ref_intent" {
					action = "remediation.maintenance.intent"
				}
				return s.strictManagedMaintenanceAudit(r, user, org.ID, resource, action, map[string]any{
					"repo_id": repo.ID, "release": source, "mapping_id": req.MappingID, "target_branch": req.TargetBranch, "event": event,
				})
			},
		})
		return err
	})
	if err != nil {
		api.JSONError(w, http.StatusConflict, "maintenance target was not repointed; creation refused or requires retry/reconciliation: "+err.Error())
		return
	}
	api.JSON(w, http.StatusOK, created)
}
