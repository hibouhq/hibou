package permissionsync

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"golang.org/x/oauth2"

	"github.com/hibouhq/hibou/internal/events"
	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/store"
)

type Store interface {
	GetOrganizationByProviderAndSlug(ctx context.Context, provider, slug string) (*store.Organization, error)
	// UpsertForgeOrgMember records a membership; repoScoped confines it to
	// the user's repository grants.
	UpsertForgeOrgMember(ctx context.Context, orgID, userID uuid.UUID, role string, repoScoped bool) error
	ListForgeOrgMembershipsByUser(ctx context.Context, userID uuid.UUID) ([]store.ForgeOrgMembership, error)
	PruneForgeOrgMembersForUser(ctx context.Context, userID uuid.UUID, keepOrgIDs []uuid.UUID) error
	GetRepositoryBySlug(ctx context.Context, orgID uuid.UUID, slug string) (*store.Repository, error)
	UpsertForgeUserRepoAccess(ctx context.Context, userID, repoID uuid.UUID, role string) error
	PruneForgeUserRepoAccess(ctx context.Context, userID uuid.UUID, keepRepoIDs []uuid.UUID) error
	ListRepositoryIDsByOrg(ctx context.Context, orgID uuid.UUID) ([]uuid.UUID, error)

	// Operator-granted roles. The sync never creates these — it only reacts to
	// the forge changing someone's standing underneath them.
	SuspendLocalRoles(ctx context.Context, userID, orgID uuid.UUID, reason string) ([]store.LocalRoleGrant, error)
	RevokeLocalRolesForOrg(ctx context.Context, userID, orgID uuid.UUID) error
}

type RBAC interface {
	AddRoleForUserInOrg(userID uuid.UUID, role string, orgID uuid.UUID) error
	RemoveRoleForUserInOrg(userID uuid.UUID, role string, orgID uuid.UUID) error
	RemoveLocalRoleForUserInOrg(userID uuid.UUID, role string, orgID uuid.UUID) error
}

// Publisher lets the sync announce a capability it parked. Optional: a nil bus
// degrades to logging, which is right for the CLI paths that sync without a
// running notification stack.
type Publisher interface {
	Publish(ctx context.Context, event events.Event)
}

type Service struct {
	store  Store
	rbac   RBAC
	forges map[string]forge.Provider
	bus    Publisher
	log    zerolog.Logger
}

// WithPublisher attaches an event bus for suspension notifications.
func (s *Service) WithPublisher(bus Publisher) *Service {
	if s != nil {
		s.bus = bus
	}
	return s
}

func NewService(store Store, rbac RBAC, forges map[string]forge.Provider, log zerolog.Logger) *Service {
	if forges == nil {
		forges = map[string]forge.Provider{}
	}

	return &Service{
		store:  store,
		rbac:   rbac,
		forges: forges,
		log:    log.With().Str("component", "permissionsync").Logger(),
	}
}

func (s *Service) SyncUser(ctx context.Context, user *store.User, providerID string, token *oauth2.Token) error {
	if s == nil || s.store == nil || user == nil || token == nil {
		return nil
	}

	provider := s.forges[strings.TrimSpace(providerID)]
	if provider == nil {
		return nil
	}
	providerID = provider.ID()

	access, err := provider.ListUserAccess(ctx, token)
	if err != nil {
		return err
	}

	existingMemberships, err := s.store.ListForgeOrgMembershipsByUser(ctx, user.ID)
	if err != nil {
		return err
	}
	existingRoles := make(map[uuid.UUID]string, len(existingMemberships))
	for _, membership := range existingMemberships {
		existingRoles[membership.OrgID] = membership.Role
	}

	orgsByAccount := make(map[string]*store.Organization)
	ids := &accountIDLookup{}
	ids.resolver, _ = provider.(AccountIDResolver)
	desiredOrgRoles := make(map[uuid.UUID]string, len(access.Orgs))
	desiredOrgOrder := make([]uuid.UUID, 0, len(access.Orgs))
	// confirmedOrgs are the orgs the forge confirmed an org membership in, as
	// opposed to an org level derived from repository grants alone.
	confirmedOrgs := make(map[uuid.UUID]bool, len(access.Orgs))
	for _, orgAccess := range access.Orgs {
		accountKey := normalizeAccessKey(orgAccess.AccountLogin)
		if accountKey == "" {
			continue
		}

		org, ok, err := s.resolveOrganization(ctx, providerID, orgAccess.AccountLogin, orgsByAccount, ids)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		// Recorded before the role mapping: GitHub's plain membership level
		// ("read") maps to no org role, and such members reach the org through
		// their repository grants below — still as confirmed members.
		if !repoDerivedOrgLevel(orgAccess.Level) {
			confirmedOrgs[org.ID] = true
		}

		enumRole := forge.RoleForTier(forge.MapForgeRole(providerID, orgAccess.Level))
		if enumRole == "" {
			continue
		}
		if _, seen := desiredOrgRoles[org.ID]; !seen {
			desiredOrgOrder = append(desiredOrgOrder, org.ID)
		}
		desiredOrgRoles[org.ID] = strongerRole(desiredOrgRoles[org.ID], enumRole)
	}

	desiredRepoRoles := make(map[uuid.UUID]string, len(access.Repos))
	desiredRepoOrder := make([]uuid.UUID, 0, len(access.Repos))
	grantsByOrg := make(map[uuid.UUID]map[uuid.UUID]bool, 4)
	// Orgs reachable only through repo-level access (outside collaborators,
	// per-repo readers): they carry no org membership on the forge, so the
	// org prune below must not evict them — that was the bug where invited
	// readers lost the org from /orgs the moment THEY logged in, until the
	// org-side sync re-added it.
	repoOnlyOrgIDs := make([]uuid.UUID, 0, 4)
	for _, repoAccess := range access.Repos {
		// Resolved, not read from the org-loop's cache: a repo-only user
		// (outside collaborator) has no entry in access.Orgs, so the cache is
		// cold and the bare map read dropped their entire repo access at login
		// — which the prune below then deleted.
		org, ok, err := s.resolveOrganization(ctx, providerID, repoAccess.AccountLogin, orgsByAccount, ids)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		repoName := strings.TrimSpace(repoAccess.Name)
		if repoName == "" {
			continue
		}
		repo, err := s.store.GetRepositoryBySlug(ctx, org.ID, repoName)
		if err != nil {
			return err
		}
		if repo == nil {
			continue
		}

		enumRole := forge.RoleForTier(forge.MapForgeRole(providerID, repoAccess.Level))
		if enumRole == "" {
			continue
		}
		if _, seen := desiredRepoRoles[repo.ID]; !seen {
			desiredRepoOrder = append(desiredRepoOrder, repo.ID)
		}
		desiredRepoRoles[repo.ID] = strongerRole(desiredRepoRoles[repo.ID], enumRole)
		if grantsByOrg[org.ID] == nil {
			grantsByOrg[org.ID] = map[uuid.UUID]bool{}
			if _, hasOrgRole := desiredOrgRoles[org.ID]; !hasOrgRole {
				repoOnlyOrgIDs = append(repoOnlyOrgIDs, org.ID)
			}
		}
		grantsByOrg[org.ID][repo.ID] = true
	}

	// Repository grants are written before the memberships that scope to
	// them: a request in between sees fewer repositories, never more.
	keptRepoIDs := make([]uuid.UUID, 0, len(desiredRepoOrder))
	for _, repoID := range desiredRepoOrder {
		role := desiredRepoRoles[repoID]
		if role == "" {
			continue
		}
		if err := s.store.UpsertForgeUserRepoAccess(ctx, user.ID, repoID, role); err != nil {
			return err
		}
		keptRepoIDs = append(keptRepoIDs, repoID)
	}

	keptOrgIDs := make([]uuid.UUID, 0, len(desiredOrgOrder)+len(repoOnlyOrgIDs))
	for _, orgID := range desiredOrgOrder {
		role := desiredOrgRoles[orgID]
		if role == "" {
			continue
		}
		scoped, err := s.repoScoped(ctx, orgID, role, confirmedOrgs[orgID], grantsByOrg[orgID])
		if err != nil {
			return err
		}
		if err := s.store.UpsertForgeOrgMember(ctx, orgID, user.ID, role, scoped); err != nil {
			return err
		}
		keptOrgIDs = append(keptOrgIDs, orgID)
		priorRole := existingRoles[orgID]
		if priorRole == role {
			continue
		}
		if added := s.addOrgRole(user.ID, role, orgID); added && priorRole != "" && priorRole != role {
			s.removeOrgRole(user.ID, priorRole, orgID)
			// A downgrade says the person's standing changed, but not why: a
			// narrowed remit and a team reorganisation look identical here.
			// Keeping a privileged grant would leave a demoted admin authoring
			// findings across every repository; revoking it would silently
			// break a triage queue on a reorg. Suspension is safe in the
			// meantime and recoverable in one click.
			if roleRank(role) < roleRank(priorRole) {
				s.suspendLocalGrants(ctx, user.ID, orgID, priorRole, role)
			}
		}
	}

	// Repo-level access keeps the owning org visible as a viewer membership:
	// without it the person can open their repos but the org never appears on
	// /orgs, and the login prune would evict what the org-side sync granted.
	for _, orgID := range repoOnlyOrgIDs {
		scoped, err := s.repoScoped(ctx, orgID, "viewer", confirmedOrgs[orgID], grantsByOrg[orgID])
		if err != nil {
			return err
		}
		if err := s.store.UpsertForgeOrgMember(ctx, orgID, user.ID, "viewer", scoped); err != nil {
			return err
		}
		keptOrgIDs = append(keptOrgIDs, orgID)
		desiredOrgRoles[orgID] = "viewer"
		if existingRoles[orgID] == "" {
			s.addOrgRole(user.ID, "viewer", orgID)
		}
	}

	// Prune AFTER both halves are known: the org list alone is a narrower view
	// than what this same pass writes.
	if err := s.store.PruneForgeOrgMembersForUser(ctx, user.ID, keptOrgIDs); err != nil {
		return err
	}
	for _, membership := range existingMemberships {
		if _, keep := desiredOrgRoles[membership.OrgID]; keep {
			continue
		}
		s.removeOrgRole(user.ID, membership.Role, membership.OrgID)
		// Losing membership is not ambiguous the way a downgrade is: the person
		// may have left the company entirely, so their grants go with it rather
		// than waiting for somebody to re-confirm.
		s.revokeLocalGrants(ctx, user.ID, membership.OrgID)
	}

	return s.store.PruneForgeUserRepoAccess(ctx, user.ID, keptRepoIDs)
}

// repoDerivedOrgLevel reports an org level the forge derived from repository
// grants rather than from an org membership: GitHub reports "push"/"pull"
// for an installation account the user is not a member of (an outside
// collaborator), and "read"/"admin" for a confirmed member.
func repoDerivedOrgLevel(level string) bool {
	switch normalizeAccessKey(level) {
	case "push", "pull":
		return true
	default:
		return false
	}
}

// repoScoped decides whether a membership reaches specific repositories only.
// Admins never are. A person the forge did not confirm as an org member is.
// A confirmed member is scoped when an enrolled repository is missing from
// their grants: the forge itself withheld it (no base permission). The
// verdict is stored with the time it was reached (org_members.repo_scope_at),
// so a repository enrolled later stays invisible to any viewer/developer —
// scoped or recorded as org-wide — holding no grant on it, until a sync
// grants it.
func (s *Service) repoScoped(ctx context.Context, orgID uuid.UUID, role string, confirmedMember bool, granted map[uuid.UUID]bool) (bool, error) {
	if role != "viewer" && role != "developer" {
		return false, nil
	}
	if !confirmedMember {
		return true, nil
	}
	enrolled, err := s.store.ListRepositoryIDsByOrg(ctx, orgID)
	if err != nil {
		return false, err
	}
	for _, repoID := range enrolled {
		if !granted[repoID] {
			return true, nil
		}
	}
	return false, nil
}

// resolveOrganization maps a forge account login to its Hibou org. The slug is
// only the lookup key: an org bound to a forge account is returned only when
// the login still denotes that account — the same immutable id when the forge
// can tell, else the same exact login. Otherwise a renamed-then-re-registered
// login, or a login that merely slugifies alike, would inherit the org and its
// admin role (security audit §3.3).
func (s *Service) resolveOrganization(ctx context.Context, providerID, accountLogin string, cache map[string]*store.Organization, ids *accountIDLookup) (*store.Organization, bool, error) {
	accountKey := normalizeAccessKey(accountLogin)
	if accountKey == "" {
		return nil, false, nil
	}
	if org, ok := cache[accountKey]; ok {
		return org, org != nil, nil
	}

	org, err := s.store.GetOrganizationByProviderAndSlug(ctx, providerID, slugifyAccount(accountLogin))
	if err != nil {
		return nil, false, err
	}
	if org != nil {
		bound, err := orgBoundToLogin(ctx, org, accountLogin, ids)
		if err != nil {
			return nil, false, err
		}
		if !bound {
			s.log.Warn().Str("provider", providerID).Str("account", accountLogin).Str("org_id", org.ID.String()).
				Msg("forge account does not match the account the org is bound to; not mirroring its permissions")
			org = nil
		}
	}
	cache[accountKey] = org
	return org, org != nil, nil
}

func orgBoundToLogin(ctx context.Context, org *store.Organization, accountLogin string, ids *accountIDLookup) (bool, error) {
	if org.ForgeAccountID != "" && ids != nil && ids.resolver != nil {
		id, known, err := ids.get(ctx, accountLogin)
		if err != nil {
			return false, err
		}
		if known {
			return id == org.ForgeAccountID, nil
		}
	}
	if login := strings.TrimSpace(org.ForgeAccountLogin); login != "" {
		return strings.EqualFold(login, strings.TrimSpace(accountLogin)), nil
	}
	return true, nil
}

// AccountIDResolver maps installed accounts' lowercased logins to their
// immutable forge account ids (GitHub App installations).
type AccountIDResolver interface {
	InstallationAccountIDs(ctx context.Context) (map[string]string, error)
}

// accountIDLookup loads the login→id map at most once per sync. A failure
// aborts the sync rather than treating orgs as unbound, which would prune
// every membership on a transient API error.
type accountIDLookup struct {
	resolver AccountIDResolver
	ids      map[string]string
	loaded   bool
}

// get returns the login's account id; known is false when the forge cannot
// list ids at all (not in App mode), so the caller falls back to the login.
func (l *accountIDLookup) get(ctx context.Context, login string) (string, bool, error) {
	if !l.loaded {
		ids, err := l.resolver.InstallationAccountIDs(ctx)
		if err != nil {
			return "", false, fmt.Errorf("resolve forge account ids: %w", err)
		}
		l.ids, l.loaded = ids, true
	}
	if l.ids == nil {
		return "", false, nil
	}
	return l.ids[normalizeAccessKey(login)], true, nil
}

func (s *Service) addOrgRole(userID uuid.UUID, role string, orgID uuid.UUID) bool {
	if s.rbac == nil || role == "" || orgID == uuid.Nil || userID == uuid.Nil {
		return false
	}
	if err := s.rbac.AddRoleForUserInOrg(userID, role, orgID); err != nil {
		s.log.Warn().Err(err).Str("user_id", userID.String()).Str("org_id", orgID.String()).Str("role", role).Msg("failed to add org RBAC role during permission sync")
		return false
	}
	return true
}

func (s *Service) removeOrgRole(userID uuid.UUID, role string, orgID uuid.UUID) {
	if s.rbac == nil || role == "" || orgID == uuid.Nil || userID == uuid.Nil {
		return
	}
	if err := s.rbac.RemoveRoleForUserInOrg(userID, role, orgID); err != nil {
		s.log.Warn().Err(err).Str("user_id", userID.String()).Str("org_id", orgID.String()).Str("role", role).Msg("failed to remove org RBAC role during permission sync")
	}
}

func normalizeAccessKey(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func slugifyAccount(login string) string {
	return store.SlugifyForgeAccount(login)
}

func strongerRole(left, right string) string {
	if roleRank(right) > roleRank(left) {
		return right
	}
	return left
}

func roleRank(role string) int {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "admin":
		return 3
	case "developer":
		return 2
	case "viewer":
		return 1
	default:
		return 0
	}
}

// suspendLocalGrants parks a user's operator-granted roles in one org after the
// forge narrowed their standing.
//
// The Casbin policy is dropped so enforcement never sees a suspended grant, and
// the row is kept so an operator can see what was suspended and why, and restore
// it without re-deriving the decision.
func (s *Service) suspendLocalGrants(ctx context.Context, userID, orgID uuid.UUID, priorRole, newRole string) {
	s.suspendLocalGrantsWithReason(ctx, userID, orgID, fmt.Sprintf("forge role changed from %s to %s", priorRole, newRole))
}

// suspendLocalGrantsWithReason is suspendLocalGrants with the recorded reason
// spelled out by the caller.
func (s *Service) suspendLocalGrantsWithReason(ctx context.Context, userID, orgID uuid.UUID, reason string) {
	suspended, err := s.store.SuspendLocalRoles(ctx, userID, orgID, reason)
	if err != nil {
		s.log.Warn().Err(err).Str("user_id", userID.String()).Str("org_id", orgID.String()).
			Msg("failed to suspend local role grants after the forge narrowed a standing")
		return
	}
	for _, grant := range suspended {
		if s.rbac == nil {
			continue
		}
		if err := s.rbac.RemoveLocalRoleForUserInOrg(userID, grant.Role, orgID); err != nil {
			s.log.Warn().Err(err).Str("role", grant.Role).
				Msg("suspended a local grant but failed to drop its policy")
			continue
		}
		s.log.Info().Str("user_id", userID.String()).Str("org_id", orgID.String()).
			Str("role", grant.Role).Str("reason", reason).
			Msg("suspended a local role grant; an operator must re-confirm it")
		if s.bus != nil {
			s.bus.Publish(ctx, events.Event{
				Type: events.LocalGrantSuspended,
				Payload: map[string]any{
					"user_id":  userID.String(),
					"org_id":   orgID.String(),
					"role":     grant.Role,
					"reason":   reason,
					"severity": "medium",
				},
				Timestamp: time.Now().UTC(),
			})
		}
	}
}

// revokeLocalGrants drops a user's operator-granted roles in an org they are no
// longer a member of.
func (s *Service) revokeLocalGrants(ctx context.Context, userID, orgID uuid.UUID) {
	grants, err := s.store.SuspendLocalRoles(ctx, userID, orgID, "removed from the organization")
	if err != nil {
		s.log.Warn().Err(err).Msg("failed to read local grants while removing membership")
	}
	for _, grant := range grants {
		if s.rbac != nil {
			if err := s.rbac.RemoveLocalRoleForUserInOrg(userID, grant.Role, orgID); err != nil {
				s.log.Warn().Err(err).Str("role", grant.Role).Msg("failed to drop a local grant policy")
			}
		}
	}
	if err := s.store.RevokeLocalRolesForOrg(ctx, userID, orgID); err != nil {
		s.log.Warn().Err(err).Str("user_id", userID.String()).Str("org_id", orgID.String()).
			Msg("failed to revoke local role grants after membership ended")
	}
}
