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
	UpsertForgeOrgMember(ctx context.Context, orgID, userID uuid.UUID, role string) error
	ListForgeOrgMembershipsByUser(ctx context.Context, userID uuid.UUID) ([]store.ForgeOrgMembership, error)
	PruneForgeOrgMembersForUser(ctx context.Context, userID uuid.UUID, keepOrgIDs []uuid.UUID) error
	GetRepositoryBySlug(ctx context.Context, orgID uuid.UUID, slug string) (*store.Repository, error)
	UpsertForgeUserRepoAccess(ctx context.Context, userID, repoID uuid.UUID, role string) error
	PruneForgeUserRepoAccess(ctx context.Context, userID uuid.UUID, keepRepoIDs []uuid.UUID) error

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
	desiredOrgRoles := make(map[uuid.UUID]string, len(access.Orgs))
	desiredOrgOrder := make([]uuid.UUID, 0, len(access.Orgs))
	for _, orgAccess := range access.Orgs {
		accountKey := normalizeAccessKey(orgAccess.AccountLogin)
		if accountKey == "" {
			continue
		}

		org, ok, err := s.resolveOrganization(ctx, providerID, orgAccess.AccountLogin, orgsByAccount)
		if err != nil {
			return err
		}
		if !ok {
			continue
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

	keptOrgIDs := make([]uuid.UUID, 0, len(desiredOrgOrder))
	for _, orgID := range desiredOrgOrder {
		role := desiredOrgRoles[orgID]
		if role == "" {
			continue
		}
		if err := s.store.UpsertForgeOrgMember(ctx, orgID, user.ID, role); err != nil {
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

	desiredRepoRoles := make(map[uuid.UUID]string, len(access.Repos))
	desiredRepoOrder := make([]uuid.UUID, 0, len(access.Repos))
	for _, repoAccess := range access.Repos {
		org := orgsByAccount[normalizeAccessKey(repoAccess.AccountLogin)]
		if org == nil {
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
	}

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

	return s.store.PruneForgeUserRepoAccess(ctx, user.ID, keptRepoIDs)
}

func (s *Service) resolveOrganization(ctx context.Context, providerID, accountLogin string, cache map[string]*store.Organization) (*store.Organization, bool, error) {
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
	cache[accountKey] = org
	return org, org != nil, nil
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
	normalized := strings.ToLower(strings.TrimSpace(login))
	if normalized == "" {
		return ""
	}

	var builder strings.Builder
	builder.Grow(len(normalized))
	lastWasHyphen := false
	for _, r := range normalized {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			builder.WriteRune(r)
			lastWasHyphen = false
			continue
		}
		if lastWasHyphen {
			continue
		}
		builder.WriteByte('-')
		lastWasHyphen = true
	}

	slug := strings.Trim(builder.String(), "-")
	if len(slug) > 63 {
		slug = strings.TrimRight(slug[:63], "-")
	}
	return slug
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
	reason := fmt.Sprintf("forge role changed from %s to %s", priorRole, newRole)
	suspended, err := s.store.SuspendLocalRoles(ctx, userID, orgID, reason)
	if err != nil {
		s.log.Warn().Err(err).Str("user_id", userID.String()).Str("org_id", orgID.String()).
			Msg("failed to suspend local role grants after a forge downgrade")
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
