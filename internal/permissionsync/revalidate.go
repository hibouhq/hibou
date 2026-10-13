package permissionsync

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"github.com/hibouhq/hibou/internal/store"
)

// Membership re-validation. SyncUser runs at sign-in with the user's OAuth
// token, which is not kept; someone removed from the forge org would keep
// their role, and their API keys, until they signed in again — which they
// have no reason to do. The loop below asks the forge again with the App's
// installation token, the only credential the server holds.
const (
	// DefaultRevalidationInterval is how often RunRevalidation wakes up.
	DefaultRevalidationInterval = time.Hour
	// revalidateAfter is how long a confirmation stands before it is asked
	// again.
	revalidateAfter = 12 * time.Hour
	// unverifiableMaxAge bounds memberships the forge cannot be asked about
	// with the App token (repository collaborators, users with no recorded
	// login, accounts the App is not installed on): they expire unless a
	// sign-in re-syncs them first, which restores them.
	unverifiableMaxAge = 30 * 24 * time.Hour
	revalidationBatch  = 200
	// controlSample is how many confirmed members are asked about before a
	// "not a member" answer is trusted: a broken installation token reads
	// as "nobody is a member", which must not empty an org.
	controlSample = 5
)

// RevalidationStore is the store surface re-validation needs. StoreAdapter
// implements it; a Store without it skips re-validation.
type RevalidationStore interface {
	ListStaleForgeOrgMemberships(ctx context.Context, staleBefore time.Time, limit int) ([]store.StaleForgeOrgMembership, error)
	ListForgeOrgMemberLogins(ctx context.Context, orgID uuid.UUID, limit int) (map[uuid.UUID]string, error)
	TouchForgeOrgMember(ctx context.Context, orgID, userID uuid.UUID) error
	RemoveForgeOrgAccess(ctx context.Context, orgID, userID uuid.UUID) error
}

// OrgMembershipChecker is implemented by forges that answer "is login a
// member of org" (GitHub). A nil token makes the forge use the App's
// installation token on org.
type OrgMembershipChecker interface {
	IsOrgMember(ctx context.Context, token *oauth2.Token, login, org string) (bool, error)
}

// RunRevalidation re-validates stale forge memberships every interval until
// ctx ends.
func (s *Service) RunRevalidation(ctx context.Context, interval time.Duration) {
	if s == nil {
		return
	}
	if interval <= 0 {
		interval = DefaultRevalidationInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := s.RevalidateMemberships(ctx, time.Now()); err != nil && ctx.Err() == nil {
			s.log.Warn().Err(err).Msg("forge membership re-validation failed")
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// RevalidateMemberships re-asks the forge about forge-synced memberships not
// confirmed for revalidateAfter. Confirmed members are touched; members the
// forge says left lose the membership, its repository grants, RBAC role and
// local grants; memberships the forge cannot be asked about expire after
// unverifiableMaxAge.
func (s *Service) RevalidateMemberships(ctx context.Context, now time.Time) error {
	if s == nil || s.store == nil {
		return nil
	}
	rs, ok := s.store.(RevalidationStore)
	if !ok {
		return nil
	}
	stale, err := rs.ListStaleForgeOrgMemberships(ctx, now.Add(-revalidateAfter), revalidationBatch)
	if err != nil {
		return err
	}
	byOrg := make(map[uuid.UUID][]store.StaleForgeOrgMembership)
	order := make([]uuid.UUID, 0)
	for _, membership := range stale {
		if _, seen := byOrg[membership.OrgID]; !seen {
			order = append(order, membership.OrgID)
		}
		byOrg[membership.OrgID] = append(byOrg[membership.OrgID], membership)
	}
	installed := map[string]map[string]string{}
	for _, orgID := range order {
		if err := ctx.Err(); err != nil {
			return err
		}
		s.revalidateOrg(ctx, rs, byOrg[orgID], installed, now)
	}
	return nil
}

func (s *Service) revalidateOrg(ctx context.Context, rs RevalidationStore, memberships []store.StaleForgeOrgMembership, installed map[string]map[string]string, now time.Time) {
	first := memberships[0]
	account := strings.TrimSpace(first.ForgeAccountLogin)
	if account == "" {
		// Legacy orgs predating the recorded login: the slug provisioning
		// derived from it. A slug that is not the login reads as "not
		// installed", and the memberships age out like unverifiable ones.
		account = strings.TrimSpace(first.OrgSlug)
	}
	checker, checkable := s.forges[first.OrgProvider].(OrgMembershipChecker)
	checkable = checkable && account != "" && s.accountInstalled(ctx, first.OrgProvider, account, installed)

	confirmed := false
	var gone []store.StaleForgeOrgMembership
	for _, membership := range memberships {
		if membership.RepoScoped || !checkable || strings.TrimSpace(membership.ForgeLogin) == "" {
			if membership.SyncedAt == nil || now.Sub(*membership.SyncedAt) > unverifiableMaxAge {
				s.removeMembership(ctx, rs, membership, "membership could not be re-verified with the forge")
			}
			continue
		}
		member, err := checker.IsOrgMember(ctx, nil, membership.ForgeLogin, account)
		if err != nil {
			s.log.Warn().Err(err).Str("org_id", membership.OrgID.String()).Str("user_id", membership.UserID.String()).
				Msg("forge membership re-check failed; keeping the membership for now")
			continue
		}
		if !member {
			gone = append(gone, membership)
			continue
		}
		confirmed = true
		if err := rs.TouchForgeOrgMember(ctx, membership.OrgID, membership.UserID); err != nil {
			s.log.Warn().Err(err).Str("org_id", membership.OrgID.String()).Msg("failed to record a forge membership confirmation")
		}
	}
	if len(gone) == 0 {
		return
	}
	if !confirmed {
		confirmed = s.forgeConfirmsAnyMember(ctx, rs, checker, first.OrgID, account, gone)
	}
	if !confirmed {
		s.log.Warn().Str("org_id", first.OrgID.String()).Str("account", account).Int("unconfirmed", len(gone)).
			Msg("the forge confirmed no member of this org; not trusting its \"not a member\" answers")
		return
	}
	for _, membership := range gone {
		s.removeMembership(ctx, rs, membership, "no longer a member of the forge organization")
	}
}

// forgeConfirmsAnyMember is the positive control: some other org-wide member
// must still read as a member before anyone is removed.
func (s *Service) forgeConfirmsAnyMember(ctx context.Context, rs RevalidationStore, checker OrgMembershipChecker, orgID uuid.UUID, account string, gone []store.StaleForgeOrgMembership) bool {
	excluded := make(map[uuid.UUID]bool, len(gone))
	for _, membership := range gone {
		excluded[membership.UserID] = true
	}
	controls, err := rs.ListForgeOrgMemberLogins(ctx, orgID, controlSample+len(gone))
	if err != nil {
		s.log.Warn().Err(err).Str("org_id", orgID.String()).Msg("failed to list control members")
		return false
	}
	asked := 0
	for userID, login := range controls {
		if excluded[userID] || asked >= controlSample {
			continue
		}
		asked++
		if member, err := checker.IsOrgMember(ctx, nil, login, account); err == nil && member {
			return true
		}
	}
	return false
}

// accountInstalled reports whether the App is installed on account, so that
// the membership check runs with the installation token. Without it GitHub
// falls back to the (absent) user token and answers "not a member" for
// everyone.
func (s *Service) accountInstalled(ctx context.Context, providerID, account string, cache map[string]map[string]string) bool {
	ids, seen := cache[providerID]
	if !seen {
		if resolver, ok := s.forges[providerID].(AccountIDResolver); ok {
			loaded, err := resolver.InstallationAccountIDs(ctx)
			if err != nil {
				s.log.Warn().Err(err).Str("provider", providerID).Msg("failed to list installed forge accounts")
			}
			ids = loaded
		}
		cache[providerID] = ids
	}
	return ids[normalizeAccessKey(account)] != ""
}

func (s *Service) removeMembership(ctx context.Context, rs RevalidationStore, membership store.StaleForgeOrgMembership, reason string) {
	if err := rs.RemoveForgeOrgAccess(ctx, membership.OrgID, membership.UserID); err != nil {
		s.log.Warn().Err(err).Str("org_id", membership.OrgID.String()).Str("user_id", membership.UserID.String()).
			Msg("failed to remove a forge membership")
		return
	}
	s.removeOrgRole(membership.UserID, membership.Role, membership.OrgID)
	s.revokeLocalGrants(ctx, membership.UserID, membership.OrgID)
	s.log.Info().Str("org_id", membership.OrgID.String()).Str("user_id", membership.UserID.String()).
		Str("role", membership.Role).Str("reason", reason).Msg("removed a forge membership")
}
