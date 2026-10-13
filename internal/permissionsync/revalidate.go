package permissionsync

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/store"
)

// Membership re-validation. SyncUser runs at sign-in with the user's OAuth
// token, which is not kept; someone removed from the forge org would keep
// their role, and their API keys, until they signed in again — which they
// have no reason to do. The loop below asks the forge again with the App's
// installation token, the only credential the server holds.
//
// It is never destructive on uncertainty. A membership is removed only after
// a definitive "not a member" (a 404) given by the installation token of the
// account the org is bound to by immutable id, and only once that same token
// has confirmed some other member afterwards. Anything it cannot verify —
// repository collaborators, users with no recorded forge login, orgs never
// bound to an account id, accounts the App is not installed on — is counted
// and logged, never expired.
const (
	// DefaultRevalidationInterval is how often RunRevalidation wakes up.
	DefaultRevalidationInterval = time.Hour
	// revalidateAfter is how long a confirmation stands before it is asked
	// again; rows the loop could not decide on wait as long.
	revalidateAfter   = 12 * time.Hour
	revalidationBatch = 200
	// lateRepoInterval is how often repositories enrolled after members'
	// last sync are settled with the forge; until then those members see
	// only the repositories they hold grants on.
	lateRepoInterval = 5 * time.Minute
	lateRepoBatch    = 500
	// controlSample is how many confirmed members are asked about before a
	// "not a member" answer is trusted: a broken installation token reads
	// as "nobody is a member", which must not empty an org.
	controlSample = 5
)

// RevalidationStore is the store surface re-validation needs. StoreAdapter
// implements it; a Store without it skips re-validation.
type RevalidationStore interface {
	ListStaleForgeOrgMemberships(ctx context.Context, staleBefore time.Time, limit int) ([]store.StaleForgeOrgMembership, error)
	ListForgeOrgMemberForgeIDs(ctx context.Context, orgID uuid.UUID, limit int) (map[uuid.UUID]string, error)
	TouchForgeOrgMember(ctx context.Context, orgID, userID uuid.UUID) error
	MarkForgeOrgMemberRevalidationAttempted(ctx context.Context, orgID, userID uuid.UUID) error
	CountOrgAdmins(ctx context.Context, orgID uuid.UUID) (int, error)
	RemoveForgeOrgAccess(ctx context.Context, orgID, userID uuid.UUID) error
}

// MembershipVerifierSource is implemented by forges that verify org
// membership with an installation token bound to an immutable account id
// (GitHub App mode).
type MembershipVerifierSource interface {
	OrgMembershipVerifiers(ctx context.Context) (map[string]forge.OrgMembershipVerifier, error)
}

// loadVerifiers lists each provider's installations once. A provider that
// cannot verify maps to nil; a listing error is returned, never read as
// "installed nowhere".
func (s *Service) loadVerifiers(ctx context.Context, providers []string) (map[string]map[string]forge.OrgMembershipVerifier, error) {
	verifiers := make(map[string]map[string]forge.OrgMembershipVerifier, len(providers))
	for _, providerID := range providers {
		if _, loaded := verifiers[providerID]; loaded {
			continue
		}
		var byAccount map[string]forge.OrgMembershipVerifier
		if source, ok := s.forges[providerID].(MembershipVerifierSource); ok {
			loaded, err := source.OrgMembershipVerifiers(ctx)
			if err != nil {
				return nil, fmt.Errorf("list %s installations: %w", providerID, err)
			}
			byAccount = loaded
			if byAccount == nil {
				byAccount = map[string]forge.OrgMembershipVerifier{}
			}
		}
		verifiers[providerID] = byAccount
	}
	return verifiers, nil
}

// RunRevalidation re-validates stale forge memberships every interval, and
// settles repositories enrolled after members' last sync every
// lateRepoInterval, until ctx ends.
func (s *Service) RunRevalidation(ctx context.Context, interval time.Duration) {
	if s == nil {
		return
	}
	if interval <= 0 {
		interval = DefaultRevalidationInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	lateRepos := time.NewTicker(lateRepoInterval)
	defer lateRepos.Stop()
	for {
		s.runLateRepoGrants(ctx)
		if err := s.RevalidateMemberships(ctx, time.Now()); err != nil && ctx.Err() == nil {
			s.log.Warn().Err(err).Msg("forge membership re-validation failed")
		}
	wait:
		for {
			select {
			case <-ctx.Done():
				return
			case <-lateRepos.C:
				s.runLateRepoGrants(ctx)
			case <-ticker.C:
				break wait
			}
		}
	}
}

func (s *Service) runLateRepoGrants(ctx context.Context) {
	if err := s.GrantLateRepositories(ctx); err != nil && ctx.Err() == nil {
		s.log.Warn().Err(err).Msg("settling repositories enrolled after the last sync failed")
	}
}

// RevalidateMemberships re-asks the forge about forge-synced memberships not
// confirmed for revalidateAfter. Confirmed members are touched; members the
// forge definitively says left lose the membership, its repository grants
// and RBAC role, and their local grants are suspended. A failure to list the
// App's installations aborts the run before anything is decided.
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
	providers := make([]string, 0, 1)
	for _, membership := range stale {
		if _, seen := byOrg[membership.OrgID]; !seen {
			order = append(order, membership.OrgID)
			providers = append(providers, membership.OrgProvider)
		}
		byOrg[membership.OrgID] = append(byOrg[membership.OrgID], membership)
	}
	verifiers, err := s.loadVerifiers(ctx, providers)
	if err != nil {
		revalidationOutcomes.WithLabelValues("aborted").Inc()
		return err
	}
	for _, orgID := range order {
		if err := ctx.Err(); err != nil {
			return err
		}
		memberships := byOrg[orgID]
		s.revalidateOrg(ctx, rs, memberships, verifiers[memberships[0].OrgProvider])
	}
	return nil
}

func (s *Service) revalidateOrg(ctx context.Context, rs RevalidationStore, memberships []store.StaleForgeOrgMembership, verifiers map[string]forge.OrgMembershipVerifier) {
	first := memberships[0]
	accountID := strings.TrimSpace(first.ForgeAccountID)
	var verifier forge.OrgMembershipVerifier
	reason := ""
	switch {
	case verifiers == nil:
		reason = "forge_cannot_verify"
	case accountID == "":
		// Never resolved by login: a renamed-then-re-registered login
		// would answer for the org.
		reason = "org_not_bound"
	default:
		if verifier = verifiers[accountID]; verifier == nil {
			reason = "not_installed"
		}
	}
	if reason != "" {
		for _, membership := range memberships {
			s.unverifiable(ctx, rs, membership, reason)
		}
		s.log.Info().Str("org_id", first.OrgID.String()).Str("reason", reason).Int("memberships", len(memberships)).
			Msg("forge memberships could not be re-verified; keeping them")
		return
	}

	var gone []store.StaleForgeOrgMembership
	confirmed := make([]string, 0, len(memberships))
	for _, membership := range memberships {
		forgeID := strings.TrimSpace(membership.UserForgeID)
		switch {
		case membership.RepoScoped:
			s.unverifiable(ctx, rs, membership, "repo_scoped")
			continue
		case strings.TrimSpace(membership.ForgeLogin) == "":
			// Signed in before logins were recorded: never acted on.
			s.unverifiable(ctx, rs, membership, "no_forge_login")
			continue
		case forgeID == "" || !strings.EqualFold(membership.UserProvider, membership.OrgProvider):
			s.unverifiable(ctx, rs, membership, "provider_mismatch")
			continue
		}
		member, err := verifier.IsMember(ctx, forgeID)
		if errors.Is(err, forge.ErrMembershipUnsupported) {
			s.unverifiable(ctx, rs, membership, "personal_account")
			continue
		}
		if err != nil {
			s.log.Warn().Err(err).Str("org_id", membership.OrgID.String()).Str("user_id", membership.UserID.String()).
				Msg("forge membership re-check failed; keeping the membership")
			revalidationOutcomes.WithLabelValues("error").Inc()
			s.markAttempted(ctx, rs, membership)
			continue
		}
		if !member {
			gone = append(gone, membership)
			continue
		}
		revalidationOutcomes.WithLabelValues("confirmed").Inc()
		confirmed = append(confirmed, forgeID)
		if err := rs.TouchForgeOrgMember(ctx, membership.OrgID, membership.UserID); err != nil {
			s.log.Warn().Err(err).Str("org_id", membership.OrgID.String()).Msg("failed to record a forge membership confirmation")
		}
	}
	if len(gone) == 0 {
		return
	}
	if !s.forgeConfirmsAnyMember(ctx, rs, verifier, first.OrgID, gone, confirmed) {
		s.log.Warn().Str("org_id", first.OrgID.String()).Str("account", verifier.AccountLogin()).Int("unconfirmed", len(gone)).
			Msg("the forge confirmed no member of this org after its \"not a member\" answers; not trusting them")
		for _, membership := range gone {
			revalidationOutcomes.WithLabelValues("control_failed").Inc()
			s.markAttempted(ctx, rs, membership)
		}
		return
	}
	for _, membership := range gone {
		s.removeDeparted(ctx, rs, membership)
	}
}

// forgeConfirmsAnyMember is the positive control, asked with the verifier's
// token after every negative answer: some other org-wide member must still
// read as a member. Members confirmed earlier in this run are asked first,
// then the most recently confirmed ones on record. Everyone is named by
// immutable forge id.
func (s *Service) forgeConfirmsAnyMember(ctx context.Context, rs RevalidationStore, verifier forge.OrgMembershipVerifier, orgID uuid.UUID, gone []store.StaleForgeOrgMembership, confirmed []string) bool {
	excluded := make(map[string]bool, len(gone))
	excludedIDs := make(map[uuid.UUID]bool, len(gone))
	for _, membership := range gone {
		excluded[strings.TrimSpace(membership.UserForgeID)] = true
		excludedIDs[membership.UserID] = true
	}
	candidates := make([]string, 0, controlSample)
	seen := map[string]bool{}
	add := func(forgeID string) {
		forgeID = strings.TrimSpace(forgeID)
		if forgeID == "" || excluded[forgeID] || seen[forgeID] || len(candidates) >= controlSample {
			return
		}
		seen[forgeID] = true
		candidates = append(candidates, forgeID)
	}
	for _, forgeID := range confirmed {
		add(forgeID)
	}
	if len(candidates) < controlSample {
		controls, err := rs.ListForgeOrgMemberForgeIDs(ctx, orgID, controlSample+len(gone))
		if err != nil {
			s.log.Warn().Err(err).Str("org_id", orgID.String()).Msg("failed to list control members")
		}
		for userID, forgeID := range controls {
			if !excludedIDs[userID] {
				add(forgeID)
			}
		}
	}
	for _, forgeID := range candidates {
		if member, err := verifier.IsMember(ctx, forgeID); err == nil && member {
			return true
		}
	}
	return false
}

// removeDeparted removes a membership the forge definitively says ended.
// The org's last admin is never removed: an org nobody administers cannot
// be repaired from inside Hibou. Local grants are suspended, not revoked,
// so an operator can restore them if the forge answer was wrong.
func (s *Service) removeDeparted(ctx context.Context, rs RevalidationStore, membership store.StaleForgeOrgMembership) {
	if roleRank(membership.Role) >= roleRank("admin") {
		admins, err := rs.CountOrgAdmins(ctx, membership.OrgID)
		if err != nil || admins <= 1 {
			s.log.Warn().Err(err).Str("org_id", membership.OrgID.String()).Str("user_id", membership.UserID.String()).
				Msg("the forge says the org's last admin left; keeping the membership for an operator to resolve")
			revalidationOutcomes.WithLabelValues("last_admin_kept").Inc()
			s.markAttempted(ctx, rs, membership)
			return
		}
	}
	if err := rs.RemoveForgeOrgAccess(ctx, membership.OrgID, membership.UserID); err != nil {
		s.log.Warn().Err(err).Str("org_id", membership.OrgID.String()).Str("user_id", membership.UserID.String()).
			Msg("failed to remove a forge membership")
		s.markAttempted(ctx, rs, membership)
		return
	}
	revalidationOutcomes.WithLabelValues("removed").Inc()
	s.removeOrgRole(membership.UserID, membership.Role, membership.OrgID)
	s.suspendLocalGrantsWithReason(ctx, membership.UserID, membership.OrgID, "no longer a member of the forge organization")
	s.log.Info().Str("org_id", membership.OrgID.String()).Str("user_id", membership.UserID.String()).
		Str("role", membership.Role).Msg("removed a forge membership the forge says ended")
}

// unverifiable counts a membership the forge cannot be asked about and keeps
// it. It used to expire after 30 days, which removed collaborators and
// every pre-login-tracking user on a timer, not on evidence.
func (s *Service) unverifiable(ctx context.Context, rs RevalidationStore, membership store.StaleForgeOrgMembership, reason string) {
	revalidationOutcomes.WithLabelValues("unverifiable_" + reason).Inc()
	s.log.Debug().Str("org_id", membership.OrgID.String()).Str("user_id", membership.UserID.String()).
		Str("reason", reason).Msg("forge membership cannot be re-verified; keeping it")
	s.markAttempted(ctx, rs, membership)
}

func (s *Service) markAttempted(ctx context.Context, rs RevalidationStore, membership store.StaleForgeOrgMembership) {
	if err := rs.MarkForgeOrgMemberRevalidationAttempted(ctx, membership.OrgID, membership.UserID); err != nil {
		s.log.Warn().Err(err).Str("org_id", membership.OrgID.String()).Str("user_id", membership.UserID.String()).
			Msg("failed to record a re-validation attempt")
	}
}
