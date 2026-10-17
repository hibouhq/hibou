package permissionsync

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/store"
)

// A forge member recorded as org-wide at sign-in holds grants on every
// repository enrolled then. A repository enrolled later is not visible to
// them through that verdict (IsRepoScopedOrgMember scopes them while they
// hold no grant on it), so access never follows a snapshot. This settles the
// gap without waiting for their next sign-in: the installation token of the
// org's bound account says what the member may do on the new repository, and
// the answer becomes a grant, or the recorded verdict that the forge
// withholds repositories from them.

// LateRepoStore is the store surface for settling late repositories.
// StoreAdapter implements it; a Store without it skips the step.
type LateRepoStore interface {
	ListUngrantedLateRepoMembers(ctx context.Context, limit int) ([]store.LateRepoGrantCandidate, error)
	SetForgeOrgMemberRepoScoped(ctx context.Context, orgID, userID uuid.UUID) error
}

const (
	// lateRepoCallsPerAccount caps the forge questions one run asks per
	// installation (each is two API calls): a burst of enrolments cannot
	// spend the App's rate limit on one pass. Random order rotates the rest.
	lateRepoCallsPerAccount = 50
	// A pair or repository the forge could not answer waits before the next
	// question, doubling up to a day, instead of being asked every run.
	lateRepoBackoffMin = 15 * time.Minute
	lateRepoBackoffMax = 24 * time.Hour
	// lateRepoBackoffCap bounds the in-memory backoff table.
	lateRepoBackoffCap = 10000
)

// lateRepoBackoff remembers forge failures between runs, in memory: a repo
// slug the forge does not know (an upload can enrol any name) would
// otherwise be asked about for every member every five minutes, forever.
type lateRepoBackoff struct {
	mu      sync.Mutex
	entries map[string]lateRepoBackoffEntry
}

type lateRepoBackoffEntry struct {
	next  time.Time
	delay time.Duration
}

func (b *lateRepoBackoff) waiting(key string, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	entry, ok := b.entries[key]
	return ok && now.Before(entry.next)
}

func (b *lateRepoBackoff) failed(key string, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.entries == nil {
		b.entries = map[string]lateRepoBackoffEntry{}
	}
	if len(b.entries) >= lateRepoBackoffCap {
		for k, entry := range b.entries {
			if !now.Before(entry.next) {
				delete(b.entries, k)
			}
		}
	}
	delay := lateRepoBackoffMin
	if entry, ok := b.entries[key]; ok {
		delay = min(entry.delay*2, lateRepoBackoffMax)
	}
	if len(b.entries) < lateRepoBackoffCap {
		b.entries[key] = lateRepoBackoffEntry{next: now.Add(delay), delay: delay}
	}
}

func (b *lateRepoBackoff) succeeded(key string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.entries, key)
}

func lateRepoPairKey(c store.LateRepoGrantCandidate) string {
	return "pair:" + c.OrgID.String() + ":" + c.UserID.String() + ":" + c.RepoID.String()
}

func lateRepoRepoKey(c store.LateRepoGrantCandidate) string {
	return "repo:" + c.OrgID.String() + ":" + c.RepoID.String()
}

// GrantLateRepositories asks the forge about members recorded as org-wide
// who hold no grant on a repository enrolled after their verdict. A failure
// to list installations aborts; a pair the forge cannot answer is left as it
// is (the member stays scoped for that repository).
func (s *Service) GrantLateRepositories(ctx context.Context) error {
	if s == nil || s.store == nil {
		return nil
	}
	ls, ok := s.store.(LateRepoStore)
	if !ok {
		return nil
	}
	candidates, err := ls.ListUngrantedLateRepoMembers(ctx, lateRepoBatch)
	if err != nil || len(candidates) == 0 {
		return err
	}
	providers := make([]string, 0, 1)
	for _, candidate := range candidates {
		providers = append(providers, candidate.OrgProvider)
	}
	verifiers, err := s.loadVerifiers(ctx, providers)
	if err != nil {
		return err
	}
	now := s.now()
	withheld := map[[2]uuid.UUID]bool{}
	calls := map[string]int{}
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return err
		}
		key := [2]uuid.UUID{candidate.OrgID, candidate.UserID}
		if withheld[key] || !strings.EqualFold(candidate.UserProvider, candidate.OrgProvider) {
			continue
		}
		pairKey, repoKey := lateRepoPairKey(candidate), lateRepoRepoKey(candidate)
		if s.lateRepos.waiting(repoKey, now) || s.lateRepos.waiting(pairKey, now) {
			revalidationOutcomes.WithLabelValues("late_repo_backoff").Inc()
			continue
		}
		account := candidate.OrgProvider + ":" + strings.TrimSpace(candidate.ForgeAccountID)
		if calls[account] >= lateRepoCallsPerAccount {
			revalidationOutcomes.WithLabelValues("late_repo_budget").Inc()
			continue
		}
		verifier := verifiers[candidate.OrgProvider][strings.TrimSpace(candidate.ForgeAccountID)]
		if verifier == nil {
			revalidationOutcomes.WithLabelValues("late_repo_unverifiable").Inc()
			continue
		}
		calls[account]++
		level, err := verifier.RepoLevel(ctx, candidate.RepoSlug, candidate.UserForgeID)
		if err != nil {
			if errors.Is(err, forge.ErrRepositoryNotFound) {
				// The repository is unknown to the forge: asking about the
				// other members cannot succeed either.
				s.lateRepos.failed(repoKey, now)
				revalidationOutcomes.WithLabelValues("late_repo_not_found").Inc()
			} else {
				s.lateRepos.failed(pairKey, now)
				revalidationOutcomes.WithLabelValues("late_repo_error").Inc()
			}
			s.log.Debug().Err(err).Str("org_id", candidate.OrgID.String()).Str("user_id", candidate.UserID.String()).
				Str("repo_id", candidate.RepoID.String()).Msg("could not ask the forge about a repository enrolled after the last sync")
			continue
		}
		s.lateRepos.succeeded(pairKey)
		s.lateRepos.succeeded(repoKey)
		role := forge.RoleForTier(forge.MapForgeRole(candidate.OrgProvider, level))
		if role == "" {
			withheld[key] = true
			if err := ls.SetForgeOrgMemberRepoScoped(ctx, candidate.OrgID, candidate.UserID); err != nil {
				s.log.Warn().Err(err).Str("org_id", candidate.OrgID.String()).Str("user_id", candidate.UserID.String()).
					Msg("failed to record that the forge withholds a repository")
				continue
			}
			revalidationOutcomes.WithLabelValues("late_repo_withheld").Inc()
			continue
		}
		if err := s.store.UpsertForgeUserRepoAccess(ctx, candidate.UserID, candidate.RepoID, role); err != nil {
			s.log.Warn().Err(err).Str("user_id", candidate.UserID.String()).Str("repo_id", candidate.RepoID.String()).
				Msg("failed to grant a repository enrolled after the last sync")
			continue
		}
		revalidationOutcomes.WithLabelValues("late_repo_granted").Inc()
	}
	return nil
}
