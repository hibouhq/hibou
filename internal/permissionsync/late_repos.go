package permissionsync

import (
	"context"
	"strings"

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
	withheld := map[[2]uuid.UUID]bool{}
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return err
		}
		key := [2]uuid.UUID{candidate.OrgID, candidate.UserID}
		if withheld[key] || !strings.EqualFold(candidate.UserProvider, candidate.OrgProvider) {
			continue
		}
		verifier := verifiers[candidate.OrgProvider][strings.TrimSpace(candidate.ForgeAccountID)]
		if verifier == nil {
			revalidationOutcomes.WithLabelValues("late_repo_unverifiable").Inc()
			continue
		}
		level, err := verifier.RepoLevel(ctx, candidate.RepoSlug, candidate.UserForgeID)
		if err != nil {
			revalidationOutcomes.WithLabelValues("late_repo_error").Inc()
			s.log.Debug().Err(err).Str("org_id", candidate.OrgID.String()).Str("user_id", candidate.UserID.String()).
				Str("repo_id", candidate.RepoID.String()).Msg("could not ask the forge about a repository enrolled after the last sync")
			continue
		}
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
