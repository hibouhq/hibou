package repoconfig

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/store"
)

const onboardingBranchName = "hibou/configure"

type OnboardingService struct {
	forges map[string]forge.Provider
	log    zerolog.Logger
}

func NewOnboardingService(forges map[string]forge.Provider, log zerolog.Logger) *OnboardingService {
	if forges == nil {
		forges = map[string]forge.Provider{}
	}
	return &OnboardingService{forges: forges, log: log.With().Str("component", "repoconfig.onboarding").Logger()}
}

// ErrForeignRepository refuses onboarding a repository whose owner is not the
// forge account the requesting org is bound to.
var ErrForeignRepository = errors.New("repository owner is not the organization's forge account")

// CreateOnboardingPRForOrg is CreateOnboardingPR on behalf of org: it writes a
// branch and opens a PR with an installation token minted by owner, so owner
// must be the org's own forge account (security audit §3.1). The context is
// also bound to that account so no token for another installation can be
// minted further down.
func (s *OnboardingService) CreateOnboardingPRForOrg(ctx context.Context, org *store.Organization, providerID, owner, repo, defaultBranch string) (*forge.PullRequest, error) {
	if org == nil || !org.OwnsForgeOwner(owner) {
		return nil, ErrForeignRepository
	}
	return s.CreateOnboardingPR(forge.WithInstallationOwner(ctx, owner), providerID, owner, repo, defaultBranch)
}

func (s *OnboardingService) CreateOnboardingPR(ctx context.Context, providerID, owner, repo, defaultBranch string) (*forge.PullRequest, error) {
	provider := s.forges[providerID]
	if provider == nil {
		return nil, fmt.Errorf("repo config provider %q not configured", providerID)
	}

	branch, err := provider.GetBranch(ctx, owner, repo, defaultBranch)
	if err != nil {
		return nil, fmt.Errorf("load default branch: %w", err)
	}

	baseRef := branch.SHA
	if strings.EqualFold(provider.ID(), "forgejo") || strings.EqualFold(provider.ID(), "gitea") {
		baseRef = branch.Name
	}
	if err := provider.CreateBranch(ctx, owner, repo, onboardingBranchName, baseRef); err != nil {
		return nil, fmt.Errorf("create onboarding branch: %w", err)
	}
	if err := provider.CreateOrUpdateFile(ctx, owner, repo, RepoConfigPath, onboardingBranchName, "chore: add Hibou quality gate config", DefaultYAML()); err != nil {
		return nil, fmt.Errorf("write onboarding config: %w", err)
	}

	pr, err := provider.CreatePullRequest(ctx, owner, repo, forge.CreatePROptions{
		Title: "Configure Hibou quality gates",
		Body: strings.TrimSpace(`This PR adds a starter .hibou.yaml file so Hibou can enforce branch-aware weakness quality gates from the repository itself.

What this config does:
- Defines weakness thresholds for code findings only
- Applies different thresholds per branch pattern
- Keeps vulnerability (CVE) gates managed in Hibou

You can adjust the thresholds in .hibou.yaml and merge this PR when ready.

Every key is described in the schema, which your editor uses for completion: https://hibouhq.com/schemas/v1/hibou-config.schema.json`),
		Head: onboardingBranchName,
		Base: defaultBranch,
	})
	if err != nil {
		return nil, fmt.Errorf("create onboarding pull request: %w", err)
	}

	s.log.Info().Str("provider", providerID).Str("owner", owner).Str("repo", repo).Int("number", pr.Number).Msg("created onboarding pull request")
	return pr, nil
}
