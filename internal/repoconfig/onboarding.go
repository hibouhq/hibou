package repoconfig

import (
	"context"
	"fmt"
	"strings"

	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/forge"
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

Docs: https://hibou.dev/docs/config-as-code`),
		Head: onboardingBranchName,
		Base: defaultBranch,
	})
	if err != nil {
		return nil, fmt.Errorf("create onboarding pull request: %w", err)
	}

	s.log.Info().Str("provider", providerID).Str("owner", owner).Str("repo", repo).Int("number", pr.Number).Msg("created onboarding pull request")
	return pr, nil
}
