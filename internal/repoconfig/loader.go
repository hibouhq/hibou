package repoconfig

import (
	"context"
	"errors"
	"fmt"

	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/forge"
)

const RepoConfigPath = ".hibou.yaml"
const maxRepoConfigBytes = 64 * 1024

type Loader struct {
	forges map[string]forge.Provider
	log    zerolog.Logger
}

func NewLoader(forges map[string]forge.Provider, log zerolog.Logger) *Loader {
	if forges == nil {
		forges = map[string]forge.Provider{}
	}
	return &Loader{forges: forges, log: log.With().Str("component", "repoconfig.loader").Logger()}
}

func (l *Loader) Load(ctx context.Context, providerID, owner, repo, defaultBranch string) (*RepoConfig, error) {
	provider := l.forges[providerID]
	if provider == nil {
		return nil, fmt.Errorf("repo config provider %q not configured", providerID)
	}

	content, err := provider.GetFileContent(ctx, owner, repo, RepoConfigPath, defaultBranch)
	if err != nil {
		if errors.Is(err, forge.ErrFileNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("load repo config: %w", err)
	}
	if len(content) > maxRepoConfigBytes {
		l.log.Warn().Str("provider", providerID).Str("owner", owner).Str("repo", repo).Int("size_bytes", len(content)).Msg("repo config exceeds size limit, ignoring file")
		return nil, nil
	}

	cfg, err := Parse(content)
	if err != nil {
		l.log.Warn().Err(err).Str("provider", providerID).Str("owner", owner).Str("repo", repo).Msg("invalid repo config, ignoring file")
		return nil, nil
	}

	return cfg, nil
}
