package cmd

import (
	"fmt"

	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/config"
	"github.com/hibouhq/hibou/internal/forge"
)

func configuredForges(cfg config.Config, log zerolog.Logger) (map[string]forge.Provider, error) {
	providers := make(map[string]forge.Provider)
	for _, fc := range cfg.Forges {
		if fc.ClientID == "" {
			log.Warn().Str("id", fc.ID).Msg("forge has no OAuth client id, skipping (development only)")
			continue
		}
		switch fc.Type {
		case "github":
			var opts []forge.GitHubOption
			if fc.AppID > 0 && fc.PrivateKey != "" {
				opts = append(opts, forge.WithAppCredentials(fc.AppID, []byte(fc.PrivateKey)))
			}
			tier, err := forge.ParseTier(fc.Tier)
			if err != nil {
				return nil, fmt.Errorf("forge %q: %w", fc.ID, err)
			}
			opts = append(opts, forge.WithTier(tier))
			if len(cfg.Auth.AllowedOrgs) > 0 {
				opts = append(opts, forge.WithOrgMembershipScope())
			}
			providers[fc.ID] = forge.NewGitHub(fc.ClientID, fc.ClientSecret, fc.WebhookSecret, opts...)
		case "forgejo", "gitea":
			providers[fc.ID] = forge.NewForgejo(fc.URL, fc.ClientID, fc.ClientSecret, fc.WebhookSecret, fc.Token)
		case "gitlab":
			providers[fc.ID] = forge.NewGitLab(fc.URL, fc.ClientID, fc.ClientSecret, fc.WebhookSecret)
		default:
			log.Warn().Str("type", fc.Type).Str("id", fc.ID).Msg("unknown forge type, skipping")
		}
	}
	return providers, nil
}
