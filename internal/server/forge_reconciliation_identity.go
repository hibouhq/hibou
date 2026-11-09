package server

import (
	"context"
	"errors"

	"github.com/hibouhq/hibou/internal/forge"
)

func (s *Server) verifyObservedWebhookIdentity(ctx context.Context, provider string, event forge.WebhookEvent) error {
	var observed forge.Repository
	switch typed := event.(type) {
	case forge.PushEvent:
		observed = typed.Repo
	case forge.PullRequestEvent:
		observed = typed.Repo
	case forge.BuildEvent:
		observed = typed.Repo
	case forge.ReleaseEvent:
		observed = typed.Repo
	default:
		return nil
	}
	repo, err := s.queries.GetRepositoryByProvider(ctx, provider, observed.ProviderID)
	if err != nil || repo == nil {
		return err
	}
	if observed.OwnerID == "" || observed.OwnerID == "0" || observed.ProviderRepoID == "" {
		return errors.New("webhook omitted immutable repository/account identity")
	}
	matches, err := s.queries.ForgeObservedIdentityMatches(ctx, repo.ID, observed.OwnerID, observed.ProviderRepoID)
	if err != nil {
		return err
	}
	if !matches {
		return errors.New("webhook account/repository identities differ from enrollment")
	}
	return nil
}
