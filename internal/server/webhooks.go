package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/forge"
)

type webhookResponse struct {
	Received bool `json:"received"`
}

type forgeEventHandler func(ctx context.Context, providerID string, event forge.WebhookEvent) error

// @Summary      Receive forge webhook
// @Description  Validates and records forge webhook updates for refs and pull requests.
// @Tags         webhooks
// @Accept       json
// @Produce      json
// @Param        provider  path      string  true  "Forge provider ID"
// @Success      200       {object}  api.Response{data=server.webhookResponse}
// @Failure      401       {object}  api.Response
// @Failure      404       {object}  api.Response
// @Failure      500       {object}  api.Response
// @Router       /webhooks/{provider} [post]
func (s *Server) handleWebhook(w http.ResponseWriter, r *http.Request) {
	providerID := strings.TrimSpace(chi.URLParam(r, "provider"))
	provider, ok := s.forges[providerID]
	if !ok || provider == nil {
		api.JSONError(w, http.StatusNotFound, "provider not configured")
		return
	}

	payload, err := provider.ValidateWebhookPayload(r, "")
	if err != nil {
		api.JSONError(w, http.StatusUnauthorized, "invalid webhook payload")
		return
	}

	eventType := webhookEventType(provider.ID(), r)
	if eventType == "" {
		api.JSONError(w, http.StatusBadRequest, "missing webhook event type")
		return
	}

	event, err := provider.ParseWebhookEvent(eventType, payload)
	if err != nil {
		if errors.Is(err, forge.ErrUnsupportedWebhookEvent) {
			s.log.Debug().Str("provider", providerID).Str("event_type", eventType).Msg("ignored unsupported webhook event")
			api.JSON(w, http.StatusOK, webhookResponse{Received: true})
			return
		}
		api.JSONError(w, http.StatusBadRequest, "unsupported webhook event")
		return
	}
	handlers := s.webhookHandlers[event.EventType()]
	if len(handlers) == 0 {
		s.log.Debug().Str("provider", providerID).Str("event_type", event.EventType()).Msg("ignored unhandled webhook event")
		api.JSON(w, http.StatusOK, webhookResponse{Received: true})
		return
	}
	for _, handler := range handlers {
		if err := handler(r.Context(), providerID, event); err != nil {
			s.log.Error().Err(err).Str("provider", providerID).Str("event_type", event.EventType()).Msg("failed to process webhook event")
			api.JSONError(w, http.StatusInternalServerError, "failed to process webhook")
			return
		}
	}

	api.JSON(w, http.StatusOK, webhookResponse{Received: true})
}

func (s *Server) registerWebhookHandler(eventType string, h forgeEventHandler) {
	eventType = strings.TrimSpace(eventType)
	if eventType == "" || h == nil {
		return
	}
	if s.webhookHandlers == nil {
		s.webhookHandlers = make(map[string][]forgeEventHandler)
	}
	s.webhookHandlers[eventType] = append(s.webhookHandlers[eventType], h)
}

func (s *Server) registerDefaultWebhookHandlers() {
	s.registerWebhookHandler("push", func(ctx context.Context, providerID string, event forge.WebhookEvent) error {
		typed, ok := event.(forge.PushEvent)
		if !ok {
			return fmt.Errorf("unexpected push webhook event type %T", event)
		}
		request, _ := http.NewRequestWithContext(ctx, http.MethodPost, "/", nil)
		return s.handlePushWebhookEvent(request, providerID, typed)
	})
	s.registerWebhookHandler("pull_request", func(ctx context.Context, providerID string, event forge.WebhookEvent) error {
		typed, ok := event.(forge.PullRequestEvent)
		if !ok {
			return fmt.Errorf("unexpected pull_request webhook event type %T", event)
		}
		request, _ := http.NewRequestWithContext(ctx, http.MethodPost, "/", nil)
		provider := s.forges[providerID]
		forgeType := providerID
		if provider != nil {
			forgeType = provider.ID()
		}
		return s.handlePullRequestWebhookEvent(request, providerID, forgeType, typed)
	})
	s.registerWebhookHandler("installation", func(ctx context.Context, providerID string, event forge.WebhookEvent) error {
		typed, ok := event.(forge.InstallationEvent)
		if !ok {
			return fmt.Errorf("unexpected installation webhook event type %T", event)
		}
		if s.inventorySvc == nil {
			return nil
		}
		return s.inventorySvc.ApplyInstallation(ctx, providerID, typed)
	})
	s.registerWebhookHandler("installation", func(ctx context.Context, providerID string, event forge.WebhookEvent) error {
		typed, ok := event.(forge.InstallationEvent)
		if !ok {
			return fmt.Errorf("unexpected installation webhook event type %T", event)
		}
		if s.orgProvisionSvc == nil {
			return nil
		}
		return s.orgProvisionSvc.RecordInstallation(ctx, providerID, typed)
	})
	s.registerWebhookHandler("installation_repositories", func(ctx context.Context, providerID string, event forge.WebhookEvent) error {
		typed, ok := event.(forge.InstallationRepositoriesEvent)
		if !ok {
			return fmt.Errorf("unexpected installation_repositories webhook event type %T", event)
		}
		if s.inventorySvc == nil {
			return nil
		}
		return s.inventorySvc.ApplyInstallationRepositories(ctx, providerID, typed)
	})
	s.registerWebhookHandler("repository", func(ctx context.Context, providerID string, event forge.WebhookEvent) error {
		typed, ok := event.(forge.RepositoryEvent)
		if !ok {
			return fmt.Errorf("unexpected repository webhook event type %T", event)
		}
		if s.inventorySvc == nil {
			return nil
		}
		return s.inventorySvc.ApplyRepository(ctx, providerID, typed)
	})
}

func (s *Server) handlePushWebhookEvent(r *http.Request, providerID string, event forge.PushEvent) error {
	s.log.Info().
		Str("provider", providerID).
		Str("repository", event.Repo.FullName).
		Str("ref", event.Ref).
		Str("commit_sha", event.After).
		Msg("received push webhook")

	repo, err := s.queries.GetRepositoryByProvider(r.Context(), providerID, event.Repo.ProviderID)
	if err != nil {
		return err
	}
	if repo == nil {
		s.log.Debug().Str("provider", providerID).Str("repository", event.Repo.ProviderID).Msg("ignoring push webhook for unknown repository")
		return nil
	}

	refType := refTypeFromName(event.Ref)
	refName := normalizeStoredRefName(event.Ref)
	_, err = s.queries.UpsertRef(r.Context(), repo.ID, refName, refType, nil, nil, stringPtr(event.After))
	return err
}

func (s *Server) handlePullRequestWebhookEvent(r *http.Request, providerID, forgeType string, event forge.PullRequestEvent) error {
	s.log.Info().
		Str("provider", providerID).
		Str("repository", event.Repo.FullName).
		Int("number", event.Number).
		Str("source_branch", event.SourceBranch).
		Str("target_branch", event.TargetBranch).
		Str("commit_sha", event.HeadSHA).
		Msg("received pull request webhook")

	repo, err := s.queries.GetRepositoryByProvider(r.Context(), providerID, event.Repo.ProviderID)
	if err != nil {
		return err
	}
	if repo == nil {
		s.log.Debug().Str("provider", providerID).Str("repository", event.Repo.ProviderID).Msg("ignoring pull request webhook for unknown repository")
		return nil
	}

	var mergeTargetRefID *uuid.UUID
	if targetBranch := strings.TrimSpace(event.TargetBranch); targetBranch != "" {
		targetRef, err := s.queries.UpsertRef(r.Context(), repo.ID, targetBranch, refTypeFromName(targetBranch), nil, nil, nil)
		if err != nil {
			return err
		}
		if targetRef != nil {
			mergeTargetRefID = &targetRef.ID
		}
	}

	refName := pullRequestRefName(forgeType, event.Number)
	ref, err := s.queries.UpsertRef(r.Context(), repo.ID, refName, refTypeFromName(refName), nil, mergeTargetRefID, stringPtr(event.HeadSHA))
	if err != nil {
		return err
	}
	if ref == nil {
		return nil
	}

	prState, prMergedAt, prClosedAt, shouldUpdate := pullRequestLifecycleState(event.Action, event.Merged)
	if !shouldUpdate {
		return nil
	}

	_, err = s.queries.UpdateRefPRState(r.Context(), ref.ID, stringPtr(prState), event.Title, event.SourceBranch, prMergedAt, prClosedAt)
	return err
}

func pullRequestLifecycleState(action string, merged bool) (string, *time.Time, *time.Time, bool) {
	now := time.Now().UTC()
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "closed":
		if merged {
			return "merged", &now, &now, true
		}
		return "closed", nil, &now, true
	case "opened", "reopened":
		return "open", nil, nil, true
	default:
		return "", nil, nil, false
	}
}

func webhookEventType(forgeType string, r *http.Request) string {
	switch forgeType {
	case "github":
		return strings.TrimSpace(r.Header.Get("X-GitHub-Event"))
	case "gitea", "forgejo":
		return strings.TrimSpace(r.Header.Get("X-Gitea-Event"))
	case "gitlab":
		return strings.TrimSpace(r.Header.Get("X-Gitlab-Event"))
	default:
		return ""
	}
}

func pullRequestRefName(forgeType string, number int) string {
	if forgeType == "gitlab" {
		return "refs/merge-requests/" + strconv.Itoa(number) + "/head"
	}
	return "refs/pull/" + strconv.Itoa(number) + "/head"
}

func stringPtr(value string) *string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return &value
}
