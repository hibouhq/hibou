package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/events"
	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/store"
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

	r.Body = http.MaxBytesReader(w, r.Body, forge.MaxWebhookPayloadBytes)
	payload, err := s.verifiedWebhookPayload(r, providerID, provider)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			api.JSONError(w, http.StatusRequestEntityTooLarge, "webhook payload too large")
			return
		}
		api.JSONError(w, http.StatusUnauthorized, "invalid webhook payload")
		return
	}

	// Replays of a verified delivery (same delivery id, or byte-identical
	// body) are acknowledged without reprocessing. Keys are released when
	// processing fails, so the forge's own redelivery still goes through.
	replayKeys := webhookReplayKeys(providerID, provider.ID(), r, payload)
	deliveries := s.webhookDeliveries()
	if !deliveries.claim(replayKeys, time.Now()) {
		s.log.Warn().Str("provider", providerID).Msg("ignored replayed webhook delivery")
		api.JSON(w, http.StatusOK, webhookResponse{Received: true})
		return
	}
	processed := false
	defer func() {
		if !processed {
			deliveries.release(replayKeys)
		}
	}()

	eventType := webhookEventType(provider.ID(), r)
	if eventType == "" {
		api.JSONError(w, http.StatusBadRequest, "missing webhook event type")
		return
	}

	event, err := provider.ParseWebhookEvent(eventType, payload)
	if err != nil {
		if errors.Is(err, forge.ErrUnsupportedWebhookEvent) {
			processed = true
			s.log.Debug().Str("provider", providerID).Str("event_type", eventType).Msg("ignored unsupported webhook event")
			api.JSON(w, http.StatusOK, webhookResponse{Received: true})
			return
		}
		api.JSONError(w, http.StatusBadRequest, "unsupported webhook event")
		return
	}
	if push, ok := event.(forge.PushEvent); ok {
		// before/after reach git command lines (secret scanning): only object
		// ids pass, never anything that could parse as an option.
		if !isWebhookCommitSHA(push.Before) || !isWebhookCommitSHA(push.After) {
			api.JSONError(w, http.StatusBadRequest, "invalid push commit sha")
			return
		}
	}
	handlers := s.webhookHandlers[event.EventType()]
	if len(handlers) == 0 {
		processed = true
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

	processed = true
	api.JSON(w, http.StatusOK, webhookResponse{Received: true})
}

// webhookSecretReporter is implemented by forges that can say whether they
// hold a webhook secret at all.
type webhookSecretReporter interface {
	HasWebhookSecret() bool
}

// verifiedWebhookPayload returns the authenticated webhook body. A forge
// without a webhook secret fails closed, except in development, where the
// payload is accepted unverified and every delivery says so in the log
// (startup already refuses a secret-less forge outside development).
func (s *Server) verifiedWebhookPayload(r *http.Request, providerID string, provider forge.Provider) ([]byte, error) {
	if reporter, ok := provider.(webhookSecretReporter); ok && !reporter.HasWebhookSecret() && s.cfg.IsDevelopment() {
		s.log.Warn().Str("provider", providerID).Msg("INSECURE: accepting an UNVERIFIED webhook payload because this forge has no webhook secret (development only)")
		return forge.ReadWebhookPayload(r, providerID)
	}
	return provider.ValidateWebhookPayload(r, "")
}

// webhookCommitSHA matches a full SHA-1 or SHA-256 object id. Branch creation
// and deletion use the all-zero id, which also matches.
var webhookCommitSHA = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)

func isWebhookCommitSHA(sha string) bool {
	return webhookCommitSHA.MatchString(sha)
}

// webhookDeliveryHeader names the header carrying a forge's unique delivery id.
func webhookDeliveryHeader(forgeType string) string {
	switch forgeType {
	case "github":
		return "X-GitHub-Delivery"
	case "gitlab":
		return "X-Gitlab-Event-UUID"
	case "forgejo", "gitea":
		return "X-Gitea-Delivery"
	default:
		return ""
	}
}

// webhookReplayKeys identifies a delivery twice over: by its delivery id
// (unsigned header) and by the digest of its signed body, so a captured
// delivery replayed under a fresh delivery id is still caught.
func webhookReplayKeys(providerID, forgeType string, r *http.Request, payload []byte) []string {
	digest := sha256.Sum256(payload)
	keys := []string{providerID + "|body|" + hex.EncodeToString(digest[:])}
	if header := webhookDeliveryHeader(forgeType); header != "" {
		if id := strings.TrimSpace(r.Header.Get(header)); id != "" && len(id) <= 128 {
			keys = append(keys, providerID+"|id|"+id)
		}
	}
	return keys
}

const (
	webhookReplayTTL     = time.Hour
	webhookReplayMaxKeys = 50000
)

// webhookDeliveryCaches holds one replay window per Server. Replicas each
// keep their own window, which still stops a replay burst against any one.
var webhookDeliveryCaches sync.Map

func (s *Server) webhookDeliveries() *webhookDeliveryCache {
	if cache, ok := webhookDeliveryCaches.Load(s); ok {
		return cache.(*webhookDeliveryCache)
	}
	cache, _ := webhookDeliveryCaches.LoadOrStore(s, newWebhookDeliveryCache(webhookReplayTTL, webhookReplayMaxKeys))
	return cache.(*webhookDeliveryCache)
}

// webhookDeliveryCache is a bounded, TTL-expiring set of seen delivery keys.
type webhookDeliveryCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	maxKeys int
	seen    map[string]time.Time
}

func newWebhookDeliveryCache(ttl time.Duration, maxKeys int) *webhookDeliveryCache {
	return &webhookDeliveryCache{ttl: ttl, maxKeys: maxKeys, seen: make(map[string]time.Time)}
}

// claim records keys and reports true when none was seen within the TTL.
func (c *webhookDeliveryCache) claim(keys []string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, key := range keys {
		if seenAt, ok := c.seen[key]; ok && now.Sub(seenAt) < c.ttl {
			return false
		}
	}
	if len(c.seen)+len(keys) > c.maxKeys {
		c.evict(now, len(keys))
	}
	for _, key := range keys {
		c.seen[key] = now
	}
	return true
}

func (c *webhookDeliveryCache) release(keys []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, key := range keys {
		delete(c.seen, key)
	}
}

// evict drops expired keys, then the oldest ones until room is made: under a
// flood the window shrinks rather than memory growing.
func (c *webhookDeliveryCache) evict(now time.Time, room int) {
	for key, seenAt := range c.seen {
		if now.Sub(seenAt) >= c.ttl {
			delete(c.seen, key)
		}
	}
	for len(c.seen)+room > c.maxKeys {
		var oldestKey string
		var oldest time.Time
		for key, seenAt := range c.seen {
			if oldestKey == "" || seenAt.Before(oldest) {
				oldestKey, oldest = key, seenAt
			}
		}
		if oldestKey == "" {
			return
		}
		delete(c.seen, oldestKey)
	}
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
	s.registerWebhookHandler("build", func(ctx context.Context, providerID string, event forge.WebhookEvent) error {
		typed, ok := event.(forge.BuildEvent)
		if !ok {
			return fmt.Errorf("unexpected build webhook event type %T", event)
		}
		return s.handleBuildWebhookEvent(ctx, providerID, typed)
	})
	s.registerWebhookHandler("release", func(ctx context.Context, providerID string, event forge.WebhookEvent) error {
		typed, ok := event.(forge.ReleaseEvent)
		if !ok {
			return fmt.Errorf("unexpected release webhook event type %T", event)
		}
		request, _ := http.NewRequestWithContext(ctx, http.MethodPost, "/", nil)
		return s.handleReleaseWebhookEvent(request, providerID, typed)
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
	s.registerWebhookHandler("installation_repositories", func(ctx context.Context, providerID string, event forge.WebhookEvent) error {
		typed, ok := event.(forge.InstallationRepositoriesEvent)
		if !ok {
			return fmt.Errorf("unexpected installation_repositories webhook event type %T", event)
		}
		if s.orgProvisionSvc == nil {
			return nil
		}
		return s.orgProvisionSvc.RecordInstallationRepositories(ctx, providerID, typed)
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

// handleBuildWebhookEvent fails snapshots whose build ended without them.
//
// A pipeline that dies before its upload step leaves a pending snapshot that no
// upload will ever complete. Without this it shows as in-progress until the
// stale-pending window closes; with it, the chip turns red as the run does.
func (s *Server) handleBuildWebhookEvent(ctx context.Context, providerID string, event forge.BuildEvent) error {
	if event.Succeeded || strings.TrimSpace(event.CommitSHA) == "" {
		// A successful run completes its own snapshot by uploading.
		return nil
	}
	repo, err := s.queries.GetRepositoryByProvider(ctx, providerID, event.Repo.ProviderID)
	if err != nil {
		return err
	}
	if repo == nil {
		return nil
	}
	failed, err := s.queries.FailPendingSnapshotsForBuild(ctx, repo.ID, event.CommitSHA, event.RunID)
	if err != nil {
		return err
	}
	if failed > 0 {
		s.log.Info().
			Str("provider", providerID).
			Str("repository", event.Repo.FullName).
			Str("commit_sha", event.CommitSHA).
			Str("run_id", event.RunID).
			Str("conclusion", event.Conclusion).
			Int64("snapshots", failed).
			Msg("failed pending snapshots after the build ended without them")
	}
	return nil
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

	// A tag deletion (zero After SHA) is a release-removal signal (ADR-024
	// §5b), not a ref update: don't record a zero-SHA ref state.
	if refType == store.RefTypeTag && isDeletedRefSHA(event.After) {
		release, err := s.queries.GetReleaseByRepoVersion(r.Context(), repo.ID, refName)
		if err != nil {
			return err
		}
		if release != nil {
			s.removeDerivedRelease(r.Context(), repo, release, "tag_deleted")
		}
		return nil
	}

	if _, err := s.queries.UpsertRef(r.Context(), repo.ID, refName, refType, store.UpsertRefOptions{LatestCommitSHA: stringPtr(event.After)}); err != nil {
		return err
	}

	s.maybeEnqueueSecretScan(r.Context(), repo, refType, refName, event)
	s.maybeEnqueueDepExtraction(r.Context(), repo, refType, refName, event)
	if refType == store.RefTypeBranch {
		s.refreshApplicabilityAsync(repo, refName)
	}
	return nil
}

// isDeletedRefSHA reports the all-zero commit SHA forges send when a push
// event describes a ref deletion.
func isDeletedRefSHA(sha string) bool {
	sha = strings.TrimSpace(sha)
	if sha == "" {
		return true
	}
	for _, char := range sha {
		if char != '0' {
			return false
		}
	}
	return true
}

// handleReleaseWebhookEvent ingests a forge release into the releases table
// (ADR-024 §5): tag resolved to a ref (created if the push webhook has not
// landed yet), latest complete snapshot of that ref attached when one exists,
// row upserted on the (repo, version) identity with the forge release URL.
func (s *Server) handleReleaseWebhookEvent(r *http.Request, providerID string, event forge.ReleaseEvent) error {
	s.log.Info().
		Str("provider", providerID).
		Str("repository", event.Repo.FullName).
		Str("tag", event.TagName).
		Str("action", event.Action).
		Msg("received release webhook")

	if event.Draft {
		return nil
	}
	tagName := strings.TrimSpace(event.TagName)
	if tagName == "" {
		return nil
	}

	repo, err := s.queries.GetRepositoryByProvider(r.Context(), providerID, event.Repo.ProviderID)
	if err != nil {
		return err
	}
	if repo == nil {
		s.log.Debug().Str("provider", providerID).Str("repository", event.Repo.ProviderID).Msg("ignoring release webhook for unknown repository")
		return nil
	}

	switch event.Action {
	case "deleted", "unpublished":
		// Removal is derived like creation (ADR-024 §5b): the release goes
		// away with its source — unless rollout history exists, which wins.
		release, err := s.queries.GetReleaseByRepoVersion(r.Context(), repo.ID, tagName)
		if err != nil {
			return err
		}
		if release != nil {
			s.removeDerivedRelease(r.Context(), repo, release, "forge_release_deleted")
		}
		return nil
	}

	ref, err := s.queries.UpsertRef(r.Context(), repo.ID, tagName, store.RefTypeTag, store.UpsertRefOptions{})
	if err != nil {
		return err
	}

	// Attach the tag's latest analysis only when the release is new: an
	// existing release keeps the build it shipped — a re-published forge
	// release must not silently repoint it (the reconcile pass on snapshot
	// completion owns re-tag divergence, ADR-024 §5).
	var snapshotID *uuid.UUID
	existing, err := s.queries.GetReleaseByRepoVersion(r.Context(), repo.ID, tagName)
	if err != nil {
		return err
	}
	if existing == nil {
		snapshot, err := s.queries.GetLatestCompleteSnapshotByRef(r.Context(), ref.ID)
		if err != nil {
			return err
		}
		if snapshot != nil {
			snapshotID = &snapshot.ID
		}
	}

	var htmlURL *string
	if trimmed := strings.TrimSpace(event.HTMLURL); trimmed != "" {
		htmlURL = &trimmed
	}
	buildMetadata := json.RawMessage("{}")
	if name := strings.TrimSpace(event.Name); name != "" && name != tagName {
		encoded, err := json.Marshal(map[string]any{"release_name": name, "prerelease": event.Prerelease})
		if err == nil {
			buildMetadata = encoded
		}
	} else if event.Prerelease {
		buildMetadata = json.RawMessage(`{"prerelease":true}`)
	}

	release, err := s.queries.UpsertRelease(r.Context(), store.UpsertReleaseParams{
		RepoID:        repo.ID,
		RefID:         ref.ID,
		SnapshotID:    snapshotID,
		Version:       tagName,
		BuildMetadata: buildMetadata,
		HTMLURL:       htmlURL,
		Source:        store.ReleaseSourceForge,
		PublishedAt:   event.PublishedAt,
	})
	if err != nil {
		return err
	}

	if release.SnapshotID != nil {
		if err := s.pinReleaseSnapshot(r.Context(), *release.SnapshotID); err != nil {
			s.log.Warn().Err(err).Str("snapshot_id", release.SnapshotID.String()).Msg("failed to pin release snapshot; retention may prune it")
		}
	}
	return nil
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
		targetRef, err := s.queries.UpsertRef(r.Context(), repo.ID, targetBranch, refTypeFromName(targetBranch), store.UpsertRefOptions{})
		if err != nil {
			return err
		}
		if targetRef != nil {
			mergeTargetRefID = &targetRef.ID
		}
	}

	refName := pullRequestRefName(forgeType, event.Number)
	ref, err := s.queries.UpsertRef(r.Context(), repo.ID, refName, refTypeFromName(refName), store.UpsertRefOptions{
		MergeTargetRefID: mergeTargetRefID,
		LatestCommitSHA:  stringPtr(event.HeadSHA),
		PRTitle:          event.Title,
		PRSourceBranch:   event.SourceBranch,
	})
	if err != nil {
		return err
	}
	if ref == nil {
		return nil
	}

	// A new head push (synchronize) or reopen changes the PR delta, so re-evaluate
	// and re-post the gate check for this ref — no CI re-run. Skip closed/merged.
	// When the new head has no analyzed snapshot yet, the publisher posts a
	// pending "waiting for upload" check on it, so the PR immediately shows a
	// Hibou check that blocks the merge (under branch protection) until the
	// real verdict replaces it.
	if !event.Merged && !strings.Contains(strings.ToLower(event.Action), "clos") {
		// Pre-create the head's pending snapshot so the UI shows the commit as
		// awaited and the CI upload adopts the row rather than racing it.
		if headSHA := strings.TrimSpace(event.HeadSHA); headSHA != "" {
			if _, err := s.queries.CreatePlaceholderSnapshot(r.Context(), ref.ID, headSHA); err != nil {
				s.log.Warn().Err(err).Str("ref_id", ref.ID.String()).Str("commit_sha", headSHA).Msg("create placeholder snapshot for PR head")
			}
			s.maybeEnqueuePRDepExtraction(r.Context(), repo, ref, headSHA)
		}
		s.bus.Publish(r.Context(), events.Event{
			Type:    events.GateRecomputeRequested,
			Payload: map[string]any{"ref_id": ref.ID.String()},
		})
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

// pullRequestRefName returns the canonical PR ref (refs/pull/N, or
// refs/merge-requests/N on GitLab). A PR is one ref; the /head and /merge
// variants from CI uploads normalize to this same name.
func pullRequestRefName(forgeType string, number int) string {
	if forgeType == "gitlab" {
		return "refs/merge-requests/" + strconv.Itoa(number)
	}
	return "refs/pull/" + strconv.Itoa(number)
}

func stringPtr(value string) *string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return &value
}
