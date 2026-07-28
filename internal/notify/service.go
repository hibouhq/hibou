package notify

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/events"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
	"github.com/hibouhq/hibou/internal/ws"
)

type Service struct {
	store NotifyStore
	live  ws.LiveDelivery
	bus   *events.Bus
	log   zerolog.Logger
}

type NotifyStore interface {
	CreateNotification(ctx context.Context, arg dbgen.CreateNotificationParams) (dbgen.Notification, error)
	ListNotificationsByUser(ctx context.Context, arg dbgen.ListNotificationsByUserParams) ([]dbgen.Notification, error)
	CountNotificationsByUser(ctx context.Context, userID uuid.UUID) (int64, error)
	CountUnreadNotifications(ctx context.Context, userID uuid.UUID) (int64, error)
	MarkNotificationRead(ctx context.Context, arg dbgen.MarkNotificationReadParams) error
	MarkAllNotificationsRead(ctx context.Context, userID uuid.UUID) error
}

type recipientResolver interface {
	GetSnapshotByID(ctx context.Context, id uuid.UUID) (*store.Snapshot, error)
	GetRefByID(ctx context.Context, id uuid.UUID) (*store.Ref, error)
	GetRepositoryByID(ctx context.Context, id uuid.UUID) (*store.Repository, error)
	GetOrganizationByID(ctx context.Context, id uuid.UUID) (*store.Organization, error)
	ListOrgMembers(ctx context.Context, orgID uuid.UUID, limit, offset int) ([]store.OrgMember, int, error)
}

func NewService(store NotifyStore, live ws.LiveDelivery, bus *events.Bus, log zerolog.Logger) *Service {
	return &Service{store: store, live: live, bus: bus, log: log.With().Str("component", "notify.service").Logger()}
}

func (s *Service) Subscribe() {
	if s == nil || s.bus == nil {
		return
	}

	s.bus.Subscribe(events.ScanCompleted, func(ctx context.Context, event events.Event) {
		s.handleScanCompleted(ctx, event.Payload)
	})
	s.bus.Subscribe(events.ScanFailed, func(ctx context.Context, event events.Event) {
		s.handleScanFailed(ctx, event.Payload)
	})
	s.bus.Subscribe(events.ScanStale, func(ctx context.Context, event events.Event) {
		s.handleScanStale(ctx, event.Payload)
	})
	s.bus.Subscribe(events.VulnDiscovered, func(ctx context.Context, event events.Event) {
		s.handleVulnDiscovered(ctx, event.Payload)
	})
	s.bus.Subscribe(events.VulnerabilityCreated, func(ctx context.Context, event events.Event) {
		s.handleVulnerabilityCreated(ctx, event.Payload)
	})
	s.bus.Subscribe(events.RetentionWarnAt, func(ctx context.Context, event events.Event) {
		s.handleRetentionWarnAt(ctx, event.Payload)
	})
	s.bus.Subscribe(events.RetentionEviction, func(ctx context.Context, event events.Event) {
		s.handleRetentionEviction(ctx, event.Payload)
	})
	s.bus.Subscribe(events.RetentionProtected, func(ctx context.Context, event events.Event) {
		s.handleRetentionProtected(ctx, event.Payload)
	})
}

func (s *Service) handleScanCompleted(ctx context.Context, payload any) {
	repoName, repoID, recipients, err := s.resolveRecipients(ctx, payload)
	if err != nil {
		s.log.Debug().Err(err).Msg("resolve recipients for scan completed")
		return
	}
	body := "Scan completed for repo " + repoName
	s.createForRecipients(ctx, recipients, dbgen.CreateNotificationParams{
		Type:     string(events.ScanCompleted),
		Title:    "Scan completed",
		Body:     body,
		Link:     s.repoTabLink(ctx, repoID, "dependencies", ""),
		Severity: dbgen.NullSeverityLevel{SeverityLevel: dbgen.SeverityLevelInfo, Valid: true},
	})
}

func (s *Service) handleScanFailed(ctx context.Context, payload any) {
	repoName, repoID, recipients, err := s.resolveRecipients(ctx, payload)
	if err != nil {
		s.log.Debug().Err(err).Msg("resolve recipients for scan failed")
		return
	}
	body := "Scan failed for repo " + repoName
	s.createForRecipients(ctx, recipients, dbgen.CreateNotificationParams{
		Type:     string(events.ScanFailed),
		Title:    "Scan failed",
		Body:     body,
		Link:     s.repoTabLink(ctx, repoID, "dependencies", ""),
		Severity: dbgen.NullSeverityLevel{SeverityLevel: dbgen.SeverityLevelHigh, Valid: true},
	})
}

func (s *Service) handleScanStale(ctx context.Context, payload any) {
	repoName, repoID, recipients, err := s.resolveRecipients(ctx, payload)
	if err != nil {
		s.log.Debug().Err(err).Msg("resolve recipients for stale scan")
		return
	}
	data, _ := payload.(map[string]any)
	lastScanAt := stringValue(data, "last_scan_completed_at", "unknown")
	body := fmt.Sprintf("Repo %s has no completed scan since %s", repoName, lastScanAt)
	s.createForRecipients(ctx, recipients, dbgen.CreateNotificationParams{
		Type:     string(events.ScanStale),
		Title:    "Repository scan stale",
		Body:     body,
		Link:     s.repoTabLink(ctx, repoID, "dependencies", ""),
		Severity: dbgen.NullSeverityLevel{SeverityLevel: dbgen.SeverityLevelMedium, Valid: true},
	})
}

func (s *Service) handleVulnDiscovered(ctx context.Context, payload any) {
	data, _ := payload.(map[string]any)
	repoName, repoID, recipients, err := s.resolveRecipients(ctx, payload)
	if err != nil {
		s.log.Debug().Err(err).Msg("resolve recipients for vulnerability discovered")
		return
	}
	severity := strings.ToLower(stringValue(data, "severity", "critical"))
	severityLevel := dbgen.SeverityLevelCritical
	if severity != "critical" {
		severityLevel = dbgen.SeverityLevelHigh
	}
	vulnID := vulnerabilityLabel(data)
	body := fmt.Sprintf("New %s vulnerability %s found in repo %s", severity, vulnID, repoName)
	s.createForRecipients(ctx, recipients, dbgen.CreateNotificationParams{
		Type:     string(events.VulnDiscovered),
		Title:    "New vulnerability discovered",
		Body:     body,
		Link:     s.repoTabLink(ctx, repoID, "vulnerabilities", vulnSearchQuery(data)),
		Severity: dbgen.NullSeverityLevel{SeverityLevel: severityLevel, Valid: true},
	})
}

func (s *Service) handleVulnerabilityCreated(ctx context.Context, payload any) {
	data, _ := payload.(map[string]any)
	repoName, repoID, recipients, err := s.resolveRecipients(ctx, payload)
	if err != nil {
		s.log.Debug().Err(err).Msg("resolve recipients for vulnerability created")
		return
	}
	severity := strings.ToLower(stringValue(data, "severity", "critical"))
	severityLevel := dbgen.SeverityLevelCritical
	if severity != "critical" {
		severityLevel = dbgen.SeverityLevelHigh
	}
	vulnID := vulnerabilityLabel(data)
	body := fmt.Sprintf("New %s vulnerability %s found in repo %s", severity, vulnID, repoName)
	s.createForRecipients(ctx, recipients, dbgen.CreateNotificationParams{
		Type:     string(events.VulnerabilityCreated),
		Title:    "New vulnerability created",
		Body:     body,
		Link:     s.repoTabLink(ctx, repoID, "vulnerabilities", vulnSearchQuery(data)),
		Severity: dbgen.NullSeverityLevel{SeverityLevel: severityLevel, Valid: true},
	})
}

func (s *Service) handleRetentionWarnAt(ctx context.Context, payload any) {
	repoName, repoID, recipients, err := s.resolveRecipients(ctx, payload)
	if err != nil {
		s.log.Debug().Err(err).Msg("resolve recipients for retention warn_at")
		return
	}
	data, _ := payload.(map[string]any)
	body := fmt.Sprintf("Repo %s reached %.0f%% of its retention storage budget", repoName, floatValue(data, "usage_ratio", 0)*100)
	s.createForRecipients(ctx, recipients, dbgen.CreateNotificationParams{
		Type:     string(events.RetentionWarnAt),
		Title:    "Retention budget warning",
		Body:     body,
		Link:     s.repoLink(ctx, repoID),
		Severity: dbgen.NullSeverityLevel{SeverityLevel: dbgen.SeverityLevelMedium, Valid: true},
	})
}

func (s *Service) handleRetentionEviction(ctx context.Context, payload any) {
	repoName, repoID, recipients, err := s.resolveRecipients(ctx, payload)
	if err != nil {
		s.log.Debug().Err(err).Msg("resolve recipients for retention eviction")
		return
	}
	body := "Retention reclaim started for repo " + repoName
	s.createForRecipients(ctx, recipients, dbgen.CreateNotificationParams{
		Type:     string(events.RetentionEviction),
		Title:    "Retention reclaim started",
		Body:     body,
		Link:     s.repoLink(ctx, repoID),
		Severity: dbgen.NullSeverityLevel{SeverityLevel: dbgen.SeverityLevelHigh, Valid: true},
	})
}

func (s *Service) handleRetentionProtected(ctx context.Context, payload any) {
	repoName, repoID, recipients, err := s.resolveRecipients(ctx, payload)
	if err != nil {
		s.log.Debug().Err(err).Msg("resolve recipients for retention protected-exceeds-budget")
		return
	}
	body := "Protected snapshots keep repo " + repoName + " above its retention budget"
	s.createForRecipients(ctx, recipients, dbgen.CreateNotificationParams{
		Type:     string(events.RetentionProtected),
		Title:    "Protected snapshots exceed budget",
		Body:     body,
		Link:     s.repoLink(ctx, repoID),
		Severity: dbgen.NullSeverityLevel{SeverityLevel: dbgen.SeverityLevelHigh, Valid: true},
	})
}

func (s *Service) createForRecipients(ctx context.Context, recipients []uuid.UUID, base dbgen.CreateNotificationParams) {
	for _, userID := range recipients {
		params := base
		params.UserID = userID
		notification, err := s.store.CreateNotification(ctx, params)
		if err != nil {
			s.log.Error().Err(err).Str("user_id", userID.String()).Msg("create notification")
			continue
		}
		if s.live != nil {
			payload, err := jsonNotification(notification)
			if err == nil {
				s.live.PublishToUsers(ctx, []uuid.UUID{userID}, ws.Message{Type: string(events.NotificationNew), Payload: payload})
			}
		}
	}
}

func (s *Service) resolveRecipients(ctx context.Context, payload any) (string, uuid.UUID, []uuid.UUID, error) {
	resolver, ok := s.store.(recipientResolver)
	if !ok {
		return "", uuid.Nil, nil, errors.New("store does not support recipient resolution")
	}

	data, _ := payload.(map[string]any)
	if userIDs := userIDsFromPayload(data); len(userIDs) > 0 {
		return stringValue(data, "repo_name", "repository"), uuidFromPayload(data, "repo_id"), userIDs, nil
	}
	if repoID := uuidFromPayload(data, "repo_id"); repoID != uuid.Nil {
		return s.resolveRecipientsForRepo(ctx, resolver, repoID)
	}

	snapshotID := uuidFromPayload(data, "snapshot_id")
	if snapshotID == uuid.Nil {
		return stringValue(data, "repo_name", "repository"), uuidFromPayload(data, "repo_id"), nil, errors.New("snapshot_id is required")
	}

	return s.resolveRecipientsForSnapshot(ctx, resolver, snapshotID)
}

func (s *Service) resolveRecipientsForRepo(ctx context.Context, resolver recipientResolver, repoID uuid.UUID) (string, uuid.UUID, []uuid.UUID, error) {
	repo, err := resolver.GetRepositoryByID(ctx, repoID)
	if err != nil || repo == nil {
		return "", uuid.Nil, nil, fmt.Errorf("load repository: %w", err)
	}
	recipients, err := listRecipientUserIDs(ctx, resolver, repo.OrgID)
	if err != nil {
		return "", uuid.Nil, nil, err
	}
	return repo.Name, repo.ID, recipients, nil
}

func (s *Service) resolveRecipientsForSnapshot(ctx context.Context, resolver recipientResolver, snapshotID uuid.UUID) (string, uuid.UUID, []uuid.UUID, error) {
	snapshot, err := resolver.GetSnapshotByID(ctx, snapshotID)
	if err != nil || snapshot == nil {
		return "", uuid.Nil, nil, fmt.Errorf("load snapshot: %w", err)
	}
	ref, err := resolver.GetRefByID(ctx, snapshot.RefID)
	if err != nil || ref == nil {
		return "", uuid.Nil, nil, fmt.Errorf("load ref: %w", err)
	}
	repo, err := resolver.GetRepositoryByID(ctx, ref.RepoID)
	if err != nil || repo == nil {
		return "", uuid.Nil, nil, fmt.Errorf("load repository: %w", err)
	}
	recipients, err := listRecipientUserIDs(ctx, resolver, repo.OrgID)
	if err != nil {
		return "", uuid.Nil, nil, err
	}
	return repo.Name, repo.ID, recipients, nil
}

func listRecipientUserIDs(ctx context.Context, resolver recipientResolver, orgID uuid.UUID) ([]uuid.UUID, error) {
	members, _, err := resolver.ListOrgMembers(ctx, orgID, 1000, 0)
	if err != nil {
		return nil, fmt.Errorf("list org members: %w", err)
	}
	recipients := make([]uuid.UUID, 0, len(members))
	for _, member := range members {
		recipients = append(recipients, member.UserID)
	}
	return recipients, nil
}

// repoLink resolves the SPA route for a repository. Routes are org-scoped and
// slug-based (/orgs/{provider}/{orgSlug}/repos/{repoSlug}); the old
// /repos/{uuid} shape matched no route, so every notification click was a
// silent no-op. Unresolvable repos yield "" and the panel renders no link.
func (s *Service) repoLink(ctx context.Context, repoID uuid.UUID) string {
	if repoID == uuid.Nil {
		return ""
	}
	resolver, ok := s.store.(recipientResolver)
	if !ok {
		return ""
	}
	repo, err := resolver.GetRepositoryByID(ctx, repoID)
	if err != nil || repo == nil {
		return ""
	}
	org, err := resolver.GetOrganizationByID(ctx, repo.OrgID)
	if err != nil || org == nil {
		return ""
	}
	return "/orgs/" + org.Provider + "/" + org.Slug + "/repos/" + repo.Slug
}

// repoTabLink deep-links a notification to the tab (and optional query) where
// the event is actually visible, instead of the repo overview.
func (s *Service) repoTabLink(ctx context.Context, repoID uuid.UUID, tab, rawQuery string) string {
	base := s.repoLink(ctx, repoID)
	if base == "" {
		return ""
	}
	link := base + "/" + tab
	if rawQuery != "" {
		link += "?" + rawQuery
	}
	return link
}

// vulnerabilityLabel picks the human-facing identifier for a notification:
// the advisory/rule id (CVE-…, GHSA-…, G101) plus the affected component.
// advisory_id and id are internal UUIDs and are deliberately NOT used — they
// mean nothing to a reader and match nothing when searched.
func vulnerabilityLabel(data map[string]any) string {
	label := stringValue(data, "identifier", stringValue(data, "cve", ""))
	if label == "" {
		return "unknown"
	}
	if component := stringValue(data, "component", ""); component != "" {
		return label + " in " + component
	}
	return label
}

// vulnSearchQuery pre-fills the vulnerabilities tab's free-text search. Only a
// real identifier is linkable: a UUID would return an empty list, which is
// worse than landing on the unfiltered tab.
func vulnSearchQuery(data map[string]any) string {
	identifier := strings.TrimSpace(stringValue(data, "identifier", stringValue(data, "cve", "")))
	if identifier == "" || isUUIDLike(identifier) {
		return ""
	}
	return "search=" + url.QueryEscape(identifier)
}

// isUUIDLike guards against regressions that put an internal id back into a
// user-facing search link.
func isUUIDLike(value string) bool {
	_, err := uuid.Parse(strings.TrimSpace(value))
	return err == nil
}

func stringValue(data map[string]any, key, fallback string) string {
	if data == nil {
		return fallback
	}
	if raw, ok := data[key]; ok {
		if value, ok := raw.(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return fallback
}

func uuidFromPayload(data map[string]any, key string) uuid.UUID {
	parsed, _ := uuid.Parse(stringValue(data, key, ""))
	return parsed
}

func userIDsFromPayload(data map[string]any) []uuid.UUID {
	if data == nil {
		return nil
	}
	if raw, ok := data["user_ids"].([]any); ok {
		ids := make([]uuid.UUID, 0, len(raw))
		for _, item := range raw {
			if value, ok := item.(string); ok {
				if parsed, err := uuid.Parse(value); err == nil {
					ids = append(ids, parsed)
				}
			}
		}
		return ids
	}
	if raw := stringValue(data, "user_id", ""); raw != "" {
		if parsed, err := uuid.Parse(raw); err == nil {
			return []uuid.UUID{parsed}
		}
	}
	return nil
}

func floatValue(data map[string]any, key string, fallback float64) float64 {
	if data == nil {
		return fallback
	}
	switch value := data[key].(type) {
	case float64:
		return value
	case float32:
		return float64(value)
	case int:
		return float64(value)
	case int64:
		return float64(value)
	}
	return fallback
}
