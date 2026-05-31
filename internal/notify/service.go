package notify

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/lehibou/internal/events"
	"github.com/hibouhq/lehibou/internal/store"
	"github.com/hibouhq/lehibou/internal/store/dbgen"
	"github.com/hibouhq/lehibou/internal/ws"
)

type Service struct {
	store NotifyStore
	hub   *ws.Hub
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
	ListOrgMembers(ctx context.Context, orgID uuid.UUID, limit, offset int) ([]store.OrgMember, int, error)
}

func NewService(store NotifyStore, hub *ws.Hub, bus *events.Bus, log zerolog.Logger) *Service {
	return &Service{store: store, hub: hub, bus: bus, log: log.With().Str("component", "notify.service").Logger()}
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
		Link:     repoLink(repoID),
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
		Link:     repoLink(repoID),
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
		Link:     repoLink(repoID),
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
	vulnID := stringValue(data, "cve", stringValue(data, "advisory_id", "unknown"))
	body := fmt.Sprintf("New %s vulnerability %s found in repo %s", severity, vulnID, repoName)
	s.createForRecipients(ctx, recipients, dbgen.CreateNotificationParams{
		Type:     string(events.VulnDiscovered),
		Title:    "New vulnerability discovered",
		Body:     body,
		Link:     repoLink(repoID),
		Severity: dbgen.NullSeverityLevel{SeverityLevel: severityLevel, Valid: true},
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
		if s.hub != nil {
			payload, err := jsonNotification(notification)
			if err == nil {
				s.hub.SendToUser(userID, ws.Message{Type: string(events.NotificationNew), Payload: payload})
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
		repo, err := resolver.GetRepositoryByID(ctx, repoID)
		if err != nil || repo == nil {
			return "", uuid.Nil, nil, fmt.Errorf("load repository: %w", err)
		}
		members, _, err := resolver.ListOrgMembers(ctx, repo.OrgID, 1000, 0)
		if err != nil {
			return "", uuid.Nil, nil, fmt.Errorf("list org members: %w", err)
		}
		recipients := make([]uuid.UUID, 0, len(members))
		for _, member := range members {
			recipients = append(recipients, member.UserID)
		}
		return repo.Name, repo.ID, recipients, nil
	}

	snapshotID := uuidFromPayload(data, "snapshot_id")
	if snapshotID == uuid.Nil {
		return stringValue(data, "repo_name", "repository"), uuidFromPayload(data, "repo_id"), nil, errors.New("snapshot_id is required")
	}

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
	// NOTE: Capped at 1000 members per org for notification fan-out.
	// For orgs exceeding this limit, implement cursor-based pagination.
	members, _, err := resolver.ListOrgMembers(ctx, repo.OrgID, 1000, 0)
	if err != nil {
		return "", uuid.Nil, nil, fmt.Errorf("list org members: %w", err)
	}
	recipients := make([]uuid.UUID, 0, len(members))
	for _, member := range members {
		recipients = append(recipients, member.UserID)
	}
	return repo.Name, repo.ID, recipients, nil
}

func repoLink(repoID uuid.UUID) string {
	if repoID == uuid.Nil {
		return ""
	}
	return "/repos/" + repoID.String()
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
