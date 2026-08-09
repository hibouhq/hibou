package notify

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/events"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
	"github.com/hibouhq/hibou/internal/ws"
)

type mockNotifyStore struct {
	notifications []dbgen.Notification
	snapshot      *store.Snapshot
	ref           *store.Ref
	repo          *store.Repository
	members       []store.OrgMember
	// notified is the in-memory dedup ledger: event\x00repo\x00identifier.
	notified map[string]struct{}
}

func (m *mockNotifyStore) MarkFindingsNotified(_ context.Context, eventType string, repoID uuid.UUID, identifiers []string) ([]string, error) {
	if m.notified == nil {
		m.notified = map[string]struct{}{}
	}
	fresh := []string{}
	for _, identifier := range identifiers {
		key := eventType + "\x00" + repoID.String() + "\x00" + identifier
		if _, ok := m.notified[key]; ok {
			continue
		}
		m.notified[key] = struct{}{}
		fresh = append(fresh, identifier)
	}
	return fresh, nil
}

func (m *mockNotifyStore) CreateNotification(_ context.Context, arg dbgen.CreateNotificationParams) (dbgen.Notification, error) {
	n := dbgen.Notification{ID: uuid.New(), UserID: arg.UserID, Type: arg.Type, Title: arg.Title, Body: arg.Body, Link: arg.Link, Severity: arg.Severity, Status: string(dbgen.NotificationStatusUnread), CreatedAt: time.Now().UTC()}
	m.notifications = append(m.notifications, n)
	return n, nil
}

func (m *mockNotifyStore) ListNotificationsByUser(_ context.Context, arg dbgen.ListNotificationsByUserParams) ([]dbgen.Notification, error) {
	items := make([]dbgen.Notification, 0)
	for _, item := range m.notifications {
		if item.UserID == arg.UserID {
			items = append(items, item)
		}
	}
	return items, nil
}

func (m *mockNotifyStore) CountUnreadNotifications(_ context.Context, userID uuid.UUID) (int64, error) {
	var count int64
	for _, item := range m.notifications {
		if item.UserID == userID && item.Status == string(dbgen.NotificationStatusUnread) {
			count++
		}
	}
	return count, nil
}

func (m *mockNotifyStore) CountNotificationsByUser(_ context.Context, userID uuid.UUID) (int64, error) {
	var count int64
	for _, item := range m.notifications {
		if item.UserID == userID {
			count++
		}
	}
	return count, nil
}

func (m *mockNotifyStore) MarkNotificationRead(_ context.Context, arg dbgen.MarkNotificationReadParams) error {
	for i := range m.notifications {
		if m.notifications[i].ID == arg.ID && m.notifications[i].UserID == arg.UserID {
			m.notifications[i].Status = string(dbgen.NotificationStatusRead)
		}
	}
	return nil
}

func (m *mockNotifyStore) MarkAllNotificationsRead(_ context.Context, userID uuid.UUID) error {
	for i := range m.notifications {
		if m.notifications[i].UserID == userID {
			m.notifications[i].Status = string(dbgen.NotificationStatusRead)
		}
	}
	return nil
}

func (m *mockNotifyStore) GetSnapshotByID(context.Context, uuid.UUID) (*store.Snapshot, error) {
	return m.snapshot, nil
}
func (m *mockNotifyStore) GetRefByID(context.Context, uuid.UUID) (*store.Ref, error) {
	return m.ref, nil
}
func (m *mockNotifyStore) GetRepositoryByID(context.Context, uuid.UUID) (*store.Repository, error) {
	return m.repo, nil
}
func (m *mockNotifyStore) GetOrganizationByID(context.Context, uuid.UUID) (*store.Organization, error) {
	return &store.Organization{Provider: "github", Slug: "acme"}, nil
}
func (m *mockNotifyStore) ListOrgMembers(context.Context, uuid.UUID, int, int) ([]store.OrgMember, int, error) {
	return m.members, len(m.members), nil
}

func TestHandleScanCompletedNotifiesOnlyTheTriggeringUser(t *testing.T) {
	userID := uuid.New()
	store := &mockNotifyStore{
		snapshot: &store.Snapshot{ID: uuid.New(), RefID: uuid.New()},
		ref:      &store.Ref{ID: uuid.New(), RepoID: uuid.New()},
		repo:     &store.Repository{ID: uuid.New(), OrgID: uuid.New(), Name: "api", Slug: "api"},
		members:  []store.OrgMember{{UserID: userID}, {UserID: uuid.New()}},
	}
	fanout := ws.NewFanout(nil, ws.NewDispatcher(ws.NewHub(zerolog.Nop()), zerolog.Nop()), false, zerolog.Nop())
	service := NewService(store, fanout, events.New(zerolog.Nop()), zerolog.Nop())

	// A scheduled/webhook scan carries no user: no bell at all.
	service.handleScanCompleted(context.Background(), map[string]any{"snapshot_id": store.snapshot.ID.String()})
	if len(store.notifications) != 0 {
		t.Fatalf("scheduled scan must not notify, got %d", len(store.notifications))
	}

	// A user-triggered scan pings that user only, never the whole org.
	service.handleScanCompleted(context.Background(), map[string]any{
		"snapshot_id":          store.snapshot.ID.String(),
		"triggered_by_user_id": userID.String(),
	})
	if len(store.notifications) != 1 {
		t.Fatalf("expected 1 notification, got %d", len(store.notifications))
	}
	if store.notifications[0].UserID != userID || store.notifications[0].Type != string(events.ScanCompleted) {
		t.Fatalf("unexpected notification: %#v", store.notifications[0])
	}
	// The link must be a real SPA route (org-scoped, slug-based) deep-linking
	// to the tab where the event is visible; the old /repos/{uuid} shape
	// matched nothing and clicks were silent no-ops.
	if want := "/orgs/github/acme/repos/" + store.repo.Slug + "/dependencies"; store.notifications[0].Link != want {
		t.Fatalf("link = %q, want %q", store.notifications[0].Link, want)
	}
}

// The heart of the notification-spam fix: one bell entry per scan, only for
// identifiers the repo has never been told about, silent when nothing is new.
func TestHandleVulnerabilitiesFoundBatchesAndDedups(t *testing.T) {
	userID := uuid.New()
	store := &mockNotifyStore{
		snapshot: &store.Snapshot{ID: uuid.New(), RefID: uuid.New()},
		ref:      &store.Ref{ID: uuid.New(), RepoID: uuid.New()},
		repo:     &store.Repository{ID: uuid.New(), OrgID: uuid.New(), Name: "api", Slug: "api"},
		members:  []store.OrgMember{{UserID: userID}},
	}
	fanout := ws.NewFanout(nil, ws.NewDispatcher(ws.NewHub(zerolog.Nop()), zerolog.Nop()), false, zerolog.Nop())
	service := NewService(store, fanout, events.New(zerolog.Nop()), zerolog.Nop())

	payload := map[string]any{
		"snapshot_id": store.snapshot.ID.String(),
		"identifiers": []any{"CVE-2026-0001", "CVE-2026-0002"},
		"findings": []any{
			map[string]any{"identifier": "CVE-2026-0001", "severity": "critical", "component": "lodash@4.17.11"},
			map[string]any{"identifier": "CVE-2026-0002", "severity": "medium", "component": "yaml@2.2.2"},
		},
	}
	service.handleVulnerabilitiesFound(context.Background(), payload)

	if len(store.notifications) != 1 {
		t.Fatalf("expected ONE batched notification, got %d", len(store.notifications))
	}
	first := store.notifications[0]
	if first.Type != string(events.VulnerabilitiesFound) || first.Title != "2 new vulnerabilities" {
		t.Fatalf("unexpected notification: %q / %q", first.Type, first.Title)
	}
	if !strings.Contains(first.Body, "CVE-2026-0001") || !strings.Contains(first.Body, "lodash@4.17.11") {
		t.Fatalf("body must carry identifiers + components, got %q", first.Body)
	}
	if !first.Severity.Valid || first.Severity.SeverityLevel != dbgen.SeverityLevelCritical {
		t.Fatalf("batch severity must be the max (critical), got %#v", first.Severity)
	}

	// Re-running the same scan re-inserts the same rows: the ledger already
	// knows every identifier, so the bell stays silent.
	service.handleVulnerabilitiesFound(context.Background(), payload)
	if len(store.notifications) != 1 {
		t.Fatalf("re-notified already-known identifiers: %d notifications", len(store.notifications))
	}
}
