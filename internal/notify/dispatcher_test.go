package notify

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/lehibou/internal/events"
	"github.com/hibouhq/lehibou/internal/store/dbgen"
)

type mockDispatcherStore struct {
	mu                  sync.Mutex
	integrations        []dbgen.Integration
	healthUpdates       []dbgen.UpdateIntegrationHealthParams
	auditLogs           []dbgen.CreateAuditLogParams
	listIntegrationsErr error
}

func (m *mockDispatcherStore) ListIntegrationsByOrg(_ context.Context, orgID uuid.UUID) ([]dbgen.Integration, error) {
	if m.listIntegrationsErr != nil {
		return nil, m.listIntegrationsErr
	}
	items := make([]dbgen.Integration, 0, len(m.integrations))
	for _, item := range m.integrations {
		if item.OrgID == orgID {
			items = append(items, item)
		}
	}
	return items, nil
}

func (m *mockDispatcherStore) UpdateIntegrationHealth(_ context.Context, arg dbgen.UpdateIntegrationHealthParams) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.healthUpdates = append(m.healthUpdates, arg)
	return nil
}

func (m *mockDispatcherStore) CreateAuditLog(_ context.Context, arg dbgen.CreateAuditLogParams) (dbgen.AuditLog, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.auditLogs = append(m.auditLogs, arg)
	return dbgen.AuditLog{ID: uuid.New()}, nil
}

type mockSender struct {
	typ      string
	err      error
	calledCh chan Payload
}

func (m *mockSender) Type() string { return m.typ }

func (m *mockSender) Send(_ context.Context, payload Payload) error {
	if m.calledCh != nil {
		m.calledCh <- payload
	}
	return m.err
}

func TestDispatcherFansOutToMultipleSenders(t *testing.T) {
	orgID := uuid.New()
	slackIntegration := dbgen.Integration{ID: uuid.New(), OrgID: orgID, Name: "slack", IntegrationType: "slack", Enabled: true, Config: mustJSON(t, map[string]any{"webhook_url": "https://example.com/slack"})}
	teamsIntegration := dbgen.Integration{ID: uuid.New(), OrgID: orgID, Name: "teams", IntegrationType: "teams", Enabled: true, Config: mustJSON(t, map[string]any{"webhook_url": "https://example.com/teams"})}
	store := &mockDispatcherStore{integrations: []dbgen.Integration{slackIntegration, teamsIntegration}}
	slackSender := &mockSender{typ: "slack", calledCh: make(chan Payload, 1)}
	teamsSender := &mockSender{typ: "teams", calledCh: make(chan Payload, 1)}
	dispatcher := NewDispatcher(store, events.New(zerolog.Nop()), zerolog.Nop(), slackSender, teamsSender)

	dispatcher.handleEvent(context.Background(), events.ScanCompleted, map[string]any{
		"org_id":    orgID.String(),
		"repo_name": "api",
	})

	awaitPayload(t, slackSender.calledCh)
	awaitPayload(t, teamsSender.calledCh)

	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.healthUpdates) != 2 {
		t.Fatalf("expected 2 health updates, got %d", len(store.healthUpdates))
	}
	if len(store.auditLogs) != 2 {
		t.Fatalf("expected 2 audit logs, got %d", len(store.auditLogs))
	}
}

func TestDispatcherSenderFailureDoesNotCrash(t *testing.T) {
	orgID := uuid.New()
	store := &mockDispatcherStore{integrations: []dbgen.Integration{
		{ID: uuid.New(), OrgID: orgID, Name: "slack", IntegrationType: "slack", Enabled: true, Config: mustJSON(t, map[string]any{"webhook_url": "https://example.com/slack"})},
		{ID: uuid.New(), OrgID: orgID, Name: "discord", IntegrationType: "discord", Enabled: true, Config: mustJSON(t, map[string]any{"webhook_url": "https://example.com/discord"})},
	}}
	failing := &mockSender{typ: "slack", err: errors.New("boom"), calledCh: make(chan Payload, 1)}
	success := &mockSender{typ: "discord", calledCh: make(chan Payload, 1)}
	dispatcher := NewDispatcher(store, events.New(zerolog.Nop()), zerolog.Nop(), failing, success)

	dispatcher.handleEvent(context.Background(), events.GateFailed, map[string]any{
		"org_id":    orgID.String(),
		"repo_name": "api",
		"reason":    "new critical vulnerabilities",
	})

	awaitPayload(t, failing.calledCh)
	awaitPayload(t, success.calledCh)

	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.healthUpdates) != 2 {
		t.Fatalf("expected 2 health updates, got %d", len(store.healthUpdates))
	}
	if store.healthUpdates[0].FailureCount == 0 && store.healthUpdates[1].FailureCount == 0 {
		t.Fatalf("expected at least one failure count update, got %#v", store.healthUpdates)
	}
}

func TestDispatcherSubscribeHandlesPublishedEvents(t *testing.T) {
	orgID := uuid.New()
	store := &mockDispatcherStore{integrations: []dbgen.Integration{{
		ID:              uuid.New(),
		OrgID:           orgID,
		Name:            "webhook",
		IntegrationType: "webhook",
		Enabled:         true,
		Config:          mustJSON(t, map[string]any{"url": "https://example.com/webhook"}),
	}}}
	bus := events.New(zerolog.Nop())
	sender := &mockSender{typ: "webhook", calledCh: make(chan Payload, 1)}
	dispatcher := NewDispatcher(store, bus, zerolog.Nop(), sender)
	dispatcher.Subscribe()

	bus.Publish(context.Background(), events.Event{Type: events.VulnDiscovered, Payload: map[string]any{
		"org_id":      orgID.String(),
		"repo_name":   "api",
		"severity":    "critical",
		"advisory_id": "ADV-1",
	}})

	payload := awaitPayload(t, sender.calledCh)
	if payload.EventType != string(events.VulnDiscovered) {
		t.Fatalf("expected vuln discovered event, got %q", payload.EventType)
	}
	if payload.Severity != "critical" {
		t.Fatalf("expected critical severity, got %q", payload.Severity)
	}
}

func awaitPayload(t *testing.T, ch <-chan Payload) Payload {
	t.Helper()
	select {
	case payload := <-ch:
		return payload
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for payload")
		return Payload{}
	}
}

func mustJSON(t *testing.T, value map[string]any) json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}
	return encoded
}
