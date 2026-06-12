package notify

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/events"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type mockDispatcherStore struct {
	mu                  sync.Mutex
	integrations        []dbgen.Integration
	rules               []dbgen.NotificationRule
	healthUpdates       []dbgen.UpdateIntegrationHealthParams
	auditLogs           []dbgen.CreateAuditLogParams
	listIntegrationsErr error
	listRulesErr        error
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

func (m *mockDispatcherStore) ListEnabledRulesByOrgAndEventType(_ context.Context, orgID uuid.UUID, eventType string) ([]dbgen.NotificationRule, error) {
	if m.listRulesErr != nil {
		return nil, m.listRulesErr
	}
	items := make([]dbgen.NotificationRule, 0, len(m.rules))
	for _, item := range m.rules {
		if item.OrgID == orgID && item.EventType == eventType && item.Enabled {
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

type contextCheckingSender struct {
	typ   string
	errCh chan error
}

func (m *contextCheckingSender) Type() string { return m.typ }

func (m *contextCheckingSender) Send(ctx context.Context, _ Payload) error {
	if m.errCh != nil {
		m.errCh <- ctx.Err()
	}
	return nil
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
	awaitCondition(t, 2*time.Second, func() bool {
		store.mu.Lock()
		defer store.mu.Unlock()
		return len(store.auditLogs) >= 2 && len(store.healthUpdates) >= 2
	})

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
	awaitCondition(t, 2*time.Second, func() bool {
		store.mu.Lock()
		defer store.mu.Unlock()
		return len(store.healthUpdates) >= 2
	})

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

func TestDispatcherRulesFilterIntegrationsBySeverityAndRepo(t *testing.T) {
	orgID := uuid.New()
	repoID := uuid.New()
	allowed := dbgen.Integration{ID: uuid.New(), OrgID: orgID, Name: "slack-prod", IntegrationType: "slack", Enabled: true, Config: mustJSON(t, map[string]any{"channel": "prod"})}
	blocked := dbgen.Integration{ID: uuid.New(), OrgID: orgID, Name: "slack-dev", IntegrationType: "slack", Enabled: true, Config: mustJSON(t, map[string]any{"channel": "dev"})}
	store := &mockDispatcherStore{
		integrations: []dbgen.Integration{allowed, blocked},
		rules: []dbgen.NotificationRule{{
			ID:                uuid.New(),
			OrgID:             orgID,
			Name:              "high prod only",
			EventType:         string(events.VulnDiscovered),
			Conditions:        mustJSON(t, map[string]any{"min_severity": "high", "repo_ids": []string{repoID.String()}}),
			DestinationType:   dbgen.NotificationDestinationTypeSlack,
			DestinationConfig: mustJSON(t, map[string]any{"channel": "prod"}),
			Enabled:           true,
		}},
	}
	sender := &mockSender{typ: "slack", calledCh: make(chan Payload, 2)}
	dispatcher := NewDispatcher(store, events.New(zerolog.Nop()), zerolog.Nop(), sender)

	dispatcher.handleEvent(context.Background(), events.VulnDiscovered, map[string]any{
		"org_id":    orgID.String(),
		"repo_id":   repoID.String(),
		"repo_name": "api",
		"severity":  "critical",
	})

	awaitPayload(t, sender.calledCh)
	select {
	case <-sender.calledCh:
		t.Fatal("expected only one integration dispatch")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestDispatcherSkipsOpenCircuitWithoutProbe(t *testing.T) {
	orgID := uuid.New()
	integration := dbgen.Integration{
		ID:              uuid.New(),
		OrgID:           orgID,
		Name:            "slack",
		IntegrationType: "slack",
		Enabled:         true,
		FailureCount:    notificationCircuitBreakerThreshold,
		LastFailureAt:   sqlNullTime(time.Now().UTC()),
	}
	store := &mockDispatcherStore{integrations: []dbgen.Integration{integration}}
	sender := &mockSender{typ: "slack", calledCh: make(chan Payload, 1)}
	dispatcher := NewDispatcher(store, events.New(zerolog.Nop()), zerolog.Nop(), sender)

	dispatcher.handleEvent(context.Background(), events.ScanFailed, map[string]any{"org_id": orgID.String(), "repo_name": "api"})

	select {
	case <-sender.calledCh:
		t.Fatal("expected open circuit to skip dispatch")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestDispatcherAllowsProbeAfterCircuitResetWindow(t *testing.T) {
	orgID := uuid.New()
	integration := dbgen.Integration{
		ID:              uuid.New(),
		OrgID:           orgID,
		Name:            "slack",
		IntegrationType: "slack",
		Enabled:         true,
		FailureCount:    notificationCircuitBreakerThreshold,
		LastFailureAt:   sqlNullTime(time.Now().UTC().Add(-notificationCircuitBreakerReset - time.Minute)),
	}
	store := &mockDispatcherStore{integrations: []dbgen.Integration{integration}}
	sender := &mockSender{typ: "slack", calledCh: make(chan Payload, 1)}
	dispatcher := NewDispatcher(store, events.New(zerolog.Nop()), zerolog.Nop(), sender)

	dispatcher.handleEvent(context.Background(), events.ScanFailed, map[string]any{"org_id": orgID.String(), "repo_name": "api"})

	awaitPayload(t, sender.calledCh)
}

func TestDispatcherSkipsWhenRateLimitExceeded(t *testing.T) {
	orgID := uuid.New()
	integration := dbgen.Integration{ID: uuid.New(), OrgID: orgID, Name: "slack", IntegrationType: "slack", Enabled: true}
	store := &mockDispatcherStore{integrations: []dbgen.Integration{integration}}
	sender := &mockSender{typ: "slack", calledCh: make(chan Payload, 1)}
	dispatcher := NewDispatcher(store, events.New(zerolog.Nop()), zerolog.Nop(), sender)
	recent := make([]time.Time, notificationRateLimitPerMinute)
	for i := range recent {
		recent[i] = time.Now().UTC()
	}
	dispatcher.limiter.windows[integration.ID] = recent

	dispatcher.handleEvent(context.Background(), events.ScanCompleted, map[string]any{"org_id": orgID.String(), "repo_name": "api"})

	select {
	case <-sender.calledCh:
		t.Fatal("expected rate limit to skip dispatch")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestDispatchIntegrationAsyncDetachesFromCanceledContext(t *testing.T) {
	orgID := uuid.New()
	integration := dbgen.Integration{ID: uuid.New(), OrgID: orgID, Name: "webhook", IntegrationType: "webhook", Enabled: true}
	sender := &contextCheckingSender{typ: "webhook", errCh: make(chan error, 1)}
	dispatcher := NewDispatcher(&mockDispatcherStore{}, events.New(zerolog.Nop()), zerolog.Nop(), sender)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := dispatcher.dispatchIntegration(ctx, integration, sender, Payload{EventType: "test"}, dispatchOptions{async: true}); err != nil {
		t.Fatalf("dispatchIntegration returned error: %v", err)
	}

	select {
	case sendErr := <-sender.errCh:
		if sendErr != nil {
			t.Fatalf("expected detached async context, got %v", sendErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for async send")
	}
}

func TestHandleEventDetachesFromCanceledContext(t *testing.T) {
	orgID := uuid.New()
	sender := &mockSender{typ: "webhook", calledCh: make(chan Payload, 1)}
	store := &mockDispatcherStore{integrations: []dbgen.Integration{{
		ID:              uuid.New(),
		OrgID:           orgID,
		Name:            "webhook",
		IntegrationType: "webhook",
		Enabled:         true,
		Config:          mustJSON(t, map[string]any{"url": "https://example.com/webhook"}),
	}}}
	dispatcher := NewDispatcher(store, events.New(zerolog.Nop()), zerolog.Nop(), sender)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dispatcher.handleEvent(ctx, events.ScanCompleted, map[string]any{"org_id": orgID.String(), "repo_name": "api"})

	awaitPayload(t, sender.calledCh)
}

func TestHTTPClientWithDefaultDisablesProxy(t *testing.T) {
	baseTransport := http.DefaultTransport.(*http.Transport).Clone()
	baseTransport.Proxy = http.ProxyFromEnvironment
	client := httpClientWithDefault(&http.Client{Transport: baseTransport})

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", client.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("expected notification client proxy support to be disabled")
	}
}

func TestValidateNotificationAddressRejectsPrivateIPs(t *testing.T) {
	t.Setenv("HIBOU_ALLOW_PRIVATE_NOTIFICATION_URLS", "false")
	if err := validateNotificationAddress(context.Background(), "127.0.0.1:443"); err == nil {
		t.Fatal("expected loopback address to be rejected")
	}
	if err := validateNotificationAddress(context.Background(), "[::1]:443"); err == nil {
		t.Fatal("expected ipv6 loopback address to be rejected")
	}
	if err := validateNotificationAddress(context.Background(), "169.254.169.254:80"); err == nil {
		t.Fatal("expected metadata address to be rejected")
	}
	if err := validateNotificationAddress(context.Background(), "93.184.216.34:443"); err != nil {
		t.Fatalf("expected public address to be allowed, got %v", err)
	}
}

func TestValidateNotificationAddressAllowsPrivateIPsWhenOverridden(t *testing.T) {
	t.Setenv("HIBOU_ALLOW_PRIVATE_NOTIFICATION_URLS", "true")
	if err := validateNotificationAddress(context.Background(), "127.0.0.1:443"); err != nil {
		t.Fatalf("expected override to allow private address, got %v", err)
	}
}

func TestRuleConditionsMatchTeamAndRefPatterns(t *testing.T) {
	payload := Payload{Metadata: map[string]any{"team_id": uuid.New().String(), "ref_name": "release/2026.05"}}
	conditions := mustJSON(t, map[string]any{
		"team_ids":     []string{payload.Metadata["team_id"].(string)},
		"ref_patterns": []string{"main", "release/*"},
	})
	if !ruleConditionsMatch(conditions, payload) {
		t.Fatal("expected team and ref conditions to match")
	}
	conditions = mustJSON(t, map[string]any{"ref_patterns": []string{"main"}})
	if ruleConditionsMatch(conditions, payload) {
		t.Fatal("expected ref pattern mismatch")
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

func awaitCondition(t *testing.T, timeout time.Duration, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for condition")
}

func mustJSON(t *testing.T, value map[string]any) json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}
	return encoded
}
