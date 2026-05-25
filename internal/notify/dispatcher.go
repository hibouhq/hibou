package notify

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/lehibou/internal/audit"
	"github.com/hibouhq/lehibou/internal/events"
	"github.com/hibouhq/lehibou/internal/store/dbgen"
)

const sendTimeout = 15 * time.Second

// Payload represents data to send to an external integration.
type Payload struct {
	EventType string
	Title     string
	Body      string
	Severity  string
	Link      string
	OrgID     uuid.UUID
	RepoName  string
	Metadata  map[string]any
}

// Sender delivers notifications to an external channel.
type Sender interface {
	Type() string
	Send(ctx context.Context, payload Payload) error
}

// Dispatcher routes events to external integrations based on org notification rules.
type Dispatcher struct {
	store   DispatcherStore
	senders map[string]Sender
	bus     *events.Bus
	log     zerolog.Logger
}

type DispatcherStore interface {
	ListIntegrationsByOrg(ctx context.Context, orgID uuid.UUID) ([]dbgen.Integration, error)
	UpdateIntegrationHealth(ctx context.Context, arg dbgen.UpdateIntegrationHealthParams) error
	CreateAuditLog(ctx context.Context, arg dbgen.CreateAuditLogParams) (dbgen.AuditLog, error)
}

func NewDispatcher(store DispatcherStore, bus *events.Bus, log zerolog.Logger, senders ...Sender) *Dispatcher {
	registry := make(map[string]Sender, len(senders))
	for _, sender := range senders {
		if sender == nil {
			continue
		}
		registry[strings.ToLower(strings.TrimSpace(sender.Type()))] = sender
	}
	return &Dispatcher{
		store:   store,
		senders: registry,
		bus:     bus,
		log:     log.With().Str("component", "notify.dispatcher").Logger(),
	}
}

func (d *Dispatcher) Subscribe() {
	if d == nil || d.bus == nil {
		return
	}

	d.bus.Subscribe(events.ScanCompleted, func(ctx context.Context, event events.Event) {
		d.handleEvent(ctx, event.Type, event.Payload)
	})
	d.bus.Subscribe(events.ScanFailed, func(ctx context.Context, event events.Event) {
		d.handleEvent(ctx, event.Type, event.Payload)
	})
	d.bus.Subscribe(events.VulnDiscovered, func(ctx context.Context, event events.Event) {
		d.handleEvent(ctx, event.Type, event.Payload)
	})
	d.bus.Subscribe(events.GateFailed, func(ctx context.Context, event events.Event) {
		d.handleEvent(ctx, event.Type, event.Payload)
	})
}

func (d *Dispatcher) handleEvent(ctx context.Context, eventType events.Type, rawPayload any) {
	if d == nil || d.store == nil {
		return
	}

	payload := buildDispatchPayload(eventType, rawPayload)
	if payload.OrgID == uuid.Nil {
		d.log.Debug().Str("event_type", string(eventType)).Msg("skip notification dispatch without org id")
		return
	}

	integrations, err := d.store.ListIntegrationsByOrg(ctx, payload.OrgID)
	if err != nil {
		d.log.Error().Err(err).Str("org_id", payload.OrgID.String()).Str("event_type", string(eventType)).Msg("list org integrations")
		return
	}

	for _, integration := range integrations {
		if !integration.Enabled {
			continue
		}
		sender := d.senders[strings.ToLower(strings.TrimSpace(integration.IntegrationType))]
		if sender == nil {
			d.log.Debug().Str("integration_type", integration.IntegrationType).Str("integration_id", integration.ID.String()).Msg("skip integration without sender")
			continue
		}

		integrationPayload := payload
		integrationPayload.Metadata = cloneMetadata(payload.Metadata)
		integrationPayload.Metadata["integration_id"] = integration.ID.String()
		integrationPayload.Metadata["integration_name"] = integration.Name
		integrationPayload.Metadata["integration_type"] = integration.IntegrationType
		integrationPayload.Metadata["integration_config"] = json.RawMessage(append([]byte(nil), integration.Config...))

		go d.dispatchOne(ctx, integration, sender, integrationPayload)
	}
}

func (d *Dispatcher) dispatchOne(ctx context.Context, integration dbgen.Integration, sender Sender, payload Payload) {
	startedAt := time.Now().UTC()
	childCtx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	recordCtx, recordCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer recordCancel()

	var sendErr error
	defer func() {
		if recovered := recover(); recovered != nil {
			sendErr = fmt.Errorf("panic delivering notification: %v", recovered)
		}
		d.recordDelivery(recordCtx, integration, sender, payload, startedAt, sendErr)
	}()

	sendErr = sender.Send(childCtx, payload)
}

func (d *Dispatcher) recordDelivery(ctx context.Context, integration dbgen.Integration, sender Sender, payload Payload, startedAt time.Time, sendErr error) {
	now := time.Now().UTC()
	if sendErr != nil {
		d.log.Error().
			Err(sendErr).
			Str("integration_id", integration.ID.String()).
			Str("integration_type", integration.IntegrationType).
			Str("event_type", payload.EventType).
			Dur("duration", now.Sub(startedAt)).
			Msg("notification delivery failed")
		_ = d.store.UpdateIntegrationHealth(ctx, dbgen.UpdateIntegrationHealthParams{
			ID:            integration.ID,
			LastSuccessAt: integration.LastSuccessAt,
			LastFailureAt: sqlNullTime(now),
			FailureCount:  integration.FailureCount + 1,
		})
		d.writeAuditLog(ctx, integration, payload, "failed", sendErr)
		return
	}

	d.log.Info().
		Str("integration_id", integration.ID.String()).
		Str("integration_type", integration.IntegrationType).
		Str("sender_type", sender.Type()).
		Str("event_type", payload.EventType).
		Dur("duration", now.Sub(startedAt)).
		Msg("notification delivered")
	_ = d.store.UpdateIntegrationHealth(ctx, dbgen.UpdateIntegrationHealthParams{
		ID:            integration.ID,
		LastSuccessAt: sqlNullTime(now),
		LastFailureAt: integration.LastFailureAt,
		FailureCount:  0,
	})
	d.writeAuditLog(ctx, integration, payload, "delivered", nil)
}

func (d *Dispatcher) writeAuditLog(ctx context.Context, integration dbgen.Integration, payload Payload, status string, sendErr error) {
	contextPayload := map[string]any{
		"event_type": payload.EventType,
		"title":      payload.Title,
		"status":     status,
	}
	if payload.Link != "" {
		contextPayload["link"] = payload.Link
	}
	if payload.RepoName != "" {
		contextPayload["repo_name"] = payload.RepoName
	}
	if sendErr != nil {
		contextPayload["error"] = sendErr.Error()
	}
	encoded, err := json.Marshal(contextPayload)
	if err != nil {
		encoded = json.RawMessage(`{"status":"marshal_error"}`)
	}

	_, _ = d.store.CreateAuditLog(ctx, dbgen.CreateAuditLogParams{
		ActorType:    audit.ActorSystem,
		ActorDisplay: "notification-dispatcher",
		Action:       "integration.delivery",
		ResourceType: "integration",
		ResourceID:   integration.ID.String(),
		OrgID:        nullUUID(payload.OrgID),
		Context:      encoded,
	})
}

func buildDispatchPayload(eventType events.Type, rawPayload any) Payload {
	data, _ := rawPayload.(map[string]any)
	payload := Payload{
		EventType: string(eventType),
		Severity:  defaultDispatchSeverity(eventType, data),
		Link:      stringValue(data, "link", repoLink(uuidFromPayload(data, "repo_id"))),
		OrgID:     uuidFromPayload(data, "org_id"),
		RepoName:  stringValue(data, "repo_name", "repository"),
		Metadata:  cloneMetadata(data),
	}

	switch eventType {
	case events.ScanCompleted:
		payload.Title = "Scan completed"
		payload.Body = "Scan completed for repo " + payload.RepoName
	case events.ScanFailed:
		errMsg := stringValue(data, "error", "unknown error")
		payload.Title = "Scan failed"
		payload.Body = fmt.Sprintf("Scan failed for repo %s: %s", payload.RepoName, errMsg)
	case events.VulnDiscovered:
		vulnID := stringValue(data, "cve", stringValue(data, "advisory_id", "unknown advisory"))
		payload.Title = "New vulnerability discovered"
		payload.Body = fmt.Sprintf("New %s vulnerability %s found in repo %s", payload.Severity, vulnID, payload.RepoName)
	case events.GateFailed:
		reason := stringValue(data, "reason", stringValue(data, "description", "quality gate threshold exceeded"))
		payload.Title = "Quality gate failed"
		payload.Body = fmt.Sprintf("Quality gate failed for repo %s: %s", payload.RepoName, reason)
	default:
		payload.Title = string(eventType)
		payload.Body = stringValue(data, "message", string(eventType))
	}

	return payload
}

func defaultDispatchSeverity(eventType events.Type, data map[string]any) string {
	if severity := strings.ToLower(strings.TrimSpace(stringValue(data, "severity", ""))); severity != "" {
		return severity
	}
	if eventType == events.ScanFailed || eventType == events.GateFailed {
		return "high"
	}
	return "info"
}

func cloneMetadata(source map[string]any) map[string]any {
	if len(source) == 0 {
		return map[string]any{}
	}
	cloned := make(map[string]any, len(source))
	for key, value := range source {
		cloned[key] = value
	}
	return cloned
}

func integrationConfig(payload Payload) map[string]any {
	raw, ok := payload.Metadata["integration_config"]
	if !ok || raw == nil {
		return map[string]any{}
	}
	switch value := raw.(type) {
	case map[string]any:
		return value
	case json.RawMessage:
		var decoded map[string]any
		if err := json.Unmarshal(value, &decoded); err == nil && decoded != nil {
			return decoded
		}
	case []byte:
		var decoded map[string]any
		if err := json.Unmarshal(value, &decoded); err == nil && decoded != nil {
			return decoded
		}
	}
	return map[string]any{}
}

func configString(config map[string]any, key string) string {
	if value, ok := config[key]; ok {
		switch typed := value.(type) {
		case string:
			return strings.TrimSpace(typed)
		case fmt.Stringer:
			return strings.TrimSpace(typed.String())
		}
	}
	return ""
}

func configInt(config map[string]any, key string, fallback int) int {
	if value, ok := config[key]; ok {
		switch typed := value.(type) {
		case float64:
			return int(typed)
		case int:
			return typed
		case int32:
			return int(typed)
		case int64:
			return int(typed)
		case json.Number:
			if parsed, err := typed.Int64(); err == nil {
				return int(parsed)
			}
		case string:
			if parsed, err := strconv.Atoi(strings.TrimSpace(typed)); err == nil {
				return parsed
			}
		}
	}
	return fallback
}

func configStringSlice(config map[string]any, key string) []string {
	value, ok := config[key]
	if !ok || value == nil {
		return nil
	}
	switch typed := value.(type) {
	case []string:
		items := make([]string, 0, len(typed))
		for _, item := range typed {
			if trimmed := strings.TrimSpace(item); trimmed != "" {
				items = append(items, trimmed)
			}
		}
		return items
	case []any:
		items := make([]string, 0, len(typed))
		for _, item := range typed {
			if str, ok := item.(string); ok {
				if trimmed := strings.TrimSpace(str); trimmed != "" {
					items = append(items, trimmed)
				}
			}
		}
		return items
	case string:
		if trimmed := strings.TrimSpace(typed); trimmed != "" {
			return []string{trimmed}
		}
	}
	return nil
}

func severityColorHex(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return "#C62828"
	case "high":
		return "#EF6C00"
	case "medium":
		return "#F9A825"
	case "low":
		return "#2E7D32"
	default:
		return "#1565C0"
	}
}

func severityColorInt(severity string) int {
	value := strings.TrimPrefix(severityColorHex(severity), "#")
	parsed, err := strconv.ParseInt(value, 16, 32)
	if err != nil {
		return 0x1565C0
	}
	return int(parsed)
}

func severityLabel(severity string) string {
	trimmed := strings.TrimSpace(severity)
	if trimmed == "" {
		return "info"
	}
	return strings.ToUpper(trimmed[:1]) + strings.ToLower(trimmed[1:])
}

func renderNotificationText(payload Payload) string {
	parts := []string{payload.Title, payload.Body, "Severity: " + severityLabel(payload.Severity)}
	if payload.Link != "" {
		parts = append(parts, "Link: "+payload.Link)
	}
	return strings.Join(parts, "\n")
}

func httpClientWithDefault(client *http.Client) *http.Client {
	if client != nil {
		return client
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = (&net.Dialer{Timeout: 10 * time.Second}).DialContext
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &http.Client{Transport: transport}
}

func sqlNullTime(value time.Time) sql.NullTime {
	return sql.NullTime{Time: value, Valid: true}
}

func nullUUID(value uuid.UUID) uuid.NullUUID {
	if value == uuid.Nil {
		return uuid.NullUUID{}
	}
	return uuid.NullUUID{UUID: value, Valid: true}
}
