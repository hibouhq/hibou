package notify

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/hibouhq/lehibou/internal/audit"
	"github.com/hibouhq/lehibou/internal/events"
	"github.com/hibouhq/lehibou/internal/metrics"
	"github.com/hibouhq/lehibou/internal/store/dbgen"
)

const (
	sendTimeout                         = 15 * time.Second
	notificationCircuitBreakerThreshold = int32(5)
	notificationCircuitBreakerReset     = 30 * time.Minute
	notificationHealthFreshWindow       = 30 * time.Minute
	notificationRateLimitPerMinute      = 30
	notificationRateLimitWindow         = time.Minute
)

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
	limiter *rateLimiter
}

type rateLimiter struct {
	mu      sync.Mutex
	windows map[uuid.UUID][]time.Time
}

type dispatchOptions struct {
	async                bool
	bypassRateLimit      bool
	bypassCircuitBreaker bool
}

type IntegrationHealth struct {
	IntegrationID  string     `json:"integration_id"`
	Status         string     `json:"status"`
	LastSuccessAt  *time.Time `json:"last_success_at,omitempty"`
	LastFailureAt  *time.Time `json:"last_failure_at,omitempty"`
	FailureCount   int32      `json:"failure_count"`
	CircuitBreaker string     `json:"circuit_breaker"`
}

type DispatcherStore interface {
	ListIntegrationsByOrg(ctx context.Context, orgID uuid.UUID) ([]dbgen.Integration, error)
	ListEnabledRulesByOrgAndEventType(ctx context.Context, orgID uuid.UUID, eventType string) ([]dbgen.NotificationRule, error)
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
		limiter: &rateLimiter{windows: make(map[uuid.UUID][]time.Time)},
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
	d.bus.Subscribe(events.VulnerabilityCreated, func(ctx context.Context, event events.Event) {
		d.handleEvent(ctx, event.Type, event.Payload)
	})
	d.bus.Subscribe(events.VulnDiscovered, func(ctx context.Context, event events.Event) {
		d.handleEvent(ctx, event.Type, event.Payload)
	})
	d.bus.Subscribe(events.GatePassed, func(ctx context.Context, event events.Event) {
		d.handleEvent(ctx, event.Type, event.Payload)
	})
	d.bus.Subscribe(events.GateFailed, func(ctx context.Context, event events.Event) {
		d.handleEvent(ctx, event.Type, event.Payload)
	})
	d.bus.Subscribe(events.ScanStale, func(ctx context.Context, event events.Event) {
		d.handleEvent(ctx, event.Type, event.Payload)
	})
}

func (d *Dispatcher) handleEvent(ctx context.Context, eventType events.Type, rawPayload any) {
	if d == nil || d.store == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

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

	rules, err := d.store.ListEnabledRulesByOrgAndEventType(ctx, payload.OrgID, string(eventType))
	if err != nil {
		d.log.Error().Err(err).Str("org_id", payload.OrgID.String()).Str("event_type", string(eventType)).Msg("list notification rules")
		return
	}

	filteredIntegrations := d.selectIntegrationsForRules(payload, integrations, rules)
	if len(rules) > 0 {
		d.log.Debug().
			Str("org_id", payload.OrgID.String()).
			Str("event_type", string(eventType)).
			Int("rule_count", len(rules)).
			Int("integration_count", len(filteredIntegrations)).
			Msg("notification rules evaluated")
	}

	for _, integration := range filteredIntegrations {
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

		_ = d.dispatchIntegration(ctx, integration, sender, integrationPayload, dispatchOptions{async: true})
	}
}

func (d *Dispatcher) dispatchIntegration(ctx context.Context, integration dbgen.Integration, sender Sender, payload Payload, options dispatchOptions) error {
	if sender == nil {
		return nil
	}
	if !options.bypassCircuitBreaker && isCircuitOpen(integration) {
		if !shouldProbe(integration) {
			d.log.Warn().
				Str("integration_id", integration.ID.String()).
				Int32("failure_count", integration.FailureCount).
				Msg("circuit breaker open, skipping")
			return nil
		}
		d.log.Info().Str("integration_id", integration.ID.String()).Msg("circuit breaker probe attempt")
	}
	if !options.bypassRateLimit && d.limiter != nil && !d.limiter.allow(integration.ID, notificationRateLimitPerMinute) {
		d.log.Warn().
			Str("integration_id", integration.ID.String()).
			Int("limit_per_minute", notificationRateLimitPerMinute).
			Msg("notification rate limit exceeded, skipping")
		return nil
	}
	if options.async {
		asyncCtx, cancel := context.WithTimeout(context.Background(), sendTimeout)
		go func() {
			defer cancel()
			d.dispatchOne(asyncCtx, integration, sender, payload)
		}()
		return nil
	}
	d.dispatchOne(ctx, integration, sender, payload)
	return nil
}

func (d *Dispatcher) Replay(ctx context.Context, integration dbgen.Integration, payload Payload) error {
	if d == nil {
		return nil
	}
	sender := d.senders[strings.ToLower(strings.TrimSpace(integration.IntegrationType))]
	if sender == nil {
		return fmt.Errorf("no sender registered for integration type %q", integration.IntegrationType)
	}
	payload.Metadata = cloneMetadata(payload.Metadata)
	payload.Metadata["integration_id"] = integration.ID.String()
	payload.Metadata["integration_name"] = integration.Name
	payload.Metadata["integration_type"] = integration.IntegrationType
	payload.Metadata["integration_config"] = json.RawMessage(append([]byte(nil), integration.Config...))
	payload.Metadata["replay"] = true
	return d.dispatchIntegration(ctx, integration, sender, payload, dispatchOptions{bypassRateLimit: true, bypassCircuitBreaker: true})
}

func (d *Dispatcher) PreviewTargets(ctx context.Context, orgID uuid.UUID, payload Payload, rule dbgen.NotificationRule) ([]dbgen.Integration, error) {
	if d == nil || d.store == nil {
		return nil, nil
	}
	integrations, err := d.store.ListIntegrationsByOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	return PreviewIntegrationsForRule(payload, integrations, rule), nil
}

func PreviewIntegrationsForRule(payload Payload, integrations []dbgen.Integration, rule dbgen.NotificationRule) []dbgen.Integration {
	selected := make([]dbgen.Integration, 0, len(integrations))
	for _, integration := range integrations {
		if !integration.Enabled {
			continue
		}
		if !ruleMatchesIntegration(rule, integration) {
			continue
		}
		if !ruleConditionsMatch(rule.Conditions, payload) {
			continue
		}
		selected = append(selected, integration)
	}
	return selected
}

func IntegrationHealthFor(integration dbgen.Integration) IntegrationHealth {
	health := IntegrationHealth{
		IntegrationID:  integration.ID.String(),
		FailureCount:   integration.FailureCount,
		Status:         "degraded",
		CircuitBreaker: circuitBreakerState(integration),
	}
	if integration.LastSuccessAt.Valid {
		timestamp := integration.LastSuccessAt.Time.UTC()
		health.LastSuccessAt = &timestamp
	}
	if integration.LastFailureAt.Valid {
		timestamp := integration.LastFailureAt.Time.UTC()
		health.LastFailureAt = &timestamp
	}
	switch {
	case integration.FailureCount >= notificationCircuitBreakerThreshold:
		health.Status = "unhealthy"
	case integration.FailureCount == 0 && integration.LastSuccessAt.Valid && time.Since(integration.LastSuccessAt.Time) <= notificationHealthFreshWindow:
		health.Status = "healthy"
	default:
		health.Status = "degraded"
	}
	return health
}

func ReplayPayloadFromAuditLog(entry dbgen.AuditLog) (Payload, error) {
	var decoded map[string]any
	if err := json.Unmarshal(entry.Context, &decoded); err != nil {
		return Payload{}, err
	}
	rawPayload, _ := decoded["payload"].(map[string]any)
	if rawPayload == nil {
		rawPayload = decoded
	}
	payload := Payload{
		EventType: stringValue(rawPayload, "event_type", stringValue(decoded, "event_type", "")),
		Title:     stringValue(rawPayload, "title", stringValue(decoded, "title", "")),
		Body:      stringValue(rawPayload, "body", ""),
		Severity:  stringValue(rawPayload, "severity", "info"),
		Link:      stringValue(rawPayload, "link", stringValue(decoded, "link", "")),
		OrgID:     uuidFromPayload(rawPayload, "org_id"),
		RepoName:  stringValue(rawPayload, "repo_name", stringValue(decoded, "repo_name", "repository")),
		Metadata:  mapValue(rawPayload["metadata"]),
	}
	if payload.EventType == "" {
		return Payload{}, fmt.Errorf("audit log does not contain a replayable payload")
	}
	return payload, nil
}

func (d *Dispatcher) selectIntegrationsForRules(payload Payload, integrations []dbgen.Integration, rules []dbgen.NotificationRule) []dbgen.Integration {
	if len(rules) == 0 {
		return integrations
	}

	selected := make([]dbgen.Integration, 0, len(integrations))
	matchedRuleNames := make([]string, 0, len(rules))
	for _, integration := range integrations {
		if !integration.Enabled {
			continue
		}
		matched := false
		for _, rule := range rules {
			if !ruleMatchesIntegration(rule, integration) {
				continue
			}
			if !ruleConditionsMatch(rule.Conditions, payload) {
				continue
			}
			matched = true
			matchedRuleNames = append(matchedRuleNames, rule.Name)
			break
		}
		if matched {
			selected = append(selected, integration)
		}
	}

	if len(matchedRuleNames) > 0 {
		d.log.Debug().
			Str("org_id", payload.OrgID.String()).
			Str("event_type", payload.EventType).
			Strs("matched_rules", matchedRuleNames).
			Msg("notification rules matched")
	}

	return selected
}

func ruleMatchesIntegration(rule dbgen.NotificationRule, integration dbgen.Integration) bool {
	if !strings.EqualFold(string(rule.DestinationType), integration.IntegrationType) {
		return false
	}
	return destinationConfigMatches(rule.DestinationConfig, integration.Config)
}

func destinationConfigMatches(ruleConfig, integrationConfig json.RawMessage) bool {
	ruleValues := decodeRuleMap(ruleConfig)
	if len(ruleValues) == 0 {
		return true
	}
	integrationValues := decodeRuleMap(integrationConfig)
	for key, value := range ruleValues {
		if !valuesEqual(value, integrationValues[key]) {
			return false
		}
	}
	return true
}

func ruleConditionsMatch(raw json.RawMessage, payload Payload) bool {
	conditions := decodeRuleMap(raw)
	if len(conditions) == 0 {
		return true
	}
	if !matchesMinSeverity(conditions["min_severity"], payload.Severity) {
		return false
	}
	if !matchesRepoIDs(conditions["repo_ids"], payload.Metadata) {
		return false
	}
	if !matchesTeamIDs(conditions["team_ids"], payload.Metadata) {
		return false
	}
	if !matchesRefPatterns(conditions["ref_patterns"], payload.Metadata) {
		return false
	}
	return true
}

func decodeRuleMap(raw json.RawMessage) map[string]any {
	if len(raw) == 0 {
		return map[string]any{}
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil || decoded == nil {
		return map[string]any{}
	}
	return decoded
}

func matchesMinSeverity(condition any, actual string) bool {
	if condition == nil {
		return true
	}
	threshold, ok := condition.(string)
	if !ok {
		return true
	}
	return severityRank(actual) >= severityRank(threshold)
}

func matchesRepoIDs(condition any, metadata map[string]any) bool {
	return matchesStringIDs(condition, stringValue(metadata, "repo_id", ""))
}

func matchesTeamIDs(condition any, metadata map[string]any) bool {
	return matchesStringIDs(condition, stringValue(metadata, "team_id", ""))
}

func matchesRefPatterns(condition any, metadata map[string]any) bool {
	if condition == nil {
		return true
	}
	refName := strings.TrimSpace(stringValue(metadata, "ref_name", ""))
	if refName == "" {
		return false
	}
	for _, pattern := range stringSliceValue(condition) {
		matched, err := path.Match(pattern, refName)
		if err == nil && matched {
			return true
		}
	}
	return false
}

func matchesStringIDs(condition any, actual string) bool {
	if condition == nil {
		return true
	}
	actual = strings.TrimSpace(actual)
	if actual == "" {
		return false
	}
	for _, item := range stringSliceValue(condition) {
		if item == actual {
			return true
		}
	}
	return false
}

func severityRank(value string) int {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	default:
		return 1
	}
}

func valuesEqual(left, right any) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	if leftErr != nil || rightErr != nil {
		return false
	}
	return string(leftJSON) == string(rightJSON)
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
	destinationType := strings.ToLower(strings.TrimSpace(integration.IntegrationType))
	if destinationType == "" && sender != nil {
		destinationType = strings.ToLower(strings.TrimSpace(sender.Type()))
	}
	if sendErr != nil {
		metrics.NotificationDeliveries.WithLabelValues(destinationType, "error").Inc()
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

	metrics.NotificationDeliveries.WithLabelValues(destinationType, "success").Inc()
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
		"body":       payload.Body,
		"severity":   payload.Severity,
		"status":     status,
		"payload": map[string]any{
			"event_type": payload.EventType,
			"title":      payload.Title,
			"body":       payload.Body,
			"severity":   payload.Severity,
			"link":       payload.Link,
			"org_id":     payload.OrgID.String(),
			"repo_name":  payload.RepoName,
			"metadata":   auditMetadata(payload.Metadata),
		},
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
	case events.VulnerabilityCreated:
		vulnID := stringValue(data, "advisory_id", stringValue(data, "id", "unknown vulnerability"))
		payload.Title = "New vulnerability created"
		payload.Body = fmt.Sprintf("New %s vulnerability %s found in repo %s", payload.Severity, vulnID, payload.RepoName)
	case events.VulnDiscovered:
		vulnID := stringValue(data, "cve", stringValue(data, "advisory_id", "unknown advisory"))
		payload.Title = "New vulnerability discovered"
		payload.Body = fmt.Sprintf("New %s vulnerability %s found in repo %s", payload.Severity, vulnID, payload.RepoName)
	case events.GateFailed:
		reason := stringValue(data, "reason", stringValue(data, "description", "quality gate threshold exceeded"))
		payload.Title = "Quality gate failed"
		payload.Body = fmt.Sprintf("Quality gate failed for repo %s: %s", payload.RepoName, reason)
	case events.ScanStale:
		lastScanAt := stringValue(data, "last_scan_completed_at", "unknown")
		payload.Title = "Repository scan stale"
		payload.Body = fmt.Sprintf("Repo %s has no completed scan since %s", payload.RepoName, lastScanAt)
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
	if eventType == events.ScanStale {
		return "medium"
	}
	return "info"
}

func isCircuitOpen(integration dbgen.Integration) bool {
	return integration.FailureCount >= notificationCircuitBreakerThreshold
}

func shouldProbe(integration dbgen.Integration) bool {
	if !integration.LastFailureAt.Valid {
		return false
	}
	return time.Since(integration.LastFailureAt.Time) >= notificationCircuitBreakerReset
}

func circuitBreakerState(integration dbgen.Integration) string {
	if !isCircuitOpen(integration) {
		return "closed"
	}
	if shouldProbe(integration) {
		return "half_open"
	}
	return "open"
}

func (r *rateLimiter) allow(id uuid.UUID, limit int) bool {
	if r == nil || limit <= 0 {
		return true
	}
	now := time.Now().UTC()
	cutoff := now.Add(-notificationRateLimitWindow)
	r.mu.Lock()
	defer r.mu.Unlock()
	window := r.windows[id]
	filtered := window[:0]
	for _, timestamp := range window {
		if timestamp.After(cutoff) {
			filtered = append(filtered, timestamp)
		}
	}
	if len(filtered) >= limit {
		r.windows[id] = append([]time.Time(nil), filtered...)
		return false
	}
	filtered = append(filtered, now)
	r.windows[id] = append([]time.Time(nil), filtered...)
	return true
}

func auditMetadata(metadata map[string]any) map[string]any {
	cloned := cloneMetadata(metadata)
	delete(cloned, "integration_config")
	return cloned
}

func mapValue(raw any) map[string]any {
	switch typed := raw.(type) {
	case map[string]any:
		return cloneMetadata(typed)
	case json.RawMessage:
		var decoded map[string]any
		if err := json.Unmarshal(typed, &decoded); err == nil {
			return decoded
		}
	case []byte:
		var decoded map[string]any
		if err := json.Unmarshal(typed, &decoded); err == nil {
			return decoded
		}
	}
	return map[string]any{}
}

func stringSliceValue(value any) []string {
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
			if value, ok := item.(string); ok {
				if trimmed := strings.TrimSpace(value); trimmed != "" {
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
	transport := cloneNotificationTransport(client)
	if transport == nil {
		if client != nil {
			return client
		}
		transport = http.DefaultTransport.(*http.Transport).Clone()
	}
	transport.Proxy = nil
	transport.DialContext = notificationDialContext((&net.Dialer{Timeout: 10 * time.Second}).DialContext)
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if client == nil {
		return &http.Client{Transport: transport}
	}
	cloned := *client
	cloned.Transport = transport
	return &cloned
}

func cloneNotificationTransport(client *http.Client) *http.Transport {
	if client == nil || client.Transport == nil {
		return nil
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		return nil
	}
	return transport.Clone()
}

func notificationDialContext(dialContext func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if err := validateNotificationAddress(ctx, address); err != nil {
			return nil, err
		}
		return dialContext(ctx, network, address)
	}
}

func validateNotificationAddress(ctx context.Context, address string) error {
	if allowPrivateNotificationURLs() {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("notification destination host is empty")
	}
	ips, err := resolveNotificationIPs(ctx, host)
	if err != nil {
		return err
	}
	blocked := make([]string, 0, len(ips))
	for _, ip := range ips {
		if isBlockedNotificationIP(ip) {
			blocked = append(blocked, ip.String())
		}
	}
	if len(blocked) == 0 {
		return nil
	}
	log.Warn().Str("address", address).Strs("blocked_ips", blocked).Msg("blocked private notification destination")
	return fmt.Errorf("notification destination %q resolves to a blocked address", address)
}

func resolveNotificationIPs(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	resolved, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(resolved))
	for _, item := range resolved {
		if item.IP != nil {
			ips = append(ips, item.IP)
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("notification destination %q did not resolve to an IP", host)
	}
	return ips, nil
}

func isBlockedNotificationIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	metadataIPv4 := net.ParseIP("169.254.169.254")
	if metadataIPv4 != nil && ip.Equal(metadataIPv4) {
		return true
	}
	return false
}

func allowPrivateNotificationURLs() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("HIBOU_ALLOW_PRIVATE_NOTIFICATION_URLS")), "true")
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
