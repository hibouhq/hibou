package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/hibouhq/hibou/internal/audit"
	internalauth "github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/notify"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// callOrgHandler invokes an org-scoped handler with chi URL params and a
// JSON body, as the router would.
func callOrgHandler(t *testing.T, user *store.User, orgSlug string, method string, body any, handler http.HandlerFunc, params map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			t.Fatalf("marshal body: %v", err)
		}
	}
	req := httptest.NewRequest(method, "/", bytes.NewReader(payload))
	req = req.WithContext(internalauth.WithUser(req.Context(), user))
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("provider", "github")
	routeCtx.URLParams.Add("slug", orgSlug)
	for key, value := range params {
		routeCtx.URLParams.Add(key, value)
	}
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeCtx))
	recorder := httptest.NewRecorder()
	handler(recorder, req)
	return recorder
}

func auditEntriesFor(t *testing.T, srv *Server, resourceType, resourceID string) []dbgen.AuditLog {
	t.Helper()
	entries, err := srv.queries.ListAuditLogsByResource(context.Background(), resourceType, resourceID, 50, 0)
	if err != nil {
		t.Fatalf("ListAuditLogsByResource: %v", err)
	}
	return entries
}

func findAuditAction(entries []dbgen.AuditLog, action string) *dbgen.AuditLog {
	for i := range entries {
		if entries[i].Action == action {
			return &entries[i]
		}
	}
	return nil
}

// Q3 + Q8: integration secrets are write-only (masked even for admins, kept
// on a round-trip PUT), sealed at rest when a key is configured, and every
// change is audited by field name without the secret value.
func TestIntegrationSecretsWriteOnlySealedAndAudited(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if err := notify.SetEncryptionKey(key); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = notify.SetEncryptionKey(nil) })

	srv, org, admin, _ := newDiscoveryTestServer(t)
	const hook = "https://hooks.slack.com/services/T000/B000/XOXSECRETTOKEN"
	const hmacSecret = "integration-hmac-secret"

	rec := callOrgHandler(t, admin, org.Slug, http.MethodPost, map[string]any{
		"name":             "alerts",
		"integration_type": "slack",
		"enabled":          true,
		"config":           map[string]any{"webhook_url": hook, "secret": hmacSecret, "channel": "#sec"},
	}, srv.handleCreateIntegration, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d (%s)", rec.Code, rec.Body.String())
	}
	assertNoSecrets(t, "create response", rec.Body.String(), hook, hmacSecret)
	var created struct {
		Data dbgen.Integration `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	var shown map[string]any
	_ = json.Unmarshal(created.Data.Config, &shown)
	if shown["webhook_url"] != notify.MaskedSecret || shown["secret"] != notify.MaskedSecret || shown["channel"] != "#sec" {
		t.Fatalf("admin view of config = %v, want secrets masked", shown)
	}
	integrationID := created.Data.ID.String()

	stored, err := srv.queries.GetIntegrationByID(context.Background(), created.Data.ID)
	if err != nil || stored == nil {
		t.Fatalf("GetIntegrationByID: %v", err)
	}
	assertNoSecrets(t, "stored config", string(stored.Config), hook, hmacSecret)

	// GET is masked for the admin too.
	rec = callOrgHandler(t, admin, org.Slug, http.MethodGet, nil, srv.handleGetIntegration, map[string]string{"integrationID": integrationID})
	if rec.Code != http.StatusOK {
		t.Fatalf("get status = %d (%s)", rec.Code, rec.Body.String())
	}
	assertNoSecrets(t, "get response", rec.Body.String(), hook, hmacSecret)

	// Round-trip what GET showed, changing only the channel: secrets survive.
	rec = callOrgHandler(t, admin, org.Slug, http.MethodPut, map[string]any{
		"name":    "alerts",
		"enabled": true,
		"config":  map[string]any{"webhook_url": notify.MaskedSecret, "channel": "#alerts"},
	}, srv.handleUpdateIntegration, map[string]string{"integrationID": integrationID})
	if rec.Code != http.StatusOK {
		t.Fatalf("update status = %d (%s)", rec.Code, rec.Body.String())
	}
	assertNoSecrets(t, "update response", rec.Body.String(), hook, hmacSecret)
	stored, _ = srv.queries.GetIntegrationByID(context.Background(), created.Data.ID)
	if !strings.Contains(string(stored.Config), `"enc:v2:`) {
		t.Fatalf("stored secrets are not sealed with the row-bound v2 format: %s", stored.Config)
	}
	opened, err := notify.Secrets().OpenConfig(notify.IntegrationSealContext(*stored), stored.Config)
	if err != nil {
		t.Fatalf("OpenConfig: %v", err)
	}
	var config map[string]any
	_ = json.Unmarshal(opened, &config)
	if config["webhook_url"] != hook || config["secret"] != hmacSecret || config["channel"] != "#alerts" {
		t.Fatalf("stored config after masked round-trip = %v", config)
	}

	// Moving the destination while keeping the masked HMAC secret would send
	// it to whoever controls the new URL: refused until it is re-entered.
	const evilHook = "https://hooks.slack.com/services/T999/B999/ATTACKER"
	rec = callOrgHandler(t, admin, org.Slug, http.MethodPut, map[string]any{
		"name":    "alerts",
		"enabled": true,
		"config":  map[string]any{"webhook_url": evilHook, "secret": notify.MaskedSecret, "channel": "#alerts"},
	}, srv.handleUpdateIntegration, map[string]string{"integrationID": integrationID})
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "re-enter secret when changing webhook_url") {
		t.Fatalf("destination change with masked secret: status = %d (%s), want 422", rec.Code, rec.Body.String())
	}
	rec = callOrgHandler(t, admin, org.Slug, http.MethodPut, map[string]any{
		"name":    "alerts",
		"enabled": true,
		"config":  map[string]any{"webhook_url": evilHook, "channel": "#alerts"},
	}, srv.handleUpdateIntegration, map[string]string{"integrationID": integrationID})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("destination change with omitted secret: status = %d (%s), want 422", rec.Code, rec.Body.String())
	}
	if after, _ := srv.queries.GetIntegrationByID(context.Background(), created.Data.ID); string(after.Config) != string(stored.Config) {
		t.Fatal("a refused update changed the stored config")
	}

	rec = callOrgHandler(t, admin, org.Slug, http.MethodDelete, nil, srv.handleDeleteIntegration, map[string]string{"integrationID": integrationID})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d (%s)", rec.Code, rec.Body.String())
	}

	entries := auditEntriesFor(t, srv, "integration", integrationID)
	for _, action := range []string{audit.ActionIntegrationCreate, audit.ActionIntegrationUpdate, audit.ActionIntegrationDelete} {
		entry := findAuditAction(entries, action)
		if entry == nil {
			t.Fatalf("no %s audit entry in %d entries", action, len(entries))
		}
		assertNoSecrets(t, action+" audit context", string(entry.Context), hook, hmacSecret)
	}
	update := findAuditAction(entries, audit.ActionIntegrationUpdate)
	if !strings.Contains(string(update.Context), `"config.channel"`) {
		t.Fatalf("update audit lacks the changed field: %s", update.Context)
	}
	if strings.Contains(string(update.Context), `"config.webhook_url"`) {
		t.Fatalf("an unchanged (masked) secret was reported as changed: %s", update.Context)
	}
}

// Q3: notification-rule destination configs only select integrations, and
// never by a credential field: a rule (or a dry-run) matching on a guessed
// webhook URL would confirm the guess. Such fields are refused with 422.
func TestNotificationRuleDestinationRefusesCredentialSelectors(t *testing.T) {
	srv, org, admin, _ := newDiscoveryTestServer(t)
	const hook = "https://hooks.slack.com/services/T000/B000/RULESECRET"

	for _, handler := range []http.HandlerFunc{srv.handleCreateNotificationRule, srv.handleDryRunNotificationRule} {
		rec := callOrgHandler(t, admin, org.Slug, http.MethodPost, map[string]any{
			"name":               "critical",
			"event_type":         "scan.failed",
			"destination_type":   "slack",
			"destination_config": map[string]any{"webhook_url": hook},
			"enabled":            true,
		}, handler, nil)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("credential selector: status = %d (%s), want 422", rec.Code, rec.Body.String())
		}
		assertNoSecrets(t, "refusal", rec.Body.String(), hook)
	}

	integrationID := "6a1f2c3e-0000-4000-8000-000000000001"
	rec := callOrgHandler(t, admin, org.Slug, http.MethodPost, map[string]any{
		"name":               "critical",
		"event_type":         "scan.failed",
		"destination_type":   "slack",
		"destination_config": map[string]any{"integration_id": integrationID},
		"enabled":            true,
	}, srv.handleCreateNotificationRule, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d (%s)", rec.Code, rec.Body.String())
	}
	var created struct {
		Data dbgen.NotificationRule `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)

	rec = callOrgHandler(t, admin, org.Slug, http.MethodPut, map[string]any{
		"name":               "critical-renamed",
		"event_type":         "scan.failed",
		"destination_type":   "slack",
		"destination_config": map[string]any{"integration_id": integrationID, "webhook_url": notify.MaskedSecret},
		"enabled":            true,
	}, srv.handleUpdateNotificationRule, map[string]string{"ruleID": created.Data.ID.String()})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("update with a masked credential selector: status = %d (%s), want 422", rec.Code, rec.Body.String())
	}
	rec = callOrgHandler(t, admin, org.Slug, http.MethodPut, map[string]any{
		"name":               "critical-renamed",
		"event_type":         "scan.failed",
		"destination_type":   "slack",
		"destination_config": map[string]any{"integration_id": integrationID},
		"enabled":            true,
	}, srv.handleUpdateNotificationRule, map[string]string{"ruleID": created.Data.ID.String()})
	if rec.Code != http.StatusOK {
		t.Fatalf("update status = %d (%s)", rec.Code, rec.Body.String())
	}
	entries := auditEntriesFor(t, srv, "notification_rule", created.Data.ID.String())
	if findAuditAction(entries, audit.ActionNotificationRuleCreate) == nil || findAuditAction(entries, audit.ActionNotificationRuleUpdate) == nil {
		t.Fatalf("rule create/update not audited: %d entries", len(entries))
	}
}

// Q8: quality gate, team, client and org changes are audited.
func TestOrgConfigChangesAreAudited(t *testing.T) {
	srv, org, admin, _ := newDiscoveryTestServer(t)

	rec := callOrgHandler(t, admin, org.Slug, http.MethodPost, map[string]any{
		"name": "prod gate", "max_critical": 0, "max_high": 0, "enabled": true,
	}, srv.handleCreateQualityGate, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("gate create status = %d (%s)", rec.Code, rec.Body.String())
	}
	var gate struct {
		Data dbgen.QualityGate `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &gate)
	gateID := gate.Data.ID.String()
	rec = callOrgHandler(t, admin, org.Slug, http.MethodPut, map[string]any{
		"name": "prod gate", "max_critical": 0, "max_high": 5, "enabled": true,
	}, srv.handleUpdateQualityGate, map[string]string{"gateID": gateID})
	if rec.Code != http.StatusOK {
		t.Fatalf("gate update status = %d (%s)", rec.Code, rec.Body.String())
	}
	rec = callOrgHandler(t, admin, org.Slug, http.MethodDelete, nil, srv.handleDeleteQualityGate, map[string]string{"gateID": gateID})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("gate delete status = %d (%s)", rec.Code, rec.Body.String())
	}
	gateEntries := auditEntriesFor(t, srv, "quality_gate", gateID)
	for _, action := range []string{audit.ActionGateCreate, audit.ActionGateUpdate, audit.ActionGateDelete} {
		if findAuditAction(gateEntries, action) == nil {
			t.Fatalf("no %s audit entry", action)
		}
	}
	if update := findAuditAction(gateEntries, audit.ActionGateUpdate); !strings.Contains(string(update.Context), `"max_high"`) {
		t.Fatalf("gate update audit lacks the changed field: %s", update.Context)
	}

	teamSlug := uniqueName(t, "team")
	rec = callOrgHandler(t, admin, org.Slug, http.MethodPost, map[string]any{"name": "Sec", "slug": teamSlug}, srv.handleCreateTeam, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("team create status = %d (%s)", rec.Code, rec.Body.String())
	}
	var team struct {
		Data store.Team `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &team)
	rec = callOrgHandler(t, admin, org.Slug, http.MethodDelete, nil, srv.handleDeleteTeam, map[string]string{"teamSlug": teamSlug})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("team delete status = %d (%s)", rec.Code, rec.Body.String())
	}
	teamEntries := auditEntriesFor(t, srv, "team", team.Data.ID.String())
	if findAuditAction(teamEntries, audit.ActionTeamCreate) == nil || findAuditAction(teamEntries, audit.ActionTeamDelete) == nil {
		t.Fatalf("team create/delete not audited: %d entries", len(teamEntries))
	}

	clientSlug := uniqueName(t, "client")
	rec = callOrgHandler(t, admin, org.Slug, http.MethodPost, map[string]any{"name": "Acme", "slug": clientSlug, "contact_email": "buyer@acme.example"}, srv.handleCreateClient, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("client create status = %d (%s)", rec.Code, rec.Body.String())
	}
	var client struct {
		Data store.Client `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &client)
	rec = callOrgHandler(t, admin, org.Slug, http.MethodPut, map[string]any{"name": "Acme", "contact_email": "new-buyer@acme.example"}, srv.handleUpdateClient, map[string]string{"clientSlug": clientSlug})
	if rec.Code != http.StatusOK {
		t.Fatalf("client update status = %d (%s)", rec.Code, rec.Body.String())
	}
	clientEntries := auditEntriesFor(t, srv, "client", client.Data.ID.String())
	update := findAuditAction(clientEntries, audit.ActionClientUpdate)
	if findAuditAction(clientEntries, audit.ActionClientCreate) == nil || update == nil {
		t.Fatalf("client create/update not audited: %d entries", len(clientEntries))
	}
	if !strings.Contains(string(update.Context), `"contact_email"`) || strings.Contains(string(update.Context), "acme.example") {
		t.Fatalf("client update audit must name the field without its value: %s", update.Context)
	}
}

func assertNoSecrets(t *testing.T, where, text string, secrets ...string) {
	t.Helper()
	for _, secret := range secrets {
		if strings.Contains(text, secret) {
			t.Fatalf("%s leaks %q: %s", where, secret, text)
		}
		// Slack-style URLs: the path token alone is the credential.
		if idx := strings.LastIndex(secret, "/"); idx > 0 && strings.Contains(text, secret[idx+1:]) {
			t.Fatalf("%s leaks the token of %q: %s", where, secret, text)
		}
	}
}
