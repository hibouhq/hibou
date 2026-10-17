package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/events"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

func installKey(t *testing.T, key []byte) {
	t.Helper()
	if err := SetEncryptionKey(key); err != nil {
		t.Fatalf("SetEncryptionKey: %v", err)
	}
	t.Cleanup(func() { _ = SetEncryptionKey(nil) })
}

// P2: the generic webhook body is a DTO; the integration config (URL, HMAC
// secret) that rides in Payload.Metadata for the senders never leaves.
func TestWebhookBodyNeverCarriesIntegrationConfig(t *testing.T) {
	t.Setenv("HIBOU_ALLOW_PRIVATE_NOTIFICATION_URLS", "true")
	const hmacSecret = "whsec-super-secret-value"

	var gotBody []byte
	var gotSignature string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotSignature = r.Header.Get("X-Hibou-Signature")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	hookURL := server.URL + "/hooks/token-in-path?key=query-token"

	payload := Payload{
		EventType: "gate.failed",
		Title:     "Quality gate failed",
		Body:      "Quality gate failed for repo api",
		Severity:  "high",
		Link:      "https://hibou.example/repos/api",
		OrgID:     uuid.New(),
		RepoName:  "api",
		Metadata: map[string]any{
			"repo_id":            "repo-1",
			"integration_id":     "int-1",
			"integration_config": mustJSON(t, map[string]any{"url": hookURL, "secret": hmacSecret}),
			"secret":             "event-level-secret",
		},
	}
	if err := (&WebhookSender{}).Send(context.Background(), payload); err != nil {
		t.Fatalf("Send: %v", err)
	}

	for _, forbidden := range []string{"integration_config", hmacSecret, "token-in-path", "query-token", "event-level-secret"} {
		if bytes.Contains(gotBody, []byte(forbidden)) {
			t.Fatalf("webhook body contains %q: %s", forbidden, gotBody)
		}
	}
	var decoded map[string]any
	if err := json.Unmarshal(gotBody, &decoded); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	for _, key := range []string{"EventType", "Title", "Body", "Severity", "Link", "OrgID", "RepoName", "Metadata"} {
		if _, ok := decoded[key]; !ok {
			t.Fatalf("webhook body lacks %q: %s", key, gotBody)
		}
	}
	if metadata, _ := decoded["Metadata"].(map[string]any); metadata["repo_id"] != "repo-1" {
		t.Fatalf("non-sensitive metadata dropped: %v", decoded["Metadata"])
	}
	mac := hmac.New(sha256.New, []byte(hmacSecret))
	mac.Write(gotBody)
	if want := "sha256=" + hex.EncodeToString(mac.Sum(nil)); gotSignature != want {
		t.Fatalf("signature = %q, want %q", gotSignature, want)
	}
}

// Q1: a transport failure must not print the webhook URL — for Slack/Teams/
// Discord the path is the credential.
func TestSenderTransportErrorsRedactURL(t *testing.T) {
	t.Setenv("HIBOU_ALLOW_PRIVATE_NOTIFICATION_URLS", "true")
	listener := httptest.NewServer(http.NotFoundHandler())
	deadURL := listener.URL
	listener.Close() // connection refused from here on

	hookURL := deadURL + "/services/T000/B000/XOXSECRETTOKEN?sig=QUERYSECRET"
	userinfoURL := strings.Replace(deadURL, "http://", "http://user:PASSWORDSECRET@", 1) + "/hook"
	cases := []struct {
		name   string
		sender Sender
		config map[string]any
	}{
		{"slack", &SlackSender{}, map[string]any{"webhook_url": hookURL}},
		{"teams", &TeamsSender{}, map[string]any{"webhook_url": hookURL}},
		{"discord", &DiscordSender{}, map[string]any{"webhook_url": hookURL}},
		{"webhook", &WebhookSender{}, map[string]any{"url": userinfoURL, "secret": "s"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.sender.Send(context.Background(), Payload{
				EventType: "scan.failed",
				Metadata:  map[string]any{"integration_config": mustJSON(t, tc.config)},
			})
			if err == nil {
				t.Fatal("Send error = nil, want a transport failure")
			}
			for _, secret := range []string{"XOXSECRETTOKEN", "QUERYSECRET", "PASSWORDSECRET", "/services/"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("error leaks %q: %v", secret, err)
				}
			}
			var urlErr *url.Error
			if errors.As(err, &urlErr) {
				t.Fatalf("raw *url.Error still reachable through the chain: %v", err)
			}
		})
	}
}

// Q1: whatever a sender returns, the dispatcher scrubs secret config values
// before the error reaches the audit log.
func TestDispatcherScrubsSecretsFromDeliveryAudit(t *testing.T) {
	const hookURL = "https://hooks.slack.com/services/T000/B000/XOXSECRETTOKEN"
	orgID := uuid.New()
	integration := dbgen.Integration{
		ID: uuid.New(), OrgID: orgID, Name: "slack", IntegrationType: "slack", Enabled: true,
		Config: mustJSON(t, map[string]any{"webhook_url": hookURL}),
	}
	store := &mockDispatcherStore{integrations: []dbgen.Integration{integration}}
	leaky := &mockSender{typ: "slack", err: fmt.Errorf("delivery to %s failed", hookURL)}
	dispatcher := NewDispatcher(store, events.New(zerolog.Nop()), "", zerolog.Nop(), leaky)

	if err := dispatcher.Replay(context.Background(), integration, Payload{EventType: "scan.failed", OrgID: orgID}); err != nil {
		t.Fatalf("Replay: %v", err)
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.auditLogs) != 1 {
		t.Fatalf("audit logs = %d, want 1", len(store.auditLogs))
	}
	context := string(store.auditLogs[0].Context)
	if strings.Contains(context, "XOXSECRETTOKEN") || strings.Contains(context, "/services/") {
		t.Fatalf("audit context leaks the webhook URL: %s", context)
	}
	if !strings.Contains(context, "failed") {
		t.Fatalf("audit context lost the error: %s", context)
	}
}

func TestSecretCodecSealsAndOpensSecretFieldsOnly(t *testing.T) {
	codec, err := NewSecretCodec(testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	sc := SealContext{OrgID: uuid.New(), Table: SealTableIntegrations, RowID: uuid.New()}
	plain := mustJSON(t, map[string]any{"webhook_url": "https://hooks.example/T/B/token", "secret": "hmac", "channel": "#sec"})
	sealed, err := codec.SealConfig(sc, plain)
	if err != nil {
		t.Fatalf("SealConfig: %v", err)
	}
	if bytes.Contains(sealed, []byte("token")) || bytes.Contains(sealed, []byte("hmac")) {
		t.Fatalf("sealed config still holds plaintext: %s", sealed)
	}
	if !bytes.Contains(sealed, []byte(`"channel":"#sec"`)) {
		t.Fatalf("non-secret field changed: %s", sealed)
	}
	if !bytes.Contains(sealed, []byte(sealedPrefix)) {
		t.Fatalf("sealed values lack the version prefix: %s", sealed)
	}
	again, err := codec.SealConfig(sc, sealed)
	if err != nil || !bytes.Equal(again, sealed) {
		t.Fatalf("sealing twice must be a no-op: %s (%v)", again, err)
	}

	opened, err := codec.OpenConfig(sc, sealed)
	if err != nil {
		t.Fatalf("OpenConfig: %v", err)
	}
	var got map[string]any
	_ = json.Unmarshal(opened, &got)
	if got["webhook_url"] != "https://hooks.example/T/B/token" || got["secret"] != "hmac" || got["channel"] != "#sec" {
		t.Fatalf("opened = %v", got)
	}

	// Rows written before the key existed stay readable.
	legacy, err := codec.OpenConfig(sc, plain)
	if err != nil || !bytes.Equal(legacy, plain) {
		t.Fatalf("plaintext row = %s (%v), want unchanged", legacy, err)
	}

	// No key, or the wrong key, fails closed.
	keyless, _ := NewSecretCodec(nil)
	if _, err := keyless.OpenConfig(sc, sealed); !errors.Is(err, ErrSealedWithoutKey) {
		t.Fatalf("keyless open err = %v, want ErrSealedWithoutKey", err)
	}
	other, _ := NewSecretCodec(testKey(t))
	if _, err := other.OpenConfig(sc, sealed); !errors.Is(err, ErrSealedWithoutKey) {
		t.Fatalf("wrong-key open err = %v, want ErrSealedWithoutKey", err)
	}

	// A ciphertext moved to another field does not open (field is the AAD).
	var fields map[string]any
	_ = json.Unmarshal(sealed, &fields)
	fields["smtp_password"] = fields["secret"]
	delete(fields, "secret")
	moved, _ := json.Marshal(fields)
	if _, err := codec.OpenConfig(sc, moved); err == nil {
		t.Fatal("a sealed value moved to another field opened")
	}
}

// v2 values are bound to org, table and row: a ciphertext copied into
// another integration, another org's row or a rule does not open. v1 values
// (field-only binding) still open, and a merge re-seals them as v2.
func TestSealedValuesAreBoundToTheirRow(t *testing.T) {
	codec, err := NewSecretCodec(testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	sc := SealContext{OrgID: uuid.New(), Table: SealTableIntegrations, RowID: uuid.New()}
	sealed, err := codec.SealConfig(sc, mustJSON(t, map[string]any{"secret": "hmac"}))
	if err != nil {
		t.Fatal(err)
	}
	for name, other := range map[string]SealContext{
		"other row":   {OrgID: sc.OrgID, Table: sc.Table, RowID: uuid.New()},
		"other org":   {OrgID: uuid.New(), Table: sc.Table, RowID: sc.RowID},
		"other table": {OrgID: sc.OrgID, Table: SealTableNotificationRules, RowID: sc.RowID},
	} {
		if _, err := codec.OpenConfig(other, sealed); !errors.Is(err, ErrSealedWithoutKey) {
			t.Fatalf("%s: copied ciphertext opened (err = %v)", name, err)
		}
	}
	if _, err := codec.SealConfig(SealContext{OrgID: sc.OrgID, Table: sc.Table}, mustJSON(t, map[string]any{"secret": "x"})); err == nil {
		t.Fatal("sealing without a row id succeeded")
	}

	// A legacy enc:v1 value, AAD = field name only.
	nonce := make([]byte, codec.aead.NonceSize())
	_, _ = rand.Read(nonce)
	v1 := sealedPrefixV1 + base64.RawStdEncoding.EncodeToString(codec.aead.Seal(nonce, nonce, []byte("legacy-hmac"), []byte("secret")))
	legacy := mustJSON(t, map[string]any{"secret": v1, "url": "https://hooks.example/a"})
	opened, err := codec.OpenConfig(sc, legacy)
	if err != nil || !strings.Contains(string(opened), "legacy-hmac") {
		t.Fatalf("v1 value did not open: %s (%v)", opened, err)
	}
	merged, err := codec.MergeConfig("webhook", sc, legacy, mustJSON(t, map[string]any{"secret": MaskedSecret, "url": MaskedSecret}))
	if err != nil {
		t.Fatalf("MergeConfig: %v", err)
	}
	resealed, err := codec.SealConfig(sc, merged)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(resealed), sealedPrefixV1) || !strings.Contains(string(resealed), sealedPrefix) {
		t.Fatalf("v1 value not re-sealed as v2: %s", resealed)
	}
	if again, err := codec.OpenConfig(sc, resealed); err != nil || !strings.Contains(string(again), "legacy-hmac") {
		t.Fatalf("re-sealed value = %s (%v)", again, err)
	}
	if err := ValidateNewConfig(mustJSON(t, map[string]any{"secret": v1})); !errors.Is(err, ErrSealedValueSubmitted) {
		t.Fatalf("client-submitted v1 value err = %v", err)
	}
}

func TestParseEncryptionKey(t *testing.T) {
	key := testKey(t)
	for _, encoded := range []string{base64.StdEncoding.EncodeToString(key), base64.RawURLEncoding.EncodeToString(key)} {
		got, err := ParseEncryptionKey(encoded)
		if err != nil || !bytes.Equal(got, key) {
			t.Fatalf("ParseEncryptionKey(%q) = %x, %v", encoded, got, err)
		}
	}
	if got, err := ParseEncryptionKey(""); err != nil || got != nil {
		t.Fatalf("empty key = %x, %v; want no key", got, err)
	}
	if _, err := ParseEncryptionKey(base64.StdEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Fatal("a 5-byte key was accepted")
	}
	if _, err := ParseEncryptionKey("not base64 !!"); err == nil {
		t.Fatal("non-base64 key was accepted")
	}
}

// Q3: secrets are write-only — masked in responses, kept on round-trip.
func TestMaskAndMergeConfig(t *testing.T) {
	stored := mustJSON(t, map[string]any{"webhook_url": "https://hooks.example/T/B/token", "secret": "hmac", "smtp_password": "", "channel": "#sec"})
	masked := MaskConfig(stored)
	var view map[string]any
	_ = json.Unmarshal(masked, &view)
	if view["webhook_url"] != MaskedSecret || view["secret"] != MaskedSecret {
		t.Fatalf("masked = %s", masked)
	}
	if view["smtp_password"] != "" || view["channel"] != "#sec" {
		t.Fatalf("empty secret or plain field altered: %s", masked)
	}
	if string(MaskConfig(json.RawMessage(`"not an object"`))) != "{}" {
		t.Fatal("non-object config must mask to {}")
	}

	// The client sends back what it saw, changing one plain field and
	// omitting another secret entirely.
	codec := &SecretCodec{}
	sc := SealContext{OrgID: uuid.New(), Table: SealTableIntegrations, RowID: uuid.New()}
	merged, err := codec.MergeConfig("slack", sc, stored, mustJSON(t, map[string]any{"webhook_url": MaskedSecret, "channel": "#alerts"}))
	if err != nil {
		t.Fatalf("MergeConfig: %v", err)
	}
	var got map[string]any
	_ = json.Unmarshal(merged, &got)
	if got["webhook_url"] != "https://hooks.example/T/B/token" || got["secret"] != "hmac" || got["channel"] != "#alerts" {
		t.Fatalf("merged = %v", got)
	}

	cleared, _ := codec.MergeConfig("slack", sc, stored, mustJSON(t, map[string]any{"secret": ""}))
	_ = json.Unmarshal(cleared, &got)
	if got["secret"] != "" {
		t.Fatalf("explicit empty string must clear the secret: %v", got)
	}
	if _, err := codec.MergeConfig("slack", sc, stored, mustJSON(t, map[string]any{"secret": sealedPrefix + "forged"})); !errors.Is(err, ErrSealedValueSubmitted) {
		t.Fatalf("sealed-looking client value err = %v", err)
	}
	if err := ValidateNewConfig(mustJSON(t, map[string]any{"secret": MaskedSecret})); err == nil {
		t.Fatal("create accepted the masked marker as a secret")
	}
}

func TestChangedConfigFieldsNamesOnly(t *testing.T) {
	codec, _ := NewSecretCodec(testKey(t))
	sc := SealContext{OrgID: uuid.New(), Table: SealTableIntegrations, RowID: uuid.New()}
	before, _ := codec.SealConfig(sc, mustJSON(t, map[string]any{"secret": "old", "channel": "#a"}))
	after, _ := codec.SealConfig(sc, mustJSON(t, map[string]any{"secret": "new", "channel": "#a", "username": "bot"}))
	got := codec.ChangedConfigFields(sc, before, after)
	if strings.Join(got, ",") != "secret,username" {
		t.Fatalf("changed = %v, want [secret username]", got)
	}
	same, _ := codec.SealConfig(sc, mustJSON(t, map[string]any{"secret": "old", "channel": "#a"}))
	if fields := codec.ChangedConfigFields(sc, before, same); len(fields) != 0 {
		t.Fatalf("re-sealing the same value reported %v as changed", fields)
	}
}

// Rule matching never compares credential fields: whatever URL a rule
// guesses, dry-run (PreviewIntegrationsForRule) answers the same, so it
// cannot confirm an integration's write-only webhook URL or password.
func TestRuleMatchingIsNotASecretOracle(t *testing.T) {
	installKey(t, testKey(t))
	hook := "https://hooks.example/T/B/token"
	integration := dbgen.Integration{ID: uuid.New(), OrgID: uuid.New(), IntegrationType: "slack", Enabled: true}
	integration.Config, _ = Secrets().SealConfig(IntegrationSealContext(integration), mustJSON(t, map[string]any{"webhook_url": hook, "smtp_password": "pw", "channel": "#sec"}))
	other := dbgen.Integration{ID: uuid.New(), OrgID: integration.OrgID, IntegrationType: "slack", Enabled: true, Config: mustJSON(t, map[string]any{"channel": "#ops"})}
	integrations := []dbgen.Integration{integration, other}

	preview := func(config map[string]any) []dbgen.Integration {
		rule := dbgen.NotificationRule{DestinationType: "slack", DestinationConfig: mustJSON(t, config)}
		return PreviewIntegrationsForRule(Payload{}, integrations, rule)
	}
	// A legacy rule that selects by a credential field matches nothing,
	// whatever the guess: no oracle, and no fan-out to every integration of
	// the type (which ignoring the field would cause).
	right := preview(map[string]any{"webhook_url": hook, "smtp_password": "pw"})
	wrong := preview(map[string]any{"webhook_url": "https://hooks.example/guess", "smtp_password": "nope"})
	if len(right) != 0 || len(wrong) != 0 {
		t.Fatalf("legacy credential selector matched: right=%d wrong=%d (want 0 and 0)", len(right), len(wrong))
	}
	// The same legacy rule naming an integration_id still delivers there.
	if got := preview(map[string]any{"webhook_url": "https://hooks.example/guess", RuleIntegrationIDKey: integration.ID.String()}); len(got) != 1 || got[0].ID != integration.ID {
		t.Fatalf("legacy rule with integration_id matched %v", got)
	}

	// Non-secret fields and integration_id still select.
	if got := preview(map[string]any{"channel": "#sec"}); len(got) != 1 || got[0].ID != integration.ID {
		t.Fatalf("channel selector matched %v", got)
	}
	if got := preview(map[string]any{RuleIntegrationIDKey: other.ID.String()}); len(got) != 1 || got[0].ID != other.ID {
		t.Fatalf("integration_id selector matched %v", got)
	}

	// And new rules cannot name a credential field at all, masked or not.
	for _, config := range []map[string]any{{"webhook_url": hook}, {"url": MaskedSecret}, {"secret": ""}} {
		var selector *RuleSecretSelectorError
		if err := ValidateRuleDestinationConfig(mustJSON(t, config)); !errors.As(err, &selector) {
			t.Fatalf("ValidateRuleDestinationConfig(%v) = %v, want RuleSecretSelectorError", config, err)
		}
	}
	if err := ValidateRuleDestinationConfig(mustJSON(t, map[string]any{RuleIntegrationIDKey: 3})); err == nil {
		t.Fatal("non-string integration_id accepted")
	}
	if err := ValidateRuleDestinationConfig(mustJSON(t, map[string]any{"channel": "#sec", RuleIntegrationIDKey: other.ID.String()})); err != nil {
		t.Fatalf("valid rule config refused: %v", err)
	}
}

// Changing where credentials go while keeping a stored (masked or omitted)
// secret is refused: otherwise an admin who cannot read the SMTP password or
// HMAC secret could point the integration at their own server and receive it.
func TestMergeConfigRequiresSecretsWhenDestinationChanges(t *testing.T) {
	codec := &SecretCodec{}
	sc := SealContext{OrgID: uuid.New(), Table: SealTableIntegrations, RowID: uuid.New()}
	email := mustJSON(t, map[string]any{"smtp_host": "smtp.corp.example", "smtp_port": 587, "smtp_username": "bot", "smtp_password": "pw", "smtp_from": "a@corp.example"})
	webhook := mustJSON(t, map[string]any{"url": "https://receiver.example/hook", "secret": "hmac"})

	refused := []struct {
		kind     string
		stored   json.RawMessage
		incoming map[string]any
		field    string
		dest     string
	}{
		{"email", email, map[string]any{"smtp_host": "evil.example", "smtp_port": 587, "smtp_username": "bot", "smtp_password": MaskedSecret}, "smtp_password", "smtp_host"},
		{"email", email, map[string]any{"smtp_host": "smtp.corp.example", "smtp_port": "2525", "smtp_username": "bot"}, "smtp_password", "smtp_port"},
		{"email", email, map[string]any{"smtp_host": "smtp.corp.example", "smtp_port": 587, "smtp_username": "other"}, "smtp_password", "smtp_username"},
		{"webhook", webhook, map[string]any{"url": "https://evil.example/hook", "secret": MaskedSecret}, "secret", "url"},
		{"webhook", webhook, map[string]any{"url": MaskedSecret, "webhook_url": "https://evil.example/hook"}, "secret", "webhook_url"},
		{"unknown", email, map[string]any{"smtp_host": "evil.example", "smtp_port": 587, "smtp_username": "bot"}, "smtp_password", "smtp_host"},
	}
	for i, tc := range refused {
		_, err := codec.MergeConfig(tc.kind, sc, tc.stored, mustJSON(t, tc.incoming))
		var reenter *ReenterSecretError
		if !errors.As(err, &reenter) || reenter.Field != tc.field || reenter.Destination != tc.dest {
			t.Fatalf("case %d: err = %v, want re-enter %s when changing %s", i, err, tc.field, tc.dest)
		}
	}

	allowed := []struct {
		kind     string
		stored   json.RawMessage
		incoming map[string]any
	}{
		// Same destination ("587" == 587), secret kept.
		{"email", email, map[string]any{"smtp_host": " smtp.corp.example ", "smtp_port": "587", "smtp_username": "bot", "smtp_password": MaskedSecret, "smtp_from": "b@corp.example"}},
		// New destination with the secret re-entered, or cleared.
		{"email", email, map[string]any{"smtp_host": "smtp2.corp.example", "smtp_port": 587, "smtp_username": "bot", "smtp_password": "pw"}},
		{"webhook", webhook, map[string]any{"url": "https://new.example/hook", "secret": "new-hmac"}},
		{"webhook", webhook, map[string]any{"url": "https://new.example/hook", "secret": ""}},
		// Slack: the URL is the credential; nothing else to keep.
		{"slack", mustJSON(t, map[string]any{"webhook_url": "https://hooks.example/a", "channel": "#a"}), map[string]any{"webhook_url": "https://hooks.example/b"}},
	}
	for i, tc := range allowed {
		if _, err := codec.MergeConfig(tc.kind, sc, tc.stored, mustJSON(t, tc.incoming)); err != nil {
			t.Fatalf("allowed case %d refused: %v", i, err)
		}
	}
}

// Sealed rows: the destination comparison runs on opened values.
func TestMergeConfigComparesOpenedDestinations(t *testing.T) {
	codec, _ := NewSecretCodec(testKey(t))
	sc := SealContext{OrgID: uuid.New(), Table: SealTableIntegrations, RowID: uuid.New()}
	stored, _ := codec.SealConfig(sc, mustJSON(t, map[string]any{"url": "https://receiver.example/hook", "secret": "hmac"}))
	if _, err := codec.MergeConfig("webhook", sc, stored, mustJSON(t, map[string]any{"url": "https://receiver.example/hook"})); err != nil {
		t.Fatalf("re-sending the same URL was refused: %v", err)
	}
	var reenter *ReenterSecretError
	if _, err := codec.MergeConfig("webhook", sc, stored, mustJSON(t, map[string]any{"url": "https://evil.example/hook"})); !errors.As(err, &reenter) {
		t.Fatalf("changed URL err = %v", err)
	}
	keyless := &SecretCodec{}
	if _, err := keyless.MergeConfig("webhook", sc, stored, mustJSON(t, map[string]any{})); !errors.Is(err, ErrSealedWithoutKey) {
		t.Fatalf("keyless merge of a sealed row err = %v", err)
	}
}

// A sealed integration is delivered with its opened config.
func TestDispatcherOpensSealedConfigForSenders(t *testing.T) {
	installKey(t, testKey(t))
	hook := "https://hooks.example/T/B/token"
	orgID := uuid.New()
	integration := dbgen.Integration{ID: uuid.New(), OrgID: orgID, Name: "slack", IntegrationType: "slack", Enabled: true}
	integration.Config, _ = Secrets().SealConfig(IntegrationSealContext(integration), mustJSON(t, map[string]any{"webhook_url": hook}))
	store := &mockDispatcherStore{integrations: []dbgen.Integration{integration}}
	sender := &mockSender{typ: "slack", calledCh: make(chan Payload, 1)}
	dispatcher := NewDispatcher(store, events.New(zerolog.Nop()), "", zerolog.Nop(), sender)

	dispatcher.handleEvent(context.Background(), events.ScanFailed, map[string]any{"org_id": orgID.String(), "repo_name": "api"})
	payload := awaitPayload(t, sender.calledCh)
	if got := configString(integrationConfig(payload), "webhook_url"); got != hook {
		t.Fatalf("sender saw webhook_url %q, want the opened value", got)
	}
}
