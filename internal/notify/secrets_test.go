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
	plain := mustJSON(t, map[string]any{"webhook_url": "https://hooks.example/T/B/token", "secret": "hmac", "channel": "#sec"})
	sealed, err := codec.SealConfig(plain)
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
	again, err := codec.SealConfig(sealed)
	if err != nil || !bytes.Equal(again, sealed) {
		t.Fatalf("sealing twice must be a no-op: %s (%v)", again, err)
	}

	opened, err := codec.OpenConfig(sealed)
	if err != nil {
		t.Fatalf("OpenConfig: %v", err)
	}
	var got map[string]any
	_ = json.Unmarshal(opened, &got)
	if got["webhook_url"] != "https://hooks.example/T/B/token" || got["secret"] != "hmac" || got["channel"] != "#sec" {
		t.Fatalf("opened = %v", got)
	}

	// Rows written before the key existed stay readable.
	legacy, err := codec.OpenConfig(plain)
	if err != nil || !bytes.Equal(legacy, plain) {
		t.Fatalf("plaintext row = %s (%v), want unchanged", legacy, err)
	}

	// No key, or the wrong key, fails closed.
	keyless, _ := NewSecretCodec(nil)
	if _, err := keyless.OpenConfig(sealed); !errors.Is(err, ErrSealedWithoutKey) {
		t.Fatalf("keyless open err = %v, want ErrSealedWithoutKey", err)
	}
	other, _ := NewSecretCodec(testKey(t))
	if _, err := other.OpenConfig(sealed); !errors.Is(err, ErrSealedWithoutKey) {
		t.Fatalf("wrong-key open err = %v, want ErrSealedWithoutKey", err)
	}

	// A ciphertext moved to another field does not open (field is the AAD).
	var fields map[string]any
	_ = json.Unmarshal(sealed, &fields)
	fields["smtp_password"] = fields["secret"]
	delete(fields, "secret")
	moved, _ := json.Marshal(fields)
	if _, err := codec.OpenConfig(moved); err == nil {
		t.Fatal("a sealed value moved to another field opened")
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
	merged, err := MergeConfig(stored, mustJSON(t, map[string]any{"webhook_url": MaskedSecret, "channel": "#alerts"}))
	if err != nil {
		t.Fatalf("MergeConfig: %v", err)
	}
	var got map[string]any
	_ = json.Unmarshal(merged, &got)
	if got["webhook_url"] != "https://hooks.example/T/B/token" || got["secret"] != "hmac" || got["channel"] != "#alerts" {
		t.Fatalf("merged = %v", got)
	}

	cleared, _ := MergeConfig(stored, mustJSON(t, map[string]any{"secret": ""}))
	_ = json.Unmarshal(cleared, &got)
	if got["secret"] != "" {
		t.Fatalf("explicit empty string must clear the secret: %v", got)
	}
	if _, err := MergeConfig(stored, mustJSON(t, map[string]any{"secret": sealedPrefix + "forged"})); !errors.Is(err, ErrSealedValueSubmitted) {
		t.Fatalf("sealed-looking client value err = %v", err)
	}
	if err := ValidateNewConfig(mustJSON(t, map[string]any{"secret": MaskedSecret})); err == nil {
		t.Fatal("create accepted the masked marker as a secret")
	}
}

func TestChangedConfigFieldsNamesOnly(t *testing.T) {
	codec, _ := NewSecretCodec(testKey(t))
	before, _ := codec.SealConfig(mustJSON(t, map[string]any{"secret": "old", "channel": "#a"}))
	after, _ := codec.SealConfig(mustJSON(t, map[string]any{"secret": "new", "channel": "#a", "username": "bot"}))
	got := codec.ChangedConfigFields(before, after)
	if strings.Join(got, ",") != "secret,username" {
		t.Fatalf("changed = %v, want [secret username]", got)
	}
	same, _ := codec.SealConfig(mustJSON(t, map[string]any{"secret": "old", "channel": "#a"}))
	if fields := codec.ChangedConfigFields(before, same); len(fields) != 0 {
		t.Fatalf("re-sealing the same value reported %v as changed", fields)
	}
}

// Rules may select an integration by a secret field; with both sides sealed
// (random nonces) the match must compare opened values.
func TestRuleMatchesSealedIntegration(t *testing.T) {
	installKey(t, testKey(t))
	hook := "https://hooks.example/T/B/token"
	integrationConfig, _ := Secrets().SealConfig(mustJSON(t, map[string]any{"webhook_url": hook}))
	ruleConfig, _ := Secrets().SealConfig(mustJSON(t, map[string]any{"webhook_url": hook}))
	if bytes.Equal(integrationConfig, ruleConfig) {
		t.Fatal("expected distinct ciphertexts")
	}
	integration := dbgen.Integration{IntegrationType: "slack", Config: integrationConfig}
	rule := dbgen.NotificationRule{DestinationType: "slack", DestinationConfig: ruleConfig}
	if !ruleMatchesIntegration(rule, integration) {
		t.Fatal("sealed rule did not match its sealed integration")
	}
	other, _ := Secrets().SealConfig(mustJSON(t, map[string]any{"webhook_url": "https://hooks.example/other"}))
	rule.DestinationConfig = other
	if ruleMatchesIntegration(rule, integration) {
		t.Fatal("a different sealed URL matched")
	}
}

// A sealed integration is delivered with its opened config.
func TestDispatcherOpensSealedConfigForSenders(t *testing.T) {
	installKey(t, testKey(t))
	hook := "https://hooks.example/T/B/token"
	sealed, _ := Secrets().SealConfig(mustJSON(t, map[string]any{"webhook_url": hook}))
	orgID := uuid.New()
	integration := dbgen.Integration{ID: uuid.New(), OrgID: orgID, Name: "slack", IntegrationType: "slack", Enabled: true, Config: sealed}
	store := &mockDispatcherStore{integrations: []dbgen.Integration{integration}}
	sender := &mockSender{typ: "slack", calledCh: make(chan Payload, 1)}
	dispatcher := NewDispatcher(store, events.New(zerolog.Nop()), "", zerolog.Nop(), sender)

	dispatcher.handleEvent(context.Background(), events.ScanFailed, map[string]any{"org_id": orgID.String(), "repo_name": "api"})
	payload := awaitPayload(t, sender.calledCh)
	if got := configString(integrationConfig(payload), "webhook_url"); got != hook {
		t.Fatalf("sender saw webhook_url %q, want the opened value", got)
	}
}
