package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/hibouhq/hibou/internal/version"
)

type WebhookSender struct{ client *http.Client }

// Webhook signature headers (sent when the integration has a secret):
//
//	X-Hibou-Timestamp:     unix seconds at signing time
//	X-Hibou-Signature-256: sha256=hex(HMAC-SHA256(secret, timestamp + "." + body))
//	X-Hibou-Signature:     sha256=hex(HMAC-SHA256(secret, body))   (deprecated)
//
// Receivers should verify X-Hibou-Signature-256 and refuse a timestamp more
// than a few minutes from their clock: that bounds replay of a captured
// delivery. X-Hibou-Signature signs the body alone (replayable forever) and
// is kept only so existing receivers keep working.
const (
	WebhookTimestampHeader       = "X-Hibou-Timestamp"
	WebhookSignatureHeader       = "X-Hibou-Signature-256"
	LegacyWebhookSignatureHeader = "X-Hibou-Signature"
)

// webhookNow is the signing clock; tests replace it.
var webhookNow = time.Now

// WebhookSignature returns the X-Hibou-Signature-256 value for a body sent at
// timestamp (unix seconds, as in X-Hibou-Timestamp).
func WebhookSignature(secret []byte, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(timestamp))
	_, _ = mac.Write([]byte("."))
	_, _ = mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func signWebhookRequest(req *http.Request, secret, body []byte, now time.Time) {
	timestamp := strconv.FormatInt(now.Unix(), 10)
	req.Header.Set(WebhookTimestampHeader, timestamp)
	req.Header.Set(WebhookSignatureHeader, WebhookSignature(secret, timestamp, body))
	legacy := hmac.New(sha256.New, secret)
	_, _ = legacy.Write(body)
	req.Header.Set(LegacyWebhookSignatureHeader, "sha256="+hex.EncodeToString(legacy.Sum(nil)))
}

func (s *WebhookSender) Type() string { return "webhook" }

func (s *WebhookSender) Send(ctx context.Context, p Payload) error {
	config := integrationConfig(p)
	webhookURL := configString(config, "url")
	if webhookURL == "" {
		webhookURL = configString(config, "webhook_url")
	}
	if webhookURL == "" {
		return errors.New("webhook url is required")
	}
	secret := configString(config, "secret")
	body, err := json.Marshal(newWebhookBody(p))
	if err != nil {
		return fmt.Errorf("marshal webhook payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build webhook request: %w", transportError(err))
	}
	if secret != "" {
		signWebhookRequest(req, []byte(secret), body, webhookNow())
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Hibou-Event", p.EventType)
	req.Header.Set("User-Agent", "hibou/"+version.Version)
	resp, err := httpClientWithDefault(s.client).Do(req)
	if err != nil {
		return fmt.Errorf("send webhook: %w", transportError(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	return nil
}

// webhookBody is the generic webhook's wire format. It is built field by
// field from the payload — never by marshaling Payload itself, whose
// Metadata carries the integration config (URL, HMAC secret) for the senders.
// Key names match what receivers got before the DTO existed.
type webhookBody struct {
	EventType string         `json:"EventType"`
	Title     string         `json:"Title"`
	Body      string         `json:"Body"`
	Severity  string         `json:"Severity"`
	Link      string         `json:"Link"`
	OrgID     string         `json:"OrgID"`
	RepoName  string         `json:"RepoName"`
	Metadata  map[string]any `json:"Metadata"`
}

func newWebhookBody(p Payload) webhookBody {
	body := webhookBody{
		EventType: p.EventType,
		Title:     p.Title,
		Body:      p.Body,
		Severity:  p.Severity,
		Link:      p.Link,
		OrgID:     p.OrgID.String(),
		RepoName:  p.RepoName,
		Metadata:  publicMetadata(p.Metadata),
	}
	return body
}

// publicMetadata is the event metadata safe to send to a receiver: the
// integration config and anything named like a credential are dropped.
func publicMetadata(metadata map[string]any) map[string]any {
	out := make(map[string]any, len(metadata))
	for key, value := range metadata {
		if key == "integration_config" || IsSecretConfigKey(key) {
			continue
		}
		out[key] = value
	}
	return out
}
