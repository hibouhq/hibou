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

	"github.com/hibouhq/lehibou/internal/version"
)

type WebhookSender struct{ client *http.Client }

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
	body, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("marshal webhook payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build webhook request: %w", err)
	}
	if secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		if _, err := mac.Write(body); err != nil {
			return fmt.Errorf("sign webhook payload: %w", err)
		}
		req.Header.Set("X-Hibou-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Hibou-Event", p.EventType)
	req.Header.Set("User-Agent", "hibou/"+version.Version)
	resp, err := httpClientWithDefault(s.client).Do(req)
	if err != nil {
		return fmt.Errorf("send webhook: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	return nil
}
