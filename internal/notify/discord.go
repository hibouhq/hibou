package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

type DiscordSender struct{ client *http.Client }

func (s *DiscordSender) Type() string { return "discord" }

func (s *DiscordSender) Send(ctx context.Context, p Payload) error {
	config := integrationConfig(p)
	webhookURL := configString(config, "webhook_url")
	if webhookURL == "" {
		return errors.New("discord webhook_url is required")
	}
	body, err := json.Marshal(map[string]any{
		"embeds": []map[string]any{{
			"title":       p.Title,
			"description": renderNotificationText(p),
			"color":       severityColorInt(p.Severity),
			"url":         p.Link,
		}},
	})
	if err != nil {
		return fmt.Errorf("marshal discord payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build discord request: %w", transportError(err))
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClientWithDefault(s.client).Do(req)
	if err != nil {
		return fmt.Errorf("send discord webhook: %w", transportError(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("discord webhook returned status %d", resp.StatusCode)
	}
	return nil
}
