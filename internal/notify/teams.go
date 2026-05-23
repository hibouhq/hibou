package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type TeamsSender struct{ client *http.Client }

func (s *TeamsSender) Type() string { return "teams" }

func (s *TeamsSender) Send(ctx context.Context, p Payload) error {
	config := integrationConfig(p)
	webhookURL := configString(config, "webhook_url")
	if webhookURL == "" {
		return fmt.Errorf("teams webhook_url is required")
	}
	card := map[string]any{
		"type": "message",
		"attachments": []map[string]any{{
			"contentType": "application/vnd.microsoft.card.adaptive",
			"content": map[string]any{
				"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
				"type":    "AdaptiveCard",
				"version": "1.4",
				"body": []map[string]any{
					{"type": "TextBlock", "text": p.Title, "weight": "Bolder", "size": "Medium", "color": "Attention"},
					{"type": "TextBlock", "text": p.Body, "wrap": true},
					{"type": "TextBlock", "text": "Severity: " + severityLabel(p.Severity), "wrap": true},
				},
			},
		}},
	}
	if p.Link != "" {
		card["attachments"].([]map[string]any)[0]["content"].(map[string]any)["actions"] = []map[string]any{{
			"type":  "Action.OpenUrl",
			"title": "Open in Hibou",
			"url":   p.Link,
		}}
	}
	body, err := json.Marshal(card)
	if err != nil {
		return fmt.Errorf("marshal teams payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build teams request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClientWithDefault(s.client).Do(req)
	if err != nil {
		return fmt.Errorf("send teams webhook: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("teams webhook returned status %d", resp.StatusCode)
	}
	return nil
}
