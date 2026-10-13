package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

type SlackSender struct{ client *http.Client }

func (s *SlackSender) Type() string { return "slack" }

func (s *SlackSender) Send(ctx context.Context, p Payload) error {
	config := integrationConfig(p)
	webhookURL := configString(config, "webhook_url")
	if webhookURL == "" {
		return errors.New("slack webhook_url is required")
	}
	body, err := json.Marshal(map[string]any{
		"text": renderNotificationText(p),
		"blocks": []map[string]any{{
			"type": "section",
			"text": map[string]string{
				"type": "mrkdwn",
				"text": fmt.Sprintf("*%s*\n%s\n*Severity:* %s", p.Title, p.Body, severityLabel(p.Severity)),
			},
		}},
		"attachments": []map[string]any{{
			"color": severityColorHex(p.Severity),
		}},
	})
	if err != nil {
		return fmt.Errorf("marshal slack payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build slack request: %w", transportError(err))
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClientWithDefault(s.client).Do(req)
	if err != nil {
		return fmt.Errorf("send slack webhook: %w", transportError(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("slack webhook returned status %d", resp.StatusCode)
	}
	return nil
}
