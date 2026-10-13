package notify

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
)

// The signature covers a timestamp, so a captured delivery cannot be
// replayed later against a receiver that checks X-Hibou-Timestamp. The
// body-only legacy header is still sent for existing receivers.
func TestWebhookSignatureCoversTimestamp(t *testing.T) {
	t.Setenv("HIBOU_ALLOW_PRIVATE_NOTIFICATION_URLS", "true")
	fixed := time.Unix(1_790_000_000, 0)
	previous := webhookNow
	webhookNow = func() time.Time { return fixed }
	t.Cleanup(func() { webhookNow = previous })

	const secret = "whsec-timestamped"
	var body []byte
	var headers http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		headers = r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	payload := Payload{EventType: "scan.failed", OrgID: uuid.New(), Metadata: map[string]any{
		"integration_config": mustJSON(t, map[string]any{"url": server.URL + "/hook", "secret": secret}),
	}}
	if err := (&WebhookSender{}).Send(context.Background(), payload); err != nil {
		t.Fatalf("Send: %v", err)
	}
	timestamp := headers.Get(WebhookTimestampHeader)
	if timestamp != strconv.FormatInt(fixed.Unix(), 10) {
		t.Fatalf("%s = %q", WebhookTimestampHeader, timestamp)
	}
	if got, want := headers.Get(WebhookSignatureHeader), WebhookSignature([]byte(secret), timestamp, body); got != want {
		t.Fatalf("%s = %q, want %q", WebhookSignatureHeader, got, want)
	}
	// Another timestamp gives another signature: the old one does not verify.
	if WebhookSignature([]byte(secret), strconv.FormatInt(fixed.Unix()+600, 10), body) == headers.Get(WebhookSignatureHeader) {
		t.Fatal("signature does not depend on the timestamp")
	}
	if headers.Get(LegacyWebhookSignatureHeader) == "" {
		t.Fatal("legacy body-only signature header dropped")
	}

	// No secret, no signature headers.
	headers = nil
	payload.Metadata["integration_config"] = mustJSON(t, map[string]any{"url": server.URL + "/hook"})
	if err := (&WebhookSender{}).Send(context.Background(), payload); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if headers.Get(WebhookTimestampHeader) != "" || headers.Get(WebhookSignatureHeader) != "" {
		t.Fatalf("unsigned delivery carries signature headers: %v", headers)
	}
}
