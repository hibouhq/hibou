package notify

import (
	"context"
	"strings"
	"testing"
)

func TestSanitizeHeaderRemovesCRLF(t *testing.T) {
	value := sanitizeHeader("alerts@example.com\r\nBcc: attacker@example.com")
	if strings.ContainsAny(value, "\r\n") {
		t.Fatalf("expected CRLF to be removed, got %q", value)
	}
	if value != "alerts@example.comBcc: attacker@example.com" {
		t.Fatalf("unexpected sanitized value: %q", value)
	}
}

func TestEmailSenderRequiresTLSDialPath(t *testing.T) {
	sender := &EmailSender{}
	config := mustJSON(t, map[string]any{"smtp_host": "127.0.0.1", "smtp_port": 1, "smtp_from": "alerts@example.com\r\nBcc: attacker@example.com", "recipients": []string{"team@example.com\r\nCc: attacker@example.com"}})
	payload := Payload{
		Title:    "Scan complete\r\nX-Injected: true",
		Metadata: map[string]any{"integration_config": config},
	}

	err := sender.Send(context.Background(), payload)
	if err == nil {
		t.Fatal("expected Send to fail without a TLS-capable SMTP server")
	}
	if !strings.Contains(err.Error(), "dial smtp server") {
		t.Fatalf("expected TLS-required SMTP dial failure, got %v", err)
	}
	if got := sanitizeHeader(payload.Title); strings.ContainsAny(got, "\r\n") {
		t.Fatalf("expected subject sanitization to remove CRLF, got %q", got)
	}
}
