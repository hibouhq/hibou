package notify

import (
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"
)

// Delivery errors are scrubbed of every spelling a secret can take: SMTP
// AUTH PLAIN/LOGIN base64, URL-escaped, and short configured values.
func TestScrubSecretsCoversEncodedForms(t *testing.T) {
	const password = "p@ss/w0rd+x"
	config := map[string]any{
		"smtp_username": "bot@corp.example",
		"smtp_password": password,
		"secret":        "abc", // short values are secrets too
		"url":           "https://hooks.example/services/T0/B0/XYZTOKEN?sig=q1",
	}
	leaks := []string{
		password,
		base64.StdEncoding.EncodeToString([]byte("\x00bot@corp.example\x00" + password)),
		base64.StdEncoding.EncodeToString([]byte(password)),
		base64.RawURLEncoding.EncodeToString([]byte(password)),
		url.QueryEscape(password),
		url.PathEscape(password),
		"abc",
		url.QueryEscape("https://hooks.example/services/T0/B0/XYZTOKEN?sig=q1"),
		"hooks.example/services/T0/B0/XYZTOKEN",
	}
	for _, leak := range leaks {
		message := "535 auth failed for " + leak + " (retry)"
		got := sanitizeDeliveryError(errors.New(message), config).Error()
		if strings.Contains(got, leak) {
			t.Fatalf("scrubbed %q still contains %q: %q", message, leak, got)
		}
		if !strings.Contains(got, "[redacted]") {
			t.Fatalf("nothing redacted in %q", got)
		}
	}
	if got := scrubSecrets("all fine", map[string]any{"secret": MaskedSecret}); got != "all fine" {
		t.Fatalf("masked marker treated as a secret: %q", got)
	}
}
