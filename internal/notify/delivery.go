package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/smtp"
	"net/textproto"
	"strings"
	"time"
)

// Client deliveries (ADR-053 §5) reuse the organisation's email integration
// and the guarded network path of notifications, but carry documents and go
// to recipients the incident chose, not to the integration's own list.

// SealTableClients binds a client's delivery secrets to its row.
const SealTableClients = "clients"

// EmailAttachment is one document attached to a delivery.
type EmailAttachment struct {
	Filename    string
	ContentType string
	Data        []byte
}

// EmailMessage is a delivery email.
type EmailMessage struct {
	To          []string
	Subject     string
	Text        string
	HTML        string
	Attachments []EmailAttachment
	// Headers are extra headers, e.g. X-Hibou-Delivery.
	Headers map[string]string
}

// SendIntegrationEmail sends msg through an email integration's SMTP settings
// (opened config) and returns the Message-ID it used.
func SendIntegrationEmail(ctx context.Context, config json.RawMessage, msg EmailMessage) (string, error) {
	var parsed map[string]any
	if err := json.Unmarshal(config, &parsed); err != nil {
		return "", fmt.Errorf("email integration config: %w", err)
	}
	host := configString(parsed, "smtp_host")
	port := configInt(parsed, "smtp_port", 0)
	from := sanitizeHeader(configString(parsed, "smtp_from"))
	username := configString(parsed, "smtp_username")
	password := configString(parsed, "smtp_password")
	if host == "" || port < 1 || port > 65535 || from == "" {
		return "", errors.New("email integration requires smtp_host, smtp_port and smtp_from")
	}
	recipients := sanitizeAddressList(msg.To)
	if len(recipients) == 0 {
		return "", errors.New("no recipient")
	}
	var auth smtp.Auth
	if username != "" {
		auth = smtp.PlainAuth("", username, password, host)
	}
	messageID, body, err := buildDeliveryMessage(from, recipients, msg)
	if err != nil {
		return "", err
	}
	if err := sendMailWithRequiredTLS(ctx, host, port, auth, from, recipients, body); err != nil {
		return "", err
	}
	return messageID, nil
}

func buildDeliveryMessage(from string, recipients []string, msg EmailMessage) (string, []byte, error) {
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		return "", nil, err
	}
	domain := "hibou.invalid"
	if at := strings.LastIndex(from, "@"); at >= 0 {
		domain = strings.Trim(from[at+1:], "> ")
	}
	messageID := "<" + hex.EncodeToString(random) + "@" + domain + ">"

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	headers := []string{
		"From: " + from,
		"To: " + strings.Join(recipients, ", "),
		"Subject: " + mime.QEncoding.Encode("utf-8", sanitizeHeader(msg.Subject)),
		"Message-ID: " + messageID,
		"Date: " + time.Now().UTC().Format(time.RFC1123Z),
		"MIME-Version: 1.0",
		"Content-Type: multipart/mixed; boundary=" + writer.Boundary(),
	}
	for key, value := range msg.Headers {
		headers = append(headers, sanitizeHeader(key)+": "+sanitizeHeader(value))
	}
	head := strings.Join(headers, "\r\n") + "\r\n\r\n"

	alternative := &bytes.Buffer{}
	altWriter := multipart.NewWriter(alternative)
	for _, part := range []struct{ contentType, body string }{{"text/plain; charset=utf-8", msg.Text}, {"text/html; charset=utf-8", msg.HTML}} {
		if part.body == "" {
			continue
		}
		w, err := altWriter.CreatePart(textproto.MIMEHeader{"Content-Type": {part.contentType}, "Content-Transfer-Encoding": {"base64"}})
		if err != nil {
			return "", nil, err
		}
		if _, err := w.Write([]byte(wrapBase64(part.body))); err != nil {
			return "", nil, err
		}
	}
	if err := altWriter.Close(); err != nil {
		return "", nil, err
	}
	altPart, err := writer.CreatePart(textproto.MIMEHeader{"Content-Type": {"multipart/alternative; boundary=" + altWriter.Boundary()}})
	if err != nil {
		return "", nil, err
	}
	if _, err := altPart.Write(alternative.Bytes()); err != nil {
		return "", nil, err
	}
	for _, attachment := range msg.Attachments {
		name := sanitizeHeader(attachment.Filename)
		part, err := writer.CreatePart(textproto.MIMEHeader{
			"Content-Type":              {firstNonEmpty(attachment.ContentType, "application/octet-stream") + "; name=\"" + name + "\""},
			"Content-Disposition":       {"attachment; filename=\"" + name + "\""},
			"Content-Transfer-Encoding": {"base64"},
		})
		if err != nil {
			return "", nil, err
		}
		if _, err := part.Write([]byte(wrapBase64String(base64.StdEncoding.EncodeToString(attachment.Data)))); err != nil {
			return "", nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return "", nil, err
	}
	return messageID, append([]byte(head), buf.Bytes()...), nil
}

func wrapBase64(text string) string {
	return wrapBase64String(base64.StdEncoding.EncodeToString([]byte(text)))
}

func wrapBase64String(encoded string) string {
	var b strings.Builder
	for len(encoded) > 76 {
		b.WriteString(encoded[:76])
		b.WriteString("\r\n")
		encoded = encoded[76:]
	}
	b.WriteString(encoded)
	b.WriteString("\r\n")
	return b.String()
}

// GuardedHTTPClient is an HTTP client whose connections cannot reach private
// or link-local addresses, for requests to destinations an organisation
// configures (client webhooks, trackers).
func GuardedHTTPClient(timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = guardedNotificationDialContext(&net.Dialer{Timeout: 10 * time.Second})
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// SignWebhookRequest adds the X-Hibou-Timestamp and signature headers.
func SignWebhookRequest(req *http.Request, secret, body []byte, now time.Time) {
	signWebhookRequest(req, secret, body, now)
}
