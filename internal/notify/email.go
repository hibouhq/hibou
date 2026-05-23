package notify

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
)

type EmailSender struct {
	host string
	port int
	from string
	auth smtp.Auth
}

func (s *EmailSender) Type() string { return "email" }

func (s *EmailSender) Send(ctx context.Context, p Payload) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	config := integrationConfig(p)
	host := firstNonEmpty(configString(config, "smtp_host"), s.host)
	port := configInt(config, "smtp_port", s.port)
	from := firstNonEmpty(configString(config, "smtp_from"), s.from)
	username := configString(config, "smtp_username")
	password := configString(config, "smtp_password")
	recipients := configStringSlice(config, "recipients")

	if host == "" || port == 0 || from == "" || len(recipients) == 0 {
		return fmt.Errorf("email integration requires smtp_host, smtp_port, smtp_from, and recipients")
	}
	auth := s.auth
	if auth == nil && username != "" {
		auth = smtp.PlainAuth("", username, password, host)
	}
	from = sanitizeHeader(from)
	recipients = sanitizeAddressList(recipients)
	subject := sanitizeHeader(p.Title)
	if from == "" || len(recipients) == 0 {
		return fmt.Errorf("email integration requires valid smtp_from and recipients")
	}

	message := strings.Join([]string{
		"From: " + from,
		"To: " + strings.Join(recipients, ", "),
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		"",
		renderNotificationText(p),
	}, "\r\n")

	return sendMailWithRequiredTLS(host, port, auth, from, recipients, []byte(message))
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func sanitizeHeader(value string) string {
	value = strings.ReplaceAll(value, "\r", "")
	value = strings.ReplaceAll(value, "\n", "")
	return strings.TrimSpace(value)
}

func sanitizeAddressList(values []string) []string {
	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		if sanitized := sanitizeHeader(value); sanitized != "" {
			cleaned = append(cleaned, sanitized)
		}
	}
	return cleaned
}

func sendMailWithRequiredTLS(host string, port int, auth smtp.Auth, from string, recipients []string, message []byte) error {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}

	if port == 465 {
		conn, err := tls.Dial("tcp", addr, tlsConfig)
		if err != nil {
			return fmt.Errorf("dial smtps server: %w", err)
		}
		defer conn.Close()

		client, err := smtp.NewClient(conn, host)
		if err != nil {
			return fmt.Errorf("create smtps client: %w", err)
		}
		defer client.Close()

		return sendSMTPMessage(client, auth, from, recipients, message)
	}

	client, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("dial smtp server: %w", err)
	}
	defer client.Close()

	if ok, _ := client.Extension("STARTTLS"); !ok {
		return fmt.Errorf("smtp server does not support STARTTLS")
	}
	if err := client.StartTLS(tlsConfig); err != nil {
		return fmt.Errorf("STARTTLS required but failed: %w", err)
	}

	return sendSMTPMessage(client, auth, from, recipients, message)
}

func sendSMTPMessage(client *smtp.Client, auth smtp.Auth, from string, recipients []string, message []byte) error {
	if auth != nil {
		if ok, _ := client.Extension("AUTH"); !ok {
			return fmt.Errorf("smtp server does not support authentication")
		}
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("authenticate smtp session: %w", err)
		}
	}
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("set smtp sender: %w", err)
	}
	for _, recipient := range recipients {
		if err := client.Rcpt(recipient); err != nil {
			return fmt.Errorf("set smtp recipient %q: %w", recipient, err)
		}
	}
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("open smtp data writer: %w", err)
	}
	if _, err := writer.Write(message); err != nil {
		writer.Close()
		return fmt.Errorf("write smtp message: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("close smtp data writer: %w", err)
	}
	if err := client.Quit(); err != nil {
		return fmt.Errorf("close smtp session: %w", err)
	}
	return nil
}
