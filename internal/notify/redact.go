package notify

import (
	"errors"
	"net/url"
	"strings"
)

// Delivery errors end up in logs and in audit_logs.context, both readable by
// people who must not learn an integration's credentials. *url.Error prints
// the full request URL — for Slack/Teams/Discord the path IS the credential —
// so senders pass transport errors through transportError, and the
// dispatcher scrubs every known secret value out of the final text as a
// second line of defence.

// redactedError carries a sanitized message and keeps the cause reachable
// for errors.Is (timeouts, cancellation) without printing it.
type redactedError struct {
	msg   string
	cause error
}

func (e *redactedError) Error() string { return e.msg }
func (e *redactedError) Unwrap() error { return e.cause }

// transportError rewrites a *url.Error to "<op> <scheme>://<host>: <cause>",
// dropping userinfo, path and query. Other errors pass through.
func transportError(err error) error {
	if err == nil {
		return nil
	}
	var urlErr *url.Error
	if !errors.As(err, &urlErr) {
		return err
	}
	inner := "request failed"
	if urlErr.Err != nil {
		inner = urlErr.Err.Error()
	}
	return &redactedError{
		msg:   urlErr.Op + " " + RedactURL(urlErr.URL) + ": " + inner,
		cause: urlErr.Err,
	}
}

// RedactURL keeps only scheme and host of a URL: enough to tell which
// endpoint failed, never the token in its path, query or userinfo.
func RedactURL(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" {
		return "[redacted-url]"
	}
	scheme := parsed.Scheme
	if scheme == "" {
		scheme = "https"
	}
	return scheme + "://" + parsed.Host + "/[redacted]"
}

// scrubSecrets removes every secret value of the integration config from an
// error message. Applied to whatever a sender returned before it is logged
// or audited, whatever wrapped it.
func scrubSecrets(message string, config map[string]any) string {
	for _, secret := range secretValues(config) {
		message = strings.ReplaceAll(message, secret, "[redacted]")
		// A URL may also appear escaped or without its scheme.
		if parsed, err := url.Parse(secret); err == nil && parsed.Host != "" {
			if tail := strings.TrimPrefix(secret, parsed.Scheme+"://"); len(tail) >= 4 {
				message = strings.ReplaceAll(message, tail, "[redacted]")
			}
			if parsed.RawQuery != "" {
				message = strings.ReplaceAll(message, parsed.RawQuery, "[redacted]")
			}
			if len(parsed.Path) > 1 {
				message = strings.ReplaceAll(message, parsed.Path, "/[redacted]")
			}
			if parsed.User != nil {
				message = strings.ReplaceAll(message, parsed.User.String(), "[redacted]")
			}
		}
	}
	return message
}

// sanitizeDeliveryError returns an error safe to log and audit.
func sanitizeDeliveryError(err error, config map[string]any) error {
	if err == nil {
		return nil
	}
	original := err.Error()
	message := original
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.URL != "" {
		message = strings.ReplaceAll(message, urlErr.URL, RedactURL(urlErr.URL))
	}
	message = scrubSecrets(message, config)
	if message == original {
		return err
	}
	return &redactedError{msg: message, cause: err}
}
