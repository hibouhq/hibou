package notify

import (
	"encoding/base64"
	"errors"
	"net/url"
	"sort"
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
	for _, form := range secretForms(config) {
		message = strings.ReplaceAll(message, form, "[redacted]")
	}
	return message
}

// secretForms lists every spelling of the config's secrets that may surface
// in an error: verbatim, URL-escaped, base64 (SMTP AUTH LOGIN sends each
// credential base64-encoded; AUTH PLAIN sends base64("\x00user\x00password")),
// and for URLs the scheme-less tail, query, path and userinfo. Longest
// first, so a longer form is replaced before a shorter one breaks it up.
func secretForms(config map[string]any) []string {
	seen := map[string]bool{}
	forms := make([]string, 0, 16)
	add := func(form string, minLen int) {
		if len(form) < minLen || seen[form] {
			return
		}
		seen[form] = true
		forms = append(forms, form)
	}
	encodings := []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding}
	addEncoded := func(raw string) {
		for _, encoding := range encodings {
			add(encoding.EncodeToString([]byte(raw)), 4)
		}
	}
	for _, secret := range secretValues(config) {
		add(secret, 1)
		add(url.QueryEscape(secret), 1)
		add(url.PathEscape(secret), 1)
		addEncoded(secret)
		// A URL may also appear without its scheme, or in parts.
		if parsed, err := url.Parse(secret); err == nil && parsed.Host != "" {
			add(strings.TrimPrefix(secret, parsed.Scheme+"://"), 4)
			add(parsed.RawQuery, 1)
			if len(parsed.Path) > 1 {
				add(parsed.Path, 2)
				add(parsed.EscapedPath(), 2)
			}
			if parsed.User != nil {
				add(parsed.User.String(), 1)
			}
		}
	}
	if password := configString(config, "smtp_password"); password != "" {
		username := configString(config, "smtp_username")
		addEncoded("\x00" + username + "\x00" + password)
		addEncoded(username + "\x00" + username + "\x00" + password)
	}
	sort.SliceStable(forms, func(i, j int) bool { return len(forms[i]) > len(forms[j]) })
	return forms
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
