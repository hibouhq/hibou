// Package devicelogin is the client side of hibou's OAuth 2.0 device
// authorization grant (RFC 8628, ADR-043). It holds no UI: the CLI and the
// IDE language server print or show the code themselves.
//
// The wire types are shared with the server so the two cannot drift.
package devicelogin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// GrantType is RFC 8628's grant type for the token request.
const GrantType = "urn:ietf:params:oauth:grant-type:device_code"

// Known client identifiers. They name the client for display and audit; they
// are not secrets.
const (
	ClientCLI      = "hibou-cli"
	ClientVSCode   = "hibou-vscode"
	ClientIntelliJ = "hibou-intellij"
)

// RFC 8628 §3.5 error codes returned by the token endpoint.
const (
	ErrCodePending       = "authorization_pending"
	ErrCodeSlowDown      = "slow_down"
	ErrCodeAccessDenied  = "access_denied"
	ErrCodeExpired       = "expired_token"
	ErrCodeInvalid       = "invalid_request"
	ErrCodeInvalidGrant  = "invalid_grant"
	ErrCodeUnsupported   = "unsupported_grant_type"
	ErrCodeInvalidClient = "invalid_client"
)

var (
	// ErrUnsupported means the server has no device endpoints (older than
	// ADR-043). Callers fall back to asking for a token.
	ErrUnsupported = errors.New("this hibou server does not support browser login")
	// ErrDenied means the user clicked Deny on the approval page.
	ErrDenied = errors.New("login request was denied in the browser")
	// ErrExpired means the code expired, or was already used, before approval.
	ErrExpired = errors.New("login code expired before it was approved")
)

// CodeRequest is the body of POST /api/v1/auth/device/code.
type CodeRequest struct {
	ClientID   string `json:"client_id"`
	ClientName string `json:"client_name,omitempty"`
	// Scope is the requested preset ("cli" or "read-only"). The user can
	// change it on the approval page.
	Scope string `json:"scope,omitempty"`
}

// Authorization is the response of POST /api/v1/auth/device/code.
type Authorization struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`

	// clientID is echoed back on every poll (RFC 8628 §3.4).
	clientID string
}

// TokenRequest is the body of POST /api/v1/auth/device/token.
type TokenRequest struct {
	GrantType  string `json:"grant_type"`
	DeviceCode string `json:"device_code"`
	ClientID   string `json:"client_id"`
}

// Token is the successful response of POST /api/v1/auth/device/token.
type Token struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	TokenID     string `json:"token_id"`
	TokenName   string `json:"token_name"`
	// Orgs is "memberships": the token works in every org the user belongs to.
	Orgs   string `json:"orgs"`
	Preset string `json:"preset"`
	User   string `json:"user"`
}

// ErrorResponse is an RFC 6749 §5.2 error body.
type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// Request is what a caller asks for.
type Request struct {
	ClientID   string
	ClientName string
	Preset     string
}

// Client talks to one hibou server.
type Client struct {
	// Server is the base URL, e.g. https://hibou.example.com (no /api/v1).
	Server     string
	HTTPClient *http.Client
	// sleep is swapped by tests.
	sleep func(context.Context, time.Duration) error
}

func (c *Client) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 15 * time.Second}
}

func (c *Client) endpoint(path string) string {
	return strings.TrimRight(c.Server, "/") + "/api/v1/auth/device/" + path
}

// RequestCode starts a device login. It returns ErrUnsupported when the
// server predates ADR-043.
func (c *Client) RequestCode(ctx context.Context, req Request) (*Authorization, error) {
	status, body, err := c.post(ctx, c.endpoint("code"), CodeRequest{
		ClientID:   req.ClientID,
		ClientName: req.ClientName,
		Scope:      req.Preset,
	})
	if err != nil {
		return nil, err
	}
	switch {
	case status == http.StatusNotFound || status == http.StatusMethodNotAllowed:
		return nil, ErrUnsupported
	case status != http.StatusOK:
		return nil, serverError(status, body)
	}
	var auth Authorization
	if err := json.Unmarshal(body, &auth); err != nil || auth.DeviceCode == "" || auth.UserCode == "" {
		return nil, ErrUnsupported
	}
	if auth.Interval <= 0 {
		auth.Interval = 5
	}
	auth.clientID = req.ClientID
	return &auth, nil
}

// Poll waits for the user to approve or deny the request, honouring the
// server's interval and slow_down. It returns when ctx is cancelled, the code
// expires (ErrExpired), the user denies (ErrDenied), or a token is issued.
func (c *Client) Poll(ctx context.Context, auth *Authorization) (*Token, error) {
	interval := time.Duration(auth.Interval) * time.Second
	deadline := time.Now().Add(time.Duration(auth.ExpiresIn) * time.Second)
	sleep := c.sleep
	if sleep == nil {
		sleep = sleepCtx
	}
	for {
		if err := sleep(ctx, interval); err != nil {
			return nil, err
		}
		status, body, err := c.post(ctx, c.endpoint("token"), TokenRequest{
			GrantType:  GrantType,
			DeviceCode: auth.DeviceCode,
			ClientID:   clientIDOrDefault(auth.clientID),
		})
		if err != nil {
			// A transient network error must not abort a login the user is
			// about to approve; the deadline still bounds the loop.
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if auth.ExpiresIn > 0 && time.Now().After(deadline) {
				return nil, ErrExpired
			}
			continue
		}
		if status == http.StatusOK {
			var tok Token
			if err := json.Unmarshal(body, &tok); err != nil || tok.AccessToken == "" {
				return nil, errors.New("unexpected token response from server")
			}
			return &tok, nil
		}
		var oauthErr ErrorResponse
		_ = json.Unmarshal(body, &oauthErr)
		switch oauthErr.Error {
		case ErrCodePending:
		case ErrCodeSlowDown:
			interval += 5 * time.Second
		case ErrCodeAccessDenied:
			return nil, ErrDenied
		case ErrCodeExpired:
			return nil, ErrExpired
		default:
			if status == http.StatusTooManyRequests {
				interval += 5 * time.Second
				continue
			}
			return nil, serverError(status, body)
		}
	}
}

func clientIDOrDefault(id string) string {
	if id == "" {
		return ClientCLI
	}
	return id
}

func (c *Client) post(ctx context.Context, url string, payload any) (int, []byte, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, body, nil
}

// serverError turns an error body (OAuth or hibou's {"error":{"message"}}
// envelope) into a readable error.
func serverError(status int, body []byte) error {
	var oauthErr ErrorResponse
	if json.Unmarshal(body, &oauthErr) == nil && oauthErr.Error != "" {
		if oauthErr.ErrorDescription != "" {
			return fmt.Errorf("%s: %s", oauthErr.Error, oauthErr.ErrorDescription)
		}
		return errors.New(oauthErr.Error)
	}
	var envelope struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &envelope) == nil && envelope.Error.Message != "" {
		return fmt.Errorf("server error (HTTP %d): %s", status, envelope.Error.Message)
	}
	return fmt.Errorf("server error (HTTP %d)", status)
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
