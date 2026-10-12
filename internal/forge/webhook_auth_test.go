package forge

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

func signedGitHubRequest(t *testing.T, secret string, body []byte) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/github", bytes.NewReader(body))
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	req.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	return req
}

// §3.4: a forge without a webhook secret must refuse every payload instead of
// returning it unverified.
func TestValidateWebhookPayloadFailsClosedWithoutSecret(t *testing.T) {
	t.Parallel()

	providers := map[string]Provider{
		"github":  NewGitHub("id", "secret", ""),
		"gitlab":  NewGitLab("https://gitlab.example.com", "id", "secret", ""),
		"forgejo": NewForgejo("https://forgejo.example.com", "id", "secret", "", ""),
	}
	for name, provider := range providers {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/"+name, strings.NewReader(`{"ref":"refs/heads/main"}`))
		payload, err := provider.ValidateWebhookPayload(req, "")
		if !errors.Is(err, ErrWebhookSecretNotConfigured) {
			t.Errorf("%s: err = %v, want ErrWebhookSecretNotConfigured", name, err)
		}
		if payload != nil {
			t.Errorf("%s: unverified payload returned", name)
		}
	}
}

func TestValidateWebhookPayloadVerifiesSignature(t *testing.T) {
	t.Parallel()

	github := NewGitHub("id", "secret", "hook-secret")
	body := []byte(`{"zen":"ok"}`)
	payload, err := github.ValidateWebhookPayload(signedGitHubRequest(t, "hook-secret", body), "")
	if err != nil || !bytes.Equal(payload, body) {
		t.Fatalf("valid signature: payload=%q err=%v", payload, err)
	}
	if _, err := github.ValidateWebhookPayload(signedGitHubRequest(t, "wrong", body), ""); err == nil {
		t.Fatal("wrong signature must be rejected")
	}
}

// §3.4: the body read before authentication is bounded.
func TestValidateWebhookPayloadBoundsBody(t *testing.T) {
	t.Parallel()

	body := bytes.Repeat([]byte("a"), MaxWebhookPayloadBytes+1)
	_, err := NewGitHub("id", "secret", "hook-secret").ValidateWebhookPayload(signedGitHubRequest(t, "hook-secret", body), "")
	var tooLarge *http.MaxBytesError
	if !errors.As(err, &tooLarge) {
		t.Fatalf("oversized body: err = %v, want *http.MaxBytesError", err)
	}
}

// §3.8: the login token never asks for "repo"; read:org only when an org
// allowlist needs it and no App installation token can answer instead.
func TestGitHubOAuthScopes(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		opts []GitHubOption
		want []string
	}{
		{"default", nil, []string{"read:user", "user:email"}},
		{"oauth app with org allowlist", []GitHubOption{WithOrgMembershipScope()}, []string{"read:user", "user:email", "read:org"}},
		{"app mode with org allowlist", []GitHubOption{WithOrgMembershipScope(), WithAppCredentials(1, []byte("pem"))}, []string{"read:user", "user:email"}},
	}
	for _, tc := range cases {
		got := NewGitHub("id", "secret", "hook", tc.opts...).OAuth2Config("https://hibou.example.com/cb").Scopes
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: scopes = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestGitHubIsOrgMemberWithUserToken(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer user-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/user":
			_, _ = w.Write([]byte(`{"id":7,"login":"octocat"}`))
		case "/user/memberships/orgs/hibouhq":
			_, _ = w.Write([]byte(`{"state":"active","role":"member"}`))
		case "/user/memberships/orgs/invited":
			_, _ = w.Write([]byte(`{"state":"pending","role":"member"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	github := NewGitHub("id", "secret", "hook", WithAPIURL(server.URL), WithHTTPClient(server.Client()))
	token := &oauth2.Token{AccessToken: "user-token"}
	ctx := context.Background()

	login, err := github.AccountLogin(ctx, token)
	if err != nil || login != "octocat" {
		t.Fatalf("AccountLogin = %q, %v", login, err)
	}
	for org, want := range map[string]bool{"hibouhq": true, "invited": false, "elsewhere": false} {
		got, err := github.IsOrgMember(ctx, token, "octocat", org)
		if err != nil || got != want {
			t.Errorf("IsOrgMember(%q) = %v, %v; want %v", org, got, err, want)
		}
	}
}
