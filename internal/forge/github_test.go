package forge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

func TestGitHubUserInfoFallsBackToPrimaryEmail(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/user":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"login":"octocat","name":"Octo Cat","avatar_url":"https://example.com/avatar.png","email":""}`))
		case "/user/emails":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"email":"private@example.com","primary":true,"verified":true}]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := NewGitHub("client-id", "client-secret", "webhook-secret", WithAPIURL(server.URL), WithHTTPClient(server.Client()))

	info, err := provider.UserInfo(context.Background(), &oauth2.Token{AccessToken: "token"})
	if err != nil {
		t.Fatalf("UserInfo() error = %v", err)
	}
	if info == nil {
		t.Fatal("UserInfo() returned nil info")
	}
	if info.Email != "private@example.com" {
		t.Fatalf("UserInfo() email = %q, want %q", info.Email, "private@example.com")
	}
	if info.DisplayName != "Octo Cat" {
		t.Fatalf("UserInfo() display name = %q, want %q", info.DisplayName, "Octo Cat")
	}
}

func TestGitHubUserInfoExplainsOAuthAppRequirementForEmail403(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/user":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"login":"octocat","name":"Octo Cat","avatar_url":"https://example.com/avatar.png","email":""}`))
		case "/user/emails":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"Resource not accessible by integration","documentation_url":"https://docs.github.com/rest/users/emails#list-email-addresses-for-the-authenticated-user"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := NewGitHub("client-id", "client-secret", "webhook-secret", WithAPIURL(server.URL), WithHTTPClient(server.Client()))

	_, err := provider.UserInfo(context.Background(), &oauth2.Token{AccessToken: "token"})
	if err == nil {
		t.Fatal("UserInfo() error = nil, want OAuth App guidance")
	}
	message := err.Error()
	if !strings.Contains(message, "github login requires OAuth App credentials") {
		t.Fatalf("UserInfo() error = %q, want OAuth App guidance", message)
	}
	if !strings.Contains(message, "HIBOU_FORGE_N_APP_ID") {
		t.Fatalf("UserInfo() error = %q, want generic GitHub App variable guidance", message)
	}
	if strings.Contains(message, "HIBOU_FORGE_0_") {
		t.Fatalf("UserInfo() error = %q, want slot-agnostic forge variable guidance", message)
	}
}
