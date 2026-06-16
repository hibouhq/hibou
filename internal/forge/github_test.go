package forge

import (
	"context"
	"net/http"
	"net/http/httptest"
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
