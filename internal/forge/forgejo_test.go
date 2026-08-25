package forge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A Forgejo API call made without a token is answered with "token is required",
// so the server's own calls — commit statuses, PR comments — must carry one.
func TestForgejoCreateCommitStatusAuthenticates(t *testing.T) {
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	provider := NewForgejo(server.URL, "id", "secret", "hook", "forge-token")
	if err := provider.CreateCommitStatus(context.Background(), "owner", "repo", "abc123", CommitStatus{State: "success"}); err != nil {
		t.Fatalf("CreateCommitStatus: %v", err)
	}
	if want := "token forge-token"; gotAuth != want {
		t.Fatalf("Authorization = %q, want %q", gotAuth, want)
	}
}

// An unconfigured token must not send an empty credential, which Forgejo
// rejects differently from an absent one.
func TestForgejoOmitsAuthorizationWithoutToken(t *testing.T) {
	var hadAuth bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, hadAuth = r.Header["Authorization"]
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	provider := NewForgejo(server.URL, "id", "secret", "hook", "")
	if err := provider.CreateCommitStatus(context.Background(), "owner", "repo", "abc123", CommitStatus{State: "success"}); err != nil {
		t.Fatalf("CreateCommitStatus: %v", err)
	}
	if hadAuth {
		t.Fatal("Authorization header sent with no token configured")
	}
}
