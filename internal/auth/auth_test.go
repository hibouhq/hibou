package auth

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/store"
)

func TestRequireCapability(t *testing.T) {
	t.Parallel()

	if err := RequireCapability(context.Background(), apitoken.CapCoverage, apitoken.AccessRead, "acme", "api"); err != nil {
		t.Fatalf("session capability = %v, want nil", err)
	}

	unscoped := WithTokenAuth(context.Background(), &TokenAuth{})
	if err := RequireCapability(unscoped, apitoken.CapTriage, apitoken.AccessWrite, "other", "repo"); err != nil {
		t.Fatalf("unscoped capability = %v, want nil", err)
	}

	scoped := WithTokenAuth(context.Background(), &TokenAuth{
		Scoped: true,
		Scope: apitoken.Scope{
			Org:   "acme",
			Repos: apitoken.RepoSelector{Mode: apitoken.RepoList, Slugs: []string{"api"}},
			Permissions: map[apitoken.Capability]apitoken.AccessLevel{
				apitoken.CapCoverage: apitoken.AccessWrite,
			},
		},
	})
	if err := RequireCapability(scoped, apitoken.CapCoverage, apitoken.AccessRead, "acme", "api"); err != nil {
		t.Fatalf("allowed capability = %v, want nil", err)
	}
	for _, target := range []struct {
		capability apitoken.Capability
		org        string
		repo       string
	}{
		{apitoken.CapCoverage, "other", "api"},
		{apitoken.CapCoverage, "acme", "web"},
		{apitoken.CapTriage, "acme", "api"},
	} {
		err := RequireCapability(scoped, target.capability, apitoken.AccessRead, target.org, target.repo)
		if !errors.Is(err, ErrTokenScopeDenied) {
			t.Errorf("RequireCapability(%q, %q, %q) = %v, want ErrTokenScopeDenied", target.org, target.repo, target.capability, err)
		}
	}
}

func TestTokenAuthForAPIKeyScoped(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		scopes any
		scoped bool
	}{
		{name: "empty", scopes: nil, scoped: false},
		{name: "empty document", scopes: apitoken.Scope{}, scoped: true},
		{name: "none", scopes: apitoken.Scope{Permissions: map[apitoken.Capability]apitoken.AccessLevel{apitoken.CapCoverage: apitoken.AccessNone}}, scoped: true},
		{name: "read", scopes: apitoken.Scope{Permissions: map[apitoken.Capability]apitoken.AccessLevel{apitoken.CapCoverage: apitoken.AccessRead}}, scoped: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var scopes json.RawMessage
			if test.scopes != nil {
				encoded, err := json.Marshal(test.scopes)
				if err != nil {
					t.Fatalf("json.Marshal: %v", err)
				}
				scopes = encoded
			}
			apiKey := &store.APIKey{ID: uuid.New(), Scopes: scopes}
			tokenAuth := TokenAuthForAPIKey(apiKey)
			if tokenAuth == nil {
				t.Fatal("token auth = nil")
			}
			if tokenAuth.KeyID != apiKey.ID || tokenAuth.Scoped != test.scoped {
				t.Fatalf("token auth = %+v, want key %s scoped %t", tokenAuth, apiKey.ID, test.scoped)
			}
		})
	}
}

func TestTokenAuthForAPIKeyMalformedScopeDeniesAll(t *testing.T) {
	t.Parallel()

	tokenAuth := TokenAuthForAPIKey(&store.APIKey{ID: uuid.New(), Scopes: json.RawMessage(`{"permissions":{"unknown":"read"}}`)})
	if tokenAuth == nil || !tokenAuth.Scoped {
		t.Fatalf("token auth = %+v, want scoped deny-all token", tokenAuth)
	}
	ctx := WithTokenAuth(context.Background(), tokenAuth)
	if !errors.Is(RequireCapability(ctx, apitoken.CapCoverage, apitoken.AccessRead, "acme", "api"), ErrTokenScopeDenied) {
		t.Fatal("malformed scope should deny every capability")
	}
}

func TestRequireOrgWideCapability(t *testing.T) {
	t.Parallel()

	ctx := WithTokenAuth(context.Background(), &TokenAuth{Scoped: true, Scope: apitoken.Scope{
		Org: "acme", Repos: apitoken.RepoSelector{Mode: apitoken.RepoList, Slugs: []string{"api"}},
		Permissions: map[apitoken.Capability]apitoken.AccessLevel{apitoken.CapComponents: apitoken.AccessRead},
	}})
	if !errors.Is(RequireOrgWideCapability(ctx, apitoken.CapComponents, apitoken.AccessRead, "acme"), ErrTokenScopeDenied) {
		t.Fatal("repo-list token should not access organization-wide data")
	}
}

func TestManagerInvokeLoginHooks(t *testing.T) {
	t.Parallel()

	manager := &Manager{}
	done := make(chan struct{}, 1)
	manager.AddLoginHook(func(context.Context, *store.User, string, *oauth2.Token) {
		panic("boom")
	})
	manager.AddLoginHook(func(context.Context, *store.User, string, *oauth2.Token) {
		done <- struct{}{}
	})

	manager.invokeLoginHooks(context.Background(), &store.User{}, "github", &oauth2.Token{AccessToken: "token"})

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for login hook execution")
	}
}
