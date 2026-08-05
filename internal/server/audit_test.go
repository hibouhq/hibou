package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/store"
)

func TestRequestAuditActorSession(t *testing.T) {
	t.Parallel()

	user := &store.User{ID: uuid.New(), DisplayName: "Ada Lovelace", Email: "ada@example.com"}
	actor := requestAuditActor(httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil), user)

	if actor.Type != audit.ActorUser {
		t.Fatalf("actor type = %q, want %q", actor.Type, audit.ActorUser)
	}
	if !actor.ID.Valid || actor.ID.UUID != user.ID {
		t.Fatalf("actor id = %+v, want %s", actor.ID, user.ID)
	}
	if actor.Display != "Ada Lovelace" {
		t.Fatalf("actor display = %q, want %q", actor.Display, "Ada Lovelace")
	}
	if len(actor.Extra) != 0 {
		t.Fatalf("session actor carried token context: %+v", actor.Extra)
	}
}

func TestRequestAuditActorToken(t *testing.T) {
	t.Parallel()

	user := &store.User{ID: uuid.New(), DisplayName: "Ada Lovelace"}
	keyID := uuid.New()
	ownerID := uuid.New()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/upload", nil)
	req = req.WithContext(auth.WithTokenAuth(req.Context(), &auth.TokenAuth{
		KeyID:     keyID,
		Name:      "prod-ci-uploader",
		OwnerType: "org",
		OwnerID:   ownerID,
		Scoped:    true,
	}))
	actor := requestAuditActor(req, user)

	if actor.Type != audit.ActorAPIKey {
		t.Fatalf("actor type = %q, want %q", actor.Type, audit.ActorAPIKey)
	}
	// The token is the actor, not the owner's user account.
	if !actor.ID.Valid || actor.ID.UUID != keyID {
		t.Fatalf("actor id = %+v, want the token %s", actor.ID, keyID)
	}
	if actor.Display != "token: prod-ci-uploader" {
		t.Fatalf("actor display = %q", actor.Display)
	}
	for key, want := range map[string]any{
		"token_id":         keyID.String(),
		"token_name":       "prod-ci-uploader",
		"token_owner_type": "org",
		"token_owner_id":   ownerID.String(),
		"acting_user_id":   user.ID.String(),
	} {
		if actor.Extra[key] != want {
			t.Fatalf("context[%q] = %v, want %v", key, actor.Extra[key], want)
		}
	}
}

func TestRequestAuditActorUnnamedToken(t *testing.T) {
	t.Parallel()

	keyID := uuid.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/upload", nil)
	req = req.WithContext(auth.WithTokenAuth(req.Context(), &auth.TokenAuth{KeyID: keyID}))

	actor := requestAuditActor(req, nil)
	if actor.Display != "token: "+keyID.String() {
		t.Fatalf("actor display = %q, want the key id as fallback", actor.Display)
	}
}

func TestAuditContextJSONMergesActorContext(t *testing.T) {
	t.Parallel()

	body := auditContextJSON(map[string]any{"pr_number": 7}, map[string]any{"token_name": "release-bot"})

	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if decoded["pr_number"] != float64(7) || decoded["token_name"] != "release-bot" {
		t.Fatalf("merged context = %v", decoded)
	}
}

func TestScopeAuditSummary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		key  *store.APIKey
		want string
	}{
		{"legacy unscoped", &store.APIKey{}, "unscoped"},
		{"json null", &store.APIKey{Scopes: json.RawMessage(`null`)}, "unscoped"},
		{"malformed", &store.APIKey{Scopes: json.RawMessage(`{"repos":{"mode":"nope"}}`)}, "malformed"},
		{
			"repo list",
			&store.APIKey{Scopes: json.RawMessage(`{"org":"acme","repos":{"mode":"list","slugs":["api","web"]},"permissions":{"coverage":"read","uploads":"write","triage":"none"}}`)},
			"org=acme repos=2 repo(s) coverage:read,uploads:write",
		},
		{
			"org wide",
			&store.APIKey{Scopes: json.RawMessage(`{"org":"acme","repos":{"mode":"all"},"permissions":{"vulnerabilities":"read"}}`)},
			"org=acme repos=all vulnerabilities:read",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := scopeAuditSummary(tc.key); got != tc.want {
				t.Fatalf("summary = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestScopeAuditSummaryOmitsUngrantedCapabilities(t *testing.T) {
	t.Parallel()

	key := &store.APIKey{Scopes: json.RawMessage(`{"org":"acme","repos":{"mode":"all"},"permissions":{"admin":"none","coverage":"read"}}`)}
	summary := scopeAuditSummary(key)

	if summary != "org=acme repos=all coverage:read" {
		t.Fatalf("summary = %q, want the none-level capability omitted", summary)
	}
	if _, err := apitoken.Parse(key.Scopes); err != nil {
		t.Fatalf("fixture scope does not parse: %v", err)
	}
}
