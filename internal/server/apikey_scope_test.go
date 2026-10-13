package server

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/store"
)

func TestValidateScopedExpiry(t *testing.T) {
	t.Parallel()

	future := func(d time.Duration) *time.Time {
		at := time.Now().Add(d)
		return &at
	}

	tests := []struct {
		name      string
		scoped    bool
		expiresAt *time.Time
		wantErr   string
	}{
		{name: "unscoped without expiry is fine", scoped: false, expiresAt: nil},
		{name: "unscoped with far expiry is fine", scoped: false, expiresAt: future(3 * 366 * 24 * time.Hour)},
		{name: "scoped with 90d expiry", scoped: true, expiresAt: future(90 * 24 * time.Hour)},
		{name: "scoped at the one-year bound", scoped: true, expiresAt: future(365 * 24 * time.Hour)},
		{name: "scoped without expiry", scoped: true, expiresAt: nil, wantErr: "require an expiry"},
		{name: "scoped past expiry", scoped: true, expiresAt: future(-time.Hour), wantErr: "must be in the future"},
		{name: "scoped beyond one year", scoped: true, expiresAt: future(2 * 366 * 24 * time.Hour), wantErr: "at most one year"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := validateScopedExpiry(tc.scoped, tc.expiresAt)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("error = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestNormalizeCreateScope(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	valid := `{"org":"acme","repos":{"mode":"list","slugs":["api"]},"permissions":{"coverage":"read"}}`

	tests := []struct {
		name    string
		raw     string
		wantErr string
	}{
		{name: "omitted scope is rejected", raw: "", wantErr: "scope is required"},
		{name: "json null scope is rejected", raw: "null", wantErr: "scope is required"},
		{name: "valid scope", raw: valid},
		{name: "org-wide scope", raw: `{"org":"acme","repos":{"mode":"all"},"permissions":{"uploads":"write"}}`},
		{name: "malformed json", raw: `{"org":`, wantErr: "invalid token scope"},
		{name: "unknown capability", raw: `{"org":"acme","repos":{"mode":"all"},"permissions":{"nukes":"write"}}`, wantErr: "invalid token scope"},
		{name: "unknown access level", raw: `{"org":"acme","repos":{"mode":"all"},"permissions":{"coverage":"admin"}}`, wantErr: "invalid token scope"},
		{name: "unknown repo mode", raw: `{"org":"acme","repos":{"mode":"some"},"permissions":{"coverage":"read"}}`, wantErr: "invalid token scope"},
		{name: "empty document", raw: `{}`, wantErr: "requires an organization"},
		{name: "missing org", raw: `{"repos":{"mode":"all"},"permissions":{"coverage":"read"}}`, wantErr: "requires an organization"},
		{name: "repo list with no repos", raw: `{"org":"acme","repos":{"mode":"list"},"permissions":{"coverage":"read"}}`, wantErr: "requires at least one repository"},
		{name: "no permissions", raw: `{"org":"acme","repos":{"mode":"all"},"permissions":{"coverage":"none"}}`, wantErr: "requires at least one permission"},
		{name: "provider-qualified org", raw: `{"org":"github/acme","repos":{"mode":"all"},"permissions":{"uploads":"write"}}`, wantErr: `slug (e.g. "acme")`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := normalizeCreateScope(json.RawMessage(tc.raw), userID)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("error = nil, want %q", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %q, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("error = %v", err)
			}
			if got == nil {
				t.Fatal("scope = nil, want a normalized document")
			}
			parsed, err := apitoken.Parse(got)
			if err != nil {
				t.Fatalf("normalized scope does not parse: %v", err)
			}
			if parsed.Owner.Type != apitoken.OwnerUser || parsed.Owner.ID != userID.String() {
				t.Fatalf("owner = %+v, want the creating user %s", parsed.Owner, userID)
			}
		})
	}
}

func TestNormalizeOrgScope(t *testing.T) {
	t.Parallel()

	org := &store.Organization{ID: uuid.New(), Slug: "acme"}

	tests := []struct {
		name    string
		raw     string
		wantErr string
	}{
		{name: "valid scope", raw: `{"org":"acme","repos":{"mode":"all"},"permissions":{"uploads":"write"}}`},
		{name: "org inferred from path", raw: `{"repos":{"mode":"all"},"permissions":{"coverage":"read"}}`},
		{name: "omitted scope", raw: "", wantErr: "require a scope"},
		{name: "json null scope", raw: "null", wantErr: "require a scope"},
		{name: "wrong org", raw: `{"org":"other","repos":{"mode":"all"},"permissions":{"coverage":"read"}}`, wantErr: "must target this organization"},
		{name: "no permissions", raw: `{"org":"acme","repos":{"mode":"all"},"permissions":{}}`, wantErr: "at least one permission"},
		{name: "empty repo list", raw: `{"org":"acme","repos":{"mode":"list"},"permissions":{"coverage":"read"}}`, wantErr: "at least one repository"},
		{name: "malformed", raw: `{"org":`, wantErr: "invalid token scope"},
		{name: "membership-wide selector", raw: `{"orgs":{"mode":"memberships"},"repos":{"mode":"all"},"permissions":{"coverage":"read"}}`, wantErr: "cannot use an orgs selector"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := normalizeOrgScope(json.RawMessage(tc.raw), org)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("error = %v", err)
			}
			scope, err := apitoken.Parse(got)
			if err != nil {
				t.Fatalf("normalized scope does not parse: %v", err)
			}
			if scope.Org != "acme" {
				t.Fatalf("org = %q, want acme", scope.Org)
			}
			if scope.Owner.Type != apitoken.OwnerOrg || scope.Owner.ID != org.ID.String() {
				t.Fatalf("owner = %+v, want the org", scope.Owner)
			}
		})
	}
}

func TestNormalizeOrgScopeRewritesRequestedOwner(t *testing.T) {
	t.Parallel()

	org := &store.Organization{ID: uuid.New(), Slug: "acme"}
	raw := `{"owner":{"type":"user","id":"someone-else"},"org":"acme","repos":{"mode":"all"},"permissions":{"admin":"write"}}`

	got, err := normalizeOrgScope(json.RawMessage(raw), org)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	scope, err := apitoken.Parse(got)
	if err != nil {
		t.Fatalf("normalized scope does not parse: %v", err)
	}
	if scope.Owner.Type != apitoken.OwnerOrg || scope.Owner.ID != org.ID.String() {
		t.Fatalf("owner = %+v, want the org", scope.Owner)
	}
}

func TestNormalizeCreateScopeRewritesRequestedOwner(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	raw := `{"owner":{"type":"org","id":"acme"},"org":"acme","repos":{"mode":"all"},"permissions":{"admin":"write"}}`

	got, err := normalizeCreateScope(json.RawMessage(raw), userID)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	scope, err := apitoken.Parse(got)
	if err != nil {
		t.Fatalf("normalized scope does not parse: %v", err)
	}
	if scope.Owner.Type != apitoken.OwnerUser {
		t.Fatalf("owner type = %q, want %q", scope.Owner.Type, apitoken.OwnerUser)
	}
	if scope.Owner.ID != userID.String() {
		t.Fatalf("owner id = %q, want %q", scope.Owner.ID, userID)
	}
}
