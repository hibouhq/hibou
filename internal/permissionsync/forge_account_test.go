package permissionsync

import (
	"context"
	"testing"

	"github.com/rs/zerolog"
	"golang.org/x/oauth2"

	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/store"
)

type idResolvingProvider struct {
	fakeProvider
	ids map[string]string
}

func (p idResolvingProvider) InstallationAccountIDs(context.Context) (map[string]string, error) {
	return p.ids, nil
}

// Audit §3.3: the org's admin role must only follow the forge account the org
// is bound to. A login that is now someone else's account (rename +
// re-register) or that merely slugifies to the org's slug grants nothing.
func TestSyncUserIgnoresOrgBoundToAnotherAccount(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		login    string
		boundID  string
		boundLog string
		ids      map[string]string
		want     int
	}{
		"same account id":              {login: "acme", boundID: "42", boundLog: "acme", ids: map[string]string{"acme": "42"}, want: 1},
		"re-registered login":          {login: "acme", boundID: "42", boundLog: "acme", ids: map[string]string{"acme": "99", "acme-inc": "42"}, want: 0},
		"login not installed":          {login: "acme", boundID: "42", boundLog: "acme", ids: map[string]string{"acme-inc": "42"}, want: 0},
		"slug collision on login":      {login: "acme.corp", boundLog: "acme_corp", want: 0},
		"exact login, no id":           {login: "ACME_corp", boundLog: "acme_corp", want: 1},
		"legacy org without a binding": {login: "acme-corp", want: 1},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			slug := slugifyAccount(tc.login)
			org := testOrg("github", slug)
			org.ForgeAccountID = tc.boundID
			org.ForgeAccountLogin = tc.boundLog
			storeFake := &fakeStore{orgsBySlug: map[string]*store.Organization{"github/" + slug: org}}
			var provider forge.Provider = fakeProvider{access: forge.UserAccess{Orgs: []forge.UserOrgAccess{{AccountLogin: tc.login, Level: "admin"}}}}
			if tc.ids != nil {
				provider = idResolvingProvider{fakeProvider: provider.(fakeProvider), ids: tc.ids}
			}
			svc := NewService(storeFake, &fakeRBAC{}, map[string]forge.Provider{"github": provider}, zerolog.Nop())

			if err := svc.SyncUser(context.Background(), testUser(), "github", &oauth2.Token{AccessToken: "token"}); err != nil {
				t.Fatalf("SyncUser() error = %v", err)
			}
			if got := len(storeFake.upsertOrgMembers); got != tc.want {
				t.Fatalf("org upserts = %d, want %d", got, tc.want)
			}
		})
	}
}
