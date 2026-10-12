package store

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestOrganizationOwnsForgeOwner(t *testing.T) {
	t.Parallel()

	bound := &Organization{Slug: "acme", ForgeAccountLogin: "Acme"}
	legacy := &Organization{Slug: "acme-corp"}
	cases := []struct {
		name  string
		org   *Organization
		owner string
		want  bool
	}{
		{"exact login", bound, "acme", true},
		{"nested namespace", bound, "Acme/platform", true},
		{"other tenant", bound, "hibouhq", false},
		{"login prefix is not ownership", bound, "acme-evil", false},
		{"empty owner", bound, "", false},
		{"legacy slug", legacy, "acme-corp", true},
		{"legacy slugified login", legacy, "acme_corp", true},
		{"legacy other tenant", legacy, "hibouhq", false},
		{"nil org", nil, "acme", false},
	}
	for _, tc := range cases {
		if got := tc.org.OwnsForgeOwner(tc.owner); got != tc.want {
			t.Errorf("%s: OwnsForgeOwner(%q) = %v, want %v", tc.name, tc.owner, got, tc.want)
		}
	}
}

func openForgeAccountTestDB(t *testing.T) *Queries {
	t.Helper()
	databaseURL := os.Getenv("HIBOU_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = testDatabaseURL
	}
	var (
		db  *sql.DB
		err error
	)
	for range 10 {
		db, err = New(databaseURL)
		if err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		t.Skipf("database not available: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate() returned error: %v", err)
	}
	return NewQueries(db)
}

// Audit §3.1 / M4: when two orgs hold a row for the same provider_id, webhook
// routing must pick the org bound to the repository owner, never an
// arbitrary one, and must not route to an org bound to another account.
func TestGetRepositoryByProviderRoutesToOwningOrg(t *testing.T) {
	queries := openForgeAccountTestDB(t)
	ctx := context.Background()
	suffix := normalizeStoreTestName(t.Name()) + "-" + uuid.NewString()[:8]
	victimLogin := "victim-" + suffix
	providerID := victimLogin + "/api"

	attacker, err := queries.CreateOrganization(ctx, "attacker", "attacker-"+suffix, "attacker", "github")
	if err != nil {
		t.Fatalf("create attacker org: %v", err)
	}
	if err := queries.SetOrganizationForgeAccount(ctx, attacker.ID, "", "attacker-"+suffix); err != nil {
		t.Fatalf("bind attacker org: %v", err)
	}
	// The foreign row is older: LIMIT 1 without ordering used to return it.
	if _, err := queries.CreateRepository(ctx, attacker.ID, nil, "api", "api", "github", providerID, "main", "enrolled"); err != nil {
		t.Fatalf("create attacker repo: %v", err)
	}

	got, err := queries.GetRepositoryByProvider(ctx, "github", providerID)
	if err != nil {
		t.Fatalf("GetRepositoryByProvider() error = %v", err)
	}
	if got != nil {
		t.Fatalf("routed to org %s bound to another account", got.OrgID)
	}

	victim, err := queries.CreateOrganization(ctx, victimLogin, victimLogin, victimLogin, "github")
	if err != nil {
		t.Fatalf("create victim org: %v", err)
	}
	want, err := queries.CreateRepository(ctx, victim.ID, nil, "api", "api", "github", providerID, "main", "enrolled")
	if err != nil {
		t.Fatalf("create victim repo: %v", err)
	}
	got, err = queries.GetRepositoryByProvider(ctx, "github", providerID)
	if err != nil {
		t.Fatalf("GetRepositoryByProvider() error = %v", err)
	}
	if got == nil || got.ID != want.ID {
		t.Fatalf("routed to %+v, want victim repo %s", got, want.ID)
	}
}

func TestSetOrganizationForgeAccountIDIsWriteOnce(t *testing.T) {
	queries := openForgeAccountTestDB(t)
	ctx := context.Background()
	suffix := normalizeStoreTestName(t.Name()) + "-" + uuid.NewString()[:8]
	accountID := "id-" + suffix

	org, err := queries.CreateOrganization(ctx, "acme", "acme-"+suffix, "acme", "github")
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	if err := queries.SetOrganizationForgeAccount(ctx, org.ID, accountID, "acme"); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if err := queries.SetOrganizationForgeAccount(ctx, org.ID, "other-"+suffix, "evil"); err != nil {
		t.Fatalf("rebind: %v", err)
	}
	if err := queries.SetOrganizationForgeAccount(ctx, org.ID, accountID, "acme-inc"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	got, err := queries.GetOrganizationByForgeAccountID(ctx, "github", accountID)
	if err != nil || got == nil {
		t.Fatalf("GetOrganizationByForgeAccountID() = %v, %v", got, err)
	}
	if got.ID != org.ID || got.ForgeAccountLogin != "acme-inc" {
		t.Fatalf("binding = %+v, want org %s with login acme-inc", got, org.ID)
	}

	other, err := queries.CreateOrganization(ctx, "dup", "dup-"+suffix, "dup", "github")
	if err != nil {
		t.Fatalf("create second org: %v", err)
	}
	if err := queries.SetOrganizationForgeAccount(ctx, other.ID, accountID, "acme-inc"); err == nil {
		t.Fatal("expected unique violation binding a second org to the same account id")
	}
}

func TestGetForgeRepositoryForAccountIsScoped(t *testing.T) {
	queries := openForgeAccountTestDB(t)
	ctx := context.Background()
	suffix := normalizeStoreTestName(t.Name()) + "-" + uuid.NewString()[:8]
	owner := "owner-" + suffix
	repoID := "rid-" + suffix

	if _, err := queries.UpsertForgeRepository(ctx, ForgeRepository{
		Provider: "github", ProviderRepoID: &repoID, AccountLogin: owner, Owner: owner,
		Name: "api", FullName: owner + "/api",
	}); err != nil {
		t.Fatalf("UpsertForgeRepository() error = %v", err)
	}
	for _, key := range []string{repoID, owner + "/API"} {
		got, err := queries.GetForgeRepositoryForAccount(ctx, "github", owner, key)
		if err != nil || got == nil {
			t.Fatalf("own account lookup %q = %v, %v", key, got, err)
		}
		got, err = queries.GetForgeRepositoryForAccount(ctx, "github", "intruder-"+suffix, key)
		if err != nil {
			t.Fatalf("foreign lookup error: %v", err)
		}
		if got != nil {
			t.Fatalf("foreign account resolved %q", key)
		}
	}
}
