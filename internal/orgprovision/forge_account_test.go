package orgprovision

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/forge"
)

// verifyingForge is a forge whose App API confirms installations.
type verifyingForge struct {
	fakeForgeProvider
	accounts      map[int64]*forge.InstallationAccount
	lookups       int
	accountAdmins map[string]map[string]bool
	adminErr      error
}

func (p *verifyingForge) GetInstallationAccount(_ context.Context, id int64) (*forge.InstallationAccount, error) {
	p.lookups++
	account := p.accounts[id]
	if account == nil {
		return nil, forge.ErrInstallationNotFound
	}
	clone := *account
	return &clone, nil
}

func (p *verifyingForge) InstallationAccountIDs(context.Context) (map[string]string, error) {
	ids := map[string]string{}
	for _, account := range p.accounts {
		ids[slugifyAccount(account.AccountLogin)] = account.AccountID
	}
	return ids, nil
}

func newVerifyingService(st *fakeStore, accounts map[int64]*forge.InstallationAccount) (*Service, *verifyingForge) {
	provider := &verifyingForge{fakeForgeProvider: fakeForgeProvider{id: "github"}, accounts: accounts}
	return NewService(st, &fakeRBACSeeder{}, map[string]forge.Provider{"github": provider}, true, zerolog.New(io.Discard)), provider
}

func installed(action, account string, id int64) forge.InstallationEvent {
	return forge.InstallationEvent{
		Action:       action,
		Installation: forge.Installation{ID: id, AccountName: account},
		Sender:       forge.UserInfo{ProviderID: "installer-1"},
	}
}

func TestRecordInstallationBindsVerifiedAccountID(t *testing.T) {
	t.Parallel()

	st := newFakeStore()
	user := st.addUser("github", "installer-1")
	svc, _ := newVerifyingService(st, map[int64]*forge.InstallationAccount{
		7: {InstallationID: 7, AccountID: "42", AccountLogin: "Acme"},
	})

	if err := svc.RecordInstallation(context.Background(), "github", installed("created", "Acme", 7)); err != nil {
		t.Fatalf("record installation: %v", err)
	}
	org := st.organizations[orgKey("github", "acme")]
	if org == nil || org.ForgeAccountID != "42" || org.ForgeAccountLogin != "Acme" {
		t.Fatalf("org not bound to verified account: %+v", org)
	}
	if role := st.membershipRole(org.ID, user.ID); role != "admin" {
		t.Fatalf("role = %q, want admin", role)
	}
}

// A forged or replayed event (installation unknown to the App API, or naming a
// different account than the installation really has) must grant nothing.
func TestRecordInstallationRejectsUnverifiedInstallation(t *testing.T) {
	t.Parallel()

	cases := map[string]forge.InstallationEvent{
		"unknown installation": installed("created", "hibouhq", 99),
		"account mismatch":     installed("created", "hibouhq", 7),
		"suspended":            installed("unsuspend", "Suspended", 8),
	}
	for name, ev := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			st := newFakeStore()
			st.addUser("github", "installer-1")
			svc, _ := newVerifyingService(st, map[int64]*forge.InstallationAccount{
				7: {InstallationID: 7, AccountID: "42", AccountLogin: "attacker"},
				8: {InstallationID: 8, AccountID: "43", AccountLogin: "Suspended", Suspended: true},
			})
			if err := svc.RecordInstallation(context.Background(), "github", ev); err != nil {
				t.Fatalf("record installation: %v", err)
			}
			if len(st.forgeOrgAdmins) != 0 || len(st.organizations) != 0 {
				t.Fatalf("unverified event recorded state: admins=%d orgs=%d", len(st.forgeOrgAdmins), len(st.organizations))
			}
		})
	}
}

// Audit §3.3 attack 1: the victim renames acme→acme-inc and an attacker
// registers "acme". The attacker's account id differs, so the existing org is
// not theirs; the victim's renamed account still reaches its org by id.
func TestRecordInstallationMatchesOrgByAccountIDNotLogin(t *testing.T) {
	t.Parallel()

	st := newFakeStore()
	st.addUser("github", "installer-1")
	org := st.addOrganization("github", "acme")
	org.ForgeAccountID = "42"
	org.ForgeAccountLogin = "acme"
	svc, _ := newVerifyingService(st, map[int64]*forge.InstallationAccount{
		7: {InstallationID: 7, AccountID: "99", AccountLogin: "acme"},
		8: {InstallationID: 8, AccountID: "42", AccountLogin: "acme-inc"},
	})

	if err := svc.RecordInstallation(context.Background(), "github", installed("created", "acme", 7)); err != nil {
		t.Fatalf("record attacker installation: %v", err)
	}
	if admin := st.forgeOrgAdmins[forgeOrgAdminKey("github", "acme", "installer-1")]; admin == nil || admin.OrgID != nil {
		t.Fatalf("attacker must not be bound to the victim org: %+v", admin)
	}
	if len(st.memberships) != 0 {
		t.Fatal("attacker must not gain membership")
	}

	if err := svc.RecordInstallation(context.Background(), "github", installed("created", "acme-inc", 8)); err != nil {
		t.Fatalf("record renamed installation: %v", err)
	}
	if st.organizations[orgKey("github", "acme-inc")] != nil {
		t.Fatal("renamed account must reuse its org, not create a new one")
	}
	if org.ForgeAccountLogin != "acme-inc" {
		t.Fatalf("login not refreshed after rename: %q", org.ForgeAccountLogin)
	}
}

// Audit §3.3 attack 2 (GitLab): distinct logins slugify alike. An org bound to
// one exact login is never adopted by another.
func TestRecordInstallationRejectsSlugCollision(t *testing.T) {
	t.Parallel()

	st := newFakeStore()
	st.addUser("gitlab", "installer-1")
	org := st.addOrganization("gitlab", "acme-corp")
	org.ForgeAccountLogin = "acme_corp"
	svc := NewService(st, &fakeRBACSeeder{}, nil, true, zerolog.New(io.Discard))

	if err := svc.RecordInstallation(context.Background(), "gitlab", forge.InstallationEvent{
		Action:       "created",
		Installation: forge.Installation{AccountName: "acme.corp"},
		Sender:       forge.UserInfo{ProviderID: "installer-1"},
	}); err != nil {
		t.Fatalf("record installation: %v", err)
	}
	if len(st.memberships) != 0 {
		t.Fatal("colliding login must not gain membership")
	}
	if org.ForgeAccountLogin != "acme_corp" {
		t.Fatalf("bound login overwritten: %q", org.ForgeAccountLogin)
	}
}

// Audit A11: uninstalling the App revokes the account's admin bindings, unless
// the App API says the installation is still live (stale or forged event).
func TestRecordInstallationDeletedRevokesBindings(t *testing.T) {
	t.Parallel()

	st := newFakeStore()
	st.addForgeOrgAdmin("github", "acme", "installer-1")
	st.addForgeOrgAdmin("github", "other", "installer-2")
	svc, provider := newVerifyingService(st, map[int64]*forge.InstallationAccount{
		8: {InstallationID: 8, AccountID: "42", AccountLogin: "acme"},
	})

	if err := svc.RecordInstallation(context.Background(), "github", installed("deleted", "acme", 8)); err != nil {
		t.Fatalf("record live deleted: %v", err)
	}
	if len(st.forgeOrgAdmins) != 2 {
		t.Fatal("a live installation's bindings must survive a deleted event")
	}

	delete(provider.accounts, 8)
	if err := svc.RecordInstallation(context.Background(), "github", installed("deleted", "acme", 8)); err != nil {
		t.Fatalf("record deleted: %v", err)
	}
	if st.forgeOrgAdmins[forgeOrgAdminKey("github", "acme", "installer-1")] != nil {
		t.Fatal("uninstalled account binding must be revoked")
	}
	if st.forgeOrgAdmins[forgeOrgAdminKey("github", "other", "installer-2")] == nil {
		t.Fatal("other accounts' bindings must be kept")
	}
}

// accountAdmins answers IsAccountAdmin: account id -> admin forge user ids.
func (p *verifyingForge) IsAccountAdmin(_ context.Context, accountID, userID string) (bool, error) {
	if p.adminErr != nil {
		return false, p.adminErr
	}
	return p.accountAdmins[accountID][userID], nil
}

// A legacy org is bound to the id its login now maps to only when one of its
// recorded admins administers that account (by immutable user id); a login
// re-registered by someone else, or an unanswerable check, leaves it unbound.
func TestBackfillForgeAccountIDs(t *testing.T) {
	t.Parallel()

	st := newFakeStore()
	legacy := st.addOrganization("github", "acme")
	legacy.ForgeAccountLogin = "Acme"
	owner := st.addUser("github", "owner-1")
	st.memberships[membershipKey(legacy.ID, owner.ID)] = "admin"
	hijacked := st.addOrganization("github", "renamed")
	hijacked.ForgeAccountLogin = "renamed"
	victim := st.addUser("github", "owner-2")
	st.memberships[membershipKey(hijacked.ID, victim.ID)] = "admin"
	manual := st.addOrganization("github", "manual")
	svc, provider := newVerifyingService(st, map[int64]*forge.InstallationAccount{
		7: {InstallationID: 7, AccountID: "42", AccountLogin: "acme"},
		8: {InstallationID: 8, AccountID: "43", AccountLogin: "manual"},
		9: {InstallationID: 9, AccountID: "44", AccountLogin: "renamed"},
	})
	// Account 44 now carries the "renamed" login, but the org's admin does
	// not administer it: someone else registered the login.
	provider.accountAdmins = map[string]map[string]bool{"42": {"owner-1": true}, "44": {"stranger": true}}

	if err := svc.BackfillForgeAccountIDs(context.Background()); err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if legacy.ForgeAccountID != "42" {
		t.Fatalf("legacy org id = %q, want 42", legacy.ForgeAccountID)
	}
	if hijacked.ForgeAccountID != "" {
		t.Fatalf("org bound to a re-registered login's account %q", hijacked.ForgeAccountID)
	}
	if manual.ForgeAccountID != "" {
		t.Fatal("orgs without a recorded login must not be bound by slug")
	}

	// A failing check is not corroboration.
	st2 := newFakeStore()
	org := st2.addOrganization("github", "acme")
	org.ForgeAccountLogin = "acme"
	admin := st2.addUser("github", "owner-1")
	st2.memberships[membershipKey(org.ID, admin.ID)] = "admin"
	svc2, provider2 := newVerifyingService(st2, map[int64]*forge.InstallationAccount{7: {InstallationID: 7, AccountID: "42", AccountLogin: "acme"}})
	provider2.accountAdmins = map[string]map[string]bool{"42": {"owner-1": true}}
	provider2.adminErr = errors.New("github down")
	if err := svc2.BackfillForgeAccountIDs(context.Background()); err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if org.ForgeAccountID != "" {
		t.Fatal("bound a legacy org although the corroborating check failed")
	}
}

// S3: a legacy org (login recorded, no account id) whose login now resolves
// to an account id we have never seen may only be adopted by the installer
// already recorded for it — not by whoever registered the renamed login.
func TestRecordInstallationLegacyOrgNeedsItsRecordedInstaller(t *testing.T) {
	t.Parallel()

	st := newFakeStore()
	st.addUser("github", "installer-1")
	org := st.addOrganization("github", "acme")
	org.ForgeAccountLogin = "acme"
	owner := st.addForgeOrgAdmin("github", "acme", "owner-1")
	owner.OrgID = &org.ID
	svc, _ := newVerifyingService(st, map[int64]*forge.InstallationAccount{
		7: {InstallationID: 7, AccountID: "99", AccountLogin: "acme"},
	})

	if err := svc.RecordInstallation(context.Background(), "github", installed("created", "acme", 7)); err != nil {
		t.Fatalf("record installation: %v", err)
	}
	if org.ForgeAccountID != "" {
		t.Fatalf("legacy org adopted by an unrecorded installer: bound to %q", org.ForgeAccountID)
	}
	if len(st.memberships) != 0 {
		t.Fatal("unrecorded installer gained membership")
	}

	ev := installed("created", "acme", 7)
	ev.Sender.ProviderID = "owner-1"
	st.addUser("github", "owner-1")
	if err := svc.RecordInstallation(context.Background(), "github", ev); err != nil {
		t.Fatalf("record owner installation: %v", err)
	}
	if org.ForgeAccountID != "99" {
		t.Fatalf("recorded installer could not adopt the legacy org: id %q", org.ForgeAccountID)
	}
}

// S3: POST /orgs binds the new org to the installed account it was
// authorized against, id included.
func TestAuthorizeForgeOrgCreationAccountReturnsBinding(t *testing.T) {
	t.Parallel()

	st := newFakeStore()
	requester := st.addUser("github", "installer-1")
	st.addForgeOrgAdmin("github", "Acme", "installer-1")
	svc, provider := newVerifyingService(st, map[int64]*forge.InstallationAccount{
		7: {InstallationID: 7, AccountID: "42", AccountLogin: "Acme"},
	})
	provider.installations = []forge.Installation{{ID: 7, AccountName: "Acme"}}

	account, err := svc.AuthorizeForgeOrgCreationAccount(context.Background(), requester, "github", "acme")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if account.Login != "Acme" || account.ID != "42" {
		t.Fatalf("binding = %+v, want Acme/42", account)
	}
}

// The GitHub forge corroborates legacy bindings in production.
var _ AccountAdminVerifier = (*forge.GitHub)(nil)
