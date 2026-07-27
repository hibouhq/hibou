package orgprovision

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"golang.org/x/oauth2"

	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/store"
)

func TestRecordInstallationAutoProvisionOffRecordsInstallerOnly(t *testing.T) {
	t.Parallel()

	st := newFakeStore()
	svc := NewService(st, noopRBACSeeder{}, nil, false, zerolog.New(io.Discard))

	err := svc.RecordInstallation(context.Background(), "github", forge.InstallationEvent{
		Action:       "created",
		Installation: forge.Installation{AccountName: "Acme"},
		Sender:       forge.UserInfo{ProviderID: "installer-1"},
	})
	if err != nil {
		t.Fatalf("record installation: %v", err)
	}
	if len(st.forgeOrgAdmins) != 1 {
		t.Fatalf("expected 1 forge org admin row, got %d", len(st.forgeOrgAdmins))
	}
	admin := st.forgeOrgAdmins[forgeOrgAdminKey("github", "acme", "installer-1")]
	if admin == nil {
		t.Fatal("expected installer row to be recorded")
	}
	if admin.OrgID != nil {
		t.Fatal("expected no org binding when auto-provision is disabled")
	}
	if len(st.organizations) != 0 {
		t.Fatal("expected no organizations to be created")
	}
}

func TestRecordInstallationAutoProvisionOnExistingUserGrantsAdmin(t *testing.T) {
	t.Parallel()

	st := newFakeStore()
	user := st.addUser("github", "installer-1")
	rbac := &fakeRBACSeeder{}
	svc := NewService(st, rbac, nil, true, zerolog.New(io.Discard))

	err := svc.RecordInstallation(context.Background(), "github", forge.InstallationEvent{
		Action:       "created",
		Installation: forge.Installation{AccountName: "Acme"},
		Sender:       forge.UserInfo{ProviderID: "installer-1"},
	})
	if err != nil {
		t.Fatalf("record installation: %v", err)
	}
	org := st.organizations[orgKey("github", "acme")]
	if org == nil {
		t.Fatal("expected organization to be created")
	}
	admin := st.forgeOrgAdmins[forgeOrgAdminKey("github", "acme", "installer-1")]
	if admin == nil || admin.OrgID == nil || *admin.OrgID != org.ID {
		t.Fatal("expected installer row to bind created org")
	}
	if !admin.Granted {
		t.Fatal("expected installer row to be granted immediately")
	}
	if role := st.membershipRole(org.ID, user.ID); role != "admin" {
		t.Fatalf("expected admin membership, got %q", role)
	}
	if len(rbac.seeded) != 1 || rbac.seeded[0] != org.ID {
		t.Fatal("expected org policies to be seeded")
	}
	if len(rbac.assignments) != 1 {
		t.Fatal("expected RBAC admin assignment")
	}
	if len(st.clients) != 1 {
		t.Fatal("expected default client to be created")
	}
}

func TestRecordInstallationProvisionsFromReplayableActions(t *testing.T) {
	t.Parallel()

	// A rebuilt database can only be recovered from an action GitHub will send
	// again; "created" expires from the delivery list.
	for _, action := range []string{"created", "unsuspend", "new_permissions_accepted"} {
		t.Run(action, func(t *testing.T) {
			t.Parallel()

			st := newFakeStore()
			user := st.addUser("github", "installer-1")
			svc := NewService(st, &fakeRBACSeeder{}, nil, true, zerolog.New(io.Discard))

			if err := svc.RecordInstallation(context.Background(), "github", forge.InstallationEvent{
				Action:       action,
				Installation: forge.Installation{AccountName: "Acme"},
				Sender:       forge.UserInfo{ProviderID: "installer-1"},
			}); err != nil {
				t.Fatalf("record installation: %v", err)
			}
			org := st.organizations[orgKey("github", "acme")]
			if org == nil {
				t.Fatalf("action %q did not provision the org", action)
			}
			if role := st.membershipRole(org.ID, user.ID); role != "admin" {
				t.Fatalf("action %q gave role %q, want admin", action, role)
			}
		})
	}
}

func TestRecordInstallationIgnoresAccessRevokingActions(t *testing.T) {
	t.Parallel()

	for _, action := range []string{"suspend", "deleted"} {
		t.Run(action, func(t *testing.T) {
			t.Parallel()

			st := newFakeStore()
			st.addUser("github", "installer-1")
			svc := NewService(st, &fakeRBACSeeder{}, nil, true, zerolog.New(io.Discard))

			if err := svc.RecordInstallation(context.Background(), "github", forge.InstallationEvent{
				Action:       action,
				Installation: forge.Installation{AccountName: "Acme"},
				Sender:       forge.UserInfo{ProviderID: "installer-1"},
			}); err != nil {
				t.Fatalf("record installation: %v", err)
			}
			if st.organizations[orgKey("github", "acme")] != nil {
				t.Fatalf("action %q must not provision an org", action)
			}
		})
	}
}

func TestRecordInstallationRepositoriesProvisions(t *testing.T) {
	t.Parallel()

	for action, wantOrg := range map[string]bool{"added": true, "removed": true, "": false} {
		t.Run("action="+action, func(t *testing.T) {
			t.Parallel()

			st := newFakeStore()
			user := st.addUser("github", "installer-1")
			svc := NewService(st, &fakeRBACSeeder{}, nil, true, zerolog.New(io.Discard))

			if err := svc.RecordInstallationRepositories(context.Background(), "github", forge.InstallationRepositoriesEvent{
				Action:       action,
				Installation: forge.Installation{AccountName: "Acme"},
				Sender:       forge.UserInfo{ProviderID: "installer-1"},
			}); err != nil {
				t.Fatalf("record installation repositories: %v", err)
			}
			org := st.organizations[orgKey("github", "acme")]
			if wantOrg {
				if org == nil {
					t.Fatalf("action %q did not provision the org", action)
				}
				if role := st.membershipRole(org.ID, user.ID); role != "admin" {
					t.Fatalf("action %q gave role %q, want admin", action, role)
				}
				return
			}
			if org != nil {
				t.Fatalf("action %q must not provision an org", action)
			}
		})
	}
}

func TestRecordInstallationAutoProvisionOnWithoutUserLeavesPending(t *testing.T) {
	t.Parallel()

	st := newFakeStore()
	svc := NewService(st, noopRBACSeeder{}, nil, true, zerolog.New(io.Discard))

	err := svc.RecordInstallation(context.Background(), "github", forge.InstallationEvent{
		Action:       "created",
		Installation: forge.Installation{AccountName: "Acme"},
		Sender:       forge.UserInfo{ProviderID: "installer-1"},
	})
	if err != nil {
		t.Fatalf("record installation: %v", err)
	}
	admin := st.forgeOrgAdmins[forgeOrgAdminKey("github", "acme", "installer-1")]
	if admin == nil {
		t.Fatal("expected installer row to exist")
	}
	if admin.OrgID == nil {
		t.Fatal("expected pending installer row to reference org")
	}
	if admin.Granted {
		t.Fatal("expected pending installer row to remain ungranted")
	}
}

func TestRecordInstallationSkipsForeignPreexistingOrg(t *testing.T) {
	t.Parallel()

	st := newFakeStore()
	user := st.addUser("github", "installer-1")
	org := st.addOrganization("github", "acme")
	rbac := &fakeRBACSeeder{}
	svc := NewService(st, rbac, nil, true, zerolog.New(io.Discard))

	err := svc.RecordInstallation(context.Background(), "github", forge.InstallationEvent{
		Action:       "created",
		Installation: forge.Installation{AccountName: "Acme"},
		Sender:       forge.UserInfo{ProviderID: "installer-1"},
	})
	if err != nil {
		t.Fatalf("record installation: %v", err)
	}
	admin := st.forgeOrgAdmins[forgeOrgAdminKey("github", "acme", "installer-1")]
	if admin == nil {
		t.Fatal("expected installer row to be recorded")
	}
	if admin.OrgID != nil {
		t.Fatal("expected foreign preexisting org to remain unbound")
	}
	if admin.Granted {
		t.Fatal("expected foreign preexisting org to remain ungranted")
	}
	if role := st.membershipRole(org.ID, user.ID); role != "" {
		t.Fatalf("expected no membership grant, got %q", role)
	}
	if got := st.upsertMembershipCalls[membershipKey(org.ID, user.ID)]; got != 0 {
		t.Fatalf("expected no membership upsert, got %d", got)
	}
	if got := st.bindingChecks[org.ID.String()]; got != 1 {
		t.Fatalf("expected one binding check, got %d", got)
	}
	if len(st.clients) != 0 {
		t.Fatal("expected no default client to be created")
	}
	if len(rbac.seeded) != 0 || len(rbac.assignments) != 0 {
		t.Fatal("expected no RBAC side effects")
	}
}

func TestRecordInstallationAdoptsProvisionOwnedPreexistingOrg(t *testing.T) {
	t.Parallel()

	st := newFakeStore()
	user := st.addUser("github", "installer-1")
	org := st.addOrganization("github", "acme")
	owner := st.addForgeOrgAdmin("github", "acme", "owner-1")
	owner.OrgID = &org.ID
	rbac := &fakeRBACSeeder{}
	svc := NewService(st, rbac, nil, true, zerolog.New(io.Discard))

	err := svc.RecordInstallation(context.Background(), "github", forge.InstallationEvent{
		Action:       "created",
		Installation: forge.Installation{AccountName: "Acme"},
		Sender:       forge.UserInfo{ProviderID: "installer-1"},
	})
	if err != nil {
		t.Fatalf("record installation: %v", err)
	}
	admin := st.forgeOrgAdmins[forgeOrgAdminKey("github", "acme", "installer-1")]
	if admin == nil || admin.OrgID == nil || *admin.OrgID != org.ID {
		t.Fatal("expected installer row to bind provisioning-owned org")
	}
	if !admin.Granted {
		t.Fatal("expected provisioning-owned org to grant admin")
	}
	if role := st.membershipRole(org.ID, user.ID); role != "admin" {
		t.Fatalf("expected admin role, got %q", role)
	}
	if got := st.upsertMembershipCalls[membershipKey(org.ID, user.ID)]; got != 1 {
		t.Fatalf("expected one membership upsert, got %d", got)
	}
	if got := st.bindingChecks[org.ID.String()]; got != 1 {
		t.Fatalf("expected one binding check, got %d", got)
	}
}

func TestClaimPendingAdminGrantsAndIsIdempotent(t *testing.T) {
	t.Parallel()

	st := newFakeStore()
	user := st.addUser("github", "installer-1")
	org := st.addOrganization("github", "acme")
	admin := st.addForgeOrgAdmin("github", "acme", "installer-1")
	admin.OrgID = &org.ID
	rbac := &fakeRBACSeeder{}
	svc := NewService(st, rbac, nil, true, zerolog.New(io.Discard))

	if err := svc.ClaimPendingAdmin(context.Background(), user); err != nil {
		t.Fatalf("first claim pending admin: %v", err)
	}
	if role := st.membershipRole(org.ID, user.ID); role != "admin" {
		t.Fatalf("expected admin role after first claim, got %q", role)
	}
	if !st.forgeOrgAdmins[forgeOrgAdminKey("github", "acme", "installer-1")].Granted {
		t.Fatal("expected pending row to be marked granted")
	}

	if err := svc.ClaimPendingAdmin(context.Background(), user); err != nil {
		t.Fatalf("second claim pending admin: %v", err)
	}
	if got := st.upsertMembershipCalls[membershipKey(org.ID, user.ID)]; got != 1 {
		t.Fatalf("expected exactly one membership upsert, got %d", got)
	}
	if len(rbac.assignments) != 1 {
		t.Fatalf("expected exactly one RBAC assignment, got %d", len(rbac.assignments))
	}
}

func TestClaimPendingAdminUpgradesExistingMemberAtomically(t *testing.T) {
	t.Parallel()

	st := newFakeStore()
	user := st.addUser("github", "installer-1")
	org := st.addOrganization("github", "acme")
	admin := st.addForgeOrgAdmin("github", "acme", "installer-1")
	admin.OrgID = &org.ID
	st.memberships[membershipKey(org.ID, user.ID)] = "viewer"
	rbac := &fakeRBACSeeder{}
	svc := NewService(st, rbac, nil, true, zerolog.New(io.Discard))

	if err := svc.ClaimPendingAdmin(context.Background(), user); err != nil {
		t.Fatalf("first claim pending admin: %v", err)
	}
	if role := st.membershipRole(org.ID, user.ID); role != "admin" {
		t.Fatalf("expected admin role after upgrade, got %q", role)
	}
	if got := st.upsertMembershipCalls[membershipKey(org.ID, user.ID)]; got != 1 {
		t.Fatalf("expected one membership upsert, got %d", got)
	}
	if st.removeMemberCalls != 0 {
		t.Fatalf("expected no remove-member calls, got %d", st.removeMemberCalls)
	}

	if err := svc.ClaimPendingAdmin(context.Background(), user); err != nil {
		t.Fatalf("second claim pending admin: %v", err)
	}
	if got := st.upsertMembershipCalls[membershipKey(org.ID, user.ID)]; got != 1 {
		t.Fatalf("expected idempotent second claim, got %d membership upserts", got)
	}
	if len(rbac.assignments) != 1 {
		t.Fatalf("expected one RBAC assignment, got %d", len(rbac.assignments))
	}
}

func TestAuthorizeForgeOrgCreation(t *testing.T) {
	t.Parallel()

	provider := &fakeForgeProvider{
		id:            "github",
		installations: []forge.Installation{{ID: 1, AccountName: "Acme", AccountType: "Organization"}},
	}
	st := newFakeStore()
	st.addForgeOrgAdmin("github", "acme", "installer-1")
	svc := NewService(st, noopRBACSeeder{}, map[string]forge.Provider{"github": provider}, false, zerolog.New(io.Discard))
	requester := st.addUser("github", "installer-1")

	if err := svc.AuthorizeForgeOrgCreation(context.Background(), requester, "github", "acme"); err != nil {
		t.Fatalf("expected allow, got %v", err)
	}

	if err := svc.AuthorizeForgeOrgCreation(context.Background(), requester, "github", "other"); !errors.Is(err, ErrForgeOrgUnauthorized) {
		t.Fatalf("expected missing installation deny, got %v", err)
	}

	otherUser := st.addUser("github", "other-user")
	if err := svc.AuthorizeForgeOrgCreation(context.Background(), otherUser, "github", "acme"); !errors.Is(err, ErrForgeOrgUnauthorized) {
		t.Fatalf("expected missing installer row deny, got %v", err)
	}

	wrongProviderUser := st.addUser("gitlab", "installer-1")
	if err := svc.AuthorizeForgeOrgCreation(context.Background(), wrongProviderUser, "github", "acme"); !errors.Is(err, ErrForgeOrgUnauthorized) {
		t.Fatalf("expected wrong provider deny, got %v", err)
	}

	if err := svc.AuthorizeForgeOrgCreation(context.Background(), nil, "github", "acme"); !errors.Is(err, ErrForgeOrgUnauthorized) {
		t.Fatalf("expected nil requester deny, got %v", err)
	}
	if err := svc.AuthorizeForgeOrgCreation(context.Background(), requester, "local", "acme"); err != nil {
		t.Fatalf("expected unconfigured provider to bypass gate, got %v", err)
	}
}

func TestAuthorizeForgeOrgCreationChecksAllCollidingInstallations(t *testing.T) {
	t.Parallel()

	provider := &fakeForgeProvider{
		id: "github",
		installations: []forge.Installation{
			{ID: 1, AccountName: "foo.bar", AccountType: "Organization"},
			{ID: 2, AccountName: "foo_bar", AccountType: "Organization"},
		},
	}
	st := newFakeStore()
	requester := st.addUser("github", "installer-2")
	st.addForgeOrgAdmin("github", "foo_bar", requester.ProviderID)
	svc := NewService(st, noopRBACSeeder{}, map[string]forge.Provider{"github": provider}, false, zerolog.New(io.Discard))

	if err := svc.AuthorizeForgeOrgCreation(context.Background(), requester, "github", "foo-bar"); err != nil {
		t.Fatalf("expected colliding second installation admin to be allowed, got %v", err)
	}

	unauthorized := st.addUser("github", "installer-3")
	if err := svc.AuthorizeForgeOrgCreation(context.Background(), unauthorized, "github", "foo-bar"); !errors.Is(err, ErrForgeOrgUnauthorized) {
		t.Fatalf("expected non-admin colliding requester to be denied, got %v", err)
	}
	if err := svc.AuthorizeForgeOrgCreation(context.Background(), requester, "github", "missing"); !errors.Is(err, ErrForgeOrgUnauthorized) {
		t.Fatalf("expected missing colliding slug to be denied, got %v", err)
	}
}

func TestListOnboardableAccountsClassifiesStatuses(t *testing.T) {
	t.Parallel()

	provider := &fakeForgeProvider{
		id: "github",
		installations: []forge.Installation{
			{ID: 1, AccountName: "Imported", AccountType: "Organization"},
			{ID: 2, AccountName: "Importable", AccountType: "Organization"},
			{ID: 3, AccountName: "Pending", AccountType: "Organization"},
		},
	}
	st := newFakeStore()
	user := st.addUser("github", "installer-1")
	importedOrg := st.addOrganization("github", "imported")
	pendingOrg := st.addOrganization("github", "pending")
	st.memberships[membershipKey(importedOrg.ID, user.ID)] = "admin"
	importedAdmin := st.addForgeOrgAdmin("github", "Imported", "installer-1")
	importedAdmin.OrgID = &importedOrg.ID
	importableAdmin := st.addForgeOrgAdmin("github", "Importable", "installer-1")
	pendingAdmin := st.addForgeOrgAdmin("github", "Pending", "installer-1")
	pendingAdmin.OrgID = &pendingOrg.ID
	st.addForgeOrgAdmin("github", "Stale", "installer-1")

	svc := NewService(st, noopRBACSeeder{}, map[string]forge.Provider{"github": provider}, false, zerolog.New(io.Discard))

	accounts, err := svc.ListOnboardableAccounts(context.Background(), user)
	if err != nil {
		t.Fatalf("list onboardable accounts: %v", err)
	}
	if len(accounts) != 3 {
		t.Fatalf("expected 3 live onboardable accounts, got %d", len(accounts))
	}

	bySlug := map[string]OnboardableAccount{}
	for _, account := range accounts {
		bySlug[account.Slug] = account
	}
	if got := bySlug["imported"]; got.Status != "imported" || got.Account != "Imported" || got.Provider != "github" {
		t.Fatalf("expected imported classification, got %+v", got)
	}
	if got := bySlug["importable"]; got.Status != "importable" || got.Account != "Importable" {
		t.Fatalf("expected importable classification, got %+v", got)
	}
	if got := bySlug["pending"]; got.Status != "pending" || got.Account != "Pending" {
		t.Fatalf("expected pending classification, got %+v", got)
	}
	if _, exists := bySlug[slugifyAccount(importableAdmin.Account)]; !exists {
		t.Fatal("expected importable account in result")
	}
	if _, exists := bySlug[slugifyAccount(importedAdmin.Account)]; !exists {
		t.Fatal("expected imported account in result")
	}
	if _, exists := bySlug["stale"]; exists {
		t.Fatal("expected stale installation to be excluded")
	}
}

func TestListOnboardableAccountsDoesNotLeakForeignOrgBySlug(t *testing.T) {
	t.Parallel()

	provider := &fakeForgeProvider{
		id:            "github",
		installations: []forge.Installation{{ID: 1, AccountName: "Acme", AccountType: "Organization"}},
	}
	st := newFakeStore()
	st.failOrgLookup = true
	st.addOrganization("github", "acme")
	admin := st.addForgeOrgAdmin("github", "Acme", "installer-1")
	admin.OrgID = nil
	user := st.addUser("github", "installer-1")
	svc := NewService(st, noopRBACSeeder{}, map[string]forge.Provider{"github": provider}, false, zerolog.New(io.Discard))

	accounts, err := svc.ListOnboardableAccounts(context.Background(), user)
	if err != nil {
		t.Fatalf("list onboardable accounts: %v", err)
	}
	if len(accounts) != 1 {
		t.Fatalf("expected 1 onboardable account, got %d", len(accounts))
	}
	if got := accounts[0]; got.Status != "importable" || got.Slug != "acme" || got.Account != "Acme" {
		t.Fatalf("expected importable acme account, got %+v", got)
	}
	if st.orgLookupCalls != 0 {
		t.Fatalf("expected no org slug lookup during classification, got %d", st.orgLookupCalls)
	}
	if got := st.getOrgMemberRoleCalls[membershipKey(uuid.Nil, user.ID)]; got != 0 {
		t.Fatalf("expected no membership lookup for nil org id, got %d", got)
	}
	if admin.OrgID != nil {
		t.Fatal("expected test admin to remain unbound")
	}
	if org := st.organizations[orgKey("github", "acme")]; org == nil {
		t.Fatal("expected foreign org fixture to exist")
	}
	if st.membershipRole(orgIDForSlug(st, "github", "acme"), user.ID) != "" {
		t.Fatal("expected no accidental membership on foreign org")
	}
}

func TestListOnboardableAccountsBoundStatusesUseBoundOrgID(t *testing.T) {
	t.Parallel()

	provider := &fakeForgeProvider{
		id: "github",
		installations: []forge.Installation{
			{ID: 1, AccountName: "Imported", AccountType: "Organization"},
			{ID: 2, AccountName: "Pending", AccountType: "Organization"},
		},
	}
	st := newFakeStore()
	st.failOrgLookup = true
	user := st.addUser("github", "installer-1")
	importedOrg := st.addOrganization("github", "foreign-imported")
	pendingOrg := st.addOrganization("github", "foreign-pending")
	importedAdmin := st.addForgeOrgAdmin("github", "Imported", "installer-1")
	importedAdmin.OrgID = &importedOrg.ID
	pendingAdmin := st.addForgeOrgAdmin("github", "Pending", "installer-1")
	pendingAdmin.OrgID = &pendingOrg.ID
	st.memberships[membershipKey(importedOrg.ID, user.ID)] = "admin"
	svc := NewService(st, noopRBACSeeder{}, map[string]forge.Provider{"github": provider}, false, zerolog.New(io.Discard))

	accounts, err := svc.ListOnboardableAccounts(context.Background(), user)
	if err != nil {
		t.Fatalf("list onboardable accounts: %v", err)
	}
	if len(accounts) != 2 {
		t.Fatalf("expected 2 onboardable accounts, got %d", len(accounts))
	}

	bySlug := map[string]OnboardableAccount{}
	for _, account := range accounts {
		bySlug[account.Slug] = account
	}
	if got := bySlug["imported"]; got.Status != "imported" {
		t.Fatalf("expected imported status from bound org membership, got %+v", got)
	}
	if got := bySlug["pending"]; got.Status != "pending" {
		t.Fatalf("expected pending status from bound org without membership, got %+v", got)
	}
	if st.orgLookupCalls != 0 {
		t.Fatalf("expected no org slug lookups for bound classification, got %d", st.orgLookupCalls)
	}
	if got := st.getOrgMemberRoleCalls[membershipKey(importedOrg.ID, user.ID)]; got != 1 {
		t.Fatalf("expected one membership lookup for imported org, got %d", got)
	}
	if got := st.getOrgMemberRoleCalls[membershipKey(pendingOrg.ID, user.ID)]; got != 1 {
		t.Fatalf("expected one membership lookup for pending org, got %d", got)
	}
	if importedAdmin.OrgID == nil || pendingAdmin.OrgID == nil {
		t.Fatal("expected bound admin fixtures to stay bound")
	}
}

func TestListOnboardableAccountsScopesToInstallerRows(t *testing.T) {
	t.Parallel()

	provider := &fakeForgeProvider{
		id:            "github",
		installations: []forge.Installation{{ID: 1, AccountName: "Acme", AccountType: "Organization"}},
	}
	st := newFakeStore()
	st.addForgeOrgAdmin("github", "Acme", "other-user")
	user := st.addUser("github", "installer-1")
	svc := NewService(st, noopRBACSeeder{}, map[string]forge.Provider{"github": provider}, false, zerolog.New(io.Discard))

	accounts, err := svc.ListOnboardableAccounts(context.Background(), user)
	if err != nil {
		t.Fatalf("list onboardable accounts: %v", err)
	}
	if len(accounts) != 0 {
		t.Fatalf("expected no accounts for unrelated installer rows, got %d", len(accounts))
	}
}

func TestRecordInstallationCreatedIsIdempotent(t *testing.T) {
	t.Parallel()

	st := newFakeStore()
	st.addUser("github", "installer-1")
	rbac := &fakeRBACSeeder{}
	svc := NewService(st, rbac, nil, true, zerolog.New(io.Discard))
	event := forge.InstallationEvent{
		Action:       "created",
		Installation: forge.Installation{AccountName: "Acme"},
		Sender:       forge.UserInfo{ProviderID: "installer-1"},
	}

	if err := svc.RecordInstallation(context.Background(), "github", event); err != nil {
		t.Fatalf("first record installation: %v", err)
	}
	if err := svc.RecordInstallation(context.Background(), "github", event); err != nil {
		t.Fatalf("second record installation: %v", err)
	}
	if len(st.organizations) != 1 {
		t.Fatalf("expected one organization after replay, got %d", len(st.organizations))
	}
	if len(st.clients) != 1 {
		t.Fatalf("expected one default client after replay, got %d", len(st.clients))
	}
	if got := st.upsertMembershipCalls[st.onlyMembershipKey()]; got != 2 {
		t.Fatalf("expected replay to reassert durable admin membership twice, got %d", got)
	}
	if len(rbac.assignments) != 1 {
		t.Fatalf("expected one RBAC assignment after replay, got %d", len(rbac.assignments))
	}
}

type fakeStore struct {
	forgeOrgAdmins        map[string]*store.ForgeOrgAdmin
	organizations         map[string]*store.Organization
	users                 map[string]*store.User
	memberships           map[string]string
	getOrgMemberRoleCalls map[string]int
	membershipAdds        map[string]int
	upsertMembershipCalls map[string]int
	removeMemberCalls     int
	bindingChecks         map[string]int
	orgLookupCalls        int
	failOrgLookup         bool
	clients               map[string]*store.Client
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		forgeOrgAdmins:        map[string]*store.ForgeOrgAdmin{},
		organizations:         map[string]*store.Organization{},
		users:                 map[string]*store.User{},
		memberships:           map[string]string{},
		getOrgMemberRoleCalls: map[string]int{},
		membershipAdds:        map[string]int{},
		upsertMembershipCalls: map[string]int{},
		bindingChecks:         map[string]int{},
		clients:               map[string]*store.Client{},
	}
}

func (s *fakeStore) UpsertForgeOrgAdmin(_ context.Context, provider, account, providerUserID string) (*store.ForgeOrgAdmin, error) {
	key := forgeOrgAdminKey(provider, account, providerUserID)
	if existing := s.forgeOrgAdmins[key]; existing != nil {
		existing.UpdatedAt = time.Now().UTC()
		return cloneForgeOrgAdmin(existing), nil
	}
	admin := &store.ForgeOrgAdmin{
		ID:             uuid.New(),
		Provider:       provider,
		Account:        slugifyAccount(account),
		ProviderUserID: providerUserID,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	s.forgeOrgAdmins[key] = admin
	return cloneForgeOrgAdmin(admin), nil
}

func (s *fakeStore) SetForgeOrgAdminOrg(_ context.Context, provider, account, providerUserID string, orgID uuid.UUID) error {
	admin := s.forgeOrgAdmins[forgeOrgAdminKey(provider, account, providerUserID)]
	if admin == nil {
		return nil
	}
	admin.OrgID = &orgID
	admin.UpdatedAt = time.Now().UTC()
	return nil
}

func (s *fakeStore) MarkForgeOrgAdminGranted(_ context.Context, id uuid.UUID) error {
	for _, admin := range s.forgeOrgAdmins {
		if admin.ID == id {
			admin.Granted = true
			admin.UpdatedAt = time.Now().UTC()
			return nil
		}
	}
	return nil
}

func (s *fakeStore) ListPendingForgeOrgAdminsByUser(_ context.Context, provider, providerUserID string) ([]store.ForgeOrgAdmin, error) {
	rows := make([]store.ForgeOrgAdmin, 0)
	for _, admin := range s.forgeOrgAdmins {
		if admin.Provider == provider && admin.ProviderUserID == providerUserID && admin.OrgID != nil && !admin.Granted {
			rows = append(rows, *cloneForgeOrgAdmin(admin))
		}
	}
	return rows, nil
}

func (s *fakeStore) ListForgeOrgAdminsByUser(_ context.Context, provider, providerUserID string) ([]store.ForgeOrgAdmin, error) {
	rows := make([]store.ForgeOrgAdmin, 0)
	for _, admin := range s.forgeOrgAdmins {
		if admin.Provider == provider && admin.ProviderUserID == providerUserID {
			rows = append(rows, *cloneForgeOrgAdmin(admin))
		}
	}
	return rows, nil
}

func (s *fakeStore) GetForgeOrgAdmin(_ context.Context, provider, account, providerUserID string) (*store.ForgeOrgAdmin, error) {
	admin := s.forgeOrgAdmins[forgeOrgAdminKey(provider, account, providerUserID)]
	if admin == nil {
		return nil, nil
	}
	return cloneForgeOrgAdmin(admin), nil
}

func (s *fakeStore) ForgeOrgAdminBindingExists(_ context.Context, provider string, orgID uuid.UUID) (bool, error) {
	s.bindingChecks[orgID.String()]++
	for _, admin := range s.forgeOrgAdmins {
		if admin.Provider == provider && admin.OrgID != nil && *admin.OrgID == orgID {
			return true, nil
		}
	}
	return false, nil
}

func (s *fakeStore) GetOrganizationByProviderAndSlug(_ context.Context, provider, slug string) (*store.Organization, error) {
	s.orgLookupCalls++
	if s.failOrgLookup {
		return nil, errors.New("unexpected org slug lookup")
	}
	org := s.organizations[orgKey(provider, slug)]
	if org == nil {
		return nil, nil
	}
	clone := *org
	return &clone, nil
}

func (s *fakeStore) CreateOrganization(_ context.Context, name, slug, displayName, provider string) (*store.Organization, error) {
	key := orgKey(provider, slug)
	if _, exists := s.organizations[key]; exists {
		return nil, duplicateError{}
	}
	org := &store.Organization{ID: uuid.New(), Name: name, Slug: slug, DisplayName: displayName, Provider: provider}
	s.organizations[key] = org
	clone := *org
	return &clone, nil
}

func (s *fakeStore) AddOrgMember(_ context.Context, orgID, userID uuid.UUID, role string) error {
	key := membershipKey(orgID, userID)
	if _, exists := s.memberships[key]; exists {
		return duplicateError{}
	}
	s.memberships[key] = role
	s.membershipAdds[key]++
	return nil
}

func (s *fakeStore) UpsertOrgMemberRole(_ context.Context, orgID, userID uuid.UUID, role string) error {
	key := membershipKey(orgID, userID)
	s.memberships[key] = role
	s.upsertMembershipCalls[key]++
	return nil
}

func (s *fakeStore) RemoveOrgMember(_ context.Context, orgID, userID uuid.UUID) error {
	s.removeMemberCalls++
	delete(s.memberships, membershipKey(orgID, userID))
	return nil
}

func (s *fakeStore) GetOrgMemberRole(_ context.Context, orgID, userID uuid.UUID) (string, error) {
	s.getOrgMemberRoleCalls[membershipKey(orgID, userID)]++
	return s.memberships[membershipKey(orgID, userID)], nil
}

func (s *fakeStore) CreateClient(_ context.Context, orgID uuid.UUID, name, slug string, _ json.RawMessage, clientType string, _, _ *string, _, _ json.RawMessage) (*store.Client, error) {
	key := orgID.String() + ":" + slug
	if _, exists := s.clients[key]; exists {
		return nil, duplicateError{}
	}
	client := &store.Client{ID: uuid.New(), OrgID: orgID, Name: name, Slug: slug, ClientType: clientType}
	s.clients[key] = client
	clone := *client
	return &clone, nil
}

func (s *fakeStore) GetUserByProviderID(_ context.Context, provider, providerID string) (*store.User, error) {
	user := s.users[userKey(provider, providerID)]
	if user == nil {
		return nil, nil
	}
	clone := *user
	return &clone, nil
}

func (s *fakeStore) addUser(provider, providerID string) *store.User {
	user := &store.User{ID: uuid.New(), Provider: provider, ProviderID: providerID, Email: providerID + "@example.com", DisplayName: providerID}
	s.users[userKey(provider, providerID)] = user
	clone := *user
	return &clone
}

func (s *fakeStore) addOrganization(provider, slug string) *store.Organization {
	org := &store.Organization{ID: uuid.New(), Provider: provider, Slug: slug, Name: slug, DisplayName: slug}
	s.organizations[orgKey(provider, slug)] = org
	return org
}

func (s *fakeStore) addForgeOrgAdmin(provider, account, providerUserID string) *store.ForgeOrgAdmin {
	admin := &store.ForgeOrgAdmin{ID: uuid.New(), Provider: provider, Account: slugifyAccount(account), ProviderUserID: providerUserID}
	s.forgeOrgAdmins[forgeOrgAdminKey(provider, account, providerUserID)] = admin
	return admin
}

func (s *fakeStore) membershipRole(orgID, userID uuid.UUID) string {
	return s.memberships[membershipKey(orgID, userID)]
}

func (s *fakeStore) onlyMembershipKey() string {
	for key := range s.memberships {
		return key
	}
	return ""
}

type fakeRBACSeeder struct {
	seeded      []uuid.UUID
	assignments []string
}

func (s *fakeRBACSeeder) SeedOrgPolicies(orgID uuid.UUID) error {
	for _, seeded := range s.seeded {
		if seeded == orgID {
			return nil
		}
	}
	s.seeded = append(s.seeded, orgID)
	return nil
}

func (s *fakeRBACSeeder) AddRoleForUserInOrg(userID uuid.UUID, role string, orgID uuid.UUID) error {
	key := userID.String() + ":" + role + ":" + orgID.String()
	for _, existing := range s.assignments {
		if existing == key {
			return nil
		}
	}
	s.assignments = append(s.assignments, key)
	return nil
}

type noopRBACSeeder struct{}

func (noopRBACSeeder) SeedOrgPolicies(uuid.UUID) error { return nil }

func (noopRBACSeeder) AddRoleForUserInOrg(uuid.UUID, string, uuid.UUID) error { return nil }

type fakeForgeProvider struct {
	id            string
	installations []forge.Installation
	err           error
}

func (p *fakeForgeProvider) ID() string { return p.id }

func (p *fakeForgeProvider) Installations(context.Context) ([]forge.Installation, error) {
	return p.installations, p.err
}

func (p *fakeForgeProvider) ListRepositories(context.Context, forge.ListReposOptions) ([]forge.Repository, error) {
	return nil, forge.ErrNotImplemented
}

func (p *fakeForgeProvider) GetRepository(context.Context, string, string) (*forge.Repository, error) {
	return nil, forge.ErrNotImplemented
}

func (p *fakeForgeProvider) ListBranches(context.Context, string, string) ([]forge.Branch, error) {
	return nil, forge.ErrNotImplemented
}

func (p *fakeForgeProvider) GetBranch(context.Context, string, string, string) (*forge.Branch, error) {
	return nil, forge.ErrNotImplemented
}

func (p *fakeForgeProvider) ListTreePaths(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

func (p *fakeForgeProvider) GetFileContent(context.Context, string, string, string, string) ([]byte, error) {
	return nil, forge.ErrNotImplemented
}

func (p *fakeForgeProvider) CreateOrUpdateFile(context.Context, string, string, string, string, string, []byte) error {
	return forge.ErrNotImplemented
}

func (p *fakeForgeProvider) CreateBranch(context.Context, string, string, string, string) error {
	return forge.ErrNotImplemented
}

func (p *fakeForgeProvider) CreatePullRequest(context.Context, string, string, forge.CreatePROptions) (*forge.PullRequest, error) {
	return nil, forge.ErrNotImplemented
}

func (p *fakeForgeProvider) CreateCommitStatus(context.Context, string, string, string, forge.CommitStatus) error {
	return forge.ErrNotImplemented
}

func (p *fakeForgeProvider) ComparePatch(context.Context, string, string, string, string) (*forge.PatchDiff, error) {
	return nil, nil
}

func (p *fakeForgeProvider) ValidateWebhookPayload(*http.Request, string) ([]byte, error) {
	return nil, forge.ErrNotImplemented
}

func (p *fakeForgeProvider) ParseWebhookEvent(string, []byte) (forge.WebhookEvent, error) {
	return nil, forge.ErrNotImplemented
}

func (p *fakeForgeProvider) OAuth2Config(string) *oauth2.Config { return nil }

func (p *fakeForgeProvider) UserInfo(context.Context, *oauth2.Token) (*forge.UserInfo, error) {
	return nil, forge.ErrNotImplemented
}

func (p *fakeForgeProvider) ListUserAccess(context.Context, *oauth2.Token) (forge.UserAccess, error) {
	return forge.UserAccess{}, nil
}

type duplicateError struct{}

func (duplicateError) Error() string { return "duplicate key value violates unique constraint" }

func (duplicateError) SQLState() string { return "23505" }

func forgeOrgAdminKey(provider, account, providerUserID string) string {
	return provider + ":" + slugifyAccount(account) + ":" + providerUserID
}

func orgKey(provider, slug string) string {
	return provider + ":" + slugifyAccount(slug)
}

func userKey(provider, providerID string) string {
	return provider + ":" + providerID
}

func membershipKey(orgID, userID uuid.UUID) string {
	return orgID.String() + ":" + userID.String()
}

func orgIDForSlug(s *fakeStore, provider, slug string) uuid.UUID {
	if org := s.organizations[orgKey(provider, slug)]; org != nil {
		return org.ID
	}
	return uuid.Nil
}

func cloneForgeOrgAdmin(admin *store.ForgeOrgAdmin) *store.ForgeOrgAdmin {
	if admin == nil {
		return nil
	}
	clone := *admin
	if admin.OrgID != nil {
		orgID := *admin.OrgID
		clone.OrgID = &orgID
	}
	return &clone
}
