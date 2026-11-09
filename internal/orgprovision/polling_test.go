package orgprovision

import (
	"context"
	"errors"
	"testing"

	"github.com/hibouhq/hibou/internal/forge"
)

func TestPollingOnboardingRequiresCurrentAdministration(t *testing.T) {
	st := newFakeStore()
	user := st.addUser("github", "person")
	svc, provider := newVerifyingService(st, map[int64]*forge.InstallationAccount{
		7: {InstallationID: 7, AccountID: "42", AccountLogin: "acme"},
	})
	svc.autoProvision = false
	provider.installations = []forge.Installation{{ID: 7, AccountID: "42", AccountName: "acme"}}
	// A historical installer binding is not current authority.
	st.addForgeOrgAdmin("github", "acme", "person")
	accounts, err := svc.VerifyInstalledAccounts(context.Background(), user)
	if err != nil || len(accounts) != 0 {
		t.Fatalf("unverified account exposed: %+v %v", accounts, err)
	}
	provider.accountAdmins = map[string]map[string]bool{"42": {"person": true}}
	accounts, err = svc.VerifyInstalledAccounts(context.Background(), user)
	if err != nil || len(accounts) != 1 || accounts[0].Account != "acme" {
		t.Fatalf("verified account=%+v %v", accounts, err)
	}
	provider.adminErr = errors.New("forge unavailable")
	if _, err := svc.VerifyInstalledAccounts(context.Background(), user); err == nil {
		t.Fatal("failed authority lookup accepted")
	}
	provider.adminErr = nil
	provider.installations[0].Suspended = true
	accounts, err = svc.VerifyInstalledAccounts(context.Background(), user)
	if err != nil || len(accounts) != 0 {
		t.Fatalf("suspended account exposed: %+v %v", accounts, err)
	}
}
