package server

import (
	"context"
	"testing"

	"github.com/hibouhq/hibou/internal/store"
)

// bindTestOrgToForgeAccount records the forge account an org's repositories
// live under. Forge calls refuse repositories whose owner is not the org's
// bound account (security audit §3.1), so fixtures enrolling "acme/<repo>"
// into a randomly named org must bind it to "acme" first.
func bindTestOrgToForgeAccount(t *testing.T, srv *Server, org *store.Organization, login string) {
	t.Helper()
	if err := srv.queries.SetOrganizationForgeAccount(context.Background(), org.ID, "", login); err != nil {
		t.Fatalf("bind org to forge account %q: %v", login, err)
	}
}
