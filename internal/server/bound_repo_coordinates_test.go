package server

import (
	"context"
	"testing"

	"github.com/hibouhq/hibou/internal/forge"
)

// A repository row naming another tenant's repository (one enrolled before
// enrolment checked ownership) must never reach the forge: the forge call
// would mint that tenant's installation token (security audit §3.1).
func TestForgeCallsRefuseRepositoryOutsideBoundAccount(t *testing.T) {
	srv, org, _, _ := newDiscoveryTestServer(t)
	bindTestOrgToForgeAccount(t, srv, org, "acme")
	repo := createRepository(t, srv, org, repoSeed{
		name:          uniqueName(t, "foreign"),
		slug:          uniqueName(t, "foreign"),
		provider:      "github",
		providerID:    "victim/private",
		defaultBranch: "main",
	})
	provider := &discoveryTestForgeProvider{
		id:               "github",
		comparePatchDiff: &forge.PatchDiff{Files: []forge.PatchFile{{Path: "a.go", AddedLines: []int{1}}}},
	}

	if got := srv.changedLinesForComparison(context.Background(), repo, provider, "base", "head"); got != nil {
		t.Fatalf("foreign repository comparison = %#v, want nil", got)
	}
	if provider.comparePatchCalls != 0 {
		t.Fatalf("provider calls = %d, want 0 for a repository outside the org's account", provider.comparePatchCalls)
	}

	if _, _, ok := srv.boundRepoCoordinates(context.Background(), repo); ok {
		t.Fatal("boundRepoCoordinates accepted victim/private for an org bound to acme")
	}
	repo.ProviderID = "acme/app"
	if owner, name, ok := srv.boundRepoCoordinates(context.Background(), repo); !ok || owner != "acme" || name != "app" {
		t.Fatalf("own repository = (%q, %q, %v), want (acme, app, true)", owner, name, ok)
	}
}
