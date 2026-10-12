package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hibouhq/hibou/internal/store"
)

// Audit §3.1: an org admin must not enroll a repository owned by another
// forge account — by owner/name or by an opaque inventory id — because every
// later forge call would borrow that account's installation token.
func TestHandleEnrollRepoRejectsForeignOwner(t *testing.T) {
	t.Parallel()

	srv, org, admin, _ := newDiscoveryTestServer(t)
	foreign := uniqueName(t, "victim")
	if _, err := srv.queries.UpsertForgeRepository(context.Background(), store.ForgeRepository{
		Provider:       org.Provider,
		AccountLogin:   foreign,
		Owner:          foreign,
		Name:           "secret",
		FullName:       foreign + "/secret",
		ProviderRepoID: strptr(uniqueName(t, "rid")),
	}); err != nil {
		t.Fatalf("UpsertForgeRepository: %v", err)
	}
	inv, err := srv.queries.GetForgeRepositoryByProviderKey(context.Background(), org.Provider, foreign+"/secret")
	if err != nil || inv == nil {
		t.Fatalf("load inventory row: %v %v", inv, err)
	}

	for _, providerID := range []string{foreign + "/secret", foreign + "/not-mirrored", *inv.ProviderRepoID} {
		recorder := httptest.NewRecorder()
		srv.handleEnrollRepo(recorder, newEnrollRequest(t, admin, org.Provider, org.Slug, map[string]any{
			"name":        "secret",
			"slug":        "secret",
			"provider_id": providerID,
		}))
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("enroll %q status = %d, want 403", providerID, recorder.Code)
		}
	}
	repo, err := srv.queries.GetRepositoryBySlug(context.Background(), org.ID, "secret")
	if err != nil {
		t.Fatalf("GetRepositoryBySlug: %v", err)
	}
	if repo != nil {
		t.Fatal("foreign repository must not be stored")
	}
}

// Audit §3.1/§3.2: the clone owner never comes from the editable org name, and
// a pre-existing row pointing at another account's repository is refused
// before any token is minted.
func TestResolveSecretScanTargetEnforcesBoundOwner(t *testing.T) {
	t.Parallel()

	srv, org, _, _ := newDiscoveryTestServer(t)
	ctx := context.Background()
	if _, err := srv.queries.UpdateOrganization(ctx, org.ID, "hibouhq", "renamed by an org admin"); err != nil {
		t.Fatalf("UpdateOrganization: %v", err)
	}

	own, err := srv.queries.CreateRepository(ctx, org.ID, nil, "api", "api", org.Provider, "opaque-"+uniqueName(t, "id"), "main", "enrolled")
	if err != nil {
		t.Fatalf("CreateRepository(own): %v", err)
	}
	reloaded, err := srv.queries.GetOrganizationByID(ctx, org.ID)
	if err != nil || reloaded == nil {
		t.Fatalf("GetOrganizationByID: %v", err)
	}
	target, err := srv.mirroredSecretScanTarget(ctx, reloaded, own)
	if err != nil {
		t.Fatalf("mirroredSecretScanTarget: %v", err)
	}
	if target.owner != org.Slug {
		t.Fatalf("clone owner = %q, want bound account %q (never the org name)", target.owner, org.Slug)
	}

	foreign, err := srv.queries.CreateRepository(ctx, org.ID, nil, "victim", "victim", org.Provider, uniqueName(t, "victim")+"/repo", "main", "enrolled")
	if err != nil {
		t.Fatalf("CreateRepository(foreign): %v", err)
	}
	_, err = srv.resolveSecretScanTarget(ctx, srv.forges[org.Provider], foreign)
	if !errors.Is(err, errSecretScanSkipped) {
		t.Fatalf("resolveSecretScanTarget(foreign) error = %v, want errSecretScanSkipped", err)
	}
}
