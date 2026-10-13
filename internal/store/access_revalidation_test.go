package store

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Q4: repo_scoped is explicit, an invite clears it, and removing a forge
// membership takes its repository grants along.
func TestRepoScopedMembershipIsExplicit(t *testing.T) {
	db := openStoreTestDB(t, "repo scoped membership test")
	queries := NewQueries(db)
	ctx := context.Background()

	org := createTestOrganization(t, ctx, queries, "scoped")
	repo := createTestRepository(t, ctx, queries, org.ID, "scoped")
	user := createTestUser(t, ctx, queries, "scoped")

	// Scoped with no grants at all: still scoped (fails closed).
	if err := queries.UpsertForgeOrgMemberScoped(ctx, org.ID, user.ID, "viewer", true); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if scoped, err := queries.IsRepoScopedOrgMember(ctx, org.ID, user.ID); err != nil || !scoped {
		t.Fatalf("scoped = %v, %v; want true", scoped, err)
	}
	if err := queries.UpsertForgeUserRepoAccess(ctx, user.ID, repo.ID, "viewer"); err != nil {
		t.Fatalf("grant: %v", err)
	}
	stale, err := queries.ListStaleForgeOrgMemberships(ctx, time.Now().Add(time.Minute), 1000)
	if err != nil {
		t.Fatalf("list stale: %v", err)
	}
	found := false
	for _, membership := range stale {
		if membership.OrgID == org.ID && membership.UserID == user.ID {
			found = membership.RepoScoped && membership.OrgSlug == org.Slug
		}
	}
	if !found {
		t.Fatal("stale membership not listed with its scope")
	}

	if err := queries.RemoveForgeOrgAccess(ctx, org.ID, user.ID); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if role, err := queries.GetOrgMemberRole(ctx, org.ID, user.ID); err != nil || role != "" {
		t.Fatalf("membership survived removal: %q %v", role, err)
	}
	if grants, err := queries.ListUserRepoAccessInOrg(ctx, org.ID, user.ID); err != nil || len(grants) != 0 {
		t.Fatalf("grants survived removal: %v %v", grants, err)
	}

	if err := queries.UpsertForgeOrgMemberScoped(ctx, org.ID, user.ID, "viewer", true); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := queries.UpsertOrgMemberRole(ctx, org.ID, user.ID, "viewer"); err != nil {
		t.Fatalf("invite: %v", err)
	}
	if scoped, _ := queries.IsRepoScopedOrgMember(ctx, org.ID, user.ID); scoped {
		t.Fatal("an invite must clear repository scoping")
	}
}

// Q4: an org-owned key whose creator left the org is flagged at lookup; one
// whose creator is still a member is not.
func TestGetAPIKeyByHashFlagsDepartedCreator(t *testing.T) {
	db := openStoreTestDB(t, "api key creator membership test")
	queries := NewQueries(db)
	ctx := context.Background()

	org := createTestOrganization(t, ctx, queries, "keys")
	creator := createTestUser(t, ctx, queries, "keys")
	if err := queries.AddOrgMember(ctx, org.ID, creator.ID, "admin"); err != nil {
		t.Fatalf("add member: %v", err)
	}
	hash := HashAPIKey(uuid.NewString())
	if _, err := queries.CreateAPIKey(ctx, creator.ID, "ci", hash, json.RawMessage(`null`), nil, "org", &org.ID, ""); err != nil {
		t.Fatalf("create key: %v", err)
	}
	key, err := queries.GetAPIKeyByHash(ctx, hash)
	if err != nil || key == nil || key.CreatorLeftOrg {
		t.Fatalf("member's key flagged: %+v %v", key, err)
	}
	if err := queries.RemoveOrgMember(ctx, org.ID, creator.ID); err != nil {
		t.Fatalf("remove member: %v", err)
	}
	if key, err = queries.GetAPIKeyByHash(ctx, hash); err != nil || key == nil || !key.CreatorLeftOrg {
		t.Fatalf("departed creator's key not flagged: %+v %v", key, err)
	}
}

// Q5: the sign-in record carried on the user row.
func TestUserSignInRecord(t *testing.T) {
	db := openStoreTestDB(t, "user sign-in record test")
	queries := NewQueries(db)
	ctx := context.Background()

	user := createTestUser(t, ctx, queries, "signin")
	now := time.Now().UTC().Truncate(time.Second)
	if err := queries.SetUserForgeLogin(ctx, user.ID, "Octocat"); err != nil {
		t.Fatalf("set login: %v", err)
	}
	if err := queries.SetUserSignInAllowedAt(ctx, user.ID, &now); err != nil {
		t.Fatalf("set allowed: %v", err)
	}
	loaded, err := queries.GetUserByID(ctx, user.ID)
	if err != nil || loaded == nil || loaded.ForgeLogin != "Octocat" || loaded.SignInAllowedAt == nil || !loaded.SignInAllowedAt.Equal(now) {
		t.Fatalf("user = %+v, %v", loaded, err)
	}
	if err := queries.SetUserSignInAllowedAt(ctx, user.ID, nil); err != nil {
		t.Fatalf("clear allowed: %v", err)
	}
	if loaded, _ = queries.GetUserByID(ctx, user.ID); loaded.SignInAllowedAt != nil {
		t.Fatal("allowed-at not cleared")
	}
}
