package store

import (
	"context"
	"slices"
	"testing"
	"time"
)

// A member recorded as org-wide at sign-in does not see a repository
// enrolled afterwards until a grant (or a new sync) says they may.
func TestRepoEnrolledAfterSyncScopesOrgWideMember(t *testing.T) {
	db := openStoreTestDB(t, "repo scope after enrollment test")
	queries := NewQueries(db)
	ctx := context.Background()

	org := createTestOrganization(t, ctx, queries, "late-repo")
	first := createTestRepository(t, ctx, queries, org.ID, "first")
	user := createTestUser(t, ctx, queries, "late-repo")
	admin := createTestUser(t, ctx, queries, "late-repo-admin")

	if err := queries.UpsertForgeUserRepoAccess(ctx, user.ID, first.ID, "viewer"); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if err := queries.UpsertForgeOrgMemberScoped(ctx, org.ID, user.ID, "developer", false); err != nil {
		t.Fatalf("upsert member: %v", err)
	}
	if err := queries.UpsertForgeOrgMemberScoped(ctx, org.ID, admin.ID, "admin", false); err != nil {
		t.Fatalf("upsert admin: %v", err)
	}
	if scoped, err := queries.IsRepoScopedOrgMember(ctx, org.ID, user.ID); err != nil || scoped {
		t.Fatalf("scoped before enrollment = %v, %v; want false", scoped, err)
	}

	late := createTestRepository(t, ctx, queries, org.ID, "late")
	if scoped, err := queries.IsRepoScopedOrgMember(ctx, org.ID, user.ID); err != nil || !scoped {
		t.Fatalf("scoped after enrollment = %v, %v; want true", scoped, err)
	}
	if scoped, err := queries.IsRepoScopedOrgMember(ctx, org.ID, admin.ID); err != nil || scoped {
		t.Fatalf("admin scoped = %v, %v; want false", scoped, err)
	}
	audience, err := queries.ListRepoAudienceUserIDs(ctx, late.ID)
	if err != nil {
		t.Fatalf("audience: %v", err)
	}
	if slices.Contains(audience, user.ID) || !slices.Contains(audience, admin.ID) {
		t.Fatalf("audience of the late repo = %v, want the admin and not the ungranted member", audience)
	}
	if audience, err := queries.ListRepoAudienceUserIDs(ctx, first.ID); err != nil || !slices.Contains(audience, user.ID) {
		t.Fatalf("audience of the granted repo = %v, %v; want the member", audience, err)
	}

	if err := queries.UpsertForgeUserRepoAccess(ctx, user.ID, late.ID, "viewer"); err != nil {
		t.Fatalf("grant late: %v", err)
	}
	if scoped, err := queries.IsRepoScopedOrgMember(ctx, org.ID, user.ID); err != nil || scoped {
		t.Fatalf("scoped after grant = %v, %v; want false", scoped, err)
	}

	// An invite is org-wide by definition, repositories enrolled later
	// included.
	createTestRepository(t, ctx, queries, org.ID, "other")
	if err := queries.UpsertOrgMemberRole(ctx, org.ID, user.ID, "developer"); err != nil {
		t.Fatalf("invite: %v", err)
	}
	if scoped, err := queries.IsRepoScopedOrgMember(ctx, org.ID, user.ID); err != nil || scoped {
		t.Fatalf("invited member scoped = %v, %v; want false", scoped, err)
	}
}

// Re-validation stamps rows it could not decide; they leave the batch until
// the next window instead of starving checkable rows.
func TestStaleForgeMembershipsSkipAttemptedRows(t *testing.T) {
	db := openStoreTestDB(t, "revalidation attempted test")
	queries := NewQueries(db)
	ctx := context.Background()

	org := createTestOrganization(t, ctx, queries, "attempted")
	user := createTestUser(t, ctx, queries, "attempted")
	if err := queries.UpsertForgeOrgMemberScoped(ctx, org.ID, user.ID, "viewer", true); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	listed := func() bool {
		stale, err := queries.ListStaleForgeOrgMemberships(ctx, time.Now().Add(time.Minute), 100000)
		if err != nil {
			t.Fatalf("list stale: %v", err)
		}
		for _, membership := range stale {
			if membership.OrgID == org.ID && membership.UserID == user.ID {
				return true
			}
		}
		return false
	}
	if !listed() {
		t.Fatal("stale membership not listed")
	}
	if err := queries.MarkForgeOrgMemberRevalidationAttempted(ctx, org.ID, user.ID); err != nil {
		t.Fatalf("mark: %v", err)
	}
	stale, err := queries.ListStaleForgeOrgMemberships(ctx, time.Now().Add(-time.Minute), 100000)
	if err != nil {
		t.Fatalf("list stale: %v", err)
	}
	for _, membership := range stale {
		if membership.OrgID == org.ID && membership.UserID == user.ID {
			t.Fatal("an attempted row stayed in the batch within its window")
		}
	}
	// A sign-in re-sync clears the stamp.
	if err := queries.UpsertForgeOrgMemberScoped(ctx, org.ID, user.ID, "viewer", true); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	if !listed() {
		t.Fatal("re-synced membership not listed again once stale")
	}
}

// The late-repository pairs the permission sync settles: org-wide forge
// viewers/developers of a bound org without a grant on a newer repository.
func TestListUngrantedLateRepoMembers(t *testing.T) {
	db := openStoreTestDB(t, "late repo members test")
	queries := NewQueries(db)
	ctx := context.Background()

	org := createTestOrganization(t, ctx, queries, "late-pairs")
	if err := queries.SetOrganizationForgeAccount(ctx, org.ID, "acct-"+org.ID.String(), org.Slug); err != nil {
		t.Fatalf("bind org: %v", err)
	}
	user := createTestUser(t, ctx, queries, "late-pairs")
	if err := queries.SetUserForgeLogin(ctx, user.ID, "late-login"); err != nil {
		t.Fatalf("forge login: %v", err)
	}
	if err := queries.UpsertForgeOrgMemberScoped(ctx, org.ID, user.ID, "viewer", false); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	repo := createTestRepository(t, ctx, queries, org.ID, "late")

	find := func() bool {
		pairs, err := queries.ListUngrantedLateRepoMembers(ctx, 100000)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		for _, pair := range pairs {
			if pair.UserID == user.ID && pair.RepoID == repo.ID {
				if pair.UserForgeID != user.ProviderID || pair.RepoSlug != repo.Slug || pair.ForgeAccountID == "" {
					t.Fatalf("pair = %+v", pair)
				}
				return true
			}
		}
		return false
	}
	if !find() {
		t.Fatal("ungranted late repository not listed")
	}
	if err := queries.SetForgeOrgMemberRepoScoped(ctx, org.ID, user.ID); err != nil {
		t.Fatalf("set scoped: %v", err)
	}
	if find() {
		t.Fatal("a member recorded as scoped is still listed")
	}
}
