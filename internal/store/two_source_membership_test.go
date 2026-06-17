package store

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestTwoSourceMembershipInvariants(t *testing.T) {
	db := openStoreTestDB(t, "two-source membership test")
	queries := NewQueries(db)
	ctx := context.Background()

	t.Run("prune forge org members preserves invite membership", func(t *testing.T) {
		org := createTestOrganization(t, ctx, queries, "org-prune")
		inviteUser := createTestUser(t, ctx, queries, "invite-survives")
		forgeUser := createTestUser(t, ctx, queries, "forge-pruned")

		if err := queries.AddOrgMember(ctx, org.ID, inviteUser.ID, "admin"); err != nil {
			t.Fatalf("AddOrgMember() invite error = %v", err)
		}
		if err := queries.UpsertForgeOrgMember(ctx, org.ID, forgeUser.ID, "developer"); err != nil {
			t.Fatalf("UpsertForgeOrgMember() forge error = %v", err)
		}
		if err := queries.PruneForgeOrgMembers(ctx, org.ID, []uuid.UUID{}); err != nil {
			t.Fatalf("PruneForgeOrgMembers() error = %v", err)
		}

		role, source := mustOrgMemberState(t, db, org.ID, inviteUser.ID)
		if role != "admin" || source != "invite" {
			t.Fatalf("invite membership changed, role=%q source=%q", role, source)
		}
		if role, _ := mustOptionalOrgMemberState(t, db, org.ID, forgeUser.ID); role != "" {
			t.Fatalf("expected forge membership pruned, found role=%q", role)
		}
	})

	t.Run("forge upsert does not overwrite invite row", func(t *testing.T) {
		org := createTestOrganization(t, ctx, queries, "invite-wins")
		user := createTestUser(t, ctx, queries, "invite-wins")

		if err := queries.AddOrgMember(ctx, org.ID, user.ID, "viewer"); err != nil {
			t.Fatalf("AddOrgMember() error = %v", err)
		}
		if err := queries.UpsertForgeOrgMember(ctx, org.ID, user.ID, "admin"); err != nil {
			t.Fatalf("UpsertForgeOrgMember() error = %v", err)
		}

		role, source := mustOrgMemberState(t, db, org.ID, user.ID)
		if role != "viewer" || source != "invite" {
			t.Fatalf("invite row should win, role=%q source=%q", role, source)
		}
	})

	t.Run("manual upsert reasserts invite and survives forge prune", func(t *testing.T) {
		org := createTestOrganization(t, ctx, queries, "claim-durable")
		user := createTestUser(t, ctx, queries, "claim-durable")

		if err := queries.UpsertForgeOrgMember(ctx, org.ID, user.ID, "admin"); err != nil {
			t.Fatalf("UpsertForgeOrgMember() error = %v", err)
		}
		if err := queries.UpsertOrgMemberRole(ctx, org.ID, user.ID, "admin"); err != nil {
			t.Fatalf("UpsertOrgMemberRole() error = %v", err)
		}

		role, source, syncedAt := mustOrgMemberStateWithSync(t, db, org.ID, user.ID)
		if role != "admin" || source != "invite" {
			t.Fatalf("manual upsert should reassert durable invite row, role=%q source=%q", role, source)
		}
		if syncedAt != nil {
			t.Fatalf("manual upsert should clear synced_at, got %v", syncedAt)
		}

		if err := queries.PruneForgeOrgMembersForUser(ctx, user.ID, []uuid.UUID{}); err != nil {
			t.Fatalf("PruneForgeOrgMembersForUser() error = %v", err)
		}

		role, source = mustOrgMemberState(t, db, org.ID, user.ID)
		if role != "admin" || source != "invite" {
			t.Fatalf("claimed invite membership should survive forge prune, role=%q source=%q", role, source)
		}
	})

	t.Run("forge upsert updates forge row and prune keep retains it", func(t *testing.T) {
		org := createTestOrganization(t, ctx, queries, "forge-retain")
		user := createTestUser(t, ctx, queries, "forge-retain")

		if err := queries.UpsertForgeOrgMember(ctx, org.ID, user.ID, "developer"); err != nil {
			t.Fatalf("initial UpsertForgeOrgMember() error = %v", err)
		}
		beforeSync := time.Now().UTC()
		if err := queries.UpsertForgeOrgMember(ctx, org.ID, user.ID, "admin"); err != nil {
			t.Fatalf("second UpsertForgeOrgMember() error = %v", err)
		}
		if err := queries.PruneForgeOrgMembers(ctx, org.ID, []uuid.UUID{user.ID}); err != nil {
			t.Fatalf("PruneForgeOrgMembers() retain error = %v", err)
		}

		role, source, syncedAt := mustOrgMemberStateWithSync(t, db, org.ID, user.ID)
		if role != "admin" || source != "forge" {
			t.Fatalf("forge row not updated, role=%q source=%q", role, source)
		}
		if syncedAt == nil || syncedAt.Before(beforeSync) {
			t.Fatalf("expected synced_at set after second upsert, got %v", syncedAt)
		}

		forgeIDs, err := queries.ListForgeOrgMemberIDs(ctx, org.ID)
		if err != nil {
			t.Fatalf("ListForgeOrgMemberIDs() error = %v", err)
		}
		if len(forgeIDs) != 1 || forgeIDs[0] != user.ID {
			t.Fatalf("expected retained forge member id, got %#v", forgeIDs)
		}
	})

	t.Run("prune forge org members for user preserves invite membership", func(t *testing.T) {
		forgeOrg := createTestOrganization(t, ctx, queries, "user-prune-forge")
		inviteOrg := createTestOrganization(t, ctx, queries, "user-prune-invite")
		user := createTestUser(t, ctx, queries, "user-prune")

		if err := queries.UpsertForgeOrgMember(ctx, forgeOrg.ID, user.ID, "developer"); err != nil {
			t.Fatalf("UpsertForgeOrgMember() error = %v", err)
		}
		if err := queries.AddOrgMember(ctx, inviteOrg.ID, user.ID, "viewer"); err != nil {
			t.Fatalf("AddOrgMember() error = %v", err)
		}
		if err := queries.PruneForgeOrgMembersForUser(ctx, user.ID, []uuid.UUID{}); err != nil {
			t.Fatalf("PruneForgeOrgMembersForUser() error = %v", err)
		}

		if role, _ := mustOptionalOrgMemberState(t, db, forgeOrg.ID, user.ID); role != "" {
			t.Fatalf("expected forge membership pruned, found role=%q", role)
		}
		role, source := mustOrgMemberState(t, db, inviteOrg.ID, user.ID)
		if role != "viewer" || source != "invite" {
			t.Fatalf("invite membership changed, role=%q source=%q", role, source)
		}
	})

	t.Run("prune forge repo access preserves invite access", func(t *testing.T) {
		org := createTestOrganization(t, ctx, queries, "repo-prune")
		user := createTestUser(t, ctx, queries, "repo-prune")
		forgeRepo := createTestRepository(t, ctx, queries, org.ID, "forge-repo")
		inviteRepo := createTestRepository(t, ctx, queries, org.ID, "invite-repo")

		if err := queries.UpsertForgeUserRepoAccess(ctx, user.ID, forgeRepo.ID, "developer"); err != nil {
			t.Fatalf("UpsertForgeUserRepoAccess() error = %v", err)
		}
		if _, err := db.ExecContext(ctx, `
			INSERT INTO user_repo_access (user_id, repo_id, role, source)
			VALUES ($1, $2, $3, 'invite')
		`, user.ID, inviteRepo.ID, "viewer"); err != nil {
			t.Fatalf("manual invite user_repo_access insert error = %v", err)
		}
		if err := queries.PruneForgeUserRepoAccess(ctx, user.ID, []uuid.UUID{}); err != nil {
			t.Fatalf("PruneForgeUserRepoAccess() error = %v", err)
		}

		accessRows, err := queries.ListUserRepoAccess(ctx, user.ID)
		if err != nil {
			t.Fatalf("ListUserRepoAccess() error = %v", err)
		}
		if len(accessRows) != 1 {
			t.Fatalf("expected one surviving invite access row, got %#v", accessRows)
		}
		if accessRows[0].RepoID != inviteRepo.ID || accessRows[0].Source != "invite" || accessRows[0].Role != "viewer" {
			t.Fatalf("unexpected surviving access row %#v", accessRows[0])
		}
	})
}

func openStoreTestDB(t *testing.T, label string) *sql.DB {
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
		t.Skipf("database not available for %s: %v", label, err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})

	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate() returned error: %v", err)
	}

	return db
}

func createTestOrganization(t *testing.T, ctx context.Context, queries *Queries, prefix string) *Organization {
	t.Helper()

	suffix := normalizeStoreTestName(t.Name()) + "-" + uuid.NewString()
	org, err := queries.CreateOrganization(ctx, prefix+"-"+suffix, prefix+"-"+suffix, prefix+" "+suffix, "github")
	if err != nil {
		t.Fatalf("CreateOrganization() error = %v", err)
	}
	return org
}

func createTestUser(t *testing.T, ctx context.Context, queries *Queries, prefix string) *User {
	t.Helper()

	suffix := normalizeStoreTestName(t.Name()) + "-" + uuid.NewString()
	user, err := queries.CreateUser(ctx, prefix+"-"+suffix+"@example.com", prefix+" "+suffix, "github", prefix+"-"+suffix)
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	return user
}

func createTestRepository(t *testing.T, ctx context.Context, queries *Queries, orgID uuid.UUID, prefix string) *Repository {
	t.Helper()

	suffix := normalizeStoreTestName(t.Name()) + "-" + uuid.NewString()
	repo, err := queries.CreateRepository(ctx, orgID, nil, prefix+"-"+suffix, prefix+"-"+suffix, "github", prefix+"-"+suffix, "main", "active")
	if err != nil {
		t.Fatalf("CreateRepository() error = %v", err)
	}
	return repo
}

func mustOrgMemberState(t *testing.T, db *sql.DB, orgID, userID uuid.UUID) (string, string) {
	t.Helper()

	role, source, _ := mustOrgMemberStateWithSync(t, db, orgID, userID)
	return role, source
}

func mustOptionalOrgMemberState(t *testing.T, db *sql.DB, orgID, userID uuid.UUID) (string, string) {
	t.Helper()

	var role string
	var source string
	err := db.QueryRowContext(context.Background(), `
		SELECT role, source
		FROM org_members
		WHERE org_id = $1 AND user_id = $2
	`, orgID, userID).Scan(&role, &source)
	if err == sql.ErrNoRows {
		return "", ""
	}
	if err != nil {
		t.Fatalf("query org_members state error = %v", err)
	}
	return role, source
}

func mustOrgMemberStateWithSync(t *testing.T, db *sql.DB, orgID, userID uuid.UUID) (string, string, *time.Time) {
	t.Helper()

	var (
		role     string
		source   string
		syncedAt sql.NullTime
	)
	if err := db.QueryRowContext(context.Background(), `
		SELECT role, source, synced_at
		FROM org_members
		WHERE org_id = $1 AND user_id = $2
	`, orgID, userID).Scan(&role, &source, &syncedAt); err != nil {
		t.Fatalf("query org_members state with sync error = %v", err)
	}
	return role, source, timePtrFromNull(syncedAt)
}
