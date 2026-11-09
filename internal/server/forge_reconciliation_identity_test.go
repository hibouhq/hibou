package server

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/store"
)

func TestForgePollingRejectsReusedAccountAndRepositoryNames(t *testing.T) {
	for _, accountChanged := range []bool{false, true} {
		t.Run(map[bool]string{false: "repository_recreated", true: "account_reclaimed"}[accountChanged], func(t *testing.T) {
			srv, repo, remote := newReconciliationFixture(t)
			ctx := context.Background()
			original, err := srv.queries.GetForgeRepositoryByProviderKey(ctx, repo.Provider, repo.ProviderID)
			if err != nil {
				t.Fatal(err)
			}
			sha := strings.Repeat("a", 40)
			ref, err := srv.queries.UpsertRef(ctx, repo.ID, "main", store.RefTypeBranch, store.UpsertRefOptions{LatestCommitSHA: &sha})
			if err != nil {
				t.Fatal(err)
			}
			accountID := repo.OrgID.String()
			if accountChanged {
				accountID = uuid.NewString()
			}
			attackerRepoID := uuid.NewString()
			remote.installations = []forge.Installation{{ID: 99, AccountID: accountID, AccountName: "acme"}}
			remote.repositories = []forge.Repository{{ProviderRepoID: attackerRepoID, Owner: "acme", Name: "app", FullName: "acme/app", DefaultBranch: "attacker"}}
			if err := reconcileTestScope(t, srv, repo, "inventory"); err != nil {
				t.Fatal(err)
			}
			if _, err := srv.queries.VerifiedForgeRepositoryTarget(ctx, repo.ID); err == nil {
				t.Fatal("name reuse reauthorized polling")
			}
			if err := reconcileTestScope(t, srv, repo, "refs"); err == nil {
				t.Fatal("polling fetched state for replacement identity")
			}
			enrolled, err := srv.queries.GetRepositoryByID(ctx, repo.ID)
			if err != nil || enrolled.DefaultBranch != "main" {
				t.Fatalf("replacement changed enrollment metadata: %+v %v", enrolled, err)
			}
			current, err := srv.queries.GetRefByID(ctx, ref.ID)
			if err != nil || current.LatestCommitSHA == nil || *current.LatestCommitSHA != sha {
				t.Fatal("identity mismatch altered security history")
			}
			if err := srv.verifyObservedWebhookIdentity(ctx, repo.Provider, forge.PushEvent{
				Repo: forge.Repository{ProviderID: repo.ProviderID, ProviderRepoID: attackerRepoID, OwnerID: accountID},
			}); err == nil {
				t.Fatal("hybrid webhook accepted replacement identity")
			}
			var retainedID string
			if err := srv.db.QueryRow(`SELECT repository_id FROM forge_repository_bindings WHERE repo_id=$1`, repo.ID).Scan(&retainedID); err != nil {
				t.Fatal(err)
			}
			if retainedID != *original.ProviderRepoID {
				t.Fatal("enrollment silently rebound to replacement repository")
			}
		})
	}
}
