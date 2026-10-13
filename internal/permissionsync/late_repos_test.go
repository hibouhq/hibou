package permissionsync

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/store"
)

type lateRepoStore struct {
	revalidationStore
	candidates []store.LateRepoGrantCandidate
	scoped     []uuid.UUID
}

func (l *lateRepoStore) ListUngrantedLateRepoMembers(context.Context, int) ([]store.LateRepoGrantCandidate, error) {
	return l.candidates, nil
}

func (l *lateRepoStore) SetForgeOrgMemberRepoScoped(_ context.Context, _, userID uuid.UUID) error {
	l.scoped = append(l.scoped, userID)
	return nil
}

func lateCandidate(orgID uuid.UUID, forgeID, repo string) store.LateRepoGrantCandidate {
	return store.LateRepoGrantCandidate{
		OrgID: orgID, UserID: uuid.New(), Role: "viewer", OrgProvider: "github", ForgeAccountID: "42",
		UserProvider: "github", UserForgeID: forgeID, RepoID: uuid.New(), RepoSlug: repo,
	}
}

// A repository enrolled after a member's sync is granted when the forge
// grants it, recorded as withheld (repo_scoped) when it does not, and left
// alone when the forge cannot answer.
func TestGrantLateRepositories(t *testing.T) {
	t.Parallel()

	orgID := uuid.New()
	granted := lateCandidate(orgID, "1", "api")
	withheld := lateCandidate(orgID, "2", "api")
	unknown := lateCandidate(orgID, "3", "api")
	otherAccount := lateCandidate(orgID, "1", "api")
	otherAccount.ForgeAccountID = "99"
	st := &lateRepoStore{candidates: []store.LateRepoGrantCandidate{granted, withheld, unknown, otherAccount}}
	verifier := &scriptedVerifier{
		levels: map[string]string{"api/1": "push", "api/2": ""},
		errs:   map[string]error{"api/3": errors.New("502")},
	}
	svc := newRevalidationService(&st.revalidationStore, &fakeRBAC{}, verifyingForge{verifiers: map[string]forge.OrgMembershipVerifier{"42": verifier}})
	svc.store = st

	if err := svc.GrantLateRepositories(context.Background()); err != nil {
		t.Fatalf("GrantLateRepositories: %v", err)
	}
	if len(st.upsertRepoAccess) != 1 || st.upsertRepoAccess[0].userID != granted.UserID || st.upsertRepoAccess[0].role != "developer" {
		t.Fatalf("grants = %+v, want developer on the repo for the granted member only", st.upsertRepoAccess)
	}
	if len(st.scoped) != 1 || st.scoped[0] != withheld.UserID {
		t.Fatalf("scoped = %v, want only the member the forge withholds the repo from", st.scoped)
	}

	failing := &lateRepoStore{candidates: []store.LateRepoGrantCandidate{granted}}
	svc = newRevalidationService(&failing.revalidationStore, &fakeRBAC{}, verifyingForge{err: errors.New("github down")})
	svc.store = failing
	if err := svc.GrantLateRepositories(context.Background()); err == nil {
		t.Fatal("an installation listing error must abort")
	}
	if len(failing.upsertRepoAccess)+len(failing.scoped) != 0 {
		t.Fatal("decided something without the installation listing")
	}
}

// Re-validation names people by immutable forge id: a member whose recorded
// login was renamed is still confirmed.
func TestRevalidateMembershipsAsksByForgeID(t *testing.T) {
	t.Parallel()

	now := time.Now()
	m := staleMembership(uuid.New(), "old-login", false, now)
	m.UserForgeID = "77"
	st := &revalidationStore{stale: []store.StaleForgeOrgMembership{m}}
	verifier := &scriptedVerifier{members: map[string]bool{"77": true}}
	svc := newRevalidationService(st, &fakeRBAC{}, verifyingForge{verifiers: map[string]forge.OrgMembershipVerifier{"42": verifier}})
	if err := svc.RevalidateMemberships(context.Background(), now); err != nil {
		t.Fatalf("RevalidateMemberships() error = %v", err)
	}
	if len(st.touched) != 1 || len(st.removed) != 0 {
		t.Fatalf("touched=%v removed=%v, want the renamed member confirmed", st.touched, st.removed)
	}
}

// The GitHub forge is what production re-validation runs against.
var _ MembershipVerifierSource = (*forge.GitHub)(nil)
