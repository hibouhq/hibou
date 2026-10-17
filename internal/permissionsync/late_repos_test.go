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

// countingVerifier answers RepoLevel from a function and counts the calls.
type countingVerifier struct {
	scriptedVerifier
	answer func(repo, forgeUserID string) (string, error)
	calls  map[string]int
}

func (v *countingVerifier) RepoLevel(_ context.Context, repo, forgeUserID string) (string, error) {
	if v.calls == nil {
		v.calls = map[string]int{}
	}
	v.calls[repo]++
	return v.answer(repo, forgeUserID)
}

// A repository the forge does not know (an upload can enrol any name) is
// asked about once per backoff period, not once per member every run; a
// failing pair backs off too; and one run never spends more than its budget
// on an installation.
func TestGrantLateRepositoriesBacksOffAndBudgets(t *testing.T) {
	t.Parallel()

	orgID := uuid.New()
	var candidates []store.LateRepoGrantCandidate
	ghostID := uuid.New()
	for i := 0; i < 3; i++ {
		c := lateCandidate(orgID, "g"+string(rune('a'+i)), "ghost")
		c.RepoID = ghostID // one repository, three members
		candidates = append(candidates, c)
	}
	for i := 0; i < 2*lateRepoCallsPerAccount; i++ {
		candidates = append(candidates, lateCandidate(orgID, "u"+uuid.NewString(), "api"))
	}
	st := &lateRepoStore{candidates: candidates}
	verifier := &countingVerifier{answer: func(repo, _ string) (string, error) {
		if repo == "ghost" {
			return "", forge.ErrRepositoryNotFound
		}
		return "", errors.New("502")
	}}
	svc := newRevalidationService(&st.revalidationStore, &fakeRBAC{}, verifyingForge{verifiers: map[string]forge.OrgMembershipVerifier{"42": verifier}})
	svc.store = st
	now := time.Now()
	svc.clock = func() time.Time { return now }

	if err := svc.GrantLateRepositories(context.Background()); err != nil {
		t.Fatalf("GrantLateRepositories: %v", err)
	}
	if got := verifier.calls["ghost"]; got != 1 {
		t.Errorf("unknown repository asked %d times in one run, want 1", got)
	}
	if total := verifier.calls["ghost"] + verifier.calls["api"]; total != lateRepoCallsPerAccount {
		t.Errorf("one run asked %d questions of one installation, want the budget %d", total, lateRepoCallsPerAccount)
	}

	// Next run, five minutes later: everything that failed is backing off,
	// so only the pairs the first run had no budget for are asked.
	verifier.calls = nil
	now = now.Add(5 * time.Minute)
	if err := svc.GrantLateRepositories(context.Background()); err != nil {
		t.Fatalf("GrantLateRepositories (second run): %v", err)
	}
	if got := verifier.calls["ghost"]; got != 0 {
		t.Errorf("unknown repository asked again during its backoff (%d)", got)
	}
	if got := verifier.calls["api"]; got != lateRepoCallsPerAccount {
		t.Errorf("second run asked %d of the remaining pairs, want %d", got, lateRepoCallsPerAccount)
	}

	// After the backoff, the unknown repository is asked once more.
	verifier.calls = nil
	now = now.Add(lateRepoBackoffMin)
	if err := svc.GrantLateRepositories(context.Background()); err != nil {
		t.Fatalf("GrantLateRepositories (after backoff): %v", err)
	}
	if got := verifier.calls["ghost"]; got != 1 {
		t.Errorf("unknown repository asked %d times after its backoff, want 1", got)
	}
}
