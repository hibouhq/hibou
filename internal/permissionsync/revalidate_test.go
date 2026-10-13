package permissionsync

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/store"
)

type revalidationStore struct {
	fakeStore
	stale     []store.StaleForgeOrgMembership
	controls  map[uuid.UUID]string
	admins    int
	touched   []uuid.UUID
	removed   []uuid.UUID
	attempted []uuid.UUID
}

func (r *revalidationStore) ListStaleForgeOrgMemberships(context.Context, time.Time, int) ([]store.StaleForgeOrgMembership, error) {
	return r.stale, nil
}

func (r *revalidationStore) ListForgeOrgMemberForgeIDs(context.Context, uuid.UUID, int) (map[uuid.UUID]string, error) {
	return r.controls, nil
}

func (r *revalidationStore) TouchForgeOrgMember(_ context.Context, _, userID uuid.UUID) error {
	r.touched = append(r.touched, userID)
	return nil
}

func (r *revalidationStore) MarkForgeOrgMemberRevalidationAttempted(_ context.Context, _, userID uuid.UUID) error {
	r.attempted = append(r.attempted, userID)
	return nil
}

func (r *revalidationStore) CountOrgAdmins(context.Context, uuid.UUID) (int, error) {
	return r.admins, nil
}

func (r *revalidationStore) RemoveForgeOrgAccess(_ context.Context, _, userID uuid.UUID) error {
	r.removed = append(r.removed, userID)
	return nil
}

// scriptedVerifier answers from members (keyed by forge user id); after the
// first negative answer it switches to afterNegative when set (a token that
// broke mid-run).
type scriptedVerifier struct {
	members       map[string]bool
	afterNegative map[string]bool
	errs          map[string]error
	levels        map[string]string
	sawNegative   bool
	asked         []string
}

func (v *scriptedVerifier) RepoLevel(_ context.Context, repo, forgeUserID string) (string, error) {
	if err := v.errs[repo+"/"+forgeUserID]; err != nil {
		return "", err
	}
	return v.levels[repo+"/"+forgeUserID], nil
}

func (v *scriptedVerifier) AccountLogin() string { return "acme" }

func (v *scriptedVerifier) IsMember(_ context.Context, login string) (bool, error) {
	v.asked = append(v.asked, login)
	if err := v.errs[login]; err != nil {
		return false, err
	}
	answers := v.members
	if v.sawNegative && v.afterNegative != nil {
		answers = v.afterNegative
	}
	if !answers[login] {
		v.sawNegative = true
		return false, nil
	}
	return true, nil
}

type verifyingForge struct {
	fakeProvider
	verifiers map[string]forge.OrgMembershipVerifier
	err       error
}

func (m verifyingForge) OrgMembershipVerifiers(context.Context) (map[string]forge.OrgMembershipVerifier, error) {
	return m.verifiers, m.err
}

func staleMembership(orgID uuid.UUID, login string, scoped bool, now time.Time) store.StaleForgeOrgMembership {
	synced := now.Add(-13 * time.Hour)
	return store.StaleForgeOrgMembership{
		OrgID: orgID, UserID: uuid.New(), Role: "developer", RepoScoped: scoped, SyncedAt: &synced,
		OrgProvider: "github", OrgSlug: "acme", ForgeAccountLogin: "Acme", ForgeAccountID: "42",
		UserProvider: "github", UserForgeID: login, ForgeLogin: login,
	}
}

func newRevalidationService(st *revalidationStore, rbacFake *fakeRBAC, provider forge.Provider) *Service {
	return NewService(st, rbacFake, map[string]forge.Provider{"github": provider}, zerolog.Nop())
}

func ids(list []uuid.UUID) map[uuid.UUID]bool {
	out := map[uuid.UUID]bool{}
	for _, id := range list {
		out[id] = true
	}
	return out
}

// A member the forge definitively no longer lists loses the membership and
// RBAC role, their local grants are suspended (not revoked); a confirmed
// member is touched. Unverifiable memberships — collaborators, users with no
// recorded login — are kept however old, and stamped so they leave the batch.
func TestRevalidateMembershipsRemovesOnlyDefinitivelyDepartedMembers(t *testing.T) {
	t.Parallel()

	now := time.Now()
	orgID := uuid.New()
	stayed := staleMembership(orgID, "stayed", false, now)
	left := staleMembership(orgID, "left", false, now)
	collaborator := staleMembership(orgID, "collab", true, now)
	ancient := now.Add(-365 * 24 * time.Hour)
	collaborator.SyncedAt = &ancient
	noLogin := staleMembership(orgID, "", false, now)
	noLogin.UserForgeID = "pre-00056"
	noLogin.SyncedAt = nil
	st := &revalidationStore{stale: []store.StaleForgeOrgMembership{stayed, left, collaborator, noLogin}}
	st.localGrants = []store.LocalRoleGrant{{Role: "cve-triager"}}
	rbacFake := &fakeRBAC{}
	verifier := &scriptedVerifier{members: map[string]bool{"stayed": true}}
	svc := newRevalidationService(st, rbacFake, verifyingForge{verifiers: map[string]forge.OrgMembershipVerifier{"42": verifier}})

	if err := svc.RevalidateMemberships(context.Background(), now); err != nil {
		t.Fatalf("RevalidateMemberships() error = %v", err)
	}
	if len(st.touched) != 1 || st.touched[0] != stayed.UserID {
		t.Errorf("touched = %v, want only the confirmed member", st.touched)
	}
	if len(st.removed) != 1 || st.removed[0] != left.UserID {
		t.Errorf("removed = %v, want only the departed member", st.removed)
	}
	if len(rbacFake.removed) != 1 {
		t.Errorf("RBAC roles removed = %+v, want 1", rbacFake.removed)
	}
	if len(st.revokedForOrgs) != 0 || len(st.suspendedReasons) != 1 || len(rbacFake.removedLocal) != 1 {
		t.Errorf("local grants: revoked=%v suspended=%v policies dropped=%v; want suspended only",
			st.revokedForOrgs, st.suspendedReasons, rbacFake.removedLocal)
	}
	attempted := ids(st.attempted)
	if !attempted[collaborator.UserID] || !attempted[noLogin.UserID] {
		t.Errorf("attempted = %v, want the unverifiable rows stamped", st.attempted)
	}
	for _, login := range verifier.asked {
		if login == "collab" || login == "pre-00056" {
			t.Errorf("asked the forge about unverifiable row %q", login)
		}
	}
}

// A forge that answers "not a member" for everyone (broken installation
// token, missing permission) must not empty the org: without a positive
// answer nothing is removed.
func TestRevalidateMembershipsNeedsAPositiveControl(t *testing.T) {
	t.Parallel()

	now := time.Now()
	orgID := uuid.New()
	a := staleMembership(orgID, "a", false, now)
	b := staleMembership(orgID, "b", false, now)
	st := &revalidationStore{stale: []store.StaleForgeOrgMembership{a, b}, controls: map[uuid.UUID]string{uuid.New(): "c"}}
	verifier := &scriptedVerifier{members: map[string]bool{}}
	svc := newRevalidationService(st, &fakeRBAC{}, verifyingForge{verifiers: map[string]forge.OrgMembershipVerifier{"42": verifier}})
	if err := svc.RevalidateMemberships(context.Background(), now); err != nil {
		t.Fatalf("RevalidateMemberships() error = %v", err)
	}
	if len(st.removed) != 0 {
		t.Fatalf("removed %v without any confirmed member", st.removed)
	}
	if attempted := ids(st.attempted); !attempted[a.UserID] || !attempted[b.UserID] {
		t.Fatalf("attempted = %v, want both undecided rows stamped", st.attempted)
	}

	// A confirmed control member makes the answers trustworthy.
	st.attempted = nil
	verifier = &scriptedVerifier{members: map[string]bool{"c": true}}
	svc = newRevalidationService(st, &fakeRBAC{}, verifyingForge{verifiers: map[string]forge.OrgMembershipVerifier{"42": verifier}})
	if err := svc.RevalidateMemberships(context.Background(), now); err != nil {
		t.Fatalf("RevalidateMemberships() error = %v", err)
	}
	if len(st.removed) != 2 {
		t.Fatalf("removed = %v, want both departed members", st.removed)
	}
}

// The control must be confirmed AFTER the negative answers: a member
// confirmed before the token broke proves nothing about the answers after.
func TestRevalidateMembershipsControlFollowsTheNegative(t *testing.T) {
	t.Parallel()

	now := time.Now()
	orgID := uuid.New()
	first := staleMembership(orgID, "first", false, now)
	second := staleMembership(orgID, "second", false, now)
	st := &revalidationStore{stale: []store.StaleForgeOrgMembership{first, second}}
	// "second" reads as gone because the token broke right after "first"
	// was confirmed; from then on nobody reads as a member.
	verifier := &scriptedVerifier{members: map[string]bool{"first": true}, afterNegative: map[string]bool{}}
	svc := newRevalidationService(st, &fakeRBAC{}, verifyingForge{verifiers: map[string]forge.OrgMembershipVerifier{"42": verifier}})
	if err := svc.RevalidateMemberships(context.Background(), now); err != nil {
		t.Fatalf("RevalidateMemberships() error = %v", err)
	}
	if len(st.removed) != 0 {
		t.Fatalf("removed %v on a control confirmed only before the negative answer", st.removed)
	}
	if n := len(verifier.asked); n < 3 || verifier.asked[n-1] != "first" {
		t.Fatalf("asked = %v, want the control re-asked after the negative", verifier.asked)
	}
}

// A failure to list installations aborts the run: nothing is decided, and
// nothing reads as "not installed".
func TestRevalidateMembershipsAbortsOnInstallationListingError(t *testing.T) {
	t.Parallel()

	now := time.Now()
	m := staleMembership(uuid.New(), "someone", false, now)
	st := &revalidationStore{stale: []store.StaleForgeOrgMembership{m}}
	svc := newRevalidationService(st, &fakeRBAC{}, verifyingForge{err: errors.New("github down")})
	if err := svc.RevalidateMemberships(context.Background(), now); err == nil {
		t.Fatal("expected the listing error to abort the run")
	}
	if len(st.removed)+len(st.touched)+len(st.attempted) != 0 {
		t.Fatalf("removed=%v touched=%v attempted=%v, want nothing", st.removed, st.touched, st.attempted)
	}
}

// The account is resolved by the bound immutable id. An org never bound, or
// bound to an id the App is not installed on (even when an installation now
// carries the same login), is unverifiable: nothing is removed.
func TestRevalidateMembershipsResolvesTheAccountByID(t *testing.T) {
	t.Parallel()

	now := time.Now()
	for name, accountID := range map[string]string{"unbound": "", "renamed login re-registered": "42"} {
		m := staleMembership(uuid.New(), "someone", false, now)
		m.ForgeAccountID = accountID
		st := &revalidationStore{stale: []store.StaleForgeOrgMembership{m}, controls: map[uuid.UUID]string{uuid.New(): "c"}}
		// The installation on "acme" today is account 99, not the bound 42.
		verifier := &scriptedVerifier{members: map[string]bool{"c": true}}
		svc := newRevalidationService(st, &fakeRBAC{}, verifyingForge{verifiers: map[string]forge.OrgMembershipVerifier{"99": verifier}})
		if err := svc.RevalidateMemberships(context.Background(), now); err != nil {
			t.Fatalf("%s: RevalidateMemberships() error = %v", name, err)
		}
		if len(st.removed) != 0 || len(verifier.asked) != 0 {
			t.Fatalf("%s: removed=%v asked=%v, want neither", name, st.removed, verifier.asked)
		}
		if len(st.attempted) != 1 {
			t.Fatalf("%s: attempted = %v, want the row stamped", name, st.attempted)
		}
	}
}

// The org's last admin is never removed, even on a definitive answer.
func TestRevalidateMembershipsKeepsTheLastAdmin(t *testing.T) {
	t.Parallel()

	now := time.Now()
	admin := staleMembership(uuid.New(), "boss", false, now)
	admin.Role = "admin"
	st := &revalidationStore{stale: []store.StaleForgeOrgMembership{admin}, controls: map[uuid.UUID]string{uuid.New(): "c"}, admins: 1}
	verifier := &scriptedVerifier{members: map[string]bool{"c": true}}
	svc := newRevalidationService(st, &fakeRBAC{}, verifyingForge{verifiers: map[string]forge.OrgMembershipVerifier{"42": verifier}})
	if err := svc.RevalidateMemberships(context.Background(), now); err != nil {
		t.Fatalf("RevalidateMemberships() error = %v", err)
	}
	if len(st.removed) != 0 {
		t.Fatalf("removed the last admin: %v", st.removed)
	}

	st.admins = 2
	if err := svc.RevalidateMemberships(context.Background(), now); err != nil {
		t.Fatalf("RevalidateMemberships() error = %v", err)
	}
	if len(st.removed) != 1 {
		t.Fatalf("removed = %v, want the admin removed once another admin remains", st.removed)
	}
}

// A forge error keeps the membership and stamps it, so the row does not
// block the batch.
func TestRevalidateMembershipsKeepsMembersOnForgeErrors(t *testing.T) {
	t.Parallel()

	now := time.Now()
	m := staleMembership(uuid.New(), "flaky", false, now)
	st := &revalidationStore{stale: []store.StaleForgeOrgMembership{m}, controls: map[uuid.UUID]string{uuid.New(): "c"}}
	verifier := &scriptedVerifier{members: map[string]bool{"c": true}, errs: map[string]error{"flaky": errors.New("502")}}
	svc := newRevalidationService(st, &fakeRBAC{}, verifyingForge{verifiers: map[string]forge.OrgMembershipVerifier{"42": verifier}})
	if err := svc.RevalidateMemberships(context.Background(), now); err != nil {
		t.Fatalf("RevalidateMemberships() error = %v", err)
	}
	if len(st.removed) != 0 || len(st.attempted) != 1 {
		t.Fatalf("removed=%v attempted=%v, want kept and stamped", st.removed, st.attempted)
	}
}
