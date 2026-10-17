package permissionsync

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/events"
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
// member is touched. A user with no recorded login is asked by forge id like
// anyone else. A repo-scoped membership the store cannot re-check per
// repository is kept however old, and stamped so it leaves the batch.
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
	removed := ids(st.removed)
	if len(st.removed) != 2 || !removed[left.UserID] || !removed[noLogin.UserID] {
		t.Errorf("removed = %v, want the departed member and the departed user without a recorded login", st.removed)
	}
	if len(rbacFake.removed) != 2 {
		t.Errorf("RBAC roles removed = %+v, want 2", rbacFake.removed)
	}
	if len(st.revokedForOrgs) != 0 || len(st.suspendedReasons) != 2 || len(rbacFake.removedLocal) != 2 {
		t.Errorf("local grants: revoked=%v suspended=%v policies dropped=%v; want suspended only",
			st.revokedForOrgs, st.suspendedReasons, rbacFake.removedLocal)
	}
	attempted := ids(st.attempted)
	if !attempted[collaborator.UserID] {
		t.Errorf("attempted = %v, want the unverifiable collaborator stamped", st.attempted)
	}
	askedNoLogin := false
	for _, login := range verifier.asked {
		if login == "collab" {
			t.Errorf("asked org membership for a repo-scoped collaborator")
		}
		if login == "pre-00056" {
			askedNoLogin = true
		}
	}
	if !askedNoLogin {
		t.Error("a user without a recorded login was not asked about by forge id")
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
	bus := &recordingBus{}
	svc.WithPublisher(bus)
	if err := svc.RevalidateMemberships(context.Background(), now); err != nil {
		t.Fatalf("RevalidateMemberships() error = %v", err)
	}
	if len(st.removed) != 0 {
		t.Fatalf("removed the last admin: %v", st.removed)
	}
	if len(bus.events) != 1 || bus.events[0].Type != events.ForgeAdminDeparted {
		t.Fatalf("events = %+v, want one %s so an operator is told", bus.events, events.ForgeAdminDeparted)
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

// grantStore adds per-repository grants to the revalidation fake.
type grantStore struct {
	*revalidationStore
	grants  map[uuid.UUID][]store.ForgeRepoGrant
	deleted []uuid.UUID
}

func (g *grantStore) ListForgeRepoGrantsInOrg(_ context.Context, _, userID uuid.UUID) ([]store.ForgeRepoGrant, error) {
	return g.grants[userID], nil
}

func (g *grantStore) DeleteForgeUserRepoAccess(_ context.Context, _, repoID uuid.UUID) error {
	g.deleted = append(g.deleted, repoID)
	return nil
}

// Repo-scoped members (outside collaborators) are re-checked per granted
// repository: a withdrawn repository loses its grant, a member with none
// left loses the membership, an error keeps the grant, and nothing is
// removed when the positive control fails.
func TestRevalidateRepoScopedMembersPerRepository(t *testing.T) {
	t.Parallel()

	now := time.Now()
	orgID := uuid.New()
	stayed := staleMembership(orgID, "stayed", false, now)
	partial := staleMembership(orgID, "partial", true, now)
	gone := staleMembership(orgID, "gone", true, now)
	flaky := staleMembership(orgID, "flaky", true, now)
	apiRepo, webRepo, oldRepo := uuid.New(), uuid.New(), uuid.New()
	base := &revalidationStore{stale: []store.StaleForgeOrgMembership{stayed, partial, gone, flaky}}
	st := &grantStore{revalidationStore: base, grants: map[uuid.UUID][]store.ForgeRepoGrant{
		partial.UserID: {{RepoID: apiRepo, Slug: "api", Role: "viewer"}, {RepoID: webRepo, Slug: "web", Role: "viewer"}},
		gone.UserID:    {{RepoID: oldRepo, Slug: "old", Role: "viewer"}},
		flaky.UserID:   {{RepoID: apiRepo, Slug: "api", Role: "viewer"}},
	}}
	verifier := &scriptedVerifier{
		members: map[string]bool{"stayed": true},
		levels:  map[string]string{"api/partial": "push", "web/partial": "", "old/gone": ""},
		errs:    map[string]error{"api/flaky": errors.New("502")},
	}
	svc := newRevalidationService(base, &fakeRBAC{}, verifyingForge{verifiers: map[string]forge.OrgMembershipVerifier{"42": verifier}})
	svc.store = st

	if err := svc.RevalidateMemberships(context.Background(), now); err != nil {
		t.Fatalf("RevalidateMemberships() error = %v", err)
	}
	deleted := ids(st.deleted)
	if len(st.deleted) != 2 || !deleted[webRepo] || !deleted[oldRepo] {
		t.Errorf("deleted grants = %v, want web (partial) and old (gone)", st.deleted)
	}
	if len(base.removed) != 1 || base.removed[0] != gone.UserID {
		t.Errorf("removed = %v, want only the collaborator with no repository left", base.removed)
	}
	upgraded := false
	for _, grant := range base.upsertRepoAccess {
		if grant.userID == partial.UserID && grant.role == "developer" {
			upgraded = true
		}
	}
	if !upgraded {
		t.Errorf("the forge's new level was not recorded: %+v", base.upsertRepoAccess)
	}
	if !ids(base.attempted)[flaky.UserID] {
		t.Error("a member whose repository check failed was not stamped as attempted")
	}

	// Positive control fails: the forge confirms nobody, so its "none"
	// answers are not trusted.
	base2 := &revalidationStore{stale: []store.StaleForgeOrgMembership{gone}}
	st2 := &grantStore{revalidationStore: base2, grants: map[uuid.UUID][]store.ForgeRepoGrant{
		gone.UserID: {{RepoID: oldRepo, Slug: "old", Role: "viewer"}},
	}}
	verifier2 := &scriptedVerifier{levels: map[string]string{"old/gone": ""}}
	svc2 := newRevalidationService(base2, &fakeRBAC{}, verifyingForge{verifiers: map[string]forge.OrgMembershipVerifier{"42": verifier2}})
	svc2.store = st2
	if err := svc2.RevalidateMemberships(context.Background(), now); err != nil {
		t.Fatalf("RevalidateMemberships() error = %v", err)
	}
	if len(st2.deleted)+len(base2.removed) != 0 {
		t.Errorf("removed without a positive control: grants=%v memberships=%v", st2.deleted, base2.removed)
	}
}

type recordingBus struct{ events []events.Event }

func (b *recordingBus) Publish(_ context.Context, event events.Event) {
	b.events = append(b.events, event)
}
