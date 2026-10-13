package permissionsync

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"golang.org/x/oauth2"

	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/store"
)

type revalidationStore struct {
	fakeStore
	stale    []store.StaleForgeOrgMembership
	controls map[uuid.UUID]string
	touched  []uuid.UUID
	removed  []uuid.UUID
}

func (r *revalidationStore) ListStaleForgeOrgMemberships(context.Context, time.Time, int) ([]store.StaleForgeOrgMembership, error) {
	return r.stale, nil
}

func (r *revalidationStore) ListForgeOrgMemberLogins(context.Context, uuid.UUID, int) (map[uuid.UUID]string, error) {
	return r.controls, nil
}

func (r *revalidationStore) TouchForgeOrgMember(_ context.Context, _, userID uuid.UUID) error {
	r.touched = append(r.touched, userID)
	return nil
}

func (r *revalidationStore) RemoveForgeOrgAccess(_ context.Context, _, userID uuid.UUID) error {
	r.removed = append(r.removed, userID)
	return nil
}

type membershipForge struct {
	fakeProvider
	members   map[string]bool
	installed map[string]string
}

func (m membershipForge) IsOrgMember(_ context.Context, token *oauth2.Token, login, _ string) (bool, error) {
	if token != nil {
		panic("re-validation must use the installation token")
	}
	return m.members[login], nil
}

func (m membershipForge) InstallationAccountIDs(context.Context) (map[string]string, error) {
	return m.installed, nil
}

func staleMembership(orgID uuid.UUID, login string, scoped bool, syncedAgo time.Duration, now time.Time) store.StaleForgeOrgMembership {
	synced := now.Add(-syncedAgo)
	return store.StaleForgeOrgMembership{
		OrgID: orgID, UserID: uuid.New(), Role: "developer", RepoScoped: scoped, SyncedAt: &synced,
		OrgProvider: "github", OrgSlug: "acme", ForgeAccountLogin: "Acme", UserProvider: "github", ForgeLogin: login,
	}
}

// Q4: a member the forge no longer lists loses the membership; a confirmed
// one is touched; unverifiable memberships expire only after
// unverifiableMaxAge.
func TestRevalidateMembershipsRemovesDepartedMembers(t *testing.T) {
	t.Parallel()

	now := time.Now()
	orgID := uuid.New()
	stayed := staleMembership(orgID, "stayed", false, 13*time.Hour, now)
	left := staleMembership(orgID, "left", false, 13*time.Hour, now)
	freshCollaborator := staleMembership(orgID, "", true, 48*time.Hour, now)
	oldCollaborator := staleMembership(orgID, "", true, 31*24*time.Hour, now)
	st := &revalidationStore{stale: []store.StaleForgeOrgMembership{stayed, left, freshCollaborator, oldCollaborator}}
	rbacFake := &fakeRBAC{}
	provider := membershipForge{members: map[string]bool{"stayed": true}, installed: map[string]string{"acme": "1"}}
	svc := NewService(st, rbacFake, map[string]forge.Provider{"github": provider}, zerolog.Nop())

	if err := svc.RevalidateMemberships(context.Background(), now); err != nil {
		t.Fatalf("RevalidateMemberships() error = %v", err)
	}
	if len(st.touched) != 1 || st.touched[0] != stayed.UserID {
		t.Errorf("touched = %v, want only the confirmed member", st.touched)
	}
	removed := map[uuid.UUID]bool{}
	for _, id := range st.removed {
		removed[id] = true
	}
	if !removed[left.UserID] || !removed[oldCollaborator.UserID] || removed[stayed.UserID] || removed[freshCollaborator.UserID] {
		t.Errorf("removed = %v, want the departed member and the expired collaborator", st.removed)
	}
	if len(rbacFake.removed) != 2 {
		t.Errorf("RBAC roles removed = %+v, want 2", rbacFake.removed)
	}
}

// A forge that answers "not a member" for everyone (broken installation
// token, missing permission) must not empty the org: without one positive
// answer nothing is removed.
func TestRevalidateMembershipsNeedsAPositiveControl(t *testing.T) {
	t.Parallel()

	now := time.Now()
	orgID := uuid.New()
	a := staleMembership(orgID, "a", false, 13*time.Hour, now)
	b := staleMembership(orgID, "b", false, 13*time.Hour, now)
	st := &revalidationStore{stale: []store.StaleForgeOrgMembership{a, b}, controls: map[uuid.UUID]string{uuid.New(): "c"}}
	provider := membershipForge{members: map[string]bool{}, installed: map[string]string{"acme": "1"}}
	svc := NewService(st, &fakeRBAC{}, map[string]forge.Provider{"github": provider}, zerolog.Nop())
	if err := svc.RevalidateMemberships(context.Background(), now); err != nil {
		t.Fatalf("RevalidateMemberships() error = %v", err)
	}
	if len(st.removed) != 0 {
		t.Fatalf("removed %v without any confirmed member", st.removed)
	}

	// A confirmed control member makes the answers trustworthy.
	provider.members["c"] = true
	svc = NewService(st, &fakeRBAC{}, map[string]forge.Provider{"github": provider}, zerolog.Nop())
	if err := svc.RevalidateMemberships(context.Background(), now); err != nil {
		t.Fatalf("RevalidateMemberships() error = %v", err)
	}
	if len(st.removed) != 2 {
		t.Fatalf("removed = %v, want both departed members", st.removed)
	}
}

// Not installed on the account: the check would run without a token, so the
// memberships are unverifiable, not removed.
func TestRevalidateMembershipsSkipsUninstalledAccounts(t *testing.T) {
	t.Parallel()

	now := time.Now()
	m := staleMembership(uuid.New(), "someone", false, 13*time.Hour, now)
	st := &revalidationStore{stale: []store.StaleForgeOrgMembership{m}}
	provider := membershipForge{members: map[string]bool{"x": true}, installed: map[string]string{}}
	svc := NewService(st, &fakeRBAC{}, map[string]forge.Provider{"github": provider}, zerolog.Nop())
	if err := svc.RevalidateMemberships(context.Background(), now); err != nil {
		t.Fatalf("RevalidateMemberships() error = %v", err)
	}
	if len(st.removed) != 0 || len(st.touched) != 0 {
		t.Fatalf("removed=%v touched=%v, want neither", st.removed, st.touched)
	}
}
