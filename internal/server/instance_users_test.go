package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/audit"
	internalauth "github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/rbac"
	"github.com/hibouhq/hibou/internal/store"
)

func callAnonymize(t *testing.T, srv *Server, actor *store.User, userID string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/instance/users/"+userID+"/anonymize", nil)
	req = req.WithContext(internalauth.WithUser(req.Context(), actor))
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("userID", userID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeCtx))
	rec := httptest.NewRecorder()
	srv.handleAnonymizeUser(rec, req)
	return rec
}

// S3: an instance admin can erase a person: sessions and personal keys die,
// memberships go, identifying fields are blanked, the forge identity is
// detached, and the act is audited.
func TestAnonymizeUser(t *testing.T) {
	srv, org, admin, member := newDiscoveryTestServer(t)
	srv.cfg.InstanceAdmins = []string{strings.ToLower("github:" + admin.ProviderID)}
	ctx := context.Background()

	team, err := srv.queries.CreateTeam(ctx, org.ID, "Sec", uniqueName(t, "anon-team"))
	if err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	if err := srv.queries.AddTeamMember(ctx, team.ID, member.ID, "developer"); err != nil {
		t.Fatalf("AddTeamMember: %v", err)
	}
	if _, err := srv.queries.CreateAPIKey(ctx, member.ID, "personal", uniqueName(t, "anon-key-hash"), json.RawMessage(`{}`), nil, "user", &member.ID, ""); err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	if err := srv.queries.GrantLocalRole(ctx, member.ID, rbac.RoleCVETriager, nil, admin.ID); err != nil {
		t.Fatalf("GrantLocalRole: %v", err)
	}
	before, err := srv.queries.GetUserByID(ctx, member.ID)
	if err != nil || before == nil {
		t.Fatalf("GetUserByID: %v", err)
	}

	// Not an instance admin: refused.
	if rec := callAnonymize(t, srv, member, admin.ID.String()); rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin status = %d, want 403", rec.Code)
	}
	// Self-anonymization is refused (it would lock the operator out mid-act).
	if rec := callAnonymize(t, srv, admin, admin.ID.String()); rec.Code != http.StatusBadRequest {
		t.Fatalf("self status = %d, want 400", rec.Code)
	}

	rec := callAnonymize(t, srv, admin, member.ID.String())
	if rec.Code != http.StatusOK {
		t.Fatalf("anonymize status = %d (%s)", rec.Code, rec.Body.String())
	}

	after, err := srv.queries.GetUserByID(ctx, member.ID)
	if err != nil || after == nil {
		t.Fatalf("GetUserByID after: %v", err)
	}
	label := "deleted-" + member.ID.String()
	if after.Email != "" || after.DisplayName != label || after.AvatarURL != nil || after.ProviderID != label {
		t.Fatalf("user after anonymize = %+v", after)
	}
	if after.SessionEpoch <= before.SessionEpoch {
		t.Fatalf("session epoch %d -> %d, want bumped", before.SessionEpoch, after.SessionEpoch)
	}
	if role, _ := srv.queries.GetOrgMemberRole(ctx, org.ID, member.ID); role != "" {
		t.Fatalf("org role after anonymize = %q, want none", role)
	}
	var remaining int
	if err := srv.db.QueryRowContext(ctx, `
		SELECT (SELECT count(*) FROM api_keys WHERE user_id = $1 AND owner_type = 'user')
		     + (SELECT count(*) FROM team_members WHERE user_id = $1)
		     + (SELECT count(*) FROM local_role_grants WHERE user_id = $1)`, member.ID).Scan(&remaining); err != nil {
		t.Fatalf("count remaining: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("%d keys/team memberships/grants survive anonymization", remaining)
	}

	entry := findAuditAction(auditEntriesFor(t, srv, "user", member.ID.String()), audit.ActionUserAnonymize)
	if entry == nil {
		t.Fatal("anonymization not audited")
	}
	if strings.Contains(string(entry.Context), before.Email) {
		t.Fatalf("audit context keeps the erased email: %s", entry.Context)
	}

	if rec := callAnonymize(t, srv, admin, "00000000-0000-0000-0000-000000000001"); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown user status = %d, want 404", rec.Code)
	}
}

// Anonymization keeps the org's CI keys working (their creator is detached,
// as on user deletion), clears the forge login and allowlist confirmation,
// drops the removed memberships' RBAC roles and runs the session revoke hooks
// (which close websockets). It is refused while the user is an org's last
// admin.
func TestAnonymizeUserKeepsOrgKeysAndRefusesLastAdmin(t *testing.T) {
	srv, org, admin, member := newDiscoveryTestServer(t)
	srv.cfg.InstanceAdmins = []string{strings.ToLower("github:" + admin.ProviderID)}
	ctx := context.Background()
	enforcer, err := rbac.New(srv.db)
	if err != nil {
		t.Skipf("rbac enforcer unavailable: %v", err)
	}
	srv.enforcer = enforcer
	srv.authMgr = internalauth.New(internalauth.Config{SessionSecret: "test-session-secret"}, srv.queries)
	var hooked []string
	srv.authMgr.AddRevokeHook(func(userID uuid.UUID) { hooked = append(hooked, userID.String()) })

	if err := enforcer.AddRoleForUserInOrg(member.ID, "viewer", org.ID); err != nil {
		t.Fatalf("AddRoleForUserInOrg: %v", err)
	}
	if err := srv.queries.SetUserForgeLogin(ctx, member.ID, "octo-member"); err != nil {
		t.Fatalf("SetUserForgeLogin: %v", err)
	}
	now := time.Now()
	if err := srv.queries.SetUserSignInAllowedAt(ctx, member.ID, &now); err != nil {
		t.Fatalf("SetUserSignInAllowedAt: %v", err)
	}
	orgKeyHash := uniqueName(t, "anon-org-key-hash")
	if _, err := srv.queries.CreateAPIKey(ctx, member.ID, "ci", orgKeyHash, json.RawMessage(`{}`), nil, "org", &org.ID, ""); err != nil {
		t.Fatalf("CreateAPIKey(org): %v", err)
	}

	// The member is the only admin of a second org: refused, with its name.
	solo, err := srv.queries.CreateOrganization(ctx, uniqueName(t, "solo-org"), uniqueName(t, "solo-org"), "Solo", "github")
	if err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	if err := srv.queries.AddOrgMember(ctx, solo.ID, member.ID, "admin"); err != nil {
		t.Fatalf("AddOrgMember: %v", err)
	}
	rec := callAnonymize(t, srv, admin, member.ID.String())
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), solo.Name) {
		t.Fatalf("last admin status = %d (%s), want 409 naming %s", rec.Code, rec.Body.String(), solo.Name)
	}
	if after, _ := srv.queries.GetUserByID(ctx, member.ID); after == nil || after.Email == "" {
		t.Fatal("a refused anonymization changed the user")
	}

	if err := srv.queries.AddOrgMember(ctx, solo.ID, admin.ID, "admin"); err != nil {
		t.Fatalf("AddOrgMember(second admin): %v", err)
	}
	// A key the member created in an org they have since left is refused
	// today (creator_membership_valid); anonymizing must not revive it by
	// detaching its creator.
	left, err := srv.queries.CreateOrganization(ctx, uniqueName(t, "left-org"), uniqueName(t, "left-org"), "Left", "github")
	if err != nil {
		t.Fatalf("CreateOrganization(left): %v", err)
	}
	leftKeyHash := uniqueName(t, "anon-left-org-key-hash")
	if _, err := srv.queries.CreateAPIKey(ctx, member.ID, "ci", leftKeyHash, json.RawMessage(`{}`), nil, "org", &left.ID, ""); err != nil {
		t.Fatalf("CreateAPIKey(left org): %v", err)
	}
	if key, err := srv.queries.GetAPIKeyByHash(ctx, leftKeyHash); err != nil || key == nil || !key.CreatorLeftOrg {
		t.Fatalf("precondition: the departed creator's key must be refused (%v, %v)", key, err)
	}
	rec = callAnonymize(t, srv, admin, member.ID.String())
	if rec.Code != http.StatusOK {
		t.Fatalf("anonymize status = %d (%s)", rec.Code, rec.Body.String())
	}

	after, err := srv.queries.GetUserByID(ctx, member.ID)
	if err != nil || after == nil {
		t.Fatalf("GetUserByID after: %v", err)
	}
	if after.ForgeLogin != "" || after.SignInAllowedAt != nil {
		t.Fatalf("forge login %q / signin_allowed_at %v survive anonymization", after.ForgeLogin, after.SignInAllowedAt)
	}
	key, err := srv.queries.GetAPIKeyByHash(ctx, orgKeyHash)
	if err != nil || key == nil {
		t.Fatalf("org key after anonymize: %v, %v", key, err)
	}
	if err := internalauth.ValidateAPIKey(key, time.Now()); err != nil {
		t.Fatalf("org-owned CI key stopped working: %v", err)
	}
	if revived, err := srv.queries.GetAPIKeyByHash(ctx, leftKeyHash); err != nil || revived != nil {
		t.Fatalf("the key of an org the user had left survives anonymization: %+v, %v", revived, err)
	}
	if !strings.Contains(rec.Body.String(), `"org_api_keys_revoked":1`) {
		t.Fatalf("response does not count the revoked key: %s", rec.Body.String())
	}
	if roles := enforcer.GetRolesForUserInOrg(member.ID, org.ID); len(roles) != 0 {
		t.Fatalf("RBAC org roles survive anonymization: %v", roles)
	}
	if len(hooked) != 1 || hooked[0] != member.ID.String() {
		t.Fatalf("revoke hooks ran for %v, want the anonymized user once", hooked)
	}
}
