package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

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
