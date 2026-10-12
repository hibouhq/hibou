package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/config"
	"github.com/hibouhq/hibou/internal/rbac"
	"github.com/hibouhq/hibou/internal/store"
)

func watchRequest(t *testing.T, email string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/instance/advisories/watches",
		strings.NewReader(`{"label":"Apache Tomcat","product_keys":["apachetomcat"]}`))
	return request.WithContext(auth.WithUser(request.Context(),
		&store.User{ID: uuid.New(), Email: email, Provider: "github", ProviderID: "1"}))
}

// The instance-admin list has to be able to change watches, because it is the
// only authority configured outside the database.
//
// The gate this replaced asked Casbin for admin on `instance/*`, which only a
// granted role carries — and granting goes through the same gate. On a fresh
// instance nobody holds a role, so nobody could grant one, so nobody could ever
// create a watch. A closed loop with no entry point, and the feature was
// unusable on every deployment.
func TestWatchWriterAcceptsAnInstanceAdmin(t *testing.T) {
	srv := &Server{
		cfg: config.Config{InstanceAdmins: []string{"admin@example.com"}},
		log: zerolog.Nop(),
	}
	recorder := httptest.NewRecorder()
	user, ok := srv.requireWatchWriter(recorder, watchRequest(t, "admin@example.com"))
	if !ok {
		t.Fatalf("instance admin refused: %d %s", recorder.Code, recorder.Body)
	}
	if user == nil {
		t.Fatal("no user returned for an accepted request")
	}
}

// Everyone else is refused, and told what would let them through. "Requires
// instance authority" names no role and no place to get one.
func TestWatchWriterRefusesAndSaysWhatIsNeeded(t *testing.T) {
	databaseURL := os.Getenv("HIBOU_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = testDatabaseURL
	}
	db, err := store.New(databaseURL)
	if err != nil {
		t.Skipf("database not available: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := store.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	enforcer, err := rbac.New(db)
	if err != nil {
		t.Skipf("rbac enforcer unavailable: %v", err)
	}
	srv := &Server{
		cfg:      config.Config{InstanceAdmins: []string{"admin@example.com"}},
		enforcer: enforcer,
		log:      zerolog.Nop(),
	}
	recorder := httptest.NewRecorder()
	if _, ok := srv.requireWatchWriter(recorder, watchRequest(t, "dev@example.com")); ok {
		t.Fatal("a user with no role was allowed to change watches")
	}
	if recorder.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), rbac.RoleSubscriptionWriter) {
		t.Errorf("refusal does not name the role that would grant access: %s", recorder.Body)
	}
}

// Anonymous is 401, not 403: there is nothing to refuse yet.
func TestWatchWriterRejectsAnonymous(t *testing.T) {
	srv := &Server{cfg: config.Config{}, log: zerolog.Nop()}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/instance/advisories/watches", nil)
	if _, ok := srv.requireWatchWriter(recorder, request); ok {
		t.Fatal("anonymous request was allowed")
	}
	if recorder.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", recorder.Code)
	}
}

// Granting a local role is itself gated, and must stay reachable for the same
// bootstrap reason.
func TestInstanceAuthorityAcceptsAnInstanceAdmin(t *testing.T) {
	srv := &Server{
		cfg: config.Config{InstanceAdmins: []string{"admin@example.com"}},
		log: zerolog.Nop(),
	}
	recorder := httptest.NewRecorder()
	if _, ok := srv.requireInstanceAuthority(recorder, watchRequest(t, "admin@example.com")); !ok {
		t.Fatalf("instance admin cannot grant roles: %d %s", recorder.Code, recorder.Body)
	}
	other := httptest.NewRecorder()
	if _, ok := srv.requireInstanceAuthority(other, watchRequest(t, "dev@example.com")); ok {
		t.Fatal("a non-admin was allowed to grant roles")
	}
}
