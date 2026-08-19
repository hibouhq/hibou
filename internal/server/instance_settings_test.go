package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/config"
	"github.com/hibouhq/hibou/internal/store"
)

func TestIsInstanceAdmin(t *testing.T) {
	srv := &Server{
		cfg: config.Config{InstanceAdmins: []string{"admin@example.com"}},
		log: zerolog.Nop(),
	}

	// No user in context: never an admin.
	anonymous := httptest.NewRequest("GET", "/api/v1/instance/settings/banners", nil)
	if srv.isInstanceAdmin(anonymous) {
		t.Fatal("anonymous request must not be instance admin")
	}

	// Listed email matches case-insensitively.
	admin := anonymous.WithContext(auth.WithUser(anonymous.Context(), &store.User{Email: "Admin@Example.com"}))
	if !srv.isInstanceAdmin(admin) {
		t.Fatal("listed email must be instance admin (case-insensitive)")
	}

	// Org membership is irrelevant: an unlisted user is not an instance admin.
	member := anonymous.WithContext(auth.WithUser(anonymous.Context(), &store.User{Email: "dev@example.com"}))
	if srv.isInstanceAdmin(member) {
		t.Fatal("unlisted email must not be instance admin")
	}
}

// The file-backed list is re-read on every check so a mounted Secret edit
// takes effect live; a transiently unreadable file keeps the last loaded list
// instead of locking everyone out (or keeping a wiped admin in).
func TestInstanceAdminsFileHotReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "emails")
	if err := os.WriteFile(path, []byte("First@Example.com\n"), 0o600); err != nil {
		t.Fatalf("write admins file: %v", err)
	}

	srv := &Server{
		cfg: config.Config{InstanceAdminsFile: path},
		log: zerolog.Nop(),
	}

	requestFor := func(email string) *http.Request {
		req := httptest.NewRequest("GET", "/api/v1/instance/settings/banners", nil)
		return req.WithContext(auth.WithUser(req.Context(), &store.User{Email: email}))
	}

	if !srv.isInstanceAdmin(requestFor("first@example.com")) {
		t.Fatal("file-listed email must be instance admin")
	}

	// Edit the file: the change applies on the very next check, no restart.
	if err := os.WriteFile(path, []byte("second@example.com,third@example.com"), 0o600); err != nil {
		t.Fatalf("rewrite admins file: %v", err)
	}
	if srv.isInstanceAdmin(requestFor("first@example.com")) {
		t.Fatal("removed email must lose instance admin immediately")
	}
	if !srv.isInstanceAdmin(requestFor("second@example.com")) || !srv.isInstanceAdmin(requestFor("third@example.com")) {
		t.Fatal("added emails must gain instance admin immediately")
	}

	// Unreadable file: keep the last successfully loaded list.
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove admins file: %v", err)
	}
	if !srv.isInstanceAdmin(requestFor("second@example.com")) {
		t.Fatal("transient read failure must keep the last loaded list")
	}
}
