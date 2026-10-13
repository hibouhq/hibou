package ws

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/store"
)

// A valid session whose user the sign-in allowlist no longer admits is
// refused before the upgrade, not after the first session re-check.
func TestHTTPHandlerRefusesUsersOutsideTheAllowlist(t *testing.T) {
	databaseURL := os.Getenv("HIBOU_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = "postgres://hibou:hibou@localhost:5432/hibou_test?sslmode=disable"
	}
	db, err := store.New(databaseURL)
	if err != nil {
		t.Skipf("database not available: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := store.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	queries := store.NewQueries(db)
	ctx := context.Background()
	suffix := uuid.NewString()
	user, err := queries.CreateUser(ctx, "ws-allowlist-"+suffix+"@example.com", "WS", "github", "ws-allowlist-"+suffix)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	dial := func(allowed []string) int {
		t.Helper()
		mgr := auth.New(auth.Config{SessionSecret: "test-session-secret", AllowedUsers: allowed, Log: zerolog.Nop()}, queries)
		recorder := httptest.NewRecorder()
		mgr.SetSessionCookie(recorder, user)
		server := httptest.NewServer(NewHub(zerolog.Nop()).HTTPHandler(mgr, queries))
		defer server.Close()

		header := http.Header{}
		for _, cookie := range recorder.Result().Cookies() {
			header.Add("Cookie", cookie.Name+"="+cookie.Value)
		}
		dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		conn, resp, err := websocket.Dial(dialCtx, "ws"+strings.TrimPrefix(server.URL, "http"), &websocket.DialOptions{HTTPHeader: header})
		if err == nil {
			_ = conn.Close(websocket.StatusNormalClosure, "test complete")
			return http.StatusSwitchingProtocols
		}
		if resp == nil {
			t.Fatalf("dial failed without a response: %v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	if status := dial([]string{"github:someone-else"}); status != http.StatusForbidden {
		t.Fatalf("user outside the allowlist: status %d, want 403", status)
	}
	if status := dial([]string{"github:" + user.ProviderID}); status != http.StatusSwitchingProtocols {
		t.Fatalf("allowlisted user: status %d, want the upgrade", status)
	}
}
