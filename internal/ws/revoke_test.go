package ws

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// S3: revoking a user's sessions closes their sockets on this replica and
// leaves other users' alone.
func TestCloseUserClosesOnlyThatUsersSockets(t *testing.T) {
	hub := NewHub(zerolog.Nop())
	revoked, kept := uuid.New(), uuid.New()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		owner := kept
		if r.URL.Query().Get("revoked") != "" {
			owner = revoked
		}
		c := hub.Register(conn, owner)
		defer hub.Unregister(c)
		for {
			if _, _, err := conn.Read(context.Background()); err != nil {
				return
			}
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	url := "ws" + strings.TrimPrefix(server.URL, "http")
	dial := func(suffix string) *websocket.Conn {
		conn, resp, err := websocket.Dial(ctx, url+suffix, nil)
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() { _ = conn.CloseNow() })
		return conn
	}
	revokedConn := dial("?revoked=1")
	dial("")
	for hub.userConnectionCount(revoked) == 0 || hub.userConnectionCount(kept) == 0 {
		if ctx.Err() != nil {
			t.Fatal("timed out waiting for registration")
		}
		time.Sleep(10 * time.Millisecond)
	}

	hub.CloseUser(revoked)
	if _, _, err := revokedConn.Read(ctx); websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Fatalf("revoked socket read err = %v, want policy-violation close", err)
	}
	for hub.userConnectionCount(revoked) != 0 {
		if ctx.Err() != nil {
			t.Fatal("revoked connection still registered")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if hub.userConnectionCount(kept) != 1 {
		t.Fatal("another user's socket was closed")
	}
}

// Other replicas: the session re-check closes a socket whose session no
// longer validates.
func TestWatchSessionClosesRevokedSession(t *testing.T) {
	t.Parallel()

	conn := &fakePinger{}
	var valid atomic.Bool
	valid.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		watchSession(ctx, conn, 5*time.Millisecond, func(context.Context) bool { return valid.Load() })
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	conn.mu.Lock()
	closedEarly := conn.closed
	conn.mu.Unlock()
	if closedEarly {
		t.Fatal("valid session closed")
	}
	valid.Store(false)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watchSession did not return")
	}
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if !conn.closed {
		t.Fatal("revoked session not closed")
	}
}
