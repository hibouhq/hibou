package ws

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// The websocket handler lifts the server-wide deadlines itself, after the
// session check (the hardening middleware no longer does it for anonymous
// callers). liftDeadlines must actually clear the write deadline.
func TestLiftDeadlinesClearsServerWriteTimeout(t *testing.T) {
	t.Parallel()

	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/lifted" {
			liftDeadlines(w)
		}
		time.Sleep(300 * time.Millisecond)
		_, _ = io.WriteString(w, "late")
	}))
	backend.Config.WriteTimeout = 100 * time.Millisecond
	backend.Start()
	defer backend.Close()

	get := func(path string) string {
		resp, err := backend.Client().Get(backend.URL + path)
		if err != nil {
			return ""
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return string(body)
	}
	if got := get("/lifted"); got != "late" {
		t.Fatalf("lifted: body %q, want the late write delivered", got)
	}
	if got := get("/kept"); got == "late" {
		t.Fatal("without liftDeadlines the write timeout must apply")
	}
}
