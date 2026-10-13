package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store"
)

// SessionIssuedAt returns the signed issue time and refuses tampered or
// missing cookies, so callers can demand a recent sign-in.
func TestSessionIssuedAt(t *testing.T) {
	mgr := New(Config{SessionSecret: testSessionSecret}, nil)
	user := &store.User{ID: uuid.New(), SessionEpoch: 3}
	issued := time.Now().Add(-5 * time.Hour).Truncate(time.Second)

	recorder := httptest.NewRecorder()
	mgr.setSessionCookieAt(recorder, user, issued)
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, cookie := range recorder.Result().Cookies() {
		request.AddCookie(cookie)
	}
	got, err := mgr.SessionIssuedAt(request)
	if err != nil {
		t.Fatalf("SessionIssuedAt: %v", err)
	}
	if !got.Equal(issued) {
		t.Fatalf("issued = %s, want %s", got, issued)
	}

	if _, err := mgr.SessionIssuedAt(httptest.NewRequest(http.MethodGet, "/", nil)); err == nil {
		t.Fatal("no cookie accepted")
	}

	tampered := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, cookie := range recorder.Result().Cookies() {
		parts := strings.Split(cookie.Value, "|")
		parts[2] = "31" // a different (hex) timestamp under the old signature
		cookie.Value = strings.Join(parts, "|")
		tampered.AddCookie(cookie)
	}
	if _, err := mgr.SessionIssuedAt(tampered); err == nil {
		t.Fatal("tampered timestamp accepted")
	}
}
