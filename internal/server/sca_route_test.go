package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSCAEnableRouteDoesNotFallThroughToNotFound(t *testing.T) {
	s := newRoutedTestServer(t)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/orgs/github/example/sca/enable",
		strings.NewReader(`{"provider_ids":["example/app"]}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	s.router.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("registered endpoint should require authentication, not return 404: status=%d body=%s", response.Code, response.Body)
	}
}
