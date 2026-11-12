package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestManagedExecutionRemainsDisabledPendingApprovedBackend(t *testing.T) {
	t.Setenv("HIBOU_REMEDIATION_CONTROLLER", "true")
	t.Setenv("HIBOU_REMEDIATION_ENABLED", "false")
	recorder := httptest.NewRecorder()
	if (&Server{}).requireManagedExecution(recorder, httptest.NewRequest(http.MethodPost, "/", nil)) {
		t.Fatal("legacy controller configuration enabled an unapproved executor")
	}
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), "ADR-056") {
		t.Fatalf("managed execution did not fail explicitly: %d %s", recorder.Code, recorder.Body.String())
	}
}
