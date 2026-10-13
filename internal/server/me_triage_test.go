package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/config"
)

// The SPA hides the CVE triage tab unless /users/me says the caller holds the
// instance-wide authority the triage routes require.
func TestGetMeReportsCVETriageAuthority(t *testing.T) {
	srv := &Server{
		cfg: config.Config{InstanceAdmins: []string{"admin@example.com"}},
		log: zerolog.Nop(),
	}
	for email, want := range map[string]bool{"admin@example.com": true, "dev@example.com": false} {
		request := watchRequest(t, email)
		request.Method = http.MethodGet
		recorder := httptest.NewRecorder()
		srv.handleGetMe(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s: status %d", email, recorder.Code)
		}
		var body struct {
			Data struct {
				CanTriageCVEs bool `json:"can_triage_cves"`
			} `json:"data"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s: decode: %v", email, err)
		}
		if body.Data.CanTriageCVEs != want {
			t.Errorf("%s: can_triage_cves = %v, want %v", email, body.Data.CanTriageCVEs, want)
		}
	}
}
