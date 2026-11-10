package forge

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGitHubRetiresOnlyOwnPendingGateWithoutCreatingChecks(t *testing.T) {
	tokens := &tokenServer{}
	tokenHandler := tokens.handler(reportInstallation)
	retired, patched, created := false, 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/repos/acme/app/commits/head/check-runs":
			status := "in_progress"
			if retired {
				status = "completed"
			}
			fmt.Fprintf(w, `{"total_count":4,"check_runs":[
				{"id":10,"name":"hibou/security","status":%q,"app":{"id":1}},
				{"id":11,"name":"hibou/security","status":"in_progress","app":{"id":2}},
				{"id":12,"name":"hibou/security","status":"completed","app":{"id":1}},
				{"id":13,"name":"other/check","status":"in_progress","app":{"id":1}}]}`, status)
		case r.Method == http.MethodPatch && r.URL.Path == "/repos/acme/app/check-runs/10":
			var body struct {
				Status, Conclusion string
				Output             struct{ Title, Summary string }
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if body.Status != "completed" || body.Conclusion != "neutral" || body.Output.Summary != retiredGateSummary {
				t.Errorf("unexpected retirement: %+v", body)
			}
			retired = true
			patched++
			fmt.Fprint(w, `{"id":10}`)
		case r.Method == http.MethodPost && r.URL.Path == "/repos/acme/app/check-runs":
			created++
			t.Error("cleanup created a new check")
			w.WriteHeader(http.StatusBadRequest)
		default:
			tokenHandler.ServeHTTP(w, r)
		}
	}))
	defer server.Close()
	g := NewGitHub("", "", "", WithAPIURL(server.URL), WithAppCredentials(1, testAppKeyPEM(t)), WithTier(TierReport))
	for range 2 {
		if err := g.RetirePendingGate(context.Background(), "acme", "app", "head", securityStatusContext); err != nil {
			t.Fatal(err)
		}
	}
	if patched != 1 || created != 0 {
		t.Fatalf("cleanup not idempotent: patches=%d creates=%d", patched, created)
	}
	if len(tokens.requests) != 1 || tokens.requests[0].Repositories0() != "app" || tokens.requests[0].Permissions["checks"] != "write" {
		t.Fatalf("cleanup token not confined: %+v", tokens.requests)
	}
}

func TestGitHubRetirementDoesNotHideWriteErrors(t *testing.T) {
	tokens := &tokenServer{}
	tokenHandler := tokens.handler(reportInstallation)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/app/commits/head/check-runs":
			fmt.Fprint(w, `{"total_count":1,"check_runs":[{"id":10,"name":"hibou/security","status":"in_progress","app":{"id":1}}]}`)
		case "/repos/acme/app/check-runs/10":
			w.WriteHeader(http.StatusForbidden)
		default:
			tokenHandler.ServeHTTP(w, r)
		}
	}))
	defer server.Close()
	g := NewGitHub("", "", "", WithAPIURL(server.URL), WithAppCredentials(1, testAppKeyPEM(t)), WithTier(TierReport))
	if err := g.RetirePendingGate(context.Background(), "acme", "app", "head", securityStatusContext); err == nil {
		t.Fatal("cleanup hid denied check write")
	}
}

func TestGitHubCommitStatusRetirementOnlyUpdatesPendingContext(t *testing.T) {
	for _, state := range []string{"pending", "success", "failure", ""} {
		t.Run(state, func(t *testing.T) {
			writes := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					if state == "" {
						fmt.Fprint(w, `{"total_count":0,"statuses":[]}`)
					} else {
						fmt.Fprintf(w, `{"total_count":1,"statuses":[{"context":"hibou/security","state":%q}]}`, state)
					}
					return
				}
				writes++
				var status map[string]string
				if err := json.NewDecoder(r.Body).Decode(&status); err != nil {
					t.Error(err)
				}
				if status["state"] != "success" || status["description"] != "Not evaluated: PR reporting is not configured" {
					t.Errorf("unexpected skipped status: %v", status)
				}
				fmt.Fprint(w, `{}`)
			}))
			defer server.Close()
			g := NewGitHub("", "", "", WithAPIURL(server.URL))
			if err := g.RetirePendingGate(context.Background(), "acme", "app", "head", securityStatusContext); err != nil {
				t.Fatal(err)
			}
			if (writes == 1) != (state == "pending") {
				t.Fatalf("state=%q writes=%d", state, writes)
			}
		})
	}
}
