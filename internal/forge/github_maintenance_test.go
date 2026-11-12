package forge

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMaintenanceBranchAllowlistDoesNotWeakenGlobalGuard(t *testing.T) {
	for _, tt := range []struct {
		branch   string
		patterns []string
		allowed  bool
	}{
		{"release/1.2", nil, false},
		{"release/1.2", []string{"release/*"}, true},
		{"maintenance/1.2", []string{"release/*"}, false},
		{"release/../main", []string{"release/*"}, false},
		{"release/.hidden", []string{"release/*"}, false},
		{"release/x.lock", []string{"release/*"}, false},
		{"release/a/b", []string{"release/*"}, false},
		{"hibou/maintenance-1.2", []string{"release/*"}, true},
	} {
		t.Run(tt.branch, func(t *testing.T) {
			if err := CheckMaintenanceBranch(tt.branch, tt.patterns); (err == nil) != tt.allowed {
				t.Fatalf("allowlist decision %v", err)
			}
		})
	}
	if CheckWriteBranch("release/1.2") == nil {
		t.Fatal("general namespace guard was weakened")
	}
}

func TestGitHubMaintenanceCreateOnlyConfirmedSource(t *testing.T) {
	for _, scenario := range []string{"create", "reconcile", "collision_same_sha", "user_commit", "tag_moved", "annotated", "audit_failure", "ambiguous_post"} {
		t.Run(scenario, func(t *testing.T) {
			source := strings.Repeat("a", 40)
			other := strings.Repeat("b", 40)
			annotation := strings.Repeat("c", 40)
			exists := scenario == "reconcile" || scenario == "collision_same_sha" || scenario == "user_commit"
			writes := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Method == http.MethodPatch || r.Method == http.MethodPut || r.Method == http.MethodDelete {
					t.Errorf("non-create ref operation: %s %s", r.Method, r.URL.Path)
				}
				switch {
				case r.URL.Path == "/repos/acme/app/git/ref/tags/v1.2.3":
					sha, kind := source, "commit"
					if scenario == "tag_moved" {
						sha = other
					}
					if scenario == "annotated" {
						sha, kind = annotation, "tag"
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"object": map[string]string{"sha": sha, "type": kind}})
				case r.URL.Path == "/repos/acme/app/git/tags/"+annotation:
					_ = json.NewEncoder(w).Encode(map[string]any{"object": map[string]string{"sha": source, "type": "commit"}})
				case r.URL.Path == "/repos/acme/app/git/ref/heads/release/1.2":
					if !exists {
						http.NotFound(w, r)
						return
					}
					sha := source
					if scenario == "user_commit" {
						sha = other
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"object": map[string]string{"sha": sha, "type": "commit"}})
				case r.URL.Path == "/repos/acme/app/git/refs" && r.Method == http.MethodPost:
					writes++
					var body map[string]string
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
					}
					if body["ref"] != "refs/heads/release/1.2" || body["sha"] != source {
						t.Errorf("unconfirmed branch write: %v", body)
					}
					exists = true
					if scenario == "ambiguous_post" {
						http.Error(w, `{"message":"retry"}`, http.StatusInternalServerError)
						return
					}
					w.WriteHeader(http.StatusCreated)
					_, _ = w.Write([]byte(`{}`))
				default:
					t.Errorf("unexpected maintenance operation %s %s", r.Method, r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			g := NewGitHub("client", "secret", "", WithAPIURL(server.URL), WithHTTPClient(server.Client()), WithTier(TierPropose))
			g.appID = 1
			g.ownerInstallations = map[string]cachedInstallation{"acme": {installation: githubInstallation{}, expiresAt: time.Now().Add(time.Hour)}}
			for _, permission := range []map[string]string{{"contents": "read"}, {"contents": "write"}} {
				g.ownerTokens[tokenCacheKey("acme", TokenScope{Repo: "app"}, permission)] = ownerToken{value: "scoped", expiresAt: time.Now().Add(time.Hour)}
			}
			var events []string
			result, err := g.CreateApprovedMaintenanceTarget(context.Background(), "acme", "app", MaintenanceCreation{
				SourceTag: "v1.2.3", SourceSHA: source, TargetBranch: "release/1.2", ApprovedPatterns: []string{"release/*"}, ReconcileExisting: scenario == "reconcile",
				Audit: func(action string, _ any) error {
					events = append(events, action)
					if scenario == "audit_failure" {
						return errors.New("audit unavailable")
					}
					return nil
				},
			})
			success := scenario == "create" || scenario == "reconcile" || scenario == "annotated" || scenario == "ambiguous_post"
			if success {
				if err != nil || result == nil {
					t.Fatalf("safe creation failed: %v %v", result, err)
				}
				if scenario == "reconcile" && (!result.Reconciled || writes != 0) {
					t.Fatalf("reconciliation wrote: %v writes=%d", result, writes)
				}
				if scenario != "reconcile" && writes != 1 {
					t.Fatalf("expected one atomic ref creation, got %d", writes)
				}
			} else {
				if err == nil || writes != 0 {
					t.Fatalf("unsafe creation succeeded: %v writes=%d", err, writes)
				}
				if (scenario == "collision_same_sha" || scenario == "user_commit") && !errors.Is(err, ErrMaintenanceTargetCollision) {
					t.Fatalf("collision was not explicit: %v", err)
				}
			}
		})
	}
}

func TestGitHubMaintenanceSuggestionsCarryAncestryEvidence(t *testing.T) {
	for _, status := range []string{"ahead", "identical", "behind", "diverged"} {
		t.Run(status, func(t *testing.T) {
			source, head := strings.Repeat("a", 40), strings.Repeat("b", 40)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Error("suggestion attempted a write")
					http.Error(w, "read only", http.StatusMethodNotAllowed)
					return
				}
				switch {
				case strings.Contains(r.URL.Path, "/git/ref/tags/"):
					_, _ = w.Write([]byte(`{"object":{"sha":"` + source + `","type":"commit"}}`))
				case strings.Contains(r.URL.Path, "/git/ref/heads/"):
					_, _ = w.Write([]byte(`{"object":{"sha":"` + head + `","type":"commit"}}`))
				case strings.Contains(r.URL.Path, "/compare/"):
					_, _ = w.Write([]byte(`{"status":"` + status + `"}`))
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			g := NewGitHub("client", "secret", "", WithAPIURL(server.URL), WithHTTPClient(server.Client()))
			evidence, err := g.InspectMaintenanceTarget(context.Background(), "acme", "app", "v1.2.3", source, "release/1.2")
			if err != nil || !evidence.TagConfirmed || !evidence.Exists || evidence.HeadSHA != head || evidence.SourceAncestor != (status == "ahead" || status == "identical") {
				t.Fatalf("incomplete ancestry evidence: %v %v", evidence, err)
			}
		})
	}
}
