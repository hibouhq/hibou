package forge

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestGitHubManagedPublicationAtomicAndReconciled(t *testing.T) {
	for _, scenario := range []string{"new", "retry", "user_commit", "stale_target", "audit_failure", "tree_failure"} {
		t.Run(scenario, func(t *testing.T) {
			var mu sync.Mutex
			var writes []string
			var treeFiles int
			base := strings.Repeat("a", 40)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Method != http.MethodGet {
					mu.Lock()
					writes = append(writes, r.URL.Path)
					mu.Unlock()
				}

				switch {
				case r.URL.Path == "/repos/acme/app/branches/main":
					head := base
					if scenario == "stale_target" {
						head = strings.Repeat("b", 40)
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"name": "main", "commit": map[string]string{"sha": head}})
				case r.URL.Path == "/repos/acme/app/git/commits/"+base:
					_, _ = w.Write([]byte(`{"tree":{"sha":"base-tree"}}`))
				case r.URL.Path == "/repos/acme/app/git/trees":
					if scenario == "tree_failure" {
						http.Error(w, `{"message":"refused"}`, http.StatusUnprocessableEntity)
						return
					}
					var body struct {
						Tree []struct {
							Path    string `json:"path"`
							Content string `json:"content"`
						} `json:"tree"`
					}
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
					}
					treeFiles = len(body.Tree)
					_, _ = w.Write([]byte(`{"sha":"complete-tree"}`))
				case r.URL.Path == "/repos/acme/app/git/commits":
					_, _ = w.Write([]byte(`{"sha":"verified-commit"}`))
				case strings.HasPrefix(r.URL.Path, "/repos/acme/app/git/ref/heads/"):
					if scenario == "new" || scenario == "tree_failure" || scenario == "audit_failure" {
						http.NotFound(w, r)
						return
					}
					sha := "verified-commit"
					if scenario == "user_commit" {
						sha = "user-commit"
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"object": map[string]string{"sha": sha}})
				case r.URL.Path == "/repos/acme/app/git/refs":
					var body map[string]string
					_ = json.NewDecoder(r.Body).Decode(&body)
					if body["sha"] != "verified-commit" {
						t.Errorf("partial base branch created: %v", body)
					}
					w.WriteHeader(http.StatusCreated)
					_, _ = w.Write([]byte(`{}`))
				case r.URL.Path == "/repos/acme/app/pulls" && r.Method == http.MethodGet:
					if scenario == "retry" {
						_, _ = w.Write([]byte(`[{"number":7,"title":"Fix","html_url":"https://github.com/acme/app/pull/7"}]`))
					} else {
						_, _ = w.Write([]byte(`[]`))
					}
				case r.URL.Path == "/repos/acme/app/pulls" && r.Method == http.MethodPost:
					_, _ = w.Write([]byte(`{"number":7,"title":"Fix","html_url":"https://github.com/acme/app/pull/7"}`))
				default:
					t.Errorf("unexpected forge operation %s %s", r.Method, r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			g := NewGitHub("client", "secret", "", WithAPIURL(server.URL), WithHTTPClient(server.Client()), WithTier(TierPropose))
			g.appID = 1
			// Preload narrowly scoped installation credentials, avoiding unrelated
			// key minting in this publication test.
			g.ownerInstallations = map[string]cachedInstallation{"acme": {installation: githubInstallation{}, expiresAt: time.Now().Add(time.Hour)}}
			for _, permission := range []map[string]string{{"contents": "read"}, {"contents": "write"}, {"pull_requests": "read"}, {"pull_requests": "write"}, {"contents": "write", "pull_requests": "write"}} {
				g.ownerTokens[tokenCacheKey("acme", TokenScope{Repo: "app"}, permission)] = ownerToken{value: "scoped", expiresAt: time.Now().Add(time.Hour)}
			}
			var events []string
			pr, err := g.PublishRemediation(context.Background(), "acme", "app", AtomicRemediationRequest{
				BaseSHA: base, Target: "main", Branch: "hibou/fix-main-test", ArtifactSHA: strings.Repeat("d", 64),
				Files: map[string][]byte{"package.json": []byte("{}\n"), "package-lock.json": []byte("{}\n")},
				Audit: func(action string, _ any) error {
					events = append(events, action)
					if scenario == "audit_failure" {
						return errors.New("audit unavailable")
					}
					return nil
				},
			})
			if scenario == "new" || scenario == "retry" {
				if err != nil || pr == nil || pr.Number != 7 {
					t.Fatalf("publication: %v %v", pr, err)
				}
				if treeFiles != 2 {
					t.Fatalf("incomplete atomic tree: %d", treeFiles)
				}
				if scenario == "retry" {
					for _, write := range writes {
						if strings.HasSuffix(write, "/refs") || strings.HasSuffix(write, "/pulls") {
							t.Fatalf("retry duplicated visible side effect: %v", writes)
						}
					}
				}
			} else if err == nil {
				t.Fatalf("unsafe publication succeeded in %s", scenario)
			}
			for _, write := range writes {
				if strings.Contains(write, "/contents/") {
					t.Fatal("file-by-file publication attempted")
				}
				if (scenario == "stale_target" || scenario == "audit_failure") && len(writes) > 0 {
					t.Fatalf("side effects after failed safety check: %v", writes)
				}
				if (scenario == "user_commit" || scenario == "tree_failure") && (strings.HasSuffix(write, "/refs") || strings.HasSuffix(write, "/pulls")) {
					t.Fatalf("unsafe visible publication: %v", writes)
				}
			}
		})
	}
}
