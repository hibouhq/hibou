package lsp

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/remediation"
)

func TestIDEManagedRegenerationThenExplicitPublication(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(strconv.FormatBool(corrupt), func(t *testing.T) {
			root := t.TempDir()
			gitCmd(t, root, "init", "-q")
			if err := os.WriteFile(filepath.Join(root, "package.json"), []byte("{}\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			gitCmd(t, root, "add", ".")
			gitCmd(t, root, "commit", "-q", "-m", "base")
			base := gitCmd(t, root, "rev-parse", "HEAD")
			jobID := uuid.NewString()
			patch := []byte("reviewed managed diff\n")
			hash := fmt.Sprintf("%x", sha256.Sum256(patch))
			artifact := remediation.Artifact{BaseSHA: base, SHA256: hash, Changes: []remediation.Change{{Path: "package.json"}},
				Units: []remediation.UnitResult{{ID: "."}}, Verification: []remediation.Verification{{DependencyFilesConsistent: true, SelectedVulnsAddressed: true, NoIntroducedVulns: true}}}
			job := func(state string, revision int) map[string]any {
				result := map[string]any{"modules": []map[string]any{{"manifest": "package.json", "unit": map[string]any{"id": ".", "upgrade_level": "minor"}}}}
				if state == "ready" {
					result["artifact"] = artifact
				}
				return map[string]any{"id": jobID, "revision": revision, "state": state, "base_sha": base, "target_branch": "main", "result": result}
			}
			published, cancelled := false, false
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer hb-test" {
					t.Error("missing authentication")
				}
				response := map[string]any{}
				switch {
				case strings.HasSuffix(r.URL.Path, "/capabilities"):
					response = map[string]any{"can_generate": true, "publication_available": true}
				case strings.HasSuffix(r.URL.Path, "/prepare"):
					var body map[string]json.RawMessage
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
					}
					if len(body) != 3 || string(body["expected_head_sha"]) != `"`+base+`"` {
						t.Errorf("wrong or source-bearing prepare payload: %v", body)
					}
					response = job("awaiting_selection", 1)
				case strings.HasSuffix(r.URL.Path, "/generate"):
					var body struct {
						Revision int `json:"revision"`
						Units    []struct {
							ID string `json:"id"`
						} `json:"units"`
					}
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
					}
					if body.Revision != 1 || len(body.Units) != 1 || body.Units[0].ID != "." {
						t.Errorf("wrong managed selection: %+v", body)
					}
					response = job("ready", 2)
				case strings.HasSuffix(r.URL.Path, "/patch"):
					w.Header().Set("Content-Type", "text/x-diff")
					data := patch
					if corrupt {
						data = []byte("tampered diff")
					}
					_, _ = w.Write(data)
					return
				case strings.HasSuffix(r.URL.Path, "/publish"):
					published = true
					response = map[string]any{"number": 42, "html_url": "https://example.test/pr/42"}
				case strings.HasSuffix(r.URL.Path, "/cancel"):
					cancelled = true
				default:
					if r.Method != http.MethodGet {
						t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
					}
					response = job("ready", 2)
				}
				if err := json.NewEncoder(w).Encode(map[string]any{"data": response}); err != nil {
					t.Error(err)
				}
			}))
			defer api.Close()
			s := &Server{server: api.URL, token: "hb-test", workspaces: map[string]*workspace{}, docs: map[string]*document{}}
			ws := newWorkspace(s, root)
			ws.repo = &repoRef{Provider: "github", Org: "acme", Repo: "app"}
			s.workspaces[root] = ws
			s.remediationDrafts = map[string]*localRemediationDraft{"local": {
				prepared: remediationPrepared{ID: "local", Root: root, BaseSHA: base, ExpiresAt: time.Now().Add(time.Hour), Units: []remediation.Unit{{ID: ".", Vulns: []string{"TEST"}}}},
				artifact: &artifact, generatedSelection: remediationGenerateParams{Root: root, ID: "local", UnitIDs: []string{"."}},
			}}
			ready, err := s.remediationManagedGenerate(t.Context(), managedRemediationParams{Root: root, LocalID: "local", TargetBranch: "main", ConsentManaged: true})
			if corrupt {
				if err == nil || ready != nil || published || !cancelled {
					t.Fatalf("corrupted managed result accepted: %v %v", ready, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if published || ready.Artifact.SHA256 != hash || strings.Count(ready.ProposalBranch, "/") != 1 {
				t.Fatal("generation published or lost artifact identity")
			}
			if _, err := s.remediationManagedPublish(t.Context(), managedRemediationParams{Root: root, JobID: jobID, Revision: 2, SHA256: "wrong"}); err == nil {
				t.Fatal("unreviewed digest accepted")
			}
			pr, err := s.remediationManagedPublish(t.Context(), managedRemediationParams{Root: root, JobID: jobID, Revision: 2, SHA256: hash})
			if err != nil || !published || pr.Number != 42 {
				t.Fatalf("explicit publication failed: %+v %v", pr, err)
			}
		})
	}
}
