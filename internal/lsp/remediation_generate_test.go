package lsp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"deps.dev/util/resolve"

	"github.com/hibouhq/hibou/internal/remediation"
)

func TestLocalRemediationPrepareGenerateApply(t *testing.T) {
	root := t.TempDir()
	gitCmd(t, root, "init", "-q")
	manifest := `{"name":"app","version":"1.0.0","dependencies":{"fixture-dependency":"1.0.0"}}` + "\n"
	lock := `{"lockfileVersion":3,"packages":{"":{"name":"app","version":"1.0.0","dependencies":{"fixture-dependency":"1.0.0"}},"node_modules/fixture-dependency":{"version":"1.0.0","resolved":"https://registry.npmjs.org/fixture-dependency/-/fixture.tgz","integrity":"sha512-` + base64.StdEncoding.EncodeToString(make([]byte, 64)) + `"}}}` + "\n"
	for name, data := range map[string]string{"package.json": manifest, "package-lock.json": lock} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	gitCmd(t, root, "add", ".")
	gitCmd(t, root, "commit", "-q", "-m", "baseline")
	afterLock := strings.ReplaceAll(lock, `"fixture-dependency":"1.0.0"`, `"fixture-dependency":"~1.0.1"`)
	afterLock = strings.ReplaceAll(afterLock, `"version":"1.0.0","resolved"`, `"version":"1.0.1","resolved"`)
	bin := filepath.Join(t.TempDir(), "npm")
	script := "#!/bin/sh\nif [ \"$1\" = --version ]; then echo fixture-1; exit 0; fi\n" +
		"if [ \"$1\" = ci ]; then exit 0; fi\nif [ \"$1\" = update ]; then\ncat > package-lock.json <<'LOCK'\n" + afterLock + "LOCK\nexit 0\nfi\nexit 1\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/orgs/github/acme/advisories/match" || r.Header.Get("Authorization") != "Bearer hb-test" {
			t.Errorf("unexpected API request: %s", r.URL.Path)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		var body map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			return
		}
		if len(body) != 3 || string(body["include_ranges"]) != "true" || string(body["repo"]) != `"app"` {
			t.Errorf("unexpected payload keys: %v", body)
		}
		var purls []string
		if err := json.Unmarshal(body["purls"], &purls); err != nil {
			t.Error(err)
			return
		}
		var matches []map[string]any
		for _, p := range purls {
			advisories := []map[string]any{}
			if strings.HasSuffix(p, "@1.0.0") {
				advisories = append(advisories, map[string]any{"canonical_id": "TEST-1", "affected_ranges": []map[string]string{{"ecosystem": "npm", "package": "fixture-dependency", "introduced": "0", "fixed": "1.0.1"}}})
			}
			matches = append(matches, map[string]any{"purl": p, "supported": true, "private_namespace": false, "decision": "allow", "advisories": advisories})
		}
		if err := json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"matches": matches}}); err != nil {
			t.Error(err)
		}
	}))
	defer api.Close()
	s := &Server{server: api.URL, token: "hb-test", workspaces: map[string]*workspace{}, docs: map[string]*document{}}
	ws := newWorkspace(s, root)
	ws.repo = &repoRef{Provider: "github", Org: "acme", Repo: "app"}
	s.workspaces[root] = ws
	s.remediationToolInspector = func(context.Context) (remediation.Tool, error) {
		return remediation.Tool{Path: bin, VersionOutput: "fixture-1", PATH: os.Getenv("PATH")}, nil
	}
	client := resolve.NewLocalClient()
	key := resolve.PackageKey{System: resolve.NPM, Name: "fixture-dependency"}
	for _, version := range []string{"1.0.0", "1.0.1"} {
		client.AddVersion(resolve.Version{VersionKey: resolve.VersionKey{PackageKey: key, VersionType: resolve.Concrete, Version: version}}, nil)
	}
	s.remediationBackendFactory = func(tool remediation.Tool, match remediation.MatchPackages) remediation.NPMBackend {
		return remediation.NPMBackend{Tool: tool, Match: match, ResolverFactory: func(string) (resolve.Client, error) { return client, nil }}
	}
	if _, err := s.remediationPrepare(t.Context(), remediationPrepareParams{Root: root}); err == nil {
		t.Fatal("missing local consent accepted")
	}
	prepared, err := s.remediationPrepare(t.Context(), remediationPrepareParams{Root: root, ConsentLocal: true, UpgradeLevel: "patch"})
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.Units) != 1 || len(prepared.Unavailable) != 0 {
		t.Fatalf("unexpected preparation: %+v", prepared)
	}
	request := remediationGenerateParams{Root: root, ID: prepared.ID, UnitIDs: []string{prepared.Units[0].ID}}
	artifact, err := s.remediationGenerate(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "package-lock.json"))
	if err != nil || string(data) != lock {
		t.Fatal("generation changed the working tree")
	}
	again, err := s.remediationGenerate(t.Context(), request)
	if err != nil || again.SHA256 != artifact.SHA256 {
		t.Fatal("generation retry changed its artifact")
	}
	bad := request
	bad.UnitIDs = []string{"other"}
	if _, err := s.remediationGenerate(t.Context(), bad); err == nil {
		t.Fatal("generation selection mutated after review")
	}
	if _, err := s.remediationApply(t.Context(), remediationApplyParams{Root: root, Artifact: *artifact}); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(filepath.Join(root, "package-lock.json"))
	if err != nil || !strings.Contains(string(data), `"version":"1.0.1"`) {
		t.Fatalf("lockfile not applied: %s %v", data, err)
	}
}
