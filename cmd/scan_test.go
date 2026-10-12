package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// hibou scan end to end against a stub server: plan, run the blocked-on-
// ruleset OpenGrep job with local rules, upload the report unbound with its
// scope and rules digest, then complete the snapshot.
func TestScanRunsPlanAndUploads(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "opengrep")
	if err := os.WriteFile(binary, []byte("fake"), 0o750); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("fake"))
	rules := filepath.Join(t.TempDir(), "rules.yaml")
	_ = os.WriteFile(rules, []byte("rules: []\n"), 0o600)

	var mu sync.Mutex
	uploads := []map[string]any{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/scanner-catalog":
			_, _ = w.Write([]byte(`{"data":{"scanners":[{"id":"opengrep","engine":"opengrep","exit_codes":{"0":"ok","1":"findings","default":"error"},
			  "command":{"args":["scan","--sarif-output={sarif}","-f","{rules}","{targets}"]},"distributions":[]}]}}`))
		case strings.HasSuffix(r.URL.Path, "/scan-plans"):
			_, _ = w.Write([]byte(`{"data":{"id":"7c9e6679-7425-40de-944b-e07fc1f90ae7","plan":{"digest":"sha256:abc","mode":"baseline","mode_reason":"first",
			  "jobs":[{"id":"opengrep-1","scanner_id":"opengrep","status":"blocked","blocked_reason":"no approved ruleset: opengrep-rules (license-review-pending)",
			  "targets":["src"],"scope":"partial","exclusions":[],"capabilities":[],"prerequisites":["source"],"command":[],
			  "artifact":{"url":"file://` + filepath.ToSlash(binary) + `","sha256":"` + hex.EncodeToString(sum[:]) + `","source":"bundle"}}]}}}`))
		case r.URL.Path == "/api/v1/upload":
			var payload map[string]any
			_ = json.NewDecoder(r.Body).Decode(&payload)
			mu.Lock()
			uploads = append(uploads, payload)
			mu.Unlock()
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"data":{"upload_id":"u","snapshot_id":"s","status":"pending"}}`))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	t.Setenv("HIBOU_SERVER", server.URL)
	t.Setenv("HIBOU_TOKEN", "test")
	savedOrg, savedRepo, savedRef, savedSHA, savedRoot := uploadOrg, uploadRepo, uploadRef, uploadCommitSHA, uploadSourceRoot
	defer func() {
		uploadOrg, uploadRepo, uploadRef, uploadCommitSHA, uploadSourceRoot = savedOrg, savedRepo, savedRef, savedSHA, savedRoot
	}()
	uploadOrg, uploadRepo, uploadRef, uploadCommitSHA = "github/acme", "app", "refs/heads/main", "abc123"
	uploadComplete, uploadNoComplete = true, false
	uploadSourceRoot = t.TempDir()
	scanOpenGrepRules, scanCacheDir, scanOutDir, scanDryRun = rules, t.TempDir(), t.TempDir(), false
	scanCommandOverride = func(_ context.Context, _, _ string, args ...string) ([]byte, int, error) {
		for _, arg := range args {
			if strings.HasPrefix(arg, "--sarif-output=") {
				_ = os.WriteFile(strings.TrimPrefix(arg, "--sarif-output="), []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Opengrep OSS"}},"results":[]}]}`), 0o600)
			}
		}
		return nil, 0, nil
	}
	defer func() { scanCommandOverride, scanOpenGrepRules, scanOutDir, scanCacheDir = nil, "", "", "" }()

	if err := runScan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(uploads) != 2 {
		t.Fatalf("want the report and the completion, got %d uploads", len(uploads))
	}
	report := uploads[0]
	if _, bound := report["plan_id"]; bound {
		t.Fatal("a local-rules run must not be bound to the plan")
	}
	if report["scope"] != "partial" || !strings.HasPrefix(report["config_digest"].(string), "sha256:") {
		t.Fatalf("report declaration = %v", report)
	}
	artifact := report["artifact"].(map[string]any)
	if decoded, _ := base64.StdEncoding.DecodeString(artifact["content_base64"].(string)); !strings.Contains(string(decoded), "Opengrep OSS") {
		t.Fatal("uploaded content is not the scanner's report")
	}
	if uploads[1]["complete"] != true {
		t.Fatalf("last call must complete the snapshot: %v", uploads[1])
	}
}
