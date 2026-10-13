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
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/hibouhq/hibou/internal/scancatalog"
)

// hibou scan end to end against a stub server: plan, run the blocked-on-
// ruleset OpenGrep job with local rules, upload the report unbound with its
// scope and rules digest, then complete the snapshot.
// scanTestCatalog stands in for the embedded catalog: one OpenGrep build
// for this runner, pinned to the fake binary's digest.
func scanTestCatalog(t *testing.T, digest string) {
	t.Helper()
	saved := scanLocalCatalog
	t.Cleanup(func() { scanLocalCatalog = saved })
	scanLocalCatalog = func() (*scancatalog.Catalog, error) {
		return &scancatalog.Catalog{SchemaVersion: 1, Revision: "test.1", Scanners: []scancatalog.Scanner{{
			ID: "opengrep", Name: "OpenGrep", Engine: "opengrep", EngineVersion: "1.0", AdapterVersion: "1",
			ExitCodes: map[string]string{"0": "ok", "1": "findings", "default": "error"},
			Command:   scancatalog.Command{Args: []string{"scan", "--sarif-output={sarif}", "-f", "{rules}", "{targets}"}},
			Distributions: []scancatalog.Distribution{{Kind: "binary", OS: runtime.GOOS, Arch: runtime.GOARCH, Asset: "opengrep_bin",
				URL: "https://example.test/opengrep_bin", SHA256: digest}},
		}}}, nil
	}
}

func TestScanRunsPlanAndUploads(t *testing.T) {
	// The offline bundle on this runner, laid out as an import writes it.
	bundle := t.TempDir()
	binary := filepath.Join(bundle, "opengrep", "1.0", "opengrep_bin")
	if err := os.MkdirAll(filepath.Dir(binary), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binary, []byte("fake"), 0o750); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("fake"))
	scanTestCatalog(t, hex.EncodeToString(sum[:]))
	scanBundleDir = bundle
	defer func() { scanBundleDir = "" }()
	rules := filepath.Join(t.TempDir(), "rules.yaml")
	_ = os.WriteFile(rules, []byte("rules: []\n"), 0o600)

	var mu sync.Mutex
	uploads := []map[string]any{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/scanner-catalog":
			// The server's command is ignored: the embedded one runs.
			_, _ = w.Write([]byte(`{"data":{"scanners":[{"id":"opengrep","engine":"opengrep","engine_version":"1.0","exit_codes":{"0":"ok","1":"findings","default":"error"},
			  "command":{"args":["--config","https://evil.example/rules","{targets}"]},"distributions":[]}]}}`))
		case strings.HasSuffix(r.URL.Path, "/scan-plans"):
			_, _ = w.Write([]byte(`{"data":{"id":"7c9e6679-7425-40de-944b-e07fc1f90ae7","plan":{"digest":"sha256:abc","mode":"baseline","mode_reason":"first",
			  "jobs":[{"id":"opengrep-1","scanner_id":"opengrep","status":"blocked","blocked_reason":"no approved ruleset: opengrep-rules (license-review-pending)",
			  "targets":["src"],"scope":"partial","exclusions":[],"capabilities":[],"prerequisites":["source"],"command":[],
			  "artifact":{"url":"file:///server/side/bundle/opengrep","sha256":"` + hex.EncodeToString(sum[:]) + `","source":"bundle"}}]}}}`))
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
		if strings.Contains(strings.Join(args, " "), "evil.example") {
			t.Errorf("server-supplied arguments reached the scanner: %v", args)
		}
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

// P1: a plan naming an artifact this CLI does not pin is refused before
// anything is fetched or executed, with a hint to upgrade the CLI.
func TestScanRefusesArtifactsTheCLIDoesNotPin(t *testing.T) {
	scanTestCatalog(t, strings.Repeat("a", 64))
	evil := sha256.Sum256([]byte("evil"))
	rules := filepath.Join(t.TempDir(), "rules.yaml")
	_ = os.WriteFile(rules, []byte("rules: []\n"), 0o600)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/scanner-catalog":
			_, _ = w.Write([]byte(`{"data":{"scanners":[]}}`))
		case strings.HasSuffix(r.URL.Path, "/scan-plans"):
			_, _ = w.Write([]byte(`{"data":{"id":"7c9e6679-7425-40de-944b-e07fc1f90ae7","plan":{"digest":"sha256:abc","mode":"baseline","mode_reason":"first",
			  "jobs":[{"id":"opengrep-1","scanner_id":"opengrep","status":"blocked","blocked_reason":"no approved ruleset: x",
			  "targets":["src"],"scope":"partial","exclusions":[],"capabilities":[],"prerequisites":[],"command":[],
			  "artifact":{"url":"https://evil.example/opengrep","sha256":"` + hex.EncodeToString(evil[:]) + `","source":"mirror"}},
			  {"id":"new-1","scanner_id":"brand-new","status":"ready","targets":["."],"scope":"full","exclusions":[],"capabilities":[],"prerequisites":[],"command":[],
			  "artifact":{"url":"https://evil.example/new","sha256":"` + hex.EncodeToString(evil[:]) + `","source":"mirror"}}]}}}`))
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
	uploadComplete, uploadNoComplete = false, true
	uploadSourceRoot = t.TempDir()
	cache := t.TempDir()
	scanOpenGrepRules, scanCacheDir, scanOutDir, scanDryRun = rules, cache, t.TempDir(), false
	scanCommandOverride = func(context.Context, string, string, ...string) ([]byte, int, error) {
		t.Fatal("nothing may run")
		return nil, 0, nil
	}
	defer func() {
		scanCommandOverride, scanOpenGrepRules, scanOutDir, scanCacheDir, uploadNoComplete = nil, "", "", "", false
	}()

	err := runScan(context.Background())
	if err == nil || !strings.Contains(err.Error(), "2 scan job(s)") {
		t.Fatalf("runScan = %v", err)
	}
	if entries, _ := os.ReadDir(cache); len(entries) != 0 {
		t.Fatalf("nothing may be fetched: %v", entries)
	}
}
