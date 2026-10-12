package scanrun

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hibouhq/hibou/internal/scancatalog"
	"github.com/hibouhq/hibou/internal/scanplan"
)

func digestOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestFetchVerifiesAndCaches(t *testing.T) {
	payload := []byte("#!/bin/sh\necho scanner\n")
	hits := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write(payload)
	}))
	defer server.Close()
	fetcher := &Fetcher{CacheDir: t.TempDir(), Client: server.Client()}
	location := scancatalog.Location{URL: server.URL + "/opengrep", SHA256: digestOf(payload)}

	path, err := fetcher.Fetch(context.Background(), location, "opengrep", true)
	if err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm()&0o100 == 0 {
		t.Fatal("binary must be executable")
	}
	if _, err := fetcher.Fetch(context.Background(), location, "opengrep", true); err != nil || hits != 1 {
		t.Fatalf("second fetch must hit the cache: hits=%d err=%v", hits, err)
	}
	// A tampered cache entry is re-downloaded, not trusted.
	if err := os.WriteFile(path, []byte("tampered"), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := fetcher.Fetch(context.Background(), location, "opengrep", true); err != nil || hits != 2 {
		t.Fatalf("tampered cache must be re-fetched: hits=%d err=%v", hits, err)
	}

	wrong := location
	wrong.SHA256 = digestOf([]byte("something else"))
	if _, err := fetcher.Fetch(context.Background(), wrong, "opengrep", true); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("digest mismatch must fail: %v", err)
	}
	if _, err := fetcher.Fetch(context.Background(), scancatalog.Location{URL: "http://plain.example.test/x", SHA256: location.SHA256}, "x", false); err == nil {
		t.Fatal("plain http must be refused")
	}
}

func TestFetchOfflineBundle(t *testing.T) {
	bundle := t.TempDir()
	payload := []byte("jar bytes")
	file := filepath.Join(bundle, "plugin.jar")
	if err := os.WriteFile(file, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	fetcher := &Fetcher{CacheDir: t.TempDir()}
	if _, err := fetcher.Fetch(context.Background(), scancatalog.Location{URL: "file://" + filepath.ToSlash(file), SHA256: digestOf(payload)}, "plugin.jar", false); err != nil {
		t.Fatal(err)
	}
	if _, err := fetcher.Fetch(context.Background(), scancatalog.Location{URL: "file:///nope/missing.jar", SHA256: digestOf(payload)}, "missing.jar", false); err == nil || !strings.Contains(err.Error(), "offline bundle is missing") {
		t.Fatalf("missing bundle artifact = %v", err)
	}
}

func TestOpenGrepAdapterRunsWithoutShell(t *testing.T) {
	payload := []byte("binary")
	bundle := t.TempDir()
	binary := filepath.Join(bundle, "opengrep")
	_ = os.WriteFile(binary, payload, 0o750)
	rules := filepath.Join(t.TempDir(), "rules.yaml")
	_ = os.WriteFile(rules, []byte("rules: []\n"), 0o600)
	out := t.TempDir()

	var gotArgs []string
	env := Environment{
		SourceRoot: "/src", OutDir: out, Fetcher: &Fetcher{CacheDir: t.TempDir()}, OpenGrepRules: rules,
		Command: func(_ context.Context, dir, name string, args ...string) ([]byte, int, error) {
			gotArgs = args
			if dir != "/src" {
				t.Errorf("dir = %s", dir)
			}
			return nil, 1, nil // 1 = findings, not an error
		},
	}
	job := scanplan.Job{ID: "opengrep-abc", Targets: []string{"java", "web"}, Exclusions: []string{"web/node_modules"},
		Artifact: &scancatalog.Location{URL: "file://" + filepath.ToSlash(binary), SHA256: digestOf(payload)}}
	entry := CatalogEntry{Scanner: scancatalog.Scanner{Engine: "opengrep", ExitCodes: map[string]string{"0": "ok", "1": "findings", "default": "error"},
		Command: scancatalog.Command{Args: []string{"scan", "--sarif-output={sarif}", "-f", "{rules}", "{targets}"}}}}

	result, err := Run(context.Background(), job, entry, env)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(gotArgs, " ")
	if !strings.Contains(joined, "--sarif-output="+filepath.Join(out, "opengrep-abc.sarif")) || !strings.Contains(joined, "-f "+rules) ||
		!strings.HasSuffix(joined, "--exclude web/node_modules java web") {
		t.Fatalf("args = %v", gotArgs)
	}
	if !result.Unbound || !strings.HasPrefix(result.ConfigDigest, "sha256:") {
		t.Fatalf("local rules must make the run unbound with a config digest: %+v", result)
	}

	env.OpenGrepRules = ""
	if _, err := Run(context.Background(), job, entry, env); err == nil {
		t.Fatal("no ruleset and no local rules must fail")
	}
}

func TestSpotBugsAdapterNeedsCompiledClasses(t *testing.T) {
	jar := []byte("findsecbugs")
	bundle := filepath.Join(t.TempDir(), "fsb.jar")
	_ = os.WriteFile(bundle, jar, 0o600)
	entry := CatalogEntry{Scanner: scancatalog.Scanner{Engine: "spotbugs"}, Distributions: []ResolvedDistribution{
		{Distribution: scancatalog.Distribution{Kind: "maven", Coordinates: "com.github.spotbugs:spotbugs-maven-plugin:4.9.3.0"}},
		{Distribution: scancatalog.Distribution{Kind: "maven", Coordinates: "com.h3xstream.findsecbugs:findsecbugs-plugin:1.13.0"},
			Location: &scancatalog.Location{URL: "file://" + filepath.ToSlash(bundle), SHA256: digestOf(jar)}},
	}}
	env := Environment{SourceRoot: t.TempDir(), OutDir: t.TempDir(), Fetcher: &Fetcher{CacheDir: t.TempDir()},
		Command: func(context.Context, string, string, ...string) ([]byte, int, error) {
			t.Fatal("mvn must not run without compiled classes")
			return nil, 0, nil
		}}
	_, err := Run(context.Background(), scanplan.Job{ID: "sb", Targets: []string{"java"}}, entry, env)
	if !errors.Is(err, ErrPrerequisite) {
		t.Fatalf("missing classes must be a prerequisite failure: %v", err)
	}
}

func TestFetchRefusesRedirectToUnapprovedHost(t *testing.T) {
	payload := []byte("x")
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(payload) }))
	defer target.Close()
	mirror := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 127.0.0.1 vs localhost: a different host name, same test machine.
		http.Redirect(w, r, strings.Replace(target.URL, "127.0.0.1", "localhost", 1)+"/x", http.StatusFound)
	}))
	defer mirror.Close()
	fetcher := &Fetcher{CacheDir: t.TempDir(), Client: mirror.Client()}
	_, err := fetcher.Fetch(context.Background(), scancatalog.Location{URL: mirror.URL + "/x", SHA256: digestOf(payload), Source: "mirror"}, "x", false)
	if err == nil || !strings.Contains(err.Error(), "not an approved host") {
		t.Fatalf("cross-host redirect from a mirror must be refused: %v", err)
	}
}
