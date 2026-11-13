package remediation

import (
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func mirrorFixture(t *testing.T, handler http.Handler) (*httptest.Server, NPMMirrorConfig) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return server, NPMMirrorConfig{URL: server.URL + "/artifactory/api/npm/packages", CAFile: ca}
}

func TestNPMMirrorMetadataAndArchivesStayOnApprovedOrigin(t *testing.T) {
	var calls atomic.Int32
	var origin string
	server, cfg := mirrorFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if !strings.HasPrefix(r.URL.Path, "/artifactory/api/npm/packages/") || r.Header.Get("Authorization") != "Bearer scoped-token" {
			t.Errorf("unscoped mirror request: %s %s", r.URL.Path, r.Header.Get("Authorization"))
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if strings.Contains(r.URL.Path, "/-/") {
			_, _ = w.Write([]byte("fixture archive"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"versions":{"1.0.0":{"dist":{"tarball":"`+origin+`/fixture/-/fixture.tgz"}}}}`)
	}))
	origin = cfg.URL
	cfg.TokenFile = filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(cfg.TokenFile, []byte("scoped-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := NewNPMMirrorClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	for _, path := range []string{"/fixture", "/fixture/-/fixture.tgz"} {
		response, err := client.Get("https://registry.npmjs.org" + path)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("mirror response: %s %v", data, err)
		}
		if path == "/fixture" && (!strings.Contains(string(data), "https://registry.npmjs.org/fixture/-/fixture.tgz") || strings.Contains(string(data), server.URL)) {
			t.Fatalf("mirror transport was not canonicalized: %s", data)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("unexpected mirror requests: %d", calls.Load())
	}
}

func TestNPMMirrorRejectsExternalArchivesRedirectsAndUntrustedTLS(t *testing.T) {
	var external atomic.Int32
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		external.Add(1)
	}))
	defer other.Close()
	_, cfg := mirrorFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/redirect"):
			http.Redirect(w, r, other.URL, http.StatusFound)
		case strings.HasSuffix(r.URL.Path, "/missing"):
			http.NotFound(w, r)
		default:
			_, _ = io.WriteString(w, `{"dist":{"tarball":"`+other.URL+`/external.tgz"}}`)
		}
	}))
	client, err := NewNPMMirrorClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	for _, path := range []string{"/external", "/redirect"} {
		resp, err := client.Get("https://registry.npmjs.org" + path)
		if resp != nil {
			resp.Body.Close()
		}
		if err == nil {
			t.Fatalf("unsafe mirror response accepted: %s", path)
		}
	}
	response, err := client.Get("https://registry.npmjs.org/missing")
	if err != nil || response.StatusCode != http.StatusNotFound {
		t.Fatalf("cache miss was hidden: %v %v", response, err)
	}
	response.Body.Close()
	if external.Load() != 0 {
		t.Fatal("mirror response triggered an external request")
	}
	cfg.CAFile = ""
	untrusted, err := NewNPMMirrorClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	response, err = untrusted.Get("https://registry.npmjs.org/missing")
	if response != nil {
		response.Body.Close()
	}
	if err == nil {
		t.Fatal("untrusted mirror TLS certificate accepted")
	}
}

func TestNPMMirrorLockTransportPreservesApprovedIdentity(t *testing.T) {
	manifest, lock := npmFixture(t, "1.0.0", "1.0.0")
	origin := "https://artifactory.internal/artifactory/api/npm/packages"
	lock = strings.ReplaceAll(lock, "https://registry.npmjs.org/", origin+"/")
	if _, err := parseNPMProject([]byte(manifest), []byte(lock), Tool{}); err == nil {
		t.Fatal("unconfigured custom origin accepted")
	}
	if _, err := parseNPMProject([]byte(manifest), []byte(lock), Tool{RegistryOrigin: origin}); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(lock), 0o600); err != nil {
		t.Fatal(err)
	}
	proxy := "http://127.0.0.1:1234/private-job/"
	if err := rewriteNPMLocations(root, "package-lock.json", []string{origin}, proxy); err != nil {
		t.Fatal(err)
	}
	if err := canonicalizeProxyLocations(root, testUnit(), proxy, origin); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "package-lock.json"))
	if err != nil || strings.Contains(string(data), "private-job") || !strings.Contains(string(data), origin+"/fixture-dependency/") {
		t.Fatalf("mirror identity transport round trip failed: %s %v", data, err)
	}
}
