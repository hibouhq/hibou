package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hibouhq/hibou/internal/advisorydb"
)

// Opt-in: public fixture only, no real project data or credentials leave the
// machine. Native install scripts remain disabled throughout.
func TestNPMOnlineRealLockedRemediation(t *testing.T) {
	if os.Getenv("HIBOU_TEST_ONLINE_NPM") != "1" {
		t.Skip("set HIBOU_TEST_ONLINE_NPM=1 for the public-registry integration fixture")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	tool, err := InspectLocalNPM(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", t.TempDir())
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(strings.ToLower(key), "npm_config_") {
			t.Setenv(key, "")
			if err := os.Unsetenv(key); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Setenv("NPM_CONFIG_USERCONFIG", filepath.Join(t.TempDir(), "empty-user.npmrc"))
	t.Setenv("NPM_CONFIG_GLOBALCONFIG", filepath.Join(t.TempDir(), "empty-global.npmrc"))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://registry.npmjs.org/is-number/6.0.0", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("public registry returned %d", response.StatusCode)
	}
	var published struct {
		Dist struct {
			Tarball   string `json:"tarball"`
			Integrity string `json:"integrity"`
		} `json:"dist"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&published); err != nil {
		t.Fatal(err)
	}
	manifest := npmManifest{Name: "hibou-public-test-fixture", Version: "1.0.0", Dependencies: map[string]string{"is-number": "6.0.0"}}
	lock := npmLock{LockfileVersion: 3, Packages: map[string]npmLockedPackage{
		"":                       {npmManifest: manifest},
		"node_modules/is-number": {npmManifest: npmManifest{Version: "6.0.0"}, Resolved: published.Dist.Tarball, Integrity: published.Dist.Integrity},
	}}
	m, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	l, err := json.Marshal(lock)
	if err != nil {
		t.Fatal(err)
	}
	root, sha := repository(t, map[string]string{"package.json": string(m) + "\n", "package-lock.json": string(l) + "\n"})
	match := func(_ context.Context, purls []string) ([]AdvisoryMatch, error) {
		var out []AdvisoryMatch
		for _, p := range purls {
			private := false
			entry := AdvisoryMatch{Purl: p, Supported: true, Decision: "allow", PrivateNamespace: &private}
			// Synthetic advisory exercises remediation; it is not a claim that
			// is-number has this vulnerability.
			if strings.HasSuffix(p, "@6.0.0") {
				entry.Advisories = []MatchedAdvisory{{CanonicalID: "HIBOU-SYNTHETIC-TEST", Ranges: []advisorydb.Range{{Ecosystem: "npm", Package: "is-number", Introduced: "0", Fixed: "7.0.0"}}}}
			}
			out = append(out, entry)
		}
		return out, nil
	}
	backend := NPMBackend{Tool: tool, Match: match}
	unit, err := backend.Prepare(ctx, root, sha, "package.json", nil, "major")
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := (Engine{Backend: backend}).Generate(ctx, Request{Repository: root, BaseSHA: sha, Units: []Unit{unit}})
	if err != nil {
		var failure *toolFailure
		if errors.As(err, &failure) {
			t.Logf("public synthetic fixture diagnostics: %s", failure.diagnostics)
		}
		t.Fatal(err)
	}
	if len(artifact.Changes) != 2 || len(artifact.Units[0].Updates) != 1 || artifact.Units[0].Updates[0].To != "7.0.0" {
		t.Fatalf("real locked remediation did not reach expected version: %+v", artifact)
	}
	if strings.Contains(string(artifact.Patch), "127.0.0.1") {
		t.Fatal("ephemeral registry leaked into real patch")
	}
	if _, err := Apply(ctx, root, *artifact); err != nil {
		t.Fatal(err)
	}
}
