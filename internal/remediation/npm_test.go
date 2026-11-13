package remediation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"deps.dev/util/resolve"

	"github.com/hibouhq/hibou/internal/advisorydb"
)

func npmFixture(t *testing.T, version, constraint string) (string, string) {
	t.Helper()
	manifest := npmManifest{Name: "app", Version: "1.0.0", Dependencies: map[string]string{"fixture-dependency": constraint}}
	lock := npmLock{LockfileVersion: 3, Packages: map[string]npmLockedPackage{
		"": {npmManifest: manifest},
		"node_modules/fixture-dependency": {
			npmManifest: npmManifest{Version: version},
			Resolved:    "https://registry.npmjs.org/fixture-dependency/-/fixture.tgz",
			Integrity:   "sha512-" + base64.StdEncoding.EncodeToString(make([]byte, 64)),
		},
	}}
	m, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	l, err := json.Marshal(lock)
	if err != nil {
		t.Fatal(err)
	}
	return string(m) + "\n", string(l) + "\n"
}

func npmMatchFixture(_ context.Context, purls []string) ([]AdvisoryMatch, error) {
	var out []AdvisoryMatch
	for _, p := range purls {
		private := false
		entry := AdvisoryMatch{Purl: p, Supported: true, Decision: "allow", PrivateNamespace: &private}
		if strings.HasSuffix(p, "@1.0.0") {
			entry.Advisories = []MatchedAdvisory{{CanonicalID: "TEST-1", Ranges: []advisorydb.Range{{Ecosystem: "npm", Package: "fixture-dependency", Introduced: "0", Fixed: "1.0.1"}}}}
		}
		out = append(out, entry)
	}
	return out, nil
}

func fixtureNPMBackend(t *testing.T) NPMBackend {
	t.Helper()
	_, lock := npmFixture(t, "1.0.1", "~1.0.1")
	tool := testTool(t, "if [ \"$1\" = ci ]; then exit 0; fi\n"+
		"if [ \"$1\" = update ]; then\ncat > package-lock.json <<'LOCK'\n"+lock+"LOCK\nexit 0\nfi\nexit 3")
	client := fixtureSCALIBR(t).Resolver
	return NPMBackend{Tool: tool, Match: npmMatchFixture, ResolverFactory: func(string) (resolve.Client, error) { return client, nil }}
}

func TestNPMWholeLockedBatch(t *testing.T) {
	manifest, lock := npmFixture(t, "1.0.0", "1.0.0")
	root, sha := repository(t, map[string]string{"package.json": manifest, "package-lock.json": lock})
	b := fixtureNPMBackend(t)
	unit, err := b.Prepare(t.Context(), root, sha, "package.json", nil, "patch")
	if err != nil {
		t.Fatal(err)
	}
	if len(unit.Vulns) != 1 || unit.Vulns[0] != "TEST-1" {
		t.Fatalf("incorrect selection: %+v", unit)
	}
	a, err := (Engine{Backend: b}).Generate(t.Context(), Request{Repository: root, BaseSHA: sha, Units: []Unit{unit}})
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Changes) != 2 || len(a.Units[0].Updates) != 1 || a.Units[0].Updates[0].To != "1.0.1" {
		t.Fatalf("incomplete locked batch: %+v", a)
	}
	if _, err := Apply(t.Context(), root, *a); err != nil {
		t.Fatal(err)
	}
	packages, err := readNPMProject(root, unit, b.Tool)
	if err != nil || packages[0].Version != "1.0.1" {
		t.Fatalf("applied lockfile: %+v %v", packages, err)
	}
}

func TestNPMPolicyAndConsistencyFailClosed(t *testing.T) {
	for _, mode := range []string{"policy-hold", "missing-advisory-evidence", "strict-check-failure", "introduced-advisory"} {
		t.Run(mode, func(t *testing.T) {
			manifest, lock := npmFixture(t, "1.0.0", "1.0.0")
			root, sha := repository(t, map[string]string{"package.json": manifest, "package-lock.json": lock})
			b := fixtureNPMBackend(t)
			unit, err := b.Prepare(t.Context(), root, sha, "package.json", nil, "patch")
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "strict-check-failure":
				b.Tool = testTool(t, "exit 19")
			case "missing-advisory-evidence":
				b.Match = func(context.Context, []string) ([]AdvisoryMatch, error) { return nil, nil }
			default:
				b.Match = func(ctx context.Context, purls []string) ([]AdvisoryMatch, error) {
					out, err := npmMatchFixture(ctx, purls)
					for i := range out {
						if strings.HasSuffix(out[i].Purl, "@1.0.1") {
							if mode == "policy-hold" {
								out[i].Decision = "hold"
								out[i].Reason = "cooldown"
							} else {
								out[i].Advisories = []MatchedAdvisory{{CanonicalID: "TEST-NEW", Ranges: []advisorydb.Range{{Ecosystem: "npm", Package: "fixture-dependency", Introduced: "1.0.1"}}}}
							}
						}
					}
					return out, err
				}
			}
			a, err := (Engine{Backend: b}).Generate(t.Context(), Request{Repository: root, BaseSHA: sha, Units: []Unit{unit}})
			if err == nil || a != nil {
				t.Fatalf("unsafe locked result returned: %v %v", a, err)
			}
			data, err := os.ReadFile(filepath.Join(root, "package-lock.json"))
			if err != nil || string(data) != lock {
				t.Fatal("failed generation changed source checkout")
			}
		})
	}
}

func TestNPMRejectsUnsupportedAndDriftingInputs(t *testing.T) {
	manifest, lock := npmFixture(t, "1.0.0", "1.0.0")
	for _, tc := range []struct{ name, manifest, lock string }{
		{"wrong-manager", strings.Replace(manifest, `"name":"app"`, `"name":"app","packageManager":"pnpm@9.0.0"`, 1), lock},
		{"workspaces", strings.Replace(manifest, `"name":"app"`, `"name":"app","workspaces":["packages/*"]`, 1), lock},
		{"old-lock-format", manifest, strings.Replace(lock, `"lockfileVersion":3`, `"lockfileVersion":2`, 1)},
		{"root-drift", strings.Replace(manifest, `"fixture-dependency":"1.0.0"`, `"fixture-dependency":"2.0.0"`, 1), lock},
		{"git-input", strings.Replace(manifest, `"fixture-dependency":"1.0.0"`, `"fixture-dependency":"git+ssh://example.test/a"`, 1), lock},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, sha := repository(t, map[string]string{"package.json": tc.manifest, "package-lock.json": tc.lock})
			if _, err := fixtureNPMBackend(t).Prepare(t.Context(), root, sha, "package.json", nil, "patch"); err == nil {
				t.Fatal("unsupported workflow accepted")
			}
		})
	}
}

func TestRealNPMStrictValidationWithoutDependencies(t *testing.T) {
	if _, err := exec.LookPath("npm"); err != nil {
		t.Skip("npm is not installed")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	tool, err := InspectLocalNPM(ctx)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	for file, data := range map[string]string{
		"package.json":      `{"name":"fixture","version":"1.0.0"}`,
		"package-lock.json": `{"name":"fixture","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"fixture","version":"1.0.0"}}}`,
	} {
		if err := os.WriteFile(filepath.Join(root, file), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	u := testUnit()
	if err := (NPMBackend{Tool: tool}).strictCheck(ctx, root, u); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "node_modules")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("strict check installed into the source workspace")
	}
}

func TestAdvisoryRangesAndMatchingCompleteness(t *testing.T) {
	entry := MatchedAdvisory{CanonicalID: "TEST", Ranges: []advisorydb.Range{{Ecosystem: "npm", Package: "fixture-dependency", Fixed: "1.0.1"}}}
	v, err := entry.OSV()
	if err != nil || v.Affected[0].Ranges[0].Events[0].Introduced != "0" {
		t.Fatalf("%v %v", v, err)
	}
	entry.Ranges = nil
	if _, err := entry.OSV(); err == nil {
		t.Fatal("missing ranges accepted")
	}
	for _, results := range [][]AdvisoryMatch{
		nil,
		{{Purl: "pkg:npm/a@1", Supported: false}},
		{{Purl: "pkg:npm/other@1", Supported: true}},
		{{Purl: "pkg:npm/a@1", Supported: true}, {Purl: "pkg:npm/a@1", Supported: true}},
	} {
		if _, err := checkedMatches(t.Context(), func(context.Context, []string) ([]AdvisoryMatch, error) { return results, nil }, []string{"pkg:npm/a@1"}); err == nil {
			t.Fatal("incomplete matching evidence accepted")
		}
	}
}
