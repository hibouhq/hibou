package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"deps.dev/util/resolve"
	"deps.dev/util/semver"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	osvpb "github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
)

type fixtureEnricher struct{ vulnerability *osvpb.Vulnerability }

func (fixtureEnricher) Name() string                       { return "vulnmatch/hibou" }
func (fixtureEnricher) Version() int                       { return 1 }
func (fixtureEnricher) Requirements() *plugin.Capabilities { return nil }
func (fixtureEnricher) RequiredPlugins() []string          { return nil }
func (e fixtureEnricher) Enrich(ctx context.Context, _ *enricher.ScanInput, inv *inventory.Inventory) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, p := range inv.Packages {
		if p.Name == "fixture-dependency" && p.Version == "1.0.0" {
			inv.PackageVulns = append(inv.PackageVulns, &inventory.PackageVuln{Package: p, Vulnerability: e.vulnerability})
		}
	}
	return nil
}

func fixtureSCALIBR(t *testing.T) SCALIBR {
	t.Helper()
	client := resolve.NewLocalClient()
	key := resolve.PackageKey{System: resolve.NPM, Name: "fixture-dependency"}
	for _, version := range []string{"1.0.0", "1.0.1"} {
		client.AddVersion(resolve.Version{VersionKey: resolve.VersionKey{PackageKey: key, VersionType: resolve.Concrete, Version: version}}, nil)
	}
	var vulnerability osvpb.Vulnerability
	if err := protojson.Unmarshal([]byte(`{
		"id":"TEST-1","affected":[{"package":{"ecosystem":"npm","name":"fixture-dependency"},
		"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.1"}]}]}]
	}`), &vulnerability); err != nil {
		t.Fatal(err)
	}
	return SCALIBR{
		Resolver: client, Enricher: fixtureEnricher{&vulnerability},
		VerifyFiles: func(_ context.Context, root string, unit Unit, _ UnitResult) (Verification, error) {
			data, err := os.ReadFile(filepath.Join(root, unit.Manifest))
			if err != nil {
				return Verification{}, err
			}
			var manifest struct {
				Dependencies map[string]string `json:"dependencies"`
			}
			if err := json.Unmarshal(data, &manifest); err != nil {
				return Verification{}, err
			}
			constraint, err := semver.NPM.ParseConstraint(manifest.Dependencies["fixture-dependency"])
			if err != nil {
				return Verification{}, err
			}
			// This fixture has precisely two published versions and one advisory.
			fixed := constraint.Match("1.0.1") && !constraint.Match("1.0.0")
			return Verification{true, fixed, true}, nil
		},
	}
}

func TestSCALIBRGeneratesRealPatchOffline(t *testing.T) {
	original := "{\n  \"name\": \"fixture-app\",\n  \"version\": \"1.0.0\",\n  \"dependencies\": {\"fixture-dependency\": \"1.0.0\"}\n}\n"
	root, sha := repository(t, map[string]string{"package.json": original})
	unit := Unit{ID: "root", Manager: "npm", Manifest: "package.json",
		RequiredFiles: []string{"package.json"}, WritableFiles: []string{"package.json"}, Vulns: []string{"TEST-1"}, UpgradeLevel: "patch",
		InputSHA256: map[string]string{"package.json": digest([]byte(original))}}
	artifact, err := (Engine{Backend: fixtureSCALIBR(t), TempDir: t.TempDir()}).Generate(t.Context(), Request{Repository: root, BaseSHA: sha, Units: []Unit{unit}})
	if err != nil {
		t.Fatal(err)
	}
	if len(artifact.Units) != 1 || len(artifact.Units[0].Updates) != 1 || !strings.Contains(string(artifact.Patch), "1.0.1") {
		t.Fatalf("missing actual SCALIBR update: %+v", artifact)
	}
	if strings.Contains(string(artifact.Patch), "-  \"name\"") {
		t.Fatal("unrelated manifest formatting changed")
	}
}

func TestSCALIBRRejectsUnsafeOrUnverifiedPaths(t *testing.T) {
	for _, mutate := range []func(*SCALIBR, *Unit){
		func(s *SCALIBR, _ *Unit) { s.VerifyFiles = nil },
		func(_ *SCALIBR, u *Unit) { u.Lockfile = "package-lock.json" },
		func(_ *SCALIBR, u *Unit) { u.RequiredFiles = []string{"package.json", "package-lock.json"} },
		func(_ *SCALIBR, u *Unit) { u.Manager = "pnpm" },
		func(_ *SCALIBR, u *Unit) { u.Manager = "poetry"; u.Manifest = "pyproject.toml" },
		func(_ *SCALIBR, u *Unit) { u.UpgradeLevel = "latest" },
	} {
		s := fixtureSCALIBR(t)
		u := Unit{Manager: "npm", Manifest: "package.json"}
		mutate(&s, &u)
		if err := s.Validate(u); err == nil {
			t.Fatal("unsupported/unverified path accepted")
		}
	}
}

type failingResolver struct{ resolve.Client }

func (c failingResolver) Versions(context.Context, resolve.PackageKey) ([]resolve.Version, error) {
	return nil, errors.New("metadata unavailable")
}

func TestSCALIBRMetadataErrorsAreFatal(t *testing.T) {
	s := fixtureSCALIBR(t)
	s.Resolver = failingResolver{s.Resolver}
	root, sha := repository(t, map[string]string{"package.json": `{"name":"app","version":"1.0.0","dependencies":{"fixture-dependency":"1.0.0"}}`})
	data, err := os.ReadFile(filepath.Join(root, "package.json"))
	if err != nil {
		t.Fatal(err)
	}
	u := Unit{ID: "root", Manager: "npm", Manifest: "package.json", RequiredFiles: []string{"package.json"}, WritableFiles: []string{"package.json"}, Vulns: []string{"TEST-1"}, InputSHA256: map[string]string{"package.json": digest(data)}}
	artifact, err := (Engine{Backend: s}).Generate(t.Context(), Request{Repository: root, BaseSHA: sha, Units: []Unit{u}})
	if err == nil || artifact != nil {
		t.Fatal("metadata failure exposed an artifact")
	}
}
