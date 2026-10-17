package depinventory

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/osv-scalibr/plugin"

	"github.com/hibouhq/hibou/internal/sbom"
)

type expectedComponent struct {
	Purl         string   `json:"purl"`
	Relationship string   `json:"relationship"`
	Resolution   string   `json:"resolution,omitempty"`
	Module       string   `json:"module,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
}

type expectedCase struct {
	Modules []struct {
		Path     string `json:"path"`
		Complete bool   `json:"complete"`
	} `json:"modules"`
	Components []expectedComponent `json:"components"`
}

// TestCorpus is the ADR-045 rollout step 1 ground truth: every lockfile
// family the first increment supports, with the relationship and scopes a
// person reading the files would assign. A SCALIBR upgrade that changes
// an answer fails here, where it is reviewed, not in a repository's
// inventory.
func TestCorpus(t *testing.T) {
	entries, err := os.ReadDir("testdata/corpus")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join("testdata/corpus", entry.Name())
		raw, err := os.ReadFile(filepath.Join(dir, "expected.json"))
		if err != nil {
			t.Fatalf("%s: %v", entry.Name(), err)
		}
		var expected expectedCase
		if err := json.Unmarshal(raw, &expected); err != nil {
			t.Fatalf("%s: decode expected: %v", entry.Name(), err)
		}
		t.Run(entry.Name(), func(t *testing.T) {
			inv, err := Extract(context.Background(), dir, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if len(inv.FileErrors) > 0 {
				t.Errorf("file errors: %v", inv.FileErrors)
			}
			got := make(map[string]Component, len(inv.Components))
			for _, component := range inv.Components {
				got[component.Module+"|"+component.Purl] = component
			}
			if len(got) != len(expected.Components) {
				t.Errorf("got %d components, want %d: %s", len(got), len(expected.Components), describe(inv.Components))
			}
			for _, want := range expected.Components {
				module := want.Module
				if module == "" {
					module = "."
				}
				component, ok := got[module+"|"+want.Purl]
				if !ok {
					t.Errorf("missing %s in module %s", want.Purl, module)
					continue
				}
				if string(component.Relationship) != want.Relationship {
					t.Errorf("%s: relationship %s, want %s", want.Purl, component.Relationship, want.Relationship)
				}
				wantResolution := want.Resolution
				if wantResolution == "" {
					wantResolution = string(ResolutionRecorded)
				}
				if string(component.Resolution) != wantResolution {
					t.Errorf("%s: resolution %s, want %s", want.Purl, component.Resolution, wantResolution)
				}
				if strings.Join(component.Scopes, ",") != strings.Join(want.Scopes, ",") {
					t.Errorf("%s: scopes %v, want %v", want.Purl, component.Scopes, want.Scopes)
				}
				if component.Path == "" || component.Line <= 0 {
					t.Errorf("%s: evidence missing (path %q line %d)", want.Purl, component.Path, component.Line)
				}
				if component.Name == "" || component.Version == "" || component.Ecosystem == "" {
					t.Errorf("%s: incomplete identity %+v", want.Purl, component)
				}
			}
			if len(inv.Modules) != len(expected.Modules) {
				t.Errorf("got %d modules, want %d: %+v", len(inv.Modules), len(expected.Modules), inv.Modules)
			}
			for _, want := range expected.Modules {
				found := false
				for _, module := range inv.Modules {
					if module.Path == want.Path {
						found = true
						if module.Complete != want.Complete {
							t.Errorf("module %s: complete %v, want %v (%s)", module.Path, module.Complete, want.Complete, module.Reason)
						}
					}
				}
				if !found {
					t.Errorf("module %s missing", want.Path)
				}
			}
		})
	}
}

func describe(components []Component) string {
	parts := make([]string, 0, len(components))
	for _, component := range components {
		parts = append(parts, component.Module+":"+component.Purl)
	}
	sort.Strings(parts)
	return strings.Join(parts, " ")
}

// TestAllowlistIsOffline is the ADR-045 §7 guarantee: no enabled extractor
// may reach the network, and the network-capable Maven extractor is never
// on the list.
func TestAllowlistIsOffline(t *testing.T) {
	names := DefaultExtractors()
	extractors, err := extractorsFor(names)
	if err != nil {
		t.Fatal(err)
	}
	if len(extractors) != len(names) {
		t.Fatalf("%d names resolved to %d extractors", len(names), len(extractors))
	}
	for _, ext := range extractors {
		if err := plugin.ValidateRequirements(ext, offlineCapabilities); err != nil {
			t.Errorf("%s: %v", ext.Name(), err)
		}
		if ext.Requirements().Network == plugin.NetworkOnline {
			t.Errorf("%s requires the network", ext.Name())
		}
	}
	for _, name := range names {
		if strings.HasSuffix(name, "net") || strings.Contains(name, "binary") {
			t.Errorf("%s must not be on the allowlist", name)
		}
	}
	if _, err := extractorsFor([]string{"java/pomxmlnet"}); err == nil {
		t.Error("the network Maven extractor must be refused")
	}
}

// TestInstalledDependenciesAreSkipped: a lockfile under node_modules is a
// dependency's own, never the repository's.
func TestInstalledDependenciesAreSkipped(t *testing.T) {
	inv, err := Extract(context.Background(), "testdata/corpus/monorepo", Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, component := range inv.Components {
		if strings.Contains(component.Path, "node_modules") {
			t.Errorf("extracted from an installed dependency: %s", component.Path)
		}
	}
	for _, module := range inv.Modules {
		if strings.Contains(module.Path, "node_modules") {
			t.Errorf("module under node_modules: %s", module.Path)
		}
	}
}

// TestCycloneDXFeedsExistingIngestion: the document the extractor renders
// is read back by the SBOM parser the upload path uses, with the module
// roots and their direct dependencies in the graph.
func TestCycloneDXFeedsExistingIngestion(t *testing.T) {
	inv, err := Extract(context.Background(), "testdata/corpus/monorepo", Options{})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := ToCycloneDX(inv, "acme/monorepo", "test", time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	components, dependencies, rootRef, _, err := sbom.ParseCycloneDXJSONGraph(doc)
	if err != nil {
		t.Fatalf("ingestion parser rejected the document: %v", err)
	}
	if rootRef != "root" {
		t.Errorf("root ref %q, want root", rootRef)
	}
	purls := make(map[string]struct{})
	for _, component := range components {
		if component.PURL != "" {
			purls[component.PURL] = struct{}{}
		}
	}
	if len(purls) != 8 {
		t.Errorf("ingested %d purls, want 8", len(purls))
	}
	dependsOn := make(map[string][]string, len(dependencies))
	for _, dependency := range dependencies {
		dependsOn[dependency.Ref] = dependency.DependsOn
	}
	if got := dependsOn["root"]; len(got) != 2 {
		t.Errorf("root depends on %v, want the two module refs", got)
	}
	if got := dependsOn["module:web"]; len(got) != 2 || !contains(got, "pkg:npm/express@4.18.2") || !contains(got, "pkg:npm/jest@29.7.0") {
		t.Errorf("web module roots %v, want express and jest", got)
	}
	if strings.Contains(string(doc), "node_modules") {
		t.Error("installed dependencies leaked into the document")
	}
	// The npm lockfile records where each package was resolved from; that
	// provenance travels as a property so private packages can be told
	// apart downstream (ADR-048 §4).
	for _, component := range components {
		if component.PURL == "pkg:npm/express@4.18.2" {
			if got := component.Properties[PropertyRegistry]; len(got) != 1 || got[0] != RegistryPublic {
				t.Errorf("express registry property %v, want public", got)
			}
		}
		if component.PURL == "pkg:golang/stdlib@1.22" {
			if got := component.Properties[PropertyRelationship]; len(got) != 1 || got[0] != string(RelationshipDirect) {
				t.Errorf("stdlib relationship %v, want direct", got)
			}
		}
	}
}

// TestReport prints the numbers ADR-045's spike asks for, on this
// repository. Run with DEPINVENTORY_REPORT=1.
func TestReport(t *testing.T) {
	if os.Getenv("DEPINVENTORY_REPORT") == "" {
		t.Skip("report")
	}
	root := os.Getenv("DEPINVENTORY_REPORT_ROOT")
	if root == "" {
		root = "../.."
	}
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	inv, err := Extract(context.Background(), root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	fmt.Printf("root=%s components=%d modules=%d duration=%s alloc_total=%.1fMiB heap_peak_delta=%.1fMiB file_errors=%d\n",
		root, len(inv.Components), len(inv.Modules), inv.Duration,
		float64(after.TotalAlloc-before.TotalAlloc)/(1<<20), float64(after.HeapSys-before.HeapSys)/(1<<20), len(inv.FileErrors))
}

// TestExcludedManifestsAreReported: dependencies.exclude (ADR-045 §8) keeps
// a test corpus out of the inventory, and the excluded files are listed so
// the exclusion is visible (ADR-034). Nothing is excluded by default.
func TestExcludedManifestsAreReported(t *testing.T) {
	root := t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("requirements.txt", "requests==2.31.0\n")
	write("internal/x/testdata/corpus/requirements.txt", "django==4.2.7\n")
	write("internal/x/testdata/README.md", "not a manifest\n")
	write("node_modules/pkg/testdata/requirements.txt", "jinja2==3.0.0\n")

	inv, err := Extract(context.Background(), root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasComponent(inv, "django") {
		t.Error("testdata is excluded without configuration")
	}
	if len(inv.Excluded) != 0 {
		t.Errorf("Excluded without configuration = %v", inv.Excluded)
	}

	inv, err = Extract(context.Background(), root, Options{Exclude: []string{"**/testdata/**"}})
	if err != nil {
		t.Fatal(err)
	}
	if hasComponent(inv, "django") {
		t.Error("an excluded lockfile was inventoried")
	}
	if !hasComponent(inv, "requests") {
		t.Error("the root manifest was lost")
	}
	want := []string{"internal/x/testdata/corpus/requirements.txt"}
	if strings.Join(inv.Excluded, ",") != strings.Join(want, ",") {
		t.Errorf("Excluded = %v, want %v", inv.Excluded, want)
	}
}

func hasComponent(inv *Inventory, name string) bool {
	for _, component := range inv.Components {
		if component.Name == name {
			return true
		}
	}
	return false
}
