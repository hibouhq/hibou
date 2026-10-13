package applicability

import (
	"testing"

	"github.com/hibouhq/hibou/internal/scancatalog"
)

func catalog(t *testing.T) *scancatalog.Catalog {
	t.Helper()
	c, err := scancatalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func scope(result Result, id string) (ScannerScope, bool) {
	for _, s := range result.Applicable {
		if s.ScannerID == id {
			return s, true
		}
	}
	return ScannerScope{}, false
}

// A mixed repository: Maven Java module, Node TypeScript module, vendored and
// built code excluded, docs ignored.
func TestDetectMixedRepository(t *testing.T) {
	result := Detect([]string{
		"README.md",
		"java/pom.xml",
		"java/src/main/java/com/acme/App.java",
		"java/target/classes/com/acme/App.class",
		"web/package.json",
		"web/src/index.ts",
		"web/node_modules/lodash/index.js",
		"web/dist/app.min.js",
		"go/go.mod",
		"go/main.go",
		"go/vendor/x/y.go",
		"scripts/release.sh",
	}, false, catalog(t))

	if result.Status != StatusComplete || result.TextOnly {
		t.Fatalf("status = %s textOnly = %v", result.Status, result.TextOnly)
	}
	if result.Languages["java"] != 1 || result.Languages["typescript"] != 1 || result.Languages["go"] != 1 || result.Languages["javascript"] != 0 {
		t.Fatalf("languages = %v", result.Languages)
	}
	if len(result.Modules) != 3 {
		t.Fatalf("modules = %+v", result.Modules)
	}
	excluded := map[string]string{}
	for _, e := range result.Exclusions {
		excluded[e.Path] = e.Reason
	}
	if excluded["web/node_modules"] != "dependency directory" || excluded["java/target"] != "build output" || excluded["go/vendor"] != "vendored code" || excluded["web/dist"] == "" {
		t.Fatalf("exclusions = %v", excluded)
	}

	opengrep, ok := scope(result, "opengrep")
	if !ok || len(opengrep.Modules) != 3 {
		t.Fatalf("opengrep scope = %+v", opengrep)
	}
	spotbugs, ok := scope(result, "spotbugs-findsecbugs")
	if !ok || len(spotbugs.Modules) != 1 || spotbugs.Modules[0] != "java" {
		t.Fatalf("spotbugs needs the Maven module only: %+v", spotbugs)
	}
	if interfile, ok := scope(result, "opengrep-interfile"); !ok || !interfile.Preview {
		t.Fatalf("interfile pre-release applies to Java, flagged preview: %+v", interfile)
	}
}

func TestDetectTextOnlyAndUnknown(t *testing.T) {
	docs := Detect([]string{"README.md", "docs/guide.md", "docs/img/arch.png"}, false, catalog(t))
	if !docs.TextOnly || len(docs.Applicable) != 0 {
		t.Fatalf("docs repo = %+v", docs)
	}
	// A docs repo with code-bearing build scripts still has applicable
	// analysis (ADR-035 §3).
	withScript := Detect([]string{"README.md", "tools/gen.py"}, false, catalog(t))
	if withScript.TextOnly {
		t.Fatal("a Python script is source")
	}
	if _, ok := scope(withScript, "opengrep"); !ok {
		t.Fatalf("opengrep must apply to the script: %+v", withScript.Applicable)
	}
	truncated := Detect([]string{"README.md"}, true, catalog(t))
	if truncated.Status != StatusTruncated || truncated.TextOnly {
		t.Fatalf("a truncated listing is never proof of text-only: %+v", truncated)
	}
	if unknown := Detect(nil, false, catalog(t)); unknown.Status != StatusUnknown {
		t.Fatalf("nil listing = %+v", unknown)
	}
}

// Gradle without Maven: SpotBugs (Maven adapter) does not apply yet.
func TestDetectGradleNotMaven(t *testing.T) {
	result := Detect([]string{"build.gradle.kts", "src/main/kotlin/App.kt"}, false, catalog(t))
	if _, ok := scope(result, "spotbugs-findsecbugs"); ok {
		t.Fatal("the SpotBugs entry is a Maven adapter")
	}
	if result.Modules[0].BuildSystem != "gradle" || result.Modules[0].Root != "." {
		t.Fatalf("modules = %+v", result.Modules)
	}
}

// Owners refine detection: an allowed exclusion hides its paths; a refused
// one is reported with why; a declared module root is added.
func TestDetectWithOverrides(t *testing.T) {
	paths := []string{"pom.xml", "src/main/java/App.java", "generated/Gen.java", "fixtures/bad.py", "tools/x/run.py"}
	result := DetectWithOverrides(paths, false, catalog(t), Overrides{
		Exclusions: []OwnerExclusion{
			{Path: "fixtures", Reason: "intentionally vulnerable samples"},
			{Path: "generated/", Reason: "protobuf output"},
		},
		ModuleRoots: []string{"tools/x"},
		Allow: func(path string, languages []string) (bool, string) {
			for _, language := range languages {
				if language == "java" {
					return false, "java is required by the org: needs an approved exception for " + path
				}
			}
			return true, ""
		},
	})
	byPath := map[string]OwnerExclusion{}
	for _, exclusion := range result.OwnerExclusions {
		byPath[exclusion.Path] = exclusion
	}
	if !byPath["fixtures"].Applied || byPath["generated"].Applied || byPath["generated"].Blocked == "" {
		t.Fatalf("owner exclusions = %+v", result.OwnerExclusions)
	}
	if result.Languages["python"] != 1 || result.Languages["java"] != 2 {
		t.Fatalf("languages after exclusions = %v", result.Languages)
	}
	declared := false
	for _, module := range result.Modules {
		declared = declared || (module.Root == "tools/x" && module.BuildSystem == "declared" && len(module.Languages) == 1)
	}
	if !declared {
		t.Fatalf("declared module root missing: %+v", result.Modules)
	}
}

// A directory named like an option or climbing out of the checkout never
// becomes a module root or an exclusion: both reach scanners as arguments
// (Q14: a module "--exclude=*" emptied the SAST scope).
func TestDetectDropsOptionLikeAndEscapingRoots(t *testing.T) {
	result := DetectWithOverrides([]string{
		"--exclude=*/pom.xml",
		"--exclude=*/src/App.java",
		"-x/node_modules/a.js",
		"../up/pom.xml",
		"java/pom.xml",
		"java/src/App.java",
	}, false, catalog(t), Overrides{ModuleRoots: []string{"-declared", "../escape", "ok"}})
	for _, module := range result.Modules {
		if !safeRoot(module.Root) {
			t.Errorf("unsafe module root planned: %q", module.Root)
		}
		if module.Root == "-declared" || module.Root == "../escape" {
			t.Errorf("declared unsafe root kept: %q", module.Root)
		}
	}
	for _, exclusion := range result.Exclusions {
		if !safeRoot(exclusion.Path) {
			t.Errorf("unsafe exclusion planned: %q", exclusion.Path)
		}
	}
	for _, s := range result.Applicable {
		for _, module := range s.Modules {
			if !safeRoot(module) {
				t.Errorf("%s targets unsafe module %q", s.ScannerID, module)
			}
		}
	}
	found := false
	for _, module := range result.Modules {
		if module.Root == "java" {
			found = true
		}
	}
	if !found {
		t.Fatalf("safe module dropped: %+v", result.Modules)
	}
}
