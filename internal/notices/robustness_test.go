package notices

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/licenseclassifier/v2/assets"
)

func TestRealClassifierCorpus(t *testing.T) {
	classifier, err := NewClassifier()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "MPL-2.0", "GPL-2.0", "LGPL-2.1"} {
		t.Run(id, func(t *testing.T) {
			// The production classifier ships these SPDX reference fixtures.
			filename := "pristine.txt"
			if id == "GPL-2.0" {
				filename = "a.txt"
			}
			data, err := assets.ReadLicenseFile("License/" + id + "/" + filename)
			if err != nil {
				t.Fatal(err)
			}
			got, confidence := classifier.Classify(data)
			if got != id || confidence < minClassifierConfidence {
				t.Fatalf("classified %s as %s (%.3f)", id, got, confidence)
			}
		})
	}
	if id, _ := classifier.Classify([]byte("This is not a licence, it is arbitrary package metadata.")); id != "" {
		t.Fatalf("classified unknown text as %q", id)
	}
}

func TestNestedLicenseChoicesKeepConjunctionsAndExceptions(t *testing.T) {
	expression := "(MIT OR Apache-2.0) AND BSD-3-Clause"
	chosen, _ := chooseAlternative(expression, "")
	if chosen != "Apache-2.0 AND BSD-3-Clause" {
		t.Fatalf("choice dropped an AND obligation: %s", chosen)
	}
	if got := strings.Join(expressionIDs("GPL-2.0-only WITH Classpath-exception-2.0"), ","); got != "GPL-2.0-only" {
		t.Fatalf("exception was treated as a licence: %s", got)
	}
	c := Component{Purl: "pkg:npm/fixture@1.0", Name: "fixture", Version: "1.0"}
	doc := Generate([]Component{c}, Options{
		Collectors: []Collector{fakeCollector{c.Purl: {Found: true, Declared: "MIT OR Apache-2.0",
			Files: []File{{Path: "LICENSE-MIT", Text: mitText}, {Path: "LICENSE-APACHE", Text: apacheText}}}}},
		Classifier: fakeClassifier{},
		Overrides:  []Override{{Purl: c.Purl, Choose: "GPL-3.0-only", Reason: "invalid fixture choice"}},
	})
	if !strings.Contains(gapKinds(doc, c.Purl), GapDisagreement) || len(doc.Texts) != 2 {
		t.Fatalf("invalid choice accepted or evidence discarded: %+v", doc)
	}
}

func TestMetadataAndOverridesCannotHideMissingEvidence(t *testing.T) {
	c := Component{Purl: "pkg:npm/fixture@1.0", Name: "fixture", Version: "1.0"}
	for _, override := range []Override{
		{Purl: c.Purl, Copyright: "Copyright 2020 Fixture Authors", Reason: "copyright only"},
		{Purl: c.Purl, License: "Apache-2.0", Reason: "identifier only"},
		{Purl: c.Purl, Choose: "MIT", Reason: "choice only"},
	} {
		doc := Generate([]Component{c}, Options{
			Collectors: []Collector{fakeCollector{c.Purl: {Found: true, Declared: "Apache-2.0"}}},
			Overrides:  []Override{override}, Classifier: fakeClassifier{},
		})
		if !strings.Contains(gapKinds(doc, c.Purl), GapNoLicenseFile) {
			t.Fatalf("override silently filled absent text: %+v", doc.Entries[0])
		}
	}
	doc := Generate([]Component{c}, Options{
		Collectors: []Collector{fakeCollector{c.Purl: {Found: true, Declared: "MIT AND Apache-2.0", Files: []File{{Text: mitText}}}}},
		Classifier: fakeClassifier{},
	})
	if !strings.Contains(gapKinds(doc, c.Purl), GapUnknown) {
		t.Fatal("one text incorrectly fulfilled two required licences")
	}
	doc = Generate([]Component{c}, Options{
		Collectors: []Collector{fakeCollector{c.Purl: {Found: true, Declared: "Apache-2.0", Files: []File{{Text: mitText}}}}},
		Classifier: fakeClassifier{},
		Overrides:  []Override{{Purl: c.Purl, Copyright: "Copyright 2020 Fixture Authors", Reason: "copyright correction only"}},
	})
	if !strings.Contains(gapKinds(doc, c.Purl), GapDisagreement) {
		t.Fatal("copyright-only override suppressed a licence disagreement")
	}
}

func TestEvidenceLimitsIncludeNoticesAndRejectSymlinks(t *testing.T) {
	dir := t.TempDir()
	for i := range maxFilesPerPackage + 3 {
		name := fmt.Sprintf("LICENSE-%02d", i)
		if err := os.WriteFile(filepath.Join(dir, name), []byte(mitText), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	files, _, issues := readDirEvidence(dir)
	if len(files) != maxFilesPerPackage || len(issues) != 1 {
		t.Fatalf("unbounded evidence: files=%d issues=%v", len(files), issues)
	}
	other := t.TempDir()
	if err := os.WriteFile(filepath.Join(other, "NOTICE"), []byte(strings.Repeat("x", maxLicenseFileBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "LICENSE-00"), filepath.Join(other, "LICENSE")); err != nil {
		t.Fatal(err)
	}
	files, notice, issues := readDirEvidence(other)
	if len(files) != 0 || notice != "" || len(issues) != 2 {
		t.Fatalf("unsafe evidence accepted: files=%v notice=%q issues=%v", files, notice, issues)
	}
}

func TestMavenArchiveAndPythonEvidenceFailuresAreReported(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "org", "example", "fixture", "1.0")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	jar, err := os.Create(filepath.Join(dir, "fixture-1.0.jar"))
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(jar)
	for name, content := range map[string]string{
		"META-INF/LICENSE": mitText, "META-INF/NOTICE": "Copyright 2020 Fixture Authors",
		"OTHER/LICENSE": "not evidence", "../LICENSE": "not evidence",
	} {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := jar.Close(); err != nil {
		t.Fatal(err)
	}
	m := &mavenCollector{opts: CacheOptions{MavenRepo: root}}
	evidence := m.Collect(Component{Purl: "pkg:maven/org.example/fixture@1.0"})
	if len(evidence.Files) != 1 || evidence.Notice == "" || len(evidence.Issues) != 0 {
		t.Fatalf("Maven archive evidence=%+v", evidence)
	}
	if err := os.WriteFile(filepath.Join(dir, "fixture-1.0.jar"), []byte("corrupt archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := m.Collect(Component{Purl: "pkg:maven/org.example/fixture@1.0"}); len(got.Issues) == 0 {
		t.Fatal("corrupt archive silently ignored")
	}
	for _, raw := range []string{
		"pkg:maven/org.example/fixture@1.0?type=..%2F..%2Fsecret",
		"pkg:npm/fixture@..%2Fsecret",
	} {
		if _, ok := parsePurl(raw); ok {
			t.Fatalf("unsafe package path accepted: %s", raw)
		}
	}
}

func TestEvidenceIssuesStayVisibleAsGaps(t *testing.T) {
	c := Component{Purl: "pkg:npm/fixture@1.0", Name: "fixture", Version: "1.0"}
	doc := Generate([]Component{c}, Options{Classifier: fakeClassifier{}, Collectors: []Collector{fakeCollector{
		c.Purl: {Found: true, Declared: "MIT", Files: []File{{Text: mitText}}, Issues: []string{"cannot read NOTICE"}},
	}}})
	if got := gapKinds(doc, c.Purl); got != GapEvidence {
		t.Fatalf("evidence failure disappeared: %s", got)
	}
}

func TestVendorEvidenceMustMatchExactVersion(t *testing.T) {
	root := t.TempDir()
	write := func(name, text string) {
		t.Helper()
		full := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("vendor/example.com/tool/LICENSE", mitText)
	write("vendor/modules.txt", "# example.com/tool v2.0.0\n")
	goCache := &goCollector{opts: CacheOptions{Root: root, GoModCache: filepath.Join(root, "empty-cache")}}
	if goCache.Collect(Component{Purl: "pkg:golang/example.com/tool@1.0.0"}).Found {
		t.Fatal("used another Go vendor version's evidence")
	}
	if got := goCache.Collect(Component{Purl: "pkg:golang/example.com/tool@2.0.0"}); !got.Found || len(got.Files) != 1 {
		t.Fatalf("binary-normalized Go version not found: %+v", got)
	}
	write("vendor/fixture/Cargo.toml", "[package]\nname='fixture'\nversion='2.0.0'\nlicense='MIT'\n")
	write("vendor/fixture/LICENSE", mitText)
	cargo := &cargoCollector{opts: CacheOptions{Root: root, CargoHome: filepath.Join(root, "empty-cargo")}}
	if cargo.Collect(Component{Purl: "pkg:cargo/fixture@1.0.0"}).Found {
		t.Fatal("used another Cargo vendor version's evidence")
	}
	if got := cargo.Collect(Component{Purl: "pkg:cargo/fixture@2.0.0"}); !got.Found || got.Declared != "MIT" {
		t.Fatalf("TOML package metadata not read: %+v", got)
	}
}

func TestMalformedAndOversizedMetadataNeverPanicsOrDisappears(t *testing.T) {
	root := t.TempDir()
	dist := filepath.Join(root, "fixture-1.0.dist-info")
	if err := os.MkdirAll(dist, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dist, "LICENSE"), []byte(mitText), 0o600); err != nil {
		t.Fatal(err)
	}
	python := &pythonCollector{opts: CacheOptions{SitePackages: []string{root}, Root: t.TempDir()}}
	if got := python.Collect(Component{Purl: "pkg:pypi/fixture@1.0"}); len(got.Issues) == 0 {
		t.Fatal("missing METADATA silently ignored")
	}
	if err := os.WriteFile(filepath.Join(dist, "METADATA"), []byte("Name: fixture\nLicense: MIT"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := python.Collect(Component{Purl: "pkg:pypi/fixture@1.0"}); got.Declared != "MIT" {
		t.Fatalf("metadata without trailing separator was not read: %+v", got)
	}
	if err := os.WriteFile(filepath.Join(root, "VERSION"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	goCache := &goCollector{opts: CacheOptions{GoRoot: root}}
	if got := goCache.Collect(Component{Purl: "pkg:golang/go@1.0.0", Version: "1.0.0"}); len(got.Issues) == 0 {
		t.Fatal("empty Go toolchain VERSION was not reported")
	}
}
