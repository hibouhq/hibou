package notices

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeClassifier identifies a text by a marker word, so tests need no corpus.
type fakeClassifier struct{}

func (fakeClassifier) Classify(text []byte) (string, float64) {
	s := string(text)
	switch {
	case strings.Contains(s, "Apache License"):
		return "Apache-2.0", 1
	case strings.Contains(s, "Permission is hereby granted"):
		return "MIT", 1
	case strings.Contains(s, "Lesser General Public"):
		return "LGPL-2.1-only", 1
	}
	return "", 0
}
func (fakeClassifier) Version() string { return "fake" }

type fakeCollector map[string]Evidence

func (f fakeCollector) Handles(Component) bool       { return true }
func (f fakeCollector) Collect(c Component) Evidence { return f[c.Purl] }

const mitText = "MIT License\n\nCopyright (c) 2019 Acme Corp\n\nPermission is hereby granted, free of charge...\n"
const apacheText = "Apache License\nVersion 2.0, January 2004\n"

func TestCopyrightLines(t *testing.T) {
	text := "MIT License\n\nCopyright (c) 2019 Acme Corp\n * Copyright 2020-2023 The Authors\r\n" +
		"The above copyright notice and this permission notice shall be included\n" +
		"Copyright (c) <year> <copyright holders>\n© 2021 Someone\n"
	got := CopyrightLines(text)
	want := []string{"Copyright (c) 2019 Acme Corp", "Copyright 2020-2023 The Authors", "© 2021 Someone"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("CopyrightLines = %q, want %q", got, want)
	}
}

func TestChooseAlternative(t *testing.T) {
	cases := []struct{ expression, choose, want, reason string }{
		{"MIT", "", "MIT", ""},
		{"MIT OR Apache-2.0", "", "Apache-2.0", "least demanding"},
		{"GPL-2.0-only OR MIT", "", "MIT", "least demanding"},
		{"MIT OR Apache-2.0", "MIT", "MIT", "override"},
		{"(LGPL-2.1-only OR MPL-2.0) ", "", "LGPL-2.1-only", "least demanding"},
		{"Apache-2.0 AND MIT", "", "Apache-2.0 AND MIT", ""},
	}
	for _, c := range cases {
		got, reason := chooseAlternative(c.expression, c.choose)
		if strings.TrimSpace(got) != c.want || reason != c.reason {
			t.Errorf("chooseAlternative(%q, %q) = %q, %q; want %q, %q", c.expression, c.choose, got, reason, c.want, c.reason)
		}
	}
}

func TestPurlBaseAndOverrideMatch(t *testing.T) {
	if got := PurlBase("pkg:npm/%40scope/name@1.2.3?x=y"); got != "pkg:npm/%40scope/name" {
		t.Fatalf("PurlBase = %q", got)
	}
	overrides := []Override{
		{Purl: "pkg:cargo/serde", Choose: "Apache-2.0", Reason: "any version"},
		{Purl: "pkg:cargo/serde@1.0.0", License: "MIT", Reason: "exact"},
	}
	if o, ok := matchOverride(overrides, "pkg:cargo/serde@1.0.0"); !ok || o.Reason != "exact" {
		t.Fatalf("exact version override must win, got %+v", o)
	}
	if o, ok := matchOverride(overrides, "pkg:cargo/serde@2.0.0"); !ok || o.Reason != "any version" {
		t.Fatalf("version-less override must apply, got %+v", o)
	}
	if _, ok := matchOverride(overrides, "pkg:cargo/other@1.0.0"); ok {
		t.Fatal("override applied to another package")
	}
}

func TestLicenseAndNoticeFileNames(t *testing.T) {
	for _, name := range []string{"LICENSE", "LICENSE.md", "LICENCE.txt", "LICENSE-MIT", "COPYING.LESSER", "MIT-LICENSE.txt", "UNLICENSE"} {
		if !isLicenseFile(name) {
			t.Errorf("%s must be a licence file", name)
		}
	}
	for _, name := range []string{"license.go", "README.md", "licenses.json.js", "index.js"} {
		if isLicenseFile(name) {
			t.Errorf("%s must not be a licence file", name)
		}
	}
	if !isNoticeFile("NOTICE") || !isNoticeFile("NOTICE.txt") || isNoticeFile("NOTICE.go") {
		t.Error("NOTICE file detection")
	}
}

func TestEscapeModulePath(t *testing.T) {
	if got := escapeModulePath("github.com/BurntSushi/toml"); got != "github.com/!burnt!sushi/toml" {
		t.Fatalf("escapeModulePath = %q", got)
	}
}

func testComponents() ([]Component, fakeCollector) {
	components := []Component{
		{Purl: "pkg:npm/zeta@1.0.0", Name: "zeta", Version: "1.0.0", Ecosystem: "npm"},
		{Purl: "pkg:npm/alpha@2.0.0", Name: "alpha", Version: "2.0.0", Ecosystem: "npm"},
		{Purl: "pkg:golang/example.com/apache@v1.0.0", Name: "example.com/apache", Version: "v1.0.0", Ecosystem: "golang"},
		{Purl: "pkg:npm/missing@0.1.0", Name: "missing", Version: "0.1.0", Ecosystem: "npm"},
		{Purl: "pkg:npm/nofile@0.2.0", Name: "nofile", Version: "0.2.0", Ecosystem: "npm"},
		{Purl: "pkg:maven/org.x/lgpl@3.0", Name: "org.x:lgpl", Version: "3.0", Ecosystem: "maven"},
		{Purl: "pkg:npm/mislabelled@1.0.0", Name: "mislabelled", Version: "1.0.0", Ecosystem: "npm"},
		{Purl: "pkg:npm/alpha@2.0.0", Name: "alpha", Version: "2.0.0", Ecosystem: "npm"}, // duplicate
	}
	collector := fakeCollector{
		"pkg:npm/zeta@1.0.0":  {Found: true, Declared: "MIT", Files: []File{{Path: "LICENSE", Text: mitText}}},
		"pkg:npm/alpha@2.0.0": {Found: true, Declared: "MIT", Files: []File{{Path: "LICENSE", Text: strings.ReplaceAll(mitText, "\n", "\r\n")}}},
		"pkg:golang/example.com/apache@v1.0.0": {Found: true, Files: []File{{Path: "LICENSE", Text: apacheText}},
			Notice: "Example\nCopyright 2020 Example Authors\n"},
		"pkg:npm/nofile@0.2.0":      {Found: true, Declared: "ISC"},
		"pkg:maven/org.x/lgpl@3.0":  {Found: true, Files: []File{{Path: "META-INF/LICENSE", Text: "GNU Lesser General Public License\n"}}},
		"pkg:npm/mislabelled@1.0.0": {Found: true, Declared: "Apache-2.0", Files: []File{{Path: "LICENSE", Text: mitText}}},
	}
	return components, collector
}

func gapKinds(doc *Document, purl string) string {
	for _, e := range doc.Entries {
		if e.Purl == purl {
			kinds := []string{}
			for _, g := range e.Gaps {
				kinds = append(kinds, g.Kind)
			}
			return strings.Join(kinds, ",")
		}
	}
	return "absent"
}

func TestGenerate(t *testing.T) {
	components, collector := testComponents()
	doc := Generate(components, Options{Collectors: []Collector{collector}, Classifier: fakeClassifier{}})

	if len(doc.Entries) != 7 {
		t.Fatalf("entries = %d, want 7 (duplicate purl merged)", len(doc.Entries))
	}
	if doc.Entries[0].Name != "alpha" || doc.Entries[len(doc.Entries)-1].Name != "zeta" {
		t.Fatalf("entries not sorted by name: first %q, last %q", doc.Entries[0].Name, doc.Entries[len(doc.Entries)-1].Name)
	}
	// The same MIT text with LF and CRLF line endings is one text.
	mit := 0
	for _, text := range doc.Texts {
		if text.License == "MIT" {
			mit++
			if got := strings.Join(text.UsedBy, ","); got != "alpha 2.0.0,mislabelled 1.0.0,zeta 1.0.0" {
				t.Errorf("MIT text used by %q", got)
			}
		}
	}
	if mit != 1 {
		t.Fatalf("distinct MIT texts = %d, want 1", mit)
	}
	want := map[string]string{
		"pkg:npm/zeta@1.0.0":                   "",
		"pkg:golang/example.com/apache@v1.0.0": "", // Apache text without a copyright line is not a gap
		"pkg:npm/missing@0.1.0":                GapNotFound + "," + GapUnknown,
		"pkg:npm/nofile@0.2.0":                 GapNoLicenseFile,
		"pkg:npm/mislabelled@1.0.0":            GapUnknown + "," + GapDisagreement,
	}
	for purl, kinds := range want {
		if got := gapKinds(doc, purl); got != kinds {
			t.Errorf("gaps of %s = %q, want %q", purl, got, kinds)
		}
	}
	if len(doc.Obligations) != 1 || doc.Obligations[0].License != "LGPL-2.1-only" {
		t.Fatalf("obligations = %+v, want one for LGPL-2.1-only", doc.Obligations)
	}
	for _, e := range doc.Entries {
		if e.Name == "example.com/apache" && (e.Notice == "" || len(e.Copyrights) != 1) {
			t.Errorf("apache entry: notice %q copyrights %q", e.Notice, e.Copyrights)
		}
	}
}

func TestOverrideClosesGap(t *testing.T) {
	components, collector := testComponents()
	doc := Generate(components, Options{Collectors: []Collector{collector}, Classifier: fakeClassifier{}, Overrides: []Override{
		{Purl: "pkg:npm/missing@0.1.0", License: "MIT", Copyright: "Copyright (c) 2018 Missing Authors", Reason: "upstream has no LICENSE file"},
		{Purl: "pkg:npm/mislabelled", License: "MIT", Reason: "package.json is wrong, LICENSE is MIT"},
	}})
	if got := gapKinds(doc, "pkg:npm/mislabelled@1.0.0"); got != "" {
		t.Errorf("corrected identifier left gaps: %q", got)
	}
	if got := gapKinds(doc, "pkg:npm/missing@0.1.0"); got != GapNotFound {
		t.Errorf("identifier/copyright override must not fabricate licence text: %q", got)
	}
}

func TestRenderIsDeterministicAndInputOrderIndependent(t *testing.T) {
	components, collector := testComponents()
	opts := Options{Collectors: []Collector{collector}, Classifier: fakeClassifier{},
		Included: []Included{{Path: "NOTICES.manual.md", Body: "# Ported code\n\nSome text.\n"}}}
	first, err := Render(Generate(components, opts), FormatMarkdown)
	if err != nil {
		t.Fatal(err)
	}
	reversed := make([]Component, len(components))
	for i, c := range components {
		reversed[len(components)-1-i] = c
	}
	second, _ := Render(Generate(reversed, opts), FormatMarkdown)
	if first != second {
		t.Fatalf("rendering depends on input order:\n%s", Diff(first, second, 40))
	}
	for _, needle := range []string{
		"7 shipped components", "## Gaps", "## Obligations beyond attribution", "### alpha 2.0.0",
		"- Copyright (c) 2019 Acme Corp", "## NOTICE files", "## Additional notices (NOTICES.manual.md)", "# Ported code",
	} {
		if !strings.Contains(first, needle) {
			t.Errorf("markdown lacks %q", needle)
		}
	}
	text, err := Render(Generate(components, opts), FormatText)
	if err != nil || !strings.Contains(text, "THIRD-PARTY NOTICES") || strings.Contains(text, "```") {
		t.Errorf("text rendering: err=%v", err)
	}
	if _, err := Render(Generate(components, opts), "pdf"); err == nil {
		t.Error("unknown format must be an error")
	}
}

func TestDiff(t *testing.T) {
	if Diff("a\nb\n", "a\nb\n", 10) != "" {
		t.Fatal("equal texts must have no diff")
	}
	got := Diff("a\nb\nc\n", "a\nx\nc\n", 10)
	if !strings.Contains(got, "-b") || !strings.Contains(got, "+x") || strings.Contains(got, "-a") {
		t.Fatalf("diff = %q", got)
	}
	if got := Diff("", "one\ntwo\nthree\n", 2); !strings.Contains(got, "more changed lines") {
		t.Fatalf("diff must be capped, got %q", got)
	}
}

func TestLocalCollectorsReadCaches(t *testing.T) {
	root := t.TempDir()
	write := func(path, content string) {
		t.Helper()
		full := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// npm: a scoped package nested under another package's node_modules.
	write("web/node_modules/host/package.json", `{"name":"host","version":"1.0.0","license":"MIT"}`)
	write("web/node_modules/host/node_modules/@scope/lib/package.json", `{"name":"@scope/lib","version":"2.1.0","license":{"type":"Apache-2.0"}}`)
	write("web/node_modules/host/node_modules/@scope/lib/LICENSE", apacheText)
	write("web/node_modules/host/node_modules/@scope/lib/NOTICE", "Lib\nCopyright 2021 Lib Authors\n")
	// Go: module cache with an escaped upper-case path.
	write("modcache/github.com/!acme/tool@v1.2.3/LICENSE", mitText)
	// Cargo: registry source with the legacy "/" expression.
	write("cargo/registry/src/index.crates.io-abc/serde-1.0.0/Cargo.toml", "[package]\nname = \"serde\"\nversion = \"1.0.0\"\nlicense = \"MIT/Apache-2.0\"\n")
	write("cargo/registry/src/index.crates.io-abc/serde-1.0.0/LICENSE-MIT", mitText)
	// Python: PEP 639 layout, name normalized.
	write("venv/lib/python3.12/site-packages/My_Pkg-3.0.dist-info/METADATA", "Metadata-Version: 2.4\nName: My.Pkg\nLicense-Expression: BSD-3-Clause\n\nbody\n")
	write("venv/lib/python3.12/site-packages/My_Pkg-3.0.dist-info/licenses/LICENSE", "BSD\nCopyright (c) 2020 Py Authors\n")

	collectors := LocalCollectors(CacheOptions{
		Root:         root,
		GoModCache:   filepath.Join(root, "modcache"),
		CargoHome:    filepath.Join(root, "cargo"),
		MavenRepo:    filepath.Join(root, "m2"),
		SitePackages: []string{filepath.Join(root, "venv/lib/python3.12/site-packages")},
	})
	collect := func(c Component) Evidence {
		for _, collector := range collectors {
			if collector.Handles(c) {
				return collector.Collect(c)
			}
		}
		return Evidence{}
	}

	npm := collect(Component{Purl: "pkg:npm/%40scope/lib@2.1.0", Ecosystem: "npm", Module: "web"})
	if !npm.Found || npm.Declared != "Apache-2.0" || len(npm.Files) != 1 || !strings.Contains(npm.Notice, "Lib Authors") {
		t.Errorf("npm evidence = %+v", npm)
	}
	if other := collect(Component{Purl: "pkg:npm/%40scope/lib@9.9.9", Ecosystem: "npm", Module: "web"}); other.Found {
		t.Error("npm: another version must not be found")
	}
	golang := collect(Component{Purl: "pkg:golang/github.com/Acme/tool@v1.2.3", Ecosystem: "golang"})
	if !golang.Found || len(golang.Files) != 1 {
		t.Errorf("go evidence = %+v", golang)
	}
	cargo := collect(Component{Purl: "pkg:cargo/serde@1.0.0", Ecosystem: "cargo"})
	if !cargo.Found || cargo.Declared != "MIT OR Apache-2.0" || len(cargo.Files) != 1 {
		t.Errorf("cargo evidence = %+v", cargo)
	}
	python := collect(Component{Purl: "pkg:pypi/my-pkg@3.0", Ecosystem: "pypi"})
	if !python.Found || python.Declared != "BSD-3-Clause" || len(python.Files) != 1 {
		t.Errorf("python evidence = %+v", python)
	}
	if maven := collect(Component{Purl: "pkg:maven/org.x/absent@1.0", Ecosystem: "maven"}); maven.Found {
		t.Error("maven: an artifact missing from the local repository must not be found")
	}
}
