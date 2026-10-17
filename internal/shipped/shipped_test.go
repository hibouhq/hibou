package shipped

import "testing"

func TestList(t *testing.T) {
	list, err := Parse([]string{"pkg:npm/@types/*", "re:^pkg:npm/eslint(-.*)?@", "pkg:golang/github.com/stretchr/testify", "tools/**", "e2e/**", "ecosystem:terraform"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		purl, eco string
		paths     []string
		want      string
	}{
		{"pkg:npm/%40types/node@20.0.0", "npm", nil, "pkg:npm/@types/*"},
		{"pkg:npm/eslint-plugin-vue@9.0.0", "npm", nil, "re:^pkg:npm/eslint(-.*)?@"},
		{"pkg:npm/eslint@8.0.0", "npm", nil, "re:^pkg:npm/eslint(-.*)?@"},
		{"pkg:golang/github.com/stretchr/testify@v1.9.0", "go", nil, "pkg:golang/github.com/stretchr/testify"},
		{"pkg:npm/react@18.2.0", "npm", []string{"tools/gen", "tools/gen/package-lock.json"}, "tools/**"},
		{"pkg:npm/react@18.2.0", "npm", []string{"web", "web/package-lock.json"}, ""},
		{"pkg:generic/hashicorp/aws@5.0.0", "terraform", nil, "ecosystem:terraform"},
		{"pkg:npm/lodash@4.17.21", "npm", nil, ""},
	}
	for _, c := range cases {
		got, _ := list.Match(c.purl, c.eco, c.paths)
		if got != c.want {
			t.Errorf("Match(%q, %v) = %q, want %q", c.purl, c.paths, got, c.want)
		}
	}
	if _, err := Parse([]string{"re:("}); err == nil {
		t.Error("invalid regexp accepted")
	}
	if _, err := Parse([]string{""}); err == nil {
		t.Error("empty pattern accepted")
	}
}

func TestPolicyDecide(t *testing.T) {
	org, _ := Parse([]string{"pkg:npm/@types/*"})
	repo, _ := Parse([]string{"tools/**"})
	overrides, _ := Parse([]string{"ecosystem:terraform"})
	defaults, _ := Parse(DefaultPatterns)
	policy := &Policy{
		Sources:         []Source{{SourceDefault, defaults}, {SourceOrganization, org}, {SourceRepository, repo}},
		Overrides:       overrides,
		ExtractorSource: "hibou-depinventory.cdx.json",
		TrustedScopes:   map[string]bool{"maven": true},
	}
	check := func(c Candidate, shipped bool, reason string) {
		t.Helper()
		d := policy.Decide(c)
		if d.Shipped != shipped || d.Reason != reason {
			t.Errorf("%s: got shipped=%v reason=%q, want %v %q", c.Purl, d.Shipped, d.Reason, shipped, reason)
		}
	}
	check(Candidate{Purl: "pkg:npm/lodash@4.17.21", Ecosystem: "npm"}, true, "")
	check(Candidate{Purl: "pkg:npm/%40types/node@20.0.0", Ecosystem: "npm"}, false, "organization: pkg:npm/@types/*")
	check(Candidate{Purl: "pkg:npm/react@18.2.0", Ecosystem: "npm", Modules: []string{"tools/gen"}}, false, "repository: tools/**")
	check(Candidate{Purl: "pkg:generic/hashicorp/aws@5.0.0", Ecosystem: "terraform"}, true, "shipped: ecosystem:terraform in .hibou.yaml")
	check(Candidate{Purl: "pkg:githubactions/actions/checkout@v4", Ecosystem: "githubactions"}, false, "default: ecosystem:githubactions")
	check(Candidate{Purl: "pkg:maven/junit/junit@4.13", Ecosystem: "maven", Scopes: []string{"test"}}, false, "declared scope: test (trusted for maven)")
	check(Candidate{Purl: "pkg:npm/jest@29.0.0", Ecosystem: "npm", Scopes: []string{"devDependencies"}}, true, "")

	// An uploaded SBOM decides: what it lists ships, even when a list
	// matches; what it omits is not shipped, inside the covered paths.
	policy.UploadedSBOM = true
	d := policy.Decide(Candidate{Purl: "pkg:npm/%40types/node@20.0.0", Ecosystem: "npm", Sources: []string{"sbom.cdx.json", "hibou-depinventory.cdx.json"}})
	if !d.Shipped || d.Ignored != "organization: pkg:npm/@types/*" {
		t.Errorf("sbom evidence: %+v", d)
	}
	check(Candidate{Purl: "pkg:npm/lodash@4.17.21", Ecosystem: "npm", Sources: []string{"hibou-depinventory.cdx.json"}, Modules: []string{"web"}}, false, "not in uploaded SBOM")
	policy.Covers = []string{"backend/**"}
	check(Candidate{Purl: "pkg:npm/lodash@4.17.21", Ecosystem: "npm", Sources: []string{"hibou-depinventory.cdx.json"}, Modules: []string{"web"}}, true, "")
	check(Candidate{Purl: "pkg:maven/x/y@1", Ecosystem: "maven", Sources: []string{"hibou-depinventory.cdx.json"}, Modules: []string{"backend/api"}}, false, "not in uploaded SBOM")

	policy.Covers = nil
	undeclared := UndeclaredModules(policy, map[string]bool{"backend": true}, []string{"backend", "web"})
	if len(undeclared) != 1 || undeclared[0] != "web" {
		t.Errorf("undeclared modules: %v", undeclared)
	}
}
