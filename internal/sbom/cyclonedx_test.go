package sbom

import "testing"

func TestParseCycloneDXJSONGraphIncludesDependenciesAndRootBomRef(t *testing.T) {
	t.Parallel()

	components, dependencies, rootBomRef, bomRefIndex, err := ParseCycloneDXJSONGraph([]byte(`{
		"bomFormat":"CycloneDX",
		"metadata":{"component":{"bom-ref":"root-app","name":"hibou","version":"1.0.0","purl":"pkg:gomod/github.com/hibouhq/hibou@1.0.0"}},
		"components":[
			{"bom-ref":"dep-a","name":"left-pad","version":"1.3.0","purl":"pkg:npm/left-pad@1.3.0"},
			{"bom-ref":"dep-b","name":"chalk","version":"5.0.0","purl":"pkg:npm/chalk@5.0.0"},
			{"bom-ref":"dep-a-alias","name":"left-pad","version":"1.3.0","purl":"pkg:npm/left-pad@1.3.0"},
			{"bom-ref":"skipped","name":"missing-version","purl":"pkg:npm/missing-version"}
		],
		"dependencies":[
			{"ref":"root-app","dependsOn":["dep-a","dep-b","dep-a"]},
			{"ref":"dep-a","dependsOn":["dep-b","missing"]}
		]
	}`))
	if err != nil {
		t.Fatalf("ParseCycloneDXJSONGraph() error = %v", err)
	}

	if rootBomRef != "root-app" {
		t.Fatalf("rootBomRef = %q, want root-app", rootBomRef)
	}
	if len(components) != 3 {
		t.Fatalf("component count = %d, want 3", len(components))
	}
	if got := components[bomRefIndex["dep-a"]].PURL; got != "pkg:npm/left-pad@1.3.0" {
		t.Fatalf("dep-a purl = %q, want left-pad purl", got)
	}
	if got := components[bomRefIndex["dep-a"]].BomRefs; len(got) != 2 {
		t.Fatalf("dep-a bom refs = %v, want 2 refs", got)
	}
	if _, ok := bomRefIndex["skipped"]; ok {
		t.Fatal("skipped component bom-ref should not resolve to a persisted component index")
	}
	if len(dependencies) != 2 {
		t.Fatalf("dependency count = %d, want 2", len(dependencies))
	}
	if got := dependencies[0].DependsOn; len(got) != 2 || got[0] != "dep-a" || got[1] != "dep-b" {
		t.Fatalf("root dependency dependsOn = %v, want [dep-a dep-b]", got)
	}

	legacyComponents, err := ParseCycloneDXJSON([]byte(`{
		"bomFormat":"CycloneDX",
		"metadata":{"component":{"bom-ref":"root-app","name":"hibou","version":"1.0.0","purl":"pkg:gomod/github.com/hibouhq/hibou@1.0.0"}},
		"components":[{"bom-ref":"dep-a","name":"left-pad","version":"1.3.0","purl":"pkg:npm/left-pad@1.3.0"}]
	}`))
	if err != nil {
		t.Fatalf("ParseCycloneDXJSON() error = %v", err)
	}
	if len(legacyComponents) != 2 {
		t.Fatalf("legacy component count = %d, want 2", len(legacyComponents))
	}
}

func TestParseCycloneDXJSONGraphFlatDocumentHasZeroDependencies(t *testing.T) {
	t.Parallel()

	components, dependencies, rootBomRef, bomRefIndex, err := ParseCycloneDXJSONGraph([]byte(`{
		"bomFormat":"CycloneDX",
		"components":[
			{"bom-ref":"dep-a","name":"left-pad","version":"1.3.0","purl":"pkg:npm/left-pad@1.3.0"},
			{"bom-ref":"dep-b","name":"go-lib","version":"1.2.3","purl":"pkg:gomod/github.com/example/lib@1.2.3"}
		]
	}`))
	if err != nil {
		t.Fatalf("ParseCycloneDXJSONGraph() error = %v", err)
	}
	if rootBomRef != "" {
		t.Fatalf("rootBomRef = %q, want empty", rootBomRef)
	}
	if len(components) != 2 {
		t.Fatalf("component count = %d, want 2", len(components))
	}
	if len(dependencies) != 0 {
		t.Fatalf("dependency count = %d, want 0", len(dependencies))
	}
	if len(bomRefIndex) != 2 {
		t.Fatalf("bomRefIndex size = %d, want 2", len(bomRefIndex))
	}
}

// Trivy (per the CycloneDX spec) splits scoped npm names into group + name.
// The stored component name must carry the scope: advisories are keyed on the
// full name, and the bare name collides with unscoped typosquat malware.
func TestParseCycloneDXJSONScopedPackagesKeepTheirScope(t *testing.T) {
	t.Parallel()

	components, err := ParseCycloneDXJSON([]byte(`{
		"bomFormat":"CycloneDX",
		"components":[
			{"group":"@babel","name":"helper-validator-identifier","version":"7.28.5","purl":"pkg:npm/%40babel/helper-validator-identifier@7.28.5"},
			{"name":"left-pad","version":"1.3.0","purl":"pkg:npm/left-pad@1.3.0"},
			{"group":"com.fasterxml.jackson.core","name":"jackson-databind","version":"2.15.0","purl":"pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.15.0"},
			{"name":"curl","version":"7.88.1","purl":"pkg:deb/debian/curl@7.88.1"}
		]
	}`))
	if err != nil {
		t.Fatalf("ParseCycloneDXJSON: %v", err)
	}
	want := map[string]string{
		"pkg:npm/%40babel/helper-validator-identifier@7.28.5":          "@babel/helper-validator-identifier",
		"pkg:npm/left-pad@1.3.0":                                       "left-pad",
		"pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.15.0": "com.fasterxml.jackson.core:jackson-databind",
		// OS packages keep the bare name: the namespace is the distro vendor.
		"pkg:deb/debian/curl@7.88.1": "curl",
	}
	if len(components) != len(want) {
		t.Fatalf("expected %d components, got %d", len(want), len(components))
	}
	for _, component := range components {
		if got := want[component.PURL]; component.Name != got {
			t.Fatalf("name for %s = %q, want %q", component.PURL, component.Name, got)
		}
	}
}

func TestCanonicalComponentNameFallsBackToGroupAndName(t *testing.T) {
	t.Parallel()

	if got := canonicalComponentName("", "@vue", "runtime-dom"); got != "@vue/runtime-dom" {
		t.Fatalf("group fallback = %q, want @vue/runtime-dom", got)
	}
	if got := canonicalComponentName("not-a-purl", "", "runtime-dom"); got != "runtime-dom" {
		t.Fatalf("bare fallback = %q, want runtime-dom", got)
	}
	if got := canonicalComponentName("pkg:golang/github.com/aws/aws-sdk-go-v2/config@v1.32.25", "", "config"); got != "github.com/aws/aws-sdk-go-v2/config" {
		t.Fatalf("golang purl = %q, want full module path", got)
	}
}

func TestParseCycloneDXJSONGraphKeepsProperties(t *testing.T) {
	doc := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"type":"library","bom-ref":"pkg:npm/express@4.18.2","name":"express","version":"4.18.2","purl":"pkg:npm/express@4.18.2","properties":[{"name":"hibou:relationship","value":"direct"},{"name":"hibou:scope","value":"dev"},{"name":"hibou:scope","value":"optional"},{"name":"","value":"ignored"}]}]}`)
	components, _, _, _, err := ParseCycloneDXJSONGraph(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(components) != 1 {
		t.Fatalf("got %d components", len(components))
	}
	props := components[0].Properties
	if got := props["hibou:relationship"]; len(got) != 1 || got[0] != "direct" {
		t.Errorf("relationship property %v", got)
	}
	if got := props["hibou:scope"]; len(got) != 2 || got[0] != "dev" || got[1] != "optional" {
		t.Errorf("scope properties %v, want dev and optional in order", got)
	}
	if _, ok := props[""]; ok {
		t.Error("an unnamed property must be dropped")
	}
}
