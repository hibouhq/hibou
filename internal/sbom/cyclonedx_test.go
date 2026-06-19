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
