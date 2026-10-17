package depinventory

import "testing"

func TestParseGraphExports(t *testing.T) {
	maven := `[INFO] --- dependency:3.6.1:tree (default-cli) @ api ---
[INFO] com.acme:api:jar:1.0.0
[INFO] +- org.slf4j:slf4j-api:jar:2.0.9:compile
[INFO] +- com.fasterxml.jackson.core:jackson-databind:jar:2.15.2:compile
[INFO] |  \- com.fasterxml.jackson.core:jackson-core:jar:2.15.2:compile
[INFO] \- junit:junit:jar:4.13.2:test
`
	components := parseMavenList(maven, "pom.xml")
	byName := map[string]Component{}
	for _, c := range components {
		byName[c.Name] = c
	}
	if len(components) != 3 {
		t.Fatalf("maven tree: %d components, want 3 (test scope dropped): %+v", len(components), components)
	}
	if c := byName["org.slf4j:slf4j-api"]; c.Relationship != RelationshipDirect || c.Version != "2.0.9" || c.Resolution != ResolutionRecorded {
		t.Errorf("slf4j: %+v", c)
	}
	if c := byName["com.fasterxml.jackson.core:jackson-core"]; c.Relationship != RelationshipIndirect {
		t.Errorf("jackson-core must be indirect: %+v", c)
	}

	list := "   org.slf4j:slf4j-api:jar:2.0.9:compile\n   org.yaml:snakeyaml:jar:2.2:runtime\n   junit:junit:jar:4.13.2:test\n"
	if got := parseMavenList(list, "deps.txt"); len(got) != 2 {
		t.Errorf("maven list: %+v", got)
	}

	gradle := `runtimeClasspath - Runtime classpath of source set 'main'.
+--- org.springframework.boot:spring-boot-starter:3.2.0
|    +--- org.springframework.boot:spring-boot:3.2.0
|    \--- org.yaml:snakeyaml:2.2 -> 2.3
\--- com.google.guava:guava:32.1.3-jre
     +--- com.google.guava:failureaccess:1.0.1
     \--- org.checkerframework:checker-qual -> 3.37.0 (*)
`
	components = parseGradleTree(gradle, "build.gradle")
	byName = map[string]Component{}
	for _, c := range components {
		byName[c.Name] = c
	}
	if len(components) != 6 {
		t.Fatalf("gradle tree: %d components: %+v", len(components), components)
	}
	if c := byName["org.springframework.boot:spring-boot-starter"]; c.Relationship != RelationshipDirect {
		t.Errorf("starter must be direct: %+v", c)
	}
	if c := byName["org.yaml:snakeyaml"]; c.Version != "2.3" || c.Relationship != RelationshipIndirect {
		t.Errorf("snakeyaml must take the resolved version: %+v", c)
	}
	if c := byName["org.checkerframework:checker-qual"]; c.Version != "3.37.0" {
		t.Errorf("checker-qual: %+v", c)
	}

	pip := "Flask==2.3.0\nWerkzeug==3.0.1\n# comment\nrequests @ git+https://x\n"
	components = parsePipFreeze(pip, "freeze.txt")
	if len(components) != 2 || components[0].Purl != "pkg:pypi/flask@2.3.0" {
		t.Errorf("pip freeze: %+v", components)
	}
}

func TestMergeResolved(t *testing.T) {
	declared := []Component{
		{Purl: "pkg:maven/org.slf4j/slf4j-api@2.0.9", Name: "org.slf4j:slf4j-api", Version: "2.0.9", Ecosystem: "maven", Relationship: RelationshipDirect, Resolution: ResolutionDeclared},
		{Purl: "pkg:maven/com.google.guava/guava", Name: "com.google.guava:guava", Ecosystem: "maven", Relationship: RelationshipDirect, Resolution: ResolutionUnresolved, Constraint: "[30.0,32.0)"},
		{Purl: "pkg:maven/x/y@1.0", Name: "x:y", Version: "1.0", Ecosystem: "maven", Relationship: RelationshipDirect, Resolution: ResolutionDeclared},
	}
	resolved := []Component{
		{Purl: "pkg:maven/org.slf4j/slf4j-api@2.0.9", Name: "org.slf4j:slf4j-api", Version: "2.0.9", Ecosystem: "maven", Relationship: RelationshipDirect, Resolution: ResolutionRecorded},
		{Purl: "pkg:maven/com.google.guava/guava@31.1-jre", Name: "com.google.guava:guava", Version: "31.1-jre", Ecosystem: "maven", Relationship: RelationshipDirect, Resolution: ResolutionRecorded},
		{Purl: "pkg:maven/x/y@1.2", Name: "x:y", Version: "1.2", Ecosystem: "maven", Relationship: RelationshipDirect, Resolution: ResolutionRecorded},
		{Purl: "pkg:maven/a/b@3", Name: "a:b", Version: "3", Ecosystem: "maven", Relationship: RelationshipIndirect, Resolution: ResolutionRecorded},
	}
	merged := MergeResolved(declared, resolved)
	if len(merged) != 5 {
		t.Fatalf("merged %d, want 5 (declared 3 + discrepancy + new): %+v", len(merged), merged)
	}
	if merged[0].Resolution != ResolutionRecorded {
		t.Errorf("same version upgrades to recorded: %+v", merged[0])
	}
	if merged[1].Version != "31.1-jre" || merged[1].Resolution != ResolutionRecorded || merged[1].Constraint != "" {
		t.Errorf("unresolved range replaced: %+v", merged[1])
	}
	if merged[2].Version != "1.0" {
		t.Errorf("declared literal kept: %+v", merged[2])
	}
}
