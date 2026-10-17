package depinventory

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestUnresolvedRangesAndExclude(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "requirements.txt", "requests>=2.0\nflask==2.3.0\n")
	writeFile(t, root, "api/pom.xml", `<project><modelVersion>4.0.0</modelVersion><groupId>x</groupId><artifactId>y</artifactId><version>1.0</version>
<dependencies>
<dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>[30.0,32.0)</version></dependency>
<dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>2.0.9</version></dependency>
</dependencies></project>`)
	writeFile(t, root, "examples/demo/requirements.txt", "django==4.2\n")

	inv, err := Extract(context.Background(), root, Options{Exclude: []string{"examples/**"}})
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Component{}
	for _, c := range inv.Components {
		byName[c.Name] = c
	}
	if _, excluded := byName["django"]; excluded {
		t.Error("examples/** must not be inventoried")
	}
	if c := byName["requests"]; c.Resolution != ResolutionUnresolved || c.Version != "" || c.Purl != "pkg:pypi/requests" || c.Constraint == "" {
		t.Errorf("requests range: %+v", c)
	}
	if c := byName["flask"]; c.Resolution != ResolutionRecorded || c.Version != "2.3.0" {
		t.Errorf("flask pin: %+v", c)
	}
	if c := byName["com.google.guava:guava"]; c.Resolution != ResolutionUnresolved || c.Version != "" || c.Constraint != "[30.0,32.0)" || c.Purl != "pkg:maven/com.google.guava/guava" {
		t.Errorf("guava range: %+v", c)
	}
	if c := byName["org.slf4j:slf4j-api"]; c.Resolution != ResolutionDeclared || c.Version != "2.0.9" {
		t.Errorf("slf4j literal: %+v", c)
	}
	document, err := ToCycloneDX(inv, "repo", "test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(document), `"hibou:constraint"`) || !strings.Contains(string(document), "[30.0,32.0)") {
		t.Error("the document must carry the constraint property")
	}
}
