package depinventory

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Every lockfile format with parent information yields the edge from the
// direct dependency to the indirect one it pulls in.
func TestExtractEdgesFromCorpus(t *testing.T) {
	cases := map[string]Edge{
		"npm-lock-v3":   {From: "pkg:npm/express@4.18.2", To: "pkg:npm/accepts@1.3.8"},
		"pnpm-v9":       {From: "pkg:npm/debug@4.3.4", To: "pkg:npm/ms@2.1.2"},
		"yarn-v1":       {From: "pkg:npm/axios@1.6.0", To: "pkg:npm/follow-redirects@1.15.3"},
		"cargo":         {From: "pkg:cargo/serde@1.0.219", To: "pkg:cargo/serde_derive@1.0.219"},
		"python-uv":     {From: "pkg:pypi/requests@2.32.3", To: "pkg:pypi/urllib3@2.2.2"},
		"python-poetry": {From: "pkg:pypi/flask@3.0.0", To: "pkg:pypi/werkzeug@3.0.1"},
	}
	for fixture, want := range cases {
		inv, err := Extract(context.Background(), filepath.Join("testdata", "corpus", fixture), Options{})
		if err != nil {
			t.Fatalf("%s: %v", fixture, err)
		}
		found := false
		for _, edge := range inv.Edges {
			if edge == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: edge %s -> %s missing in %v", fixture, want.From, want.To, inv.Edges)
		}
		document, err := ToCycloneDX(inv, fixture, "test", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(document), `"ref": "`+want.From+`"`) {
			t.Errorf("%s: the document must carry %s as a dependency source", fixture, want.From)
		}
	}
}
