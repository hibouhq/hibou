package depinventory

import "testing"

func TestIsManifestPath(t *testing.T) {
	cases := map[string]bool{
		"go.mod":                               true,
		"web/package-lock.json":                true,
		"api/requirements-dev.txt":             true,
		"services/billing/pom.xml":             true,
		"Cargo.lock":                           true,
		"node_modules/left-pad/package.json":   false,
		"web/node_modules/x/package-lock.json": false,
		"vendor/modules.txt":                   false,
		"src/main.go":                          false,
		"docs/requirements.md":                 false,
		".git/config":                          false,
		"":                                     false,
	}
	for input, want := range cases {
		if got := IsManifestPath(input); got != want {
			t.Errorf("IsManifestPath(%q) = %v, want %v", input, got, want)
		}
	}
}
