package server

import "testing"

func TestResolveTreePath(t *testing.T) {
	tree := []string{
		"ts/src/calc.ts",
		"ts/src/insecure.ts",
		"java/src/main/java/com/hibou/sample/Calc.java",
		"go/calc.go",
		"vendor/other/src/calc.ts",
		"README.md",
	}
	cases := map[string]string{
		"src/calc.ts":                "ts/src/calc.ts", // fewest extra segments beats vendor path
		"com/hibou/sample/Calc.java": "java/src/main/java/com/hibou/sample/Calc.java",
		"go/calc.go":                 "go/calc.go",
		"calc.rs":                    "",
		"README.md":                  "README.md",
	}
	for requested, want := range cases {
		if got := resolveTreePath(tree, requested); got != want {
			t.Errorf("resolveTreePath(%q) = %q, want %q", requested, got, want)
		}
	}
}
