package depinventory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateInstallConfig(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".npmrc", "registry=https://registry.npmjs.org/\nmin-release-age=3\n")
	writeFile(t, root, "web/pnpm-workspace.yaml", "packages:\n  - 'apps/*'\n")
	writeFile(t, root, "py/pyproject.toml", "[project]\nname = \"app\"\n")
	writeFile(t, root, "renovate.json", "{\n  \"extends\": [\"config:recommended\"]\n}\n")
	modules := []Module{
		{Path: ".", Files: []string{"package-lock.json"}},
		{Path: "web", Files: []string{"web/pnpm-lock.yaml"}},
		{Path: "py", Files: []string{"py/uv.lock"}},
		{Path: "legacy", Files: []string{"legacy/yarn.lock"}},
	}
	changes, err := GenerateInstallConfig(root, modules, 7, nil, "renovate", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 5 {
		t.Fatalf("changes: %+v", changes)
	}
	read := func(rel string) string {
		data, _ := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		return string(data)
	}
	if !strings.Contains(read(".npmrc"), "min-release-age=7") || !strings.Contains(read(".npmrc"), "registry=") {
		t.Errorf(".npmrc: %q", read(".npmrc"))
	}
	if !strings.Contains(read("web/pnpm-workspace.yaml"), "minimumReleaseAge: 10080") || !strings.Contains(read("web/pnpm-workspace.yaml"), "packages:") {
		t.Errorf("pnpm: %q", read("web/pnpm-workspace.yaml"))
	}
	if !strings.Contains(read("py/pyproject.toml"), "[tool.uv]\nexclude-newer = \"7 days\"") {
		t.Errorf("uv: %q", read("py/pyproject.toml"))
	}
	if !strings.Contains(read("legacy/.yarnrc.yml"), "npmMinimalAgeGate: 10080") {
		t.Errorf("yarn: %q", read("legacy/.yarnrc.yml"))
	}
	if !strings.Contains(read("renovate.json"), `"minimumReleaseAge": "7 days"`) || !strings.Contains(read("renovate.json"), "config:recommended") {
		t.Errorf("renovate: %q", read("renovate.json"))
	}
	// Idempotent: a second run changes nothing.
	again, err := GenerateInstallConfig(root, modules, 7, nil, "renovate", false)
	if err != nil || len(again) != 0 {
		t.Errorf("second run: %+v %v", again, err)
	}
	// The detector agrees with what was written.
	detected := DetectInstallConfig(root, modules)
	for module, configs := range detected {
		for _, cfg := range configs {
			if !cfg.Present || cfg.Window < 7*24*60*60*1e9 {
				t.Errorf("%s/%s not detected after generation: %+v", module, cfg.Tool, cfg)
			}
		}
	}
}
