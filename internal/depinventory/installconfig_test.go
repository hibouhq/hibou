package depinventory

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDetectInstallConfig(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".npmrc", "registry=https://registry.npmjs.org/\nmin-release-age=7\n")
	writeFile(t, root, "web/pnpm-workspace.yaml", "packages:\n  - 'apps/*'\nminimumReleaseAge: 10080\nminimumReleaseAgeStrict: true\n")
	writeFile(t, root, "legacy/.yarnrc.yml", "npmMinimalAgeGate: 7d\n")
	writeFile(t, root, "bun-app/bunfig.toml", "[install]\nminimumReleaseAge = 604800\n")
	writeFile(t, root, "py/pyproject.toml", "[project]\nname = \"app\"\n\n[tool.uv]\nexclude-newer = \"7 days\"\n")
	writeFile(t, root, "zero/.npmrc", "min-release-age=0\n")
	writeFile(t, root, "renovate.json", "{\n  \"extends\": [\"config:recommended\"],\n  \"minimumReleaseAge\": \"3 days\"\n}\n")
	writeFile(t, root, ".github/dependabot.yml", "version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n    cooldown:\n      default-days: 5\n")

	modules := []Module{
		{Path: ".", Files: []string{"package-lock.json"}},
		{Path: "web", Files: []string{"web/pnpm-lock.yaml"}},
		{Path: "legacy", Files: []string{"legacy/yarn.lock"}},
		{Path: "bun-app", Files: []string{"bun-app/bun.lock"}},
		{Path: "py", Files: []string{"py/uv.lock"}},
		{Path: "zero", Files: []string{"zero/package-lock.json"}},
		{Path: "svc", Files: []string{"svc/go.mod"}},
	}
	got := DetectInstallConfig(root, modules)

	check := func(module, tool string, present bool, window time.Duration) {
		t.Helper()
		for _, cfg := range got[module] {
			if cfg.Tool != tool {
				continue
			}
			if cfg.Present != present || cfg.Window != window {
				t.Errorf("%s/%s: present=%v window=%s (%q, note %q), want present=%v window=%s", module, tool, cfg.Present, cfg.Window, cfg.Value, cfg.Note, present, window)
			}
			return
		}
		t.Errorf("%s/%s: no config entry in %+v", module, tool, got[module])
	}
	check(".", "npm", true, 7*24*time.Hour)
	check("web", "pnpm", true, 7*24*time.Hour) // 10080 minutes
	check("legacy", "yarn", true, 7*24*time.Hour)
	check("bun-app", "bun", true, 7*24*time.Hour) // seconds
	check("py", "uv", true, 7*24*time.Hour)
	check("zero", "npm", false, 0)
	if _, ok := got["svc"]; ok {
		t.Error("a Go module has no install-time setting to check")
	}

	updaters := DetectUpdaterConfig(root)
	if len(updaters) != 2 {
		t.Fatalf("updaters %+v", updaters)
	}
	for _, u := range updaters {
		switch u.Tool {
		case "renovate":
			if !u.Present || u.Window != 3*24*time.Hour {
				t.Errorf("renovate %+v", u)
			}
		case "dependabot":
			if !u.Present || u.Window != 5*24*time.Hour {
				t.Errorf("dependabot %+v", u)
			}
		}
	}
}

func TestIsExtractionPathIncludesInstallConfig(t *testing.T) {
	for _, p := range []string{".npmrc", "web/.yarnrc.yml", "pnpm-workspace.yaml", ".github/dependabot.yml", "renovate.json5"} {
		if !IsExtractionPath(p) {
			t.Errorf("%s must be checked out", p)
		}
	}
	for _, p := range []string{"node_modules/x/.npmrc", "docs/index.md"} {
		if IsExtractionPath(p) {
			t.Errorf("%s must not be checked out", p)
		}
	}
}
