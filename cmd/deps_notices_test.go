package cmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hibouhq/hibou/internal/depinventory"
	"github.com/hibouhq/hibou/internal/repoconfig"
)

func TestNoticesShippedFilteringAndPrivatePackages(t *testing.T) {
	cfg := &repoconfig.RepoConfig{Dependencies: &repoconfig.DependenciesConfig{
		PrivateNamespaces: []string{"pkg:npm/@private/*"},
		NotShipped:        []string{"pkg:npm/build-only*"},
	}}
	components := []depinventory.Component{
		{Purl: "pkg:npm/runtime@1.0", Name: "runtime", Version: "1.0", Ecosystem: "npm", Scopes: []string{"dev"}, Module: "z"},
		{Purl: "pkg:npm/runtime@1.0", Name: "runtime", Version: "1.0", Ecosystem: "npm", Module: "a"},
		{Purl: "pkg:npm/dev-only@1.0", Name: "dev-only", Version: "1.0", Ecosystem: "npm", Scopes: []string{"dev"}},
		{Purl: "pkg:npm/build-only@1.0", Name: "build-only", Version: "1.0", Ecosystem: "npm"},
		{Purl: "pkg:npm/@private/shared@1.0", Name: "@private/shared", Version: "1.0", Ecosystem: "npm"},
	}
	kept, skipped, err := shippedComponents(components, cfg)
	if err != nil || len(kept) != 2 || skipped.excluded != 0 {
		t.Fatalf("kept=%+v skipped=%+v err=%v", kept, skipped, err)
	}
	// A privately hosted package may be third-party. No network does not mean
	// no attribution, so private_namespaces must never silently exclude it.
	if kept[0].Name != "@private/shared" || kept[1].Name != "runtime" || kept[1].Module != "a" {
		t.Fatalf("unexpected shipped components: %+v", kept)
	}
	cfg.Notices = &repoconfig.NoticesConfig{DevScopes: "keep"}
	kept, _, err = shippedComponents(components, cfg)
	if err != nil || len(kept) != 3 {
		t.Fatalf("dev_scopes keep: %+v err=%v", kept, err)
	}
}

func TestNoticesIncludeCannotEscapeRepository(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	filename := filepath.Join(outside, "private.txt")
	if err := os.WriteFile(filename, []byte("must not be included"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filename, filepath.Join(root, "NOTICE.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := readIncluded(root, []string{"NOTICE.txt"}); err == nil {
		t.Fatal("include followed a symlink outside the repository")
	}
}

func resetNoticesFlags(t *testing.T) {
	t.Helper()
	write, check, format, config, cache, strict := noticesWrite, noticesCheck, noticesFormat, noticesConfigPath, noticesGoModCache, noticesStrict
	t.Cleanup(func() {
		noticesWrite, noticesCheck, noticesFormat, noticesConfigPath, noticesGoModCache, noticesStrict = write, check, format, config, cache, strict
	})
	noticesWrite, noticesCheck, noticesFormat, noticesConfigPath, noticesGoModCache = "", "", "", "", ""
	noticesStrict = false
}

func TestNoticesCLIWriteCheckAndStrict(t *testing.T) {
	resetNoticesFlags(t)
	root := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("package.json", `{"name":"fixture","version":"1.0.0"}`)
	write("package-lock.json", `{"name":"fixture","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"fixture","version":"1.0.0"},"node_modules/absent":{"version":"1.2.3"}}}`)
	write(".hibou.yaml", "version: 1\nnotices:\n  include: [MANUAL.txt]\n")
	write("MANUAL.txt", "Fixture manual attribution")
	output := filepath.Join(root, "NOTICES.md")
	noticesWrite = output
	if err := runDepsNotices(context.Background(), []string{root}); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(first), "absent") || !strings.Contains(string(first), "Fixture manual attribution") {
		t.Fatalf("output omitted a gap or target-relative include: %s", first)
	}
	noticesWrite, noticesCheck = "", output
	if err := runDepsNotices(context.Background(), []string{root}); err != nil {
		t.Fatal(err)
	}
	noticesStrict = true
	assertExitCode(t, runDepsNotices(context.Background(), []string{root}), 1)
	noticesStrict = false
	write("NOTICES.md", "out of date")
	assertExitCode(t, runDepsNotices(context.Background(), []string{root}), 1)
	noticesWrite = output
	assertExitCode(t, runDepsNotices(context.Background(), []string{root}), 2)
	noticesWrite, noticesCheck, noticesFormat = "", "", "pdf"
	assertExitCode(t, runDepsNotices(context.Background(), []string{root}), 2)
}

func assertExitCode(t *testing.T, err error, code int) {
	t.Helper()
	var exit exitError
	if !errors.As(err, &exit) || exit.code != code {
		t.Fatalf("error=%v, want exit %d", err, code)
	}
}

func TestNoticesDirectoryInventoryDoesNotReadInstalledManifests(t *testing.T) {
	root := t.TempDir()
	module := filepath.Join(root, "node_modules", "installed-only")
	if err := os.MkdirAll(module, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(module, "package.json"), []byte(`{"name":"installed-only","version":"1.0.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	components, err := scanNoticesTargets(context.Background(), []string{root}, root, nil, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range components {
		if c.Name == "installed-only" {
			t.Fatal("installed package without lockfile scope leaked into source inventory")
		}
	}
}

func TestNoticesUnresolvedShippedIdentityIsAnError(t *testing.T) {
	_, _, err := shippedComponents([]depinventory.Component{{
		Name: "fixture", Ecosystem: "npm", Constraint: "^1", Path: "package.json",
	}}, &repoconfig.RepoConfig{})
	if err == nil || !strings.Contains(err.Error(), "unresolved shipped component") {
		t.Fatalf("unresolved component silently omitted: %v", err)
	}
}

func TestNoticesRejectsUnidentifiedAndIncompleteTargets(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "unidentified.dat")
	if err := os.WriteFile(target, []byte("not an inventory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := scanNoticesTargets(context.Background(), []string{target}, root, nil, nil, false); err == nil || !strings.Contains(err.Error(), "unidentified") {
		t.Fatalf("unidentified file accepted as complete: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"name":"fixture","version":"1.0","dependencies":{"fixture-dependency":"^1"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := scanNoticesTargets(context.Background(), []string{root}, root, nil, nil, false); err == nil || !strings.Contains(err.Error(), "incomplete inventory") {
		t.Fatalf("manifest-only inventory accepted as complete: %v", err)
	}
}

func TestNoticesCLIExplicitSBOMAndTextOutput(t *testing.T) {
	resetNoticesFlags(t)
	root := t.TempDir()
	target := filepath.Join(root, "fixture.cdx.json")
	if err := os.WriteFile(target, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[{"type":"library","name":"fixture-api","version":"1.2.3","purl":"pkg:npm/fixture-api@1.2.3"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	noticesConfigPath = filepath.Join(root, ".hibou.yaml")
	if err := os.WriteFile(noticesConfigPath, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	noticesWrite = filepath.Join(root, "NOTICES.txt")
	if err := runDepsNotices(context.Background(), []string{target}); err != nil {
		t.Fatal(err)
	}
	rendered, err := os.ReadFile(noticesWrite)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(rendered), "THIRD-PARTY NOTICES\n") || !strings.Contains(string(rendered), "pkg:npm/fixture-api@1.2.3") {
		t.Fatalf("SBOM text output=%s", rendered)
	}
	noticesCheck, noticesWrite = noticesWrite, ""
	if err := runDepsNotices(context.Background(), []string{target}); err != nil {
		t.Fatal(err)
	}
}
