package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/spf13/cobra"

	"github.com/hibouhq/hibou/internal/depinventory"
	"github.com/hibouhq/hibou/internal/notices"
	"github.com/hibouhq/hibou/internal/repoconfig"
	"github.com/hibouhq/hibou/internal/shipped"
)

// ---- hibou deps notices (ADR-051 §6) ----

var (
	noticesWrite        string
	noticesCheck        string
	noticesFormat       string
	noticesStrict       bool
	noticesConfigPath   string
	noticesGoModCache   string
	noticesGoRoot       string
	noticesMavenRepo    string
	noticesCargoHome    string
	noticesSitePackages []string
	noticesExclude      []string
)

var depsNoticesCmd = &cobra.Command{
	Use:   "notices [TARGET...]",
	Short: "Generate or check the third-party notices of what ships; local, nothing is stored or sent",
	Long: `Builds the third-party notices document (ADR-051) for the shipped
components of the targets, from the licence files the packages themselves
ship in the local package caches: the Go module cache, node_modules, the
Maven local repository, Python site-packages and the Cargo registry. Run it
after the build has installed dependencies and before packaging.

Which components: the same local inventory as "hibou deps scan" (a
directory, lockfiles, an archive), or the SBOM files you pass as targets
when your build produces its own. Components that do not ship are left out:
the not-shipped lists of .hibou.yaml, and dev or test scopes unless
notices.dev_scopes is "keep".

A component whose notice is incomplete is never dropped: it is listed with a
gap and the way to fix it. --check fails when the committed file is out of
date; --strict also fails on gaps.

No network call is made and nothing is uploaded.

Examples:
  hibou deps notices --write THIRD_PARTY_NOTICES.md
  hibou deps notices --check THIRD_PARTY_NOTICES.md
  hibou deps notices build/app.cdx.json web.cdx.json --write THIRD_PARTY_NOTICES.md
  hibou deps notices --format text --write dist/THIRD_PARTY_NOTICES.txt
  hibou deps notices --strict --check THIRD_PARTY_NOTICES.md`,
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		for _, flag := range []string{"write", "check"} {
			if cmd.Flags().Changed(flag) {
				value, err := cmd.Flags().GetString(flag)
				if err != nil || strings.TrimSpace(value) == "" {
					return exitError{2, fmt.Errorf("--%s needs a file name", flag)}
				}
			}
		}
		return runDepsNotices(cmd.Context(), args)
	},
}

func init() {
	depsNoticesCmd.Flags().StringVar(&noticesWrite, "write", "", "Write the notices to this file")
	depsNoticesCmd.Flags().StringVar(&noticesCheck, "check", "", "Exit 1, with the diff, if this file differs from the generated notices")
	depsNoticesCmd.Flags().StringVar(&noticesFormat, "format", "", "Output: markdown, text (default: from the file extension, else markdown)")
	depsNoticesCmd.Flags().BoolVar(&noticesStrict, "strict", false, "Exit 1 when a shipped component has a gap")
	depsNoticesCmd.Flags().StringVar(&noticesConfigPath, "config", "", "Path of .hibou.yaml (default: the directory target, or current directory)")
	depsNoticesCmd.Flags().StringVar(&noticesGoModCache, "gomodcache", "", "Go module cache (default GOMODCACHE, else GOPATH/pkg/mod)")
	depsNoticesCmd.Flags().StringVar(&noticesGoRoot, "goroot", "", "Matching Go installation for runtime licence evidence (default local GOROOT)")
	depsNoticesCmd.Flags().StringVar(&noticesMavenRepo, "maven-repo", "", "Maven local repository (default MAVEN_REPO_LOCAL, else ~/.m2/repository)")
	depsNoticesCmd.Flags().StringVar(&noticesCargoHome, "cargo-home", "", "Cargo home (default CARGO_HOME, else ~/.cargo)")
	depsNoticesCmd.Flags().StringArrayVar(&noticesSitePackages, "site-packages", nil, "Python site-packages directory (repeatable; default VIRTUAL_ENV and ./.venv)")
	depsNoticesCmd.Flags().StringArrayVar(&noticesExclude, "exclude", nil, "Path globs not inventoried (repeatable), e.g. examples/**")
	depsCmd.AddCommand(depsNoticesCmd)
}

// noticesSkipped counts what was left out and why, for the report on stderr.
// It is never written to the document: a dev dependency bump must not change
// the notices file.
type noticesSkipped struct {
	notShipped map[string]int // reason -> components
	excluded   int
}

func runDepsNotices(ctx context.Context, targets []string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	write, check := strings.TrimSpace(noticesWrite), strings.TrimSpace(noticesCheck)
	writeSet, checkSet := noticesWrite != "", noticesCheck != ""
	if writeSet && checkSet {
		return exitError{2, errors.New("--write and --check exclude each other")}
	}

	root := noticesRoot(targets)
	cfg, cfgDir, err := loadNoticesConfig(noticesConfigPath, root)
	if err != nil {
		return exitError{2, err}
	}
	noticesCfg := cfg.Notices
	if noticesCfg == nil {
		noticesCfg = &repoconfig.NoticesConfig{}
	}
	if (writeSet && write == "") || (checkSet && check == "") {
		return exitError{2, errors.New("--write and --check need a file name")}
	}
	format := noticesFormat
	if format == "" {
		format = notices.FormatMarkdown
		if name := strings.ToLower(write + check); strings.HasSuffix(name, ".txt") {
			format = notices.FormatText
		}
	}

	if format != "markdown" && format != "md" && format != "text" && format != "txt" {
		return exitError{2, fmt.Errorf("unknown notices format %q (markdown, text)", format)}
	}
	var warned atomic.Bool
	warn := func(message string) {
		warned.Store(true)
		fmt.Fprintln(os.Stderr, "warning:", message)
	}
	exclude := append([]string{}, noticesExclude...)
	if cfg.Dependencies != nil {
		exclude = append(exclude, cfg.Dependencies.Exclude...)
	}
	all, err := scanNoticesTargets(ctx, targets, root, exclude, warn, noticesCfg.DevScopesValue() == "keep")
	if err != nil {
		return exitError{2, err}
	}
	if warned.Load() {
		return exitError{2, errors.New("inventory reported warnings; resolve them before generating notices")}
	}
	components, skipped, err := shippedComponents(all, cfg)
	if err != nil {
		return exitError{2, err}
	}
	classifier, err := notices.NewClassifier()
	if err != nil {
		return exitError{2, err}
	}
	included, err := readIncluded(cfgDir, noticesCfg.Include)
	if err != nil {
		return exitError{2, err}
	}
	overrides := make([]notices.Override, 0, len(noticesCfg.Overrides))
	for _, o := range noticesCfg.Overrides {
		overrides = append(overrides, notices.Override{Purl: o.Purl, License: o.License, Copyright: o.Copyright, Choose: o.Choose, Reason: o.Reason})
	}
	doc := notices.Generate(components, notices.Options{
		Collectors: notices.LocalCollectors(notices.CacheOptions{
			Root:         root,
			GoModCache:   noticesGoModCache,
			GoRoot:       noticesGoRoot,
			MavenRepo:    noticesMavenRepo,
			SitePackages: noticesSitePackages,
			CargoHome:    noticesCargoHome,
		}),
		Classifier: classifier,
		Overrides:  overrides,
		Included:   included,
	})
	rendered, err := notices.Render(doc, format)
	if err != nil {
		return exitError{2, err}
	}

	reportNotices(doc, skipped)
	if err := ctx.Err(); err != nil {
		return exitError{2, err}
	}

	switch {
	case checkSet:
		committed, err := os.ReadFile(check)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return exitError{2, err}
		}
		if diff := notices.Diff(string(committed), rendered, 200); diff != "" {
			fmt.Fprint(os.Stderr, diff)
			return exitError{1, fmt.Errorf("%s is out of date; run: hibou deps notices --write %s", check, check)}
		}
		fmt.Fprintf(os.Stderr, "%s is up to date\n", check)
	case writeSet:
		if err := os.MkdirAll(filepath.Dir(write), 0o755); err != nil {
			return exitError{2, err}
		}
		if err := os.WriteFile(write, []byte(rendered), 0o644); err != nil { // #nosec G306 -- a notices file is public by nature
			return exitError{2, err}
		}
		fmt.Fprintf(os.Stderr, "wrote %s\n", write)
	default:
		fmt.Print(rendered)
	}
	if noticesStrict && doc.GapCount() > 0 {
		return exitError{1, fmt.Errorf("%d shipped component(s) have gaps (--strict)", doc.GapCount())}
	}
	return nil
}

// loadNoticesConfig reads .hibou.yaml; a missing file is the zero
// configuration (ADR-051 goal 4). It returns the directory relative paths
// resolve against.
func loadNoticesConfig(path, root string) (*repoconfig.RepoConfig, string, error) {
	candidates := []string{path}
	if path == "" {
		candidates = []string{filepath.Join(root, ".hibou.yaml"), filepath.Join(root, ".hibou.yml")}
	}
	for _, candidate := range candidates {
		data, err := os.ReadFile(candidate) // #nosec G304 -- the user's own configuration file
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, "", err
		}
		cfg, err := repoconfig.Parse(data)
		if err != nil {
			return nil, "", fmt.Errorf("%s: %w", candidate, err)
		}
		return cfg, filepath.Dir(candidate), nil
	}
	if path != "" {
		return nil, "", fmt.Errorf("%s: no such file", path)
	}
	return &repoconfig.RepoConfig{}, root, nil
}

// noticesRoot is the directory component modules are relative to: the first
// directory target, else the current directory.
func noticesRoot(targets []string) string {
	if len(targets) == 1 {
		if info, err := os.Stat(targets[0]); err == nil && info.IsDir() {
			return targets[0]
		}
	}
	return "."
}

// Directory inputs use lockfiles, not installed artifact metadata which would
// lose dev/test scope. Deliverables remain explicit file targets.
func scanNoticesTargets(ctx context.Context, targets []string, root string, exclude []string, warn func(string), keepDev bool) ([]depinventory.Component, error) {
	if len(targets) == 0 {
		targets = []string{"."}
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	var components []depinventory.Component
	for _, target := range targets {
		info, err := os.Stat(target)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			inv, err := depinventory.ScanTargets(ctx, []string{target}, depinventory.ScanOptions{Exclude: exclude, Warn: warn})
			if err != nil {
				return nil, err
			}
			if inv.UnidentifiedCount > 0 {
				return nil, fmt.Errorf("%s: %d unidentified deliverable files; supply a resolved build SBOM before generating notices", target, inv.UnidentifiedCount)
			}
			for i := range inv.Components {
				// Explicit file targets are inventoried independently from
				// source modules; their path is not a cache-relative module.
				inv.Components[i].Module = "."
			}
			components = append(components, inv.Components...)
			continue
		}
		if err := validateNoticesNPMLockfiles(target, exclude, keepDev); err != nil {
			return nil, err
		}
		inv, err := depinventory.Extract(ctx, target, depinventory.Options{Exclude: exclude, Warn: warn})
		if err != nil {
			return nil, err
		}
		if len(inv.FileErrors) > 0 {
			return nil, fmt.Errorf("inventory is incomplete: %s", strings.Join(inv.FileErrors, "; "))
		}
		for _, module := range inv.Modules {
			if !module.Complete {
				return nil, fmt.Errorf("%s: incomplete inventory for %s (%s); provide a resolved lockfile or build SBOM", target, module.Path, module.Reason)
			}
		}
		absTarget, err := filepath.Abs(target)
		if err != nil {
			return nil, err
		}
		prefix, err := filepath.Rel(absRoot, absTarget)
		if err != nil {
			return nil, err
		}
		for _, component := range inv.Components {
			component.Module = filepath.ToSlash(filepath.Join(prefix, component.Module))
			component.Path = filepath.ToSlash(filepath.Join(prefix, component.Path))
			components = append(components, component)
		}
	}
	return components, nil
}

// The source extractor deliberately ignores package.json-only dependencies.
// Notices cannot interpret that absence as a complete, empty inventory.
func validateNoticesNPMLockfiles(root string, exclude []string, keepDev bool) error {
	visited := 0
	return filepath.WalkDir(root, func(filename string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		visited++
		if visited > 200000 {
			return errors.New("source manifest traversal exceeds 200000 entries")
		}
		rel, err := filepath.Rel(root, filename)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if entry.IsDir() {
			if rel != "." && !depinventory.IsManifestPath(rel+"/package.json") {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Name() != "package.json" {
			return nil
		}
		for _, pattern := range exclude {
			if matched, err := doublestar.Match(pattern, rel); err != nil {
				return err
			} else if matched {
				return nil
			}
		}
		included, err := readIncluded(root, []string{rel})
		if err != nil {
			return err
		}
		var manifest struct {
			Dependencies         map[string]string `json:"dependencies"`
			OptionalDependencies map[string]string `json:"optionalDependencies"`
			DevDependencies      map[string]string `json:"devDependencies"`
		}
		if err := json.Unmarshal([]byte(included[0].Body), &manifest); err != nil {
			return fmt.Errorf("%s: invalid package metadata: %w", rel, err)
		}
		dependencies := len(manifest.Dependencies) + len(manifest.OptionalDependencies)
		if keepDev {
			dependencies += len(manifest.DevDependencies)
		}
		if dependencies == 0 {
			return nil
		}
		for dir := filepath.Dir(filename); ; dir = filepath.Dir(dir) {
			for _, lock := range []string{"package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock"} {
				if _, err := os.Stat(filepath.Join(dir, lock)); err == nil {
					return nil
				}
			}
			if filepath.Clean(dir) == filepath.Clean(root) || filepath.Dir(dir) == dir {
				break
			}
		}
		return fmt.Errorf("%s: incomplete inventory without a lockfile; provide a resolved lockfile or build SBOM", rel)
	})
}

// shippedComponents keeps the components that ship (ADR-045 §6, ADR-051 §4)
// with what can be known offline: the built-in defaults, the lists of
// .hibou.yaml, declared dev and test scopes unless notices.dev_scopes is
// "keep", and notices.exclude. A purl listed several times ships if any
// occurrence ships. Organization and repository lists kept on the server are
// not applied: `--check` must be reproducible from the repository alone.
func shippedComponents(all []depinventory.Component, cfg *repoconfig.RepoConfig) ([]notices.Component, noticesSkipped, error) {
	skipped := noticesSkipped{notShipped: map[string]int{}}
	deps := cfg.Dependencies
	if deps == nil {
		deps = &repoconfig.DependenciesConfig{}
	}
	defaults, err := shipped.Parse(shipped.DefaultPatterns)
	if err != nil {
		return nil, skipped, err
	}
	repoList, err := shipped.Parse(deps.NotShipped)
	if err != nil {
		return nil, skipped, fmt.Errorf("dependencies.not_shipped: %w", err)
	}
	overrides, err := shipped.Parse(deps.Shipped)
	if err != nil {
		return nil, skipped, fmt.Errorf("dependencies.shipped: %w", err)
	}
	policy := &shipped.Policy{
		Sources:       []shipped.Source{{Name: shipped.SourceDefault, List: defaults}, {Name: shipped.SourceConfig, List: repoList}},
		Overrides:     overrides,
		TrustedScopes: map[string]bool{},
	}
	if cfg.Notices.DevScopesValue() == "skip" {
		for _, c := range all {
			policy.TrustedScopes[strings.ToLower(strings.TrimSpace(c.Ecosystem))] = true
		}
	}
	var excludePatterns []string
	if cfg.Notices != nil {
		for _, e := range cfg.Notices.Exclude {
			excludePatterns = append(excludePatterns, e.Purl)
		}
	}
	// Private does not imply first-party: explicitly exclude only code owned
	// by this project, never every dependency fetched from a private registry.
	excludeList, err := shipped.Parse(excludePatterns)
	if err != nil {
		return nil, skipped, fmt.Errorf("notices.exclude: %w", err)
	}

	kept := map[string]notices.Component{}
	reasons := map[string]string{}
	for _, c := range all {
		if _, ok := excludeList.Match(c.Purl, c.Ecosystem, []string{c.Module, c.Path}); ok {
			reasons[c.Purl] = "excluded"
			continue
		}
		decision := policy.Decide(shipped.Candidate{
			Purl: c.Purl, Ecosystem: c.Ecosystem, Modules: []string{c.Module}, Paths: []string{c.Path}, Scopes: c.Scopes,
		})
		if !decision.Shipped {
			if _, seen := reasons[c.Purl]; !seen {
				reasons[c.Purl] = decision.Reason
			}
			continue
		}
		if c.Purl == "" || c.Version == "" {
			return nil, skipped, fmt.Errorf("unresolved shipped component %s (%s); provide a resolved lockfile or SBOM", c.Name, c.Path)
		}
		if existing, ok := kept[c.Purl]; ok && existing.Module <= c.Module {
			continue
		}
		delete(reasons, c.Purl)
		kept[c.Purl] = notices.Component{Purl: c.Purl, Name: c.Name, Version: c.Version, Ecosystem: c.Ecosystem, Module: c.Module}
	}
	for purl, reason := range reasons {
		if _, ships := kept[purl]; ships {
			continue
		}
		if reason == "excluded" {
			skipped.excluded++
			continue
		}
		// Group "declared scope: dev (trusted for npm)" as "declared scope".
		if i := strings.Index(reason, ":"); i > 0 {
			reason = reason[:i]
		}
		skipped.notShipped[reason]++
	}
	out := make([]notices.Component, 0, len(kept))
	for _, c := range kept {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Purl < out[j].Purl })
	return out, skipped, nil
}

func readIncluded(dir string, paths []string) ([]notices.Included, error) {
	out := make([]notices.Included, 0, len(paths))
	for _, path := range paths {
		root, err := os.OpenRoot(dir)
		if err != nil {
			return nil, err
		}
		file, openErr := root.Open(filepath.FromSlash(path))
		_ = root.Close()
		if openErr != nil {
			return nil, fmt.Errorf("notices.include: %w", openErr)
		}
		data, readErr := io.ReadAll(io.LimitReader(file, (1<<20)+1))
		closeErr := file.Close()
		err = errors.Join(readErr, closeErr)
		if err != nil {
			return nil, fmt.Errorf("notices.include: %w", err)
		}
		if len(data) > 1<<20 {
			return nil, fmt.Errorf("notices.include: %s exceeds 1 MiB", path)
		}
		out = append(out, notices.Included{Path: path, Body: string(data)})
	}
	return out, nil
}

// reportNotices prints the status and the gap list on stderr (ADR-051 §5).
func reportNotices(doc *notices.Document, skipped noticesSkipped) {
	total, gaps := len(doc.Entries), doc.GapCount()
	fmt.Fprintf(os.Stderr, "Notices: %d shipped components, %d complete, %d with gaps\n", total, total-gaps, gaps)
	var parts []string
	reasons := make([]string, 0, len(skipped.notShipped))
	for reason := range skipped.notShipped {
		reasons = append(reasons, reason)
	}
	sort.Strings(reasons)
	for _, reason := range reasons {
		parts = append(parts, fmt.Sprintf("%d %s", skipped.notShipped[reason], reason))
	}
	if skipped.excluded > 0 {
		parts = append(parts, fmt.Sprintf("%d excluded as first-party", skipped.excluded))
	}
	if len(parts) > 0 {
		fmt.Fprintf(os.Stderr, "Left out (not shipped): %s\n", strings.Join(parts, ", "))
	}
	if gaps == 0 {
		return
	}
	fmt.Fprintln(os.Stderr)
	for _, entry := range doc.Entries {
		for _, gap := range entry.Gaps {
			fmt.Fprintf(os.Stderr, "  - %s %s   %s\n       fix: %s\n", entry.Name, entry.Version, gap.Message, gap.Fix)
		}
	}
}
