// Package depinventory extracts a dependency inventory from repository
// content without executing anything (ADR-045 §1–3). It embeds OSV-SCALIBR
// behind a small interface and enables an explicit allowlist of offline
// extractors: lockfiles and the few manifests whose versions are literal.
// Nothing here resolves ranges, reaches a registry, or runs a build tool,
// so an old tag yields what was recorded then, never today's versions.
package depinventory

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/bmatcuk/doublestar/v4"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gomod"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/gradlelockfile"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/gradleverificationmetadataxml"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/pomxml"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/bunlock"
	jsmetadata "github.com/google/osv-scalibr/extractor/filesystem/language/javascript/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagelockjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/pnpmlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/yarnlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/pdmlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/pipfilelock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/poetrylock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/pylock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/uvlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/rust/cargolock"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/stats"
)

// Relationship of a component to the module that declares it (ADR-045
// §5.1). Unknown is a first-class value, never guessed into the other two.
type Relationship string

const (
	RelationshipDirect   Relationship = "direct"
	RelationshipIndirect Relationship = "indirect"
	RelationshipUnknown  Relationship = "unknown"
)

// Resolution says how exact the version is (ADR-045 §5): recorded by a
// lockfile, or only declared by a manifest.
type Resolution string

const (
	ResolutionRecorded Resolution = "recorded"
	ResolutionDeclared Resolution = "declared"
	// ResolutionUnresolved: a manifest declares a range, not a version
	// (ADR-045 §2.2). The component is listed with its constraint and
	// excluded from advisory matching; guessing a version is rejected.
	ResolutionUnresolved Resolution = "unresolved"
)

// Component is one package version found in the repository.
type Component struct {
	Purl         string
	Name         string
	Version      string
	Ecosystem    string
	Relationship Relationship
	Resolution   Resolution
	// Constraint is the declared range when Resolution is unresolved.
	Constraint string
	// Scopes are the ecosystem's own labels (npm "dev", Maven "test",
	// Poetry groups), kept as given; ADR-045 §6 decides what they mean.
	Scopes []string
	// Path of the file the component was read from, relative to the root,
	// and the line when the extractor knows it.
	Path string
	Line int
	// Module is the directory of that file, relative to the root ("." at
	// the root): the unit of completeness.
	Module string
	// Extractor is the SCALIBR plugin that produced the entry.
	Extractor string
	// Registry says where the lockfile resolved the package from (ADR-048
	// §4): "public" for the ecosystem's public registry, "private" for any
	// other source (an internal registry, a local path, a git URL), "" when
	// the format does not record it. Private packages are never sent to
	// third-party APIs.
	Registry string
	// Layer says which image layer introduced the component when the
	// source is a container image (ADR-045 §10); nil otherwise.
	Layer *LayerInfo
}

// LayerInfo attributes a component to an image layer: the index in the
// image's history, the layer's diff ID, the build command when the image
// records one, and whether the layer belongs to the base image.
type LayerInfo struct {
	Index     int    `json:"index"`
	DiffID    string `json:"diff_id,omitempty"`
	Command   string `json:"command,omitempty"`
	BaseImage bool   `json:"base_image"`
}

const (
	RegistryPublic  = "public"
	RegistryPrivate = "private"
)

// Module is one directory with a recognised manifest or lockfile.
type Module struct {
	Path string
	// Files lists the recognised files, relative to the root.
	Files []string
	// Complete is false when the module has no recorded source, so indirect
	// dependencies are unknown. Reason says why.
	Complete bool
	Reason   string
	// Ecosystems seen in the module.
	Ecosystems []string
}

// Inventory is the result of one extraction.
type Inventory struct {
	Components []Component
	Modules    []Module
	// Edges are the parent edges the lockfiles state, so an indirect
	// dependency traces back to the direct one that pulled it in.
	Edges []Edge
	// Extractors that ran, with their failures if any.
	Extractors []ExtractorStatus
	// Errors from files the extractors could not read; the inventory is
	// still returned, marked partial where they apply.
	FileErrors []string
	// InstallConfig is each module's install-time cooldown settings, by
	// module path (ADR-048 §3.1); Updaters the repository's updater
	// cooldown, when a Renovate or Dependabot config exists.
	InstallConfig map[string][]InstallConfig
	Updaters      []UpdaterConfig
	Duration      time.Duration
}

// ExtractorStatus is one plugin's outcome.
type ExtractorStatus struct {
	Name    string
	Version int
	Failed  bool
	Reason  string
}

// Options tune an extraction.
type Options struct {
	// Extractors overrides the default allowlist; names as SCALIBR
	// registers them ("go/gomod"). Every name must be offline-capable.
	Extractors []string
	// MaxFileSize skips larger files (bytes). 0 means the default.
	MaxFileSize int
	// Exclude lists repository path globs never inventoried (fixtures,
	// examples): "examples/**", "testdata/**" (ADR-045 §8).
	Exclude []string
	// SkipDirs are directory names never descended into, on top of the
	// built-in ones (.git, node_modules, vendor, build outputs).
	SkipDirs []string
	// Warn receives the engine's warnings and errors; nil drops them.
	Warn func(message string)
}

// DefaultMaxFileSize bounds a single lockfile: the largest real ones are a
// few MB; 32 MiB is a generated artefact, not a manifest.
const DefaultMaxFileSize = 32 << 20

type extractorConstructor func(*cpb.PluginConfig) (filesystem.Extractor, error)

// The allowlist is a map of constructors, not names looked up in the
// engine's registry: the registry links every extractor, detector and
// container reader it knows (55 MiB in the spike), while fifteen direct
// constructors link only the parsers in use.

// recordedExtractors read lockfiles: exact versions, indirect dependencies
// included where the format carries them.
var recordedExtractors = map[string]extractorConstructor{
	gomod.Name:                         gomod.New,
	packagelockjson.Name:               packagelockjson.New,
	pnpmlock.Name:                      pnpmlock.New,
	yarnlock.Name:                      yarnlock.New,
	bunlock.Name:                       bunlock.New,
	uvlock.Name:                        uvlock.New,
	poetrylock.Name:                    poetrylock.New,
	pdmlock.Name:                       pdmlock.New,
	pipfilelock.Name:                   pipfilelock.New,
	pylock.Name:                        pylock.New,
	requirements.Name:                  requirements.New,
	cargolock.Name:                     cargolock.New,
	gradlelockfile.Name:                gradlelockfile.New,
	gradleverificationmetadataxml.Name: gradleverificationmetadataxml.New,
}

// declaredExtractors read manifests: direct dependencies, versions only
// when literal. Maven has no lockfile convention, so this is its only
// static source (ADR-045 §2). The network-capable Maven extractor is not
// here and must never be.
var declaredExtractors = map[string]extractorConstructor{
	pomxml.Name: pomxml.New,
}

// DefaultExtractors is the allowlist. The network-capable Maven extractor
// ("java/pomxmlnet") and anything executing code are absent on purpose,
// and TestAllowlistIsOffline keeps it that way.
func DefaultExtractors() []string {
	out := make([]string, 0, len(recordedExtractors)+len(declaredExtractors))
	for name := range recordedExtractors {
		out = append(out, name)
	}
	for name := range declaredExtractors {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

var resolutionByExtractor = func() map[string]Resolution {
	m := make(map[string]Resolution, len(recordedExtractors)+len(declaredExtractors))
	for name := range recordedExtractors {
		m[name] = ResolutionRecorded
	}
	for name := range declaredExtractors {
		m[name] = ResolutionDeclared
	}
	return m
}()

// extractorsFor builds the named extractors and checks each one against
// the offline capabilities before anything is read.
func extractorsFor(names []string) ([]filesystem.Extractor, error) {
	cfg := &cpb.PluginConfig{}
	out := make([]filesystem.Extractor, 0, len(names))
	for _, name := range names {
		constructor, ok := recordedExtractors[name]
		if !ok {
			constructor, ok = declaredExtractors[name]
		}
		if !ok {
			return nil, fmt.Errorf("depinventory: extractor %q is not on the allowlist", name)
		}
		ext, err := constructor(cfg)
		if err != nil {
			return nil, fmt.Errorf("depinventory: build extractor %s: %w", name, err)
		}
		if err := plugin.ValidateRequirements(ext, offlineCapabilities); err != nil {
			return nil, fmt.Errorf("depinventory: extractor %s is not offline-capable: %w", name, err)
		}
		out = append(out, ext)
	}
	return out, nil
}

// offlineCapabilities is what the server grants: no network, a real
// directory, not the running system.
var offlineCapabilities = &plugin.Capabilities{
	OS:            plugin.OSAny,
	Network:       plugin.NetworkOffline,
	DirectFS:      true,
	RunningSystem: false,
}

// skipDirPattern matches directory names never descended into: VCS
// metadata, installed dependencies (which carry their own manifests and
// would double every count), and build outputs.
var skipDirPattern = regexp.MustCompile(`(^|[\\/])(\.git|\.hg|\.svn|node_modules|vendor|\.venv|venv|__pycache__|target|dist|build|\.gradle|\.idea|\.terraform)$`)

// Extract walks root and returns the inventory. It never follows symlinks
// out of the root and never executes repository content.
func Extract(ctx context.Context, root string, opts Options) (*Inventory, error) {
	started := time.Now()
	useLogger(opts.Warn)
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("depinventory: resolve root: %w", err)
	}
	names := opts.Extractors
	if len(names) == 0 {
		names = DefaultExtractors()
	}
	extractors, err := extractorsFor(names)
	if err != nil {
		return nil, err
	}
	skip := skipDirPattern
	if len(opts.SkipDirs) > 0 {
		quoted := make([]string, 0, len(opts.SkipDirs))
		for _, dir := range opts.SkipDirs {
			quoted = append(quoted, regexp.QuoteMeta(dir))
		}
		skip = regexp.MustCompile(skipDirPattern.String() + `|(^|[\\/])(` + strings.Join(quoted, "|") + `)$`)
	}
	maxFileSize := opts.MaxFileSize
	if maxFileSize <= 0 {
		maxFileSize = DefaultMaxFileSize
	}
	cfg := &filesystem.Config{
		Extractors:   extractors,
		ScanRoots:    scalibrfs.RealFSScanRoots(absRoot),
		SkipDirRegex: skip,
		MaxFileSize:  maxFileSize,
		ReadSymlinks: false,
		// The runner dereferences the collector; the full scanner would
		// have installed this no-op one.
		Stats: stats.NoopCollector{},
	}
	packages, statuses, err := filesystem.Run(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("depinventory: extraction failed: %w", err)
	}
	inv := &Inventory{Duration: time.Since(started)}
	for _, status := range statuses {
		entry := ExtractorStatus{Name: status.Name, Version: status.Version}
		if status.Status != nil && status.Status.Status != plugin.ScanStatusSucceeded {
			entry.Failed = status.Status.Status == plugin.ScanStatusFailed
			entry.Reason = status.Status.FailureReason
			for _, fileErr := range status.Status.FileErrors {
				if fileErr != nil {
					inv.FileErrors = append(inv.FileErrors, fileErr.FilePath+": "+fileErr.ErrorMessage)
				}
			}
		}
		inv.Extractors = append(inv.Extractors, entry)
	}
	for _, pkg := range packages.Packages {
		if component, ok := toComponent(pkg); ok {
			inv.Components = append(inv.Components, component)
		}
	}
	inv.Components = excludeComponents(inv.Components, opts.Exclude)
	// IaC and CI references (ADR-045 §9) come from hibou's own parsers.
	inv.Components = append(inv.Components, extractIaC(absRoot, opts.Exclude, func(message string) {
		if opts.Warn != nil {
			opts.Warn(message)
		}
	})...)
	inv.Components = markUnresolvedPomRanges(absRoot, inv.Components)
	inv.Components = annotateRelationships(absRoot, inv.Components)
	inv.Edges = extractEdges(absRoot, inv.Components)
	inv.Modules = buildModules(inv.Components)
	inv.InstallConfig = DetectInstallConfig(absRoot, inv.Modules)
	inv.Updaters = DetectUpdaterConfig(absRoot)
	sortComponents(inv.Components)
	return inv, nil
}

// purlTypeToEcosystem matches the names hibou's SBOM ingestion stores.
var purlTypeToEcosystem = map[string]string{
	"golang": "go",
	"npm":    "npm",
	"pypi":   "pypi",
	"cargo":  "cargo",
	"maven":  "maven",
	"nuget":  "nuget",
	"gem":    "rubygems",
}

func toComponent(pkg *extractor.Package) (Component, bool) {
	if pkg == nil || strings.TrimSpace(pkg.Name) == "" {
		return Component{}, false
	}
	purl := pkg.PURL()
	if purl == nil {
		return Component{}, false
	}
	ecosystem, known := purlTypeToEcosystem[purl.Type]
	if known {
		// Qualifiers the engine adds ("source=PUBLIC_REGISTRY") are not
		// identity for language packages: the same version in two lockfiles
		// must be one component.
		purl.Qualifiers = nil
		purl.Subpath = ""
	} else {
		ecosystem = purl.Type
	}
	component := Component{
		Purl:         purl.String(),
		Name:         pkg.Name,
		Version:      pkg.Version,
		Ecosystem:    ecosystem,
		Relationship: RelationshipUnknown,
		Resolution:   ResolutionRecorded,
	}
	if len(pkg.Plugins) > 0 {
		component.Extractor = pkg.Plugins[0]
		if resolution, ok := resolutionByExtractor[component.Extractor]; ok {
			component.Resolution = resolution
		}
	}
	if pkg.Location.Descriptor != nil && pkg.Location.Descriptor.File != nil {
		component.Path = filepath.ToSlash(pkg.Location.Descriptor.File.Path)
		component.Line = pkg.Location.Descriptor.File.LineNumber
	}
	component.Module = moduleOf(component.Path)
	// A requirements line with a comparator other than == is a range: the
	// engine reports its lower bound as the version, which ADR-045 §2.2
	// rejects as a guess. Keep the constraint, drop the version.
	if req, ok := pkg.Metadata.(*requirements.Metadata); ok && req != nil {
		if comparator := strings.TrimSpace(req.VersionComparator); comparator != "" && comparator != "==" && comparator != "===" {
			component.markUnresolved(strings.TrimSpace(req.Requirement))
			if component.Constraint == "" {
				component.Constraint = comparator + pkg.Version
			}
		}
	}
	if npm, ok := pkg.Metadata.(*jsmetadata.JavascriptPackageMetadata); ok && npm != nil {
		switch npm.Source {
		case jsmetadata.PublicRegistry:
			component.Registry = RegistryPublic
		case jsmetadata.Other, jsmetadata.Local:
			component.Registry = RegistryPrivate
		}
	}
	if groups, ok := pkg.Metadata.(osv.DepGroups); ok {
		for _, group := range groups.DepGroups() {
			if group = strings.TrimSpace(group); group != "" {
				component.Scopes = append(component.Scopes, group)
			}
		}
		sort.Strings(component.Scopes)
	}
	return component, true
}

func moduleOf(filePath string) string {
	if filePath == "" {
		return "."
	}
	dir := path.Dir(filePath)
	if dir == "" || dir == "/" {
		return "."
	}
	return dir
}

// lockfileNames are the recorded sources a module can carry; a module with
// only manifests is partial.
var lockfileNames = map[string]struct{}{
	"go.mod": {}, "package-lock.json": {}, "npm-shrinkwrap.json": {}, "pnpm-lock.yaml": {},
	"yarn.lock": {}, "bun.lock": {}, "uv.lock": {}, "poetry.lock": {}, "pdm.lock": {},
	"Pipfile.lock": {}, "pylock.toml": {}, "Cargo.lock": {}, "gradle.lockfile": {},
	"verification-metadata.xml": {},
}

func buildModules(components []Component) []Module {
	byPath := make(map[string]*Module)
	for _, component := range components {
		module, ok := byPath[component.Module]
		if !ok {
			module = &Module{Path: component.Module}
			byPath[component.Module] = module
		}
		if component.Path != "" && !contains(module.Files, component.Path) {
			module.Files = append(module.Files, component.Path)
		}
		if !contains(module.Ecosystems, component.Ecosystem) {
			module.Ecosystems = append(module.Ecosystems, component.Ecosystem)
		}
	}
	modules := make([]Module, 0, len(byPath))
	for _, module := range byPath {
		sort.Strings(module.Files)
		sort.Strings(module.Ecosystems)
		module.Complete = false
		module.Reason = "no lockfile: indirect dependencies unknown"
		for _, file := range module.Files {
			base := path.Base(file)
			if _, ok := lockfileNames[base]; ok || strings.HasPrefix(base, "requirements") {
				module.Complete = true
				module.Reason = ""
				break
			}
		}
		modules = append(modules, *module)
	}
	sort.Slice(modules, func(i, j int) bool { return modules[i].Path < modules[j].Path })
	return modules
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

// markUnresolved turns a component into an unresolved range (ADR-045
// §2.2): no version, the purl without one, the constraint kept.
func (c *Component) markUnresolved(constraint string) {
	c.Resolution = ResolutionUnresolved
	c.Constraint = constraint
	c.Version = ""
	if idx := strings.LastIndex(c.Purl, "@"); idx > strings.Index(c.Purl, "/") {
		c.Purl = c.Purl[:idx]
	}
}

// excludeComponents drops components read under an excluded path
// (ADR-045 §8): fixtures and examples are not the product.
func excludeComponents(components []Component, exclude []string) []Component {
	if len(exclude) == 0 {
		return components
	}
	out := components[:0]
	for _, component := range components {
		if IsExcludedPath(component.Path, exclude) {
			continue
		}
		out = append(out, component)
	}
	return out
}

// IsExcludedPath reports whether a repository path matches one of the
// exclude globs, as a file or as a directory prefix.
func IsExcludedPath(repoPath string, exclude []string) bool {
	repoPath = strings.TrimPrefix(strings.TrimSpace(repoPath), "./")
	if repoPath == "" {
		return false
	}
	for _, pattern := range exclude {
		pattern = strings.TrimPrefix(strings.TrimSpace(pattern), "./")
		if pattern == "" {
			continue
		}
		if ok, _ := doublestar.Match(pattern, repoPath); ok {
			return true
		}
		// "examples/**" also excludes the directory's own manifests when
		// written as "examples".
		if ok, _ := doublestar.Match(strings.TrimSuffix(pattern, "/**")+"/**", repoPath); ok {
			return true
		}
	}
	return false
}

// pomRangePattern matches a Maven version range: brackets or parentheses
// with a comma, e.g. [1.0,2.0) or (,1.5].
var pomRangePattern = regexp.MustCompile(`^[\[(][^\])]*,[^\])]*[\])]$`)

// markUnresolvedPomRanges re-reads each pom.xml for dependencies declared
// with a version range. The engine resolves a range to its lower bound,
// which ADR-045 §2.2 rejects: the component is kept with its constraint
// and no version.
func markUnresolvedPomRanges(root string, components []Component) []Component {
	ranges := make(map[string]string) // path|group:artifact -> constraint
	seen := make(map[string]struct{})
	for _, component := range components {
		if component.Extractor != pomxml.Name || component.Path == "" {
			continue
		}
		if _, done := seen[component.Path]; done {
			continue
		}
		seen[component.Path] = struct{}{}
		for coordinates, constraint := range pomRanges(filepath.Join(root, filepath.FromSlash(component.Path))) {
			ranges[component.Path+"|"+coordinates] = constraint
		}
	}
	if len(ranges) == 0 {
		return components
	}
	for i := range components {
		if constraint, ok := ranges[components[i].Path+"|"+components[i].Name]; ok {
			components[i].markUnresolved(constraint)
		}
	}
	return components
}

// pomRanges returns group:artifact -> range for every dependency of a pom
// declared with a version range. Property references are not ranges.
func pomRanges(pomPath string) map[string]string {
	data, err := os.ReadFile(pomPath) // #nosec G304 -- a path the extractor already read inside the root
	if err != nil {
		return nil
	}
	var pom struct {
		Dependencies struct {
			Dependency []pomDependency `xml:"dependency"`
		} `xml:"dependencies"`
		DependencyManagement struct {
			Dependencies struct {
				Dependency []pomDependency `xml:"dependency"`
			} `xml:"dependencies"`
		} `xml:"dependencyManagement"`
	}
	if err := xml.Unmarshal(data, &pom); err != nil { // #nosec G709 -- a pom.xml inside the extraction root, read for version strings only
		return nil
	}
	out := make(map[string]string)
	for _, dep := range append(pom.Dependencies.Dependency, pom.DependencyManagement.Dependencies.Dependency...) {
		version := strings.TrimSpace(dep.Version)
		if pomRangePattern.MatchString(version) {
			out[strings.TrimSpace(dep.GroupID)+":"+strings.TrimSpace(dep.ArtifactID)] = version
		}
	}
	return out
}

type pomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
}

func sortComponents(components []Component) {
	sort.Slice(components, func(i, j int) bool {
		if components[i].Module != components[j].Module {
			return components[i].Module < components[j].Module
		}
		if components[i].Purl != components[j].Purl {
			return components[i].Purl < components[j].Purl
		}
		return components[i].Path < components[j].Path
	})
}
