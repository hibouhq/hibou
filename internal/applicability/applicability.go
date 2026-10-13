// Package applicability decides which catalog scanners apply to a repository
// at a commit (ADR-035 §3, ADR-036 §2), from its tracked paths alone: no
// repository code runs and no build script is evaluated. An incomplete view
// (truncated listing, forge without tree support) yields "unknown", never
// "not applicable".
package applicability

import (
	"path"
	"sort"
	"strings"

	"github.com/hibouhq/hibou/internal/scancatalog"
)

// Revision versions the detection recipes; a stored result with another
// revision is stale.
const Revision = "1"

// Result statuses.
const (
	StatusComplete  = "complete"
	StatusTruncated = "truncated"
	StatusUnknown   = "unknown"
)

// Module is one build unit found from its manifest.
type Module struct {
	Root        string   `json:"root"`
	BuildSystem string   `json:"build_system"`
	Manifest    string   `json:"manifest"`
	Languages   []string `json:"languages"`
}

// Exclusion is a path left out of analysis scope, with why.
type Exclusion struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// ScannerScope is one catalog scanner that applies, and where.
type ScannerScope struct {
	ScannerID    string                   `json:"scanner_id"`
	Preview      bool                     `json:"preview,omitempty"`
	Modules      []string                 `json:"modules"`
	Languages    []string                 `json:"languages"`
	Capabilities []scancatalog.Capability `json:"capabilities"`
	Reason       string                   `json:"reason"`
}

// Result is what detection found at one commit.
type Result struct {
	Revision   string         `json:"revision"`
	Status     string         `json:"status"`
	FileCount  int            `json:"file_count"`
	Languages  map[string]int `json:"languages"`
	Modules    []Module       `json:"modules"`
	Exclusions []Exclusion    `json:"exclusions"`
	Applicable []ScannerScope `json:"applicable"`
	// TextOnly: no source language at all. Source SAST does not apply;
	// secret scanning still does (ADR-035 §3).
	TextOnly bool `json:"text_only"`
	// OwnerExclusions are the repository owners' exclusions with the
	// languages they would hide and whether they applied: one that hides
	// code the org requires scanned waits for an approved exception.
	OwnerExclusions []OwnerExclusion `json:"owner_exclusions,omitempty"`
}

// OwnerExclusion is an owner-declared excluded path.
type OwnerExclusion struct {
	Path      string   `json:"path"`
	Reason    string   `json:"reason"`
	Languages []string `json:"languages"`
	Applied   bool     `json:"applied"`
	// Blocked explains why it did not apply.
	Blocked string `json:"blocked,omitempty"`
}

// Overrides are owner refinements of detection (ADR-035 §3).
type Overrides struct {
	Exclusions  []OwnerExclusion
	ModuleRoots []string
	// Allow decides whether an exclusion hiding these languages applies;
	// nil allows all. It returns why not when it refuses.
	Allow func(path string, languages []string) (bool, string)
}

var extensionLanguages = map[string]string{
	".go": "go", ".java": "java", ".kt": "kotlin", ".kts": "kotlin",
	".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
	".ts": "typescript", ".tsx": "typescript", ".py": "python", ".rb": "ruby", ".php": "php",
	".cs": "csharp", ".rs": "rust", ".scala": "scala", ".swift": "swift", ".c": "c", ".h": "c",
	".cc": "cpp", ".cpp": "cpp", ".hpp": "cpp", ".tf": "terraform", ".sh": "shell",
}

// textExtensions are documentation and data: not source.
var textExtensions = map[string]bool{
	".md": true, ".markdown": true, ".rst": true, ".txt": true, ".adoc": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true, ".ico": true, ".pdf": true,
	".json": true, ".yaml": true, ".yml": true, ".toml": true, ".csv": true, ".lock": true,
}

// excludedDirs are dependency trees, vendored code and build output.
var excludedDirs = map[string]string{
	"node_modules": "dependency directory", "vendor": "vendored code", "third_party": "vendored code",
	"bower_components": "dependency directory", ".venv": "dependency directory", "venv": "dependency directory",
	"target": "build output", "build": "build output", "dist": "build output", "out": "build output",
	"__pycache__": "build output", ".gradle": "build output", ".git": "repository metadata",
}

// manifests map a manifest file name to its build system.
var manifests = map[string]string{
	"pom.xml": "maven", "build.gradle": "gradle", "build.gradle.kts": "gradle", "go.mod": "go",
	"package.json": "node", "Cargo.toml": "cargo", "pyproject.toml": "python", "setup.py": "python",
	"Gemfile": "ruby", "composer.json": "php", "Chart.yaml": "helm",
}

// Detect classifies a repository's tracked paths. truncated marks a listing
// the forge cut short; a nil listing means the forge could not list at all.
func Detect(paths []string, truncated bool, catalog *scancatalog.Catalog) Result {
	return DetectWithOverrides(paths, truncated, catalog, Overrides{})
}

// DetectWithOverrides is Detect with the owners' refinements applied:
// allowed exclusions remove their paths, declared module roots are added.
func DetectWithOverrides(paths []string, truncated bool, catalog *scancatalog.Catalog, overrides Overrides) Result {
	excludedByOwner := ownerExclusions(paths, overrides)
	result := Result{
		Revision:   Revision,
		Status:     StatusComplete,
		Languages:  map[string]int{},
		Modules:    []Module{},
		Exclusions: []Exclusion{},
		Applicable: []ScannerScope{},
	}
	if paths == nil {
		result.Status = StatusUnknown
		return result
	}
	if truncated {
		result.Status = StatusTruncated
	}

	excluded := map[string]string{}
	kept := make([]string, 0, len(paths))
	moduleRoots := map[string]Module{}
	for _, raw := range paths {
		file := strings.TrimPrefix(path.Clean(raw), "./")
		// An excluded path that could read as an option or climb out of the
		// checkout is still left out of the kept files, but never becomes a
		// scanner argument (safeRoot, Q14).
		if exclusion, ok := matchingExclusion(file, excludedByOwner); ok {
			if safeRoot(exclusion.Path) {
				excluded[exclusion.Path] = "owner: " + exclusion.Reason
			}
			continue
		}
		if dir, reason, ok := excludedPrefix(file); ok {
			if safeRoot(dir) {
				excluded[dir] = reason
			}
			continue
		}
		if strings.HasSuffix(file, ".min.js") {
			if safeRoot(file) {
				excluded[file] = "minified bundle"
			}
			continue
		}
		base := path.Base(file)
		if system, ok := manifests[base]; ok && safeRoot(path.Dir(file)) {
			root := path.Dir(file)
			if _, seen := moduleRoots[root]; !seen || system != "node" {
				moduleRoots[root] = Module{Root: root, BuildSystem: system, Manifest: file}
			}
		}
		if strings.HasSuffix(base, ".csproj") && safeRoot(path.Dir(file)) {
			root := path.Dir(file)
			moduleRoots[root] = Module{Root: root, BuildSystem: "dotnet", Manifest: file}
		}
		kept = append(kept, file)
	}
	result.FileCount = len(kept)
	for _, root := range overrides.ModuleRoots {
		root = strings.TrimSuffix(strings.TrimPrefix(path.Clean(root), "./"), "/")
		if _, detected := moduleRoots[root]; !detected && root != "" && safeRoot(root) {
			moduleRoots[root] = Module{Root: root, BuildSystem: "declared", Manifest: ""}
		}
	}

	roots := make([]string, 0, len(moduleRoots))
	for root := range moduleRoots {
		roots = append(roots, root)
	}
	// Longest root first: a file belongs to its nearest module.
	sort.Slice(roots, func(i, j int) bool {
		if len(roots[i]) != len(roots[j]) {
			return len(roots[i]) > len(roots[j])
		}
		return roots[i] < roots[j]
	})
	moduleLanguages := map[string]map[string]bool{}
	repoLevel := map[string]bool{}
	for _, file := range kept {
		language := languageOf(file)
		if language == "" {
			continue
		}
		result.Languages[language]++
		if root, ok := nearestRoot(file, roots); ok {
			if moduleLanguages[root] == nil {
				moduleLanguages[root] = map[string]bool{}
			}
			moduleLanguages[root][language] = true
		} else {
			repoLevel[language] = true
		}
	}
	sort.Strings(roots)
	for _, root := range roots {
		module := moduleRoots[root]
		module.Languages = sortedKeys(moduleLanguages[root])
		result.Modules = append(result.Modules, module)
	}
	for dir, reason := range excluded {
		result.Exclusions = append(result.Exclusions, Exclusion{Path: dir, Reason: reason})
	}
	sort.Slice(result.Exclusions, func(i, j int) bool { return result.Exclusions[i].Path < result.Exclusions[j].Path })

	sourceLanguages := 0
	for language := range result.Languages {
		if language != "shell" {
			sourceLanguages++
		}
	}
	result.TextOnly = sourceLanguages == 0 && result.Status == StatusComplete
	result.OwnerExclusions = overrides.Exclusions
	for i := range result.OwnerExclusions {
		applied := false
		for _, exclusion := range excludedByOwner {
			applied = applied || exclusion.Path == result.OwnerExclusions[i].Path
		}
		result.OwnerExclusions[i].Applied = applied
	}
	if catalog != nil {
		result.Applicable = applicableScanners(catalog, result, repoLevel)
	}
	return result
}

func applicableScanners(catalog *scancatalog.Catalog, result Result, repoLevel map[string]bool) []ScannerScope {
	scopes := make([]ScannerScope, 0)
	for i := range catalog.Scanners {
		scanner := &catalog.Scanners[i]
		scope := ScannerScope{ScannerID: scanner.ID, Preview: scanner.Prerelease, Modules: []string{}, Languages: []string{}, Capabilities: []scancatalog.Capability{}}
		languages := map[string]bool{}
		for _, capability := range scanner.Capabilities {
			if result.Languages[capability.Language] > 0 {
				languages[capability.Language] = true
				scope.Capabilities = append(scope.Capabilities, capability)
			}
		}
		if len(languages) == 0 {
			continue
		}
		needsBuild := len(scanner.Applicability.BuildSystems) > 0
		for _, module := range result.Modules {
			if needsBuild && !contains(scanner.Applicability.BuildSystems, module.BuildSystem) {
				continue
			}
			for _, language := range module.Languages {
				if languages[language] {
					scope.Modules = append(scope.Modules, module.Root)
					break
				}
			}
		}
		if needsBuild {
			if len(scope.Modules) == 0 {
				continue // bytecode needs a build the repo does not have
			}
			scope.Reason = "modules built with " + strings.Join(scanner.Applicability.BuildSystems, ", ")
		} else {
			for language := range languages {
				if repoLevel[language] && !contains(scope.Modules, ".") {
					scope.Modules = append(scope.Modules, ".")
					break
				}
			}
			scope.Reason = "source files in supported languages"
		}
		scope.Languages = sortedKeys(languages)
		sort.Strings(scope.Modules)
		scopes = append(scopes, scope)
	}
	return scopes
}

func excludedPrefix(file string) (string, string, bool) {
	segments := strings.Split(file, "/")
	for i, segment := range segments[:len(segments)-1] {
		if reason, ok := excludedDirs[segment]; ok {
			return strings.Join(segments[:i+1], "/"), reason, true
		}
	}
	return "", "", false
}

func languageOf(file string) string {
	base := path.Base(file)
	if base == "Dockerfile" || strings.HasPrefix(base, "Dockerfile.") {
		return "dockerfile"
	}
	extension := strings.ToLower(path.Ext(base))
	if textExtensions[extension] {
		return ""
	}
	return extensionLanguages[extension]
}

func nearestRoot(file string, rootsLongestFirst []string) (string, bool) {
	for _, root := range rootsLongestFirst {
		if root == "." || strings.HasPrefix(file, root+"/") {
			return root, true
		}
	}
	return "", false
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

// ownerExclusions computes, for each owner exclusion, the languages of the
// files it would hide, asks Allow, and returns the ones that apply.
func ownerExclusions(paths []string, overrides Overrides) []OwnerExclusion {
	applied := make([]OwnerExclusion, 0, len(overrides.Exclusions))
	for i := range overrides.Exclusions {
		exclusion := &overrides.Exclusions[i]
		exclusion.Path = strings.TrimSuffix(strings.TrimPrefix(path.Clean(exclusion.Path), "./"), "/")
		languages := map[string]bool{}
		for _, raw := range paths {
			file := strings.TrimPrefix(path.Clean(raw), "./")
			if underPath(file, exclusion.Path) {
				if language := languageOf(file); language != "" {
					languages[language] = true
				}
			}
		}
		exclusion.Languages = sortedKeys(languages)
		if overrides.Allow != nil {
			if ok, why := overrides.Allow(exclusion.Path, exclusion.Languages); !ok {
				exclusion.Blocked = why
				continue
			}
		}
		applied = append(applied, *exclusion)
	}
	return applied
}

func matchingExclusion(file string, exclusions []OwnerExclusion) (OwnerExclusion, bool) {
	for _, exclusion := range exclusions {
		if underPath(file, exclusion.Path) {
			return exclusion, true
		}
	}
	return OwnerExclusion{}, false
}

// safeRoot reports whether a module root may become a scanner target: the
// CLI passes targets to scanners as arguments, so a root that reads as an
// option ("-…", "--exclude=*") or climbs out of the checkout ("..") is
// dropped rather than planned (Q14).
func safeRoot(root string) bool {
	if root == "" || strings.HasPrefix(root, "-") || strings.HasPrefix(root, "/") {
		return false
	}
	for _, segment := range strings.Split(root, "/") {
		if segment == ".." {
			return false
		}
	}
	return true
}

func underPath(file, dir string) bool {
	return dir != "" && dir != "." && (file == dir || strings.HasPrefix(file, dir+"/"))
}
