package notices

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"go/build"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"unicode"

	toml "github.com/pelletier/go-toml/v2"
)

// Local package caches (ADR-051 §1, source S1): the exact files of the
// versions the build resolved, private packages included, with no network.

// CacheOptions locates the caches. Empty fields use each ecosystem's default.
type CacheOptions struct {
	// Root is the directory the component modules are relative to.
	Root string
	// GoModCache overrides GOMODCACHE.
	GoModCache string
	// GoRoot locates the toolchain's own licence for binary inventories.
	GoRoot string
	// MavenRepo overrides ~/.m2/repository.
	MavenRepo string
	// SitePackages lists Python site-packages directories.
	SitePackages []string
	// CargoHome overrides CARGO_HOME.
	CargoHome string
}

// LocalCollectors returns the collectors of the five supported ecosystems.
func LocalCollectors(opts CacheOptions) []Collector {
	if opts.Root == "" {
		opts.Root = "."
	}
	return []Collector{
		&goCollector{opts: opts},
		&npmCollector{root: opts.Root},
		&mavenCollector{opts: opts},
		&pythonCollector{opts: opts},
		&cargoCollector{opts: opts},
	}
}

func ecosystemIs(c Component, names ...string) bool {
	eco := strings.ToLower(strings.TrimSpace(c.Ecosystem))
	for _, name := range names {
		if eco == name || strings.HasPrefix(c.Purl, "pkg:"+name+"/") {
			return true
		}
	}
	return false
}

// ---- Go: module cache, then vendor/ ----

type goCollector struct{ opts CacheOptions }

func (g *goCollector) Handles(c Component) bool { return ecosystemIs(c, "golang", "go") }

func (g *goCollector) modCache() string {
	if g.opts.GoModCache != "" {
		return g.opts.GoModCache
	}
	if dir := os.Getenv("GOMODCACHE"); dir != "" {
		return dir
	}
	if gopath := os.Getenv("GOPATH"); gopath != "" {
		return filepath.Join(filepath.SplitList(gopath)[0], "pkg", "mod")
	}
	return filepath.Join(homeDir(), "go", "pkg", "mod")
}

// escapeModulePath applies the module cache's case encoding: an upper-case
// letter becomes "!" followed by its lower-case form.
func escapeModulePath(module string) string {
	var b strings.Builder
	for _, r := range module {
		if unicode.IsUpper(r) {
			b.WriteByte('!')
			b.WriteRune(unicode.ToLower(r))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// resolveFold walks rel under base, matching each path segment exactly or,
// failing that, ignoring case and the module cache's "!" escapes. It returns
// "" when a segment has no match.
func resolveFold(base, rel string) string {
	fold := func(s string) string { return strings.ToLower(strings.ReplaceAll(s, "!", "")) }
	current := base
	for _, segment := range strings.Split(rel, "/") {
		if segment == "" {
			continue
		}
		exact := filepath.Join(current, escapeModulePath(segment))
		if _, err := os.Stat(exact); err == nil {
			current = exact
			continue
		}
		entries, err := os.ReadDir(current)
		if err != nil {
			return ""
		}
		matched := ""
		for _, entry := range entries {
			if fold(entry.Name()) == fold(segment) {
				matched = entry.Name()
				break
			}
		}
		if matched == "" {
			return ""
		}
		current = filepath.Join(current, matched)
	}
	return current
}

func (g *goCollector) Collect(c Component) Evidence {
	purl, ok := parsePurl(c.Purl)
	if !ok {
		return Evidence{}
	}
	module := purl.Name
	if purl.Namespace != "" {
		module = purl.Namespace + "/" + purl.Name
	}
	if module == "go" {
		dir := g.opts.GoRoot
		if dir == "" {
			dir = build.Default.GOROOT
		}
		version, err := readEvidenceFile(filepath.Join(dir, "VERSION"))
		fields := strings.Fields(string(version))
		if err != nil || len(fields) == 0 || fields[0] != "go"+strings.TrimPrefix(c.Version, "go") {
			return Evidence{Issues: []string{"Go runtime version differs from the local toolchain; use --goroot for the matching installation"}}
		}
		files, notice, issues := readDirEvidence(dir)
		return Evidence{Found: true, Location: dir, Files: files, Notice: notice, Issues: issues}
	}
	// A purl's namespace is lower-cased, the module cache keeps the case
	// ("!burnt!sushi"), so directories are matched case-insensitively.
	version := purl.Version
	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}
	dir := firstExisting(
		resolveFold(g.modCache(), module+"@"+version),
	)
	if dir == "" {
		for _, vendor := range []string{
			filepath.Join(g.opts.Root, filepath.FromSlash(c.Module), "vendor"),
			filepath.Join(g.opts.Root, "vendor"),
		} {
			metadata, err := readEvidenceFile(filepath.Join(vendor, "modules.txt"))
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(metadata), "\n") {
				fields := strings.Fields(line)
				if len(fields) == 3 && fields[0] == "#" && strings.EqualFold(fields[1], module) && fields[2] == version {
					dir = resolveFold(vendor, module)
					break
				}
			}
			if dir != "" {
				break
			}
		}
	}
	if dir == "" {
		return Evidence{}
	}
	files, notice, issues := readDirEvidence(dir)
	return Evidence{Found: true, Location: dir, Files: files, Notice: notice, Issues: issues}
}

// ---- npm: node_modules next to the lockfile, nested copies included ----

type npmCollector struct {
	root   string
	mu     sync.Mutex
	index  map[string]map[string]string // node_modules dir -> "name@version" -> package dir
	issues map[string][]string
}

func (n *npmCollector) Handles(c Component) bool { return ecosystemIs(c, "npm") }

type packageJSON struct {
	Name     string          `json:"name"`
	Version  string          `json:"version"`
	License  json.RawMessage `json:"license"`
	Licenses []struct {
		Type string `json:"type"`
	} `json:"licenses"`
}

func (p packageJSON) declared() string {
	var text string
	if json.Unmarshal(p.License, &text) == nil && text != "" {
		return text
	}
	var object struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(p.License, &object) == nil && object.Type != "" {
		return object.Type
	}
	var types []string
	for _, l := range p.Licenses {
		if l.Type != "" {
			types = append(types, l.Type)
		}
	}
	return strings.Join(types, " OR ")
}

// nodeModulesIndex maps every installed "name@version" under one
// node_modules directory to its package directory, walking it once.
func (n *npmCollector) nodeModulesIndex(dir string) map[string]string {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.index == nil {
		n.index = map[string]map[string]string{}
	}
	if index, ok := n.index[dir]; ok {
		return index
	}
	index := map[string]string{}
	var issues []string
	visited := 0
	walkErr := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			issues = append(issues, "cannot traverse installed npm packages: "+evidenceError(err))
			return nil
		}
		visited++
		if visited > 200000 {
			return errors.New("npm evidence traversal exceeds 200000 entries")
		}
		if entry.IsDir() {
			if name := entry.Name(); name == ".bin" || name == ".cache" {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Name() != "package.json" || !strings.Contains(filepath.ToSlash(path), "node_modules/") {
			return nil
		}
		// Only a package root: its parent is node_modules/<name> or
		// node_modules/@scope/<name>.
		pkgDir := filepath.Dir(path)
		parent := filepath.Base(filepath.Dir(pkgDir))
		grand := filepath.Base(filepath.Dir(filepath.Dir(pkgDir)))
		if parent != "node_modules" && (!strings.HasPrefix(parent, "@") || grand != "node_modules") {
			return nil
		}
		data, err := readEvidenceFile(path)
		if err != nil {
			issues = append(issues, "cannot read npm package metadata: "+evidenceError(err))
			return nil
		}
		var pkg packageJSON
		if json.Unmarshal(data, &pkg) != nil || pkg.Name == "" || pkg.Version == "" {
			return nil
		}
		key := pkg.Name + "@" + pkg.Version
		if existing, ok := index[key]; !ok || len(pkgDir) < len(existing) {
			index[key] = pkgDir
		}
		return nil
	})
	if walkErr != nil {
		issues = append(issues, evidenceError(walkErr))
	}
	if n.issues == nil {
		n.issues = map[string][]string{}
	}
	n.issues[dir] = uniqueSorted(issues)
	n.index[dir] = index
	return index
}

func (n *npmCollector) Collect(c Component) Evidence {
	purl, ok := parsePurl(c.Purl)
	if !ok {
		return Evidence{}
	}
	name := purl.Name
	if purl.Namespace != "" {
		name = purl.Namespace + "/" + purl.Name
	}
	for _, base := range uniqueStable([]string{filepath.Join(n.root, filepath.FromSlash(c.Module)), n.root}) {
		nodeModules := filepath.Join(base, "node_modules")
		if firstExisting(nodeModules) == "" {
			continue
		}
		dir, ok := n.nodeModulesIndex(nodeModules)[name+"@"+purl.Version]
		if !ok {
			continue
		}
		evidence := Evidence{Found: true, Location: dir, Issues: append([]string{}, n.issues[nodeModules]...)}
		if data, err := readEvidenceFile(filepath.Join(dir, "package.json")); err == nil {
			var pkg packageJSON
			if json.Unmarshal(data, &pkg) == nil {
				if declared := pkg.declared(); spdxLike(declared) {
					evidence.Declared = declared
				}
			} else {
				evidence.Issues = append(evidence.Issues, "invalid npm package metadata")
			}
		} else {
			evidence.Issues = append(evidence.Issues, "cannot read npm package metadata: "+evidenceError(err))
		}
		var issues []string
		evidence.Files, evidence.Notice, issues = readDirEvidence(dir)
		evidence.Issues = append(evidence.Issues, issues...)
		return evidence
	}
	return Evidence{}
}

// ---- Maven: jars of the local repository ----

type mavenCollector struct{ opts CacheOptions }

func (m *mavenCollector) Handles(c Component) bool { return ecosystemIs(c, "maven") }

func (m *mavenCollector) repo() string {
	if m.opts.MavenRepo != "" {
		return m.opts.MavenRepo
	}
	if dir := os.Getenv("MAVEN_REPO_LOCAL"); dir != "" {
		return dir
	}
	return filepath.Join(homeDir(), ".m2", "repository")
}

func (m *mavenCollector) Collect(c Component) Evidence {
	purl, ok := parsePurl(c.Purl)
	if !ok || purl.Namespace == "" {
		return Evidence{}
	}
	dir := filepath.Join(m.repo(), filepath.FromSlash(strings.ReplaceAll(purl.Namespace, ".", "/")), purl.Name, purl.Version)
	if firstExisting(dir) == "" {
		return Evidence{}
	}
	qualifiers := purl.Qualifiers.Map()
	artifact := purl.Name + "-" + purl.Version
	if classifier := qualifiers["classifier"]; classifier != "" {
		artifact += "-" + classifier
	}
	extension := qualifiers["type"]
	if extension == "" || extension == "pom" {
		extension = "jar"
	}
	evidence := Evidence{Found: true, Location: dir}
	archive := filepath.Join(dir, artifact+"."+extension)
	files, notice, archiveErr := readZipEvidence(archive, "META-INF")
	if archiveErr == nil {
		evidence.Location = archive
	} else if !errors.Is(archiveErr, os.ErrNotExist) {
		evidence.Issues = append(evidence.Issues, "cannot read Maven archive evidence: "+evidenceError(archiveErr))
	}
	evidence.Files, evidence.Notice = files, notice
	// The POM's <licenses> names are free text ("Apache License, Version
	// 2.0"); only an SPDX-looking name is kept as the declared licence.
	// Licences inherited from a parent POM are not resolved.
	if data, err := readEvidenceFile(filepath.Join(dir, purl.Name+"-"+purl.Version+".pom")); err == nil {
		var pom struct {
			Licenses []struct {
				Name string `xml:"name"`
			} `xml:"licenses>license"`
		}
		if xml.Unmarshal(data, &pom) == nil {
			var names []string
			for _, l := range pom.Licenses {
				if spdxLike(l.Name) {
					names = append(names, strings.TrimSpace(l.Name))
				}
			}
			evidence.Declared = strings.Join(names, " AND ")
		} else {
			evidence.Issues = append(evidence.Issues, "invalid Maven POM metadata")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		evidence.Issues = append(evidence.Issues, "cannot read Maven POM metadata: "+evidenceError(err))
	}
	return evidence
}

// ---- Python: *.dist-info in site-packages ----

type pythonCollector struct {
	opts  CacheOptions
	once  sync.Once
	index map[string]string // normalized "name@version" -> dist-info dir
}

func (p *pythonCollector) Handles(c Component) bool { return ecosystemIs(c, "pypi") }

var pythonNameSeparators = regexp.MustCompile(`[-_.]+`)

func normalizePythonName(name string) string {
	return strings.ToLower(pythonNameSeparators.ReplaceAllString(name, "_"))
}

func (p *pythonCollector) sitePackages() []string {
	dirs := append([]string{}, p.opts.SitePackages...)
	var venvs []string
	if venv := os.Getenv("VIRTUAL_ENV"); venv != "" {
		venvs = append(venvs, venv)
	}
	venvs = append(venvs, filepath.Join(p.opts.Root, ".venv"), filepath.Join(p.opts.Root, "venv"))
	for _, venv := range venvs {
		matches, _ := filepath.Glob(filepath.Join(venv, "lib", "python*", "site-packages"))
		dirs = append(dirs, matches...)
		dirs = append(dirs, filepath.Join(venv, "Lib", "site-packages")) // Windows layout
	}
	return dirs
}

func (p *pythonCollector) build() {
	p.index = map[string]string{}
	for _, dir := range p.sitePackages() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			name := entry.Name()
			if !entry.IsDir() || !strings.HasSuffix(name, ".dist-info") {
				continue
			}
			stem := strings.TrimSuffix(name, ".dist-info")
			dash := strings.LastIndex(stem, "-")
			if dash <= 0 {
				continue
			}
			key := normalizePythonName(stem[:dash]) + "@" + stem[dash+1:]
			if _, ok := p.index[key]; !ok {
				p.index[key] = filepath.Join(dir, name)
			}
		}
	}
}

var metadataLicenseExpression = regexp.MustCompile(`(?m)^License-Expression:\s*(.+)$`)
var metadataLicense = regexp.MustCompile(`(?m)^License:\s*(.+)$`)

func (p *pythonCollector) Collect(c Component) Evidence {
	purl, ok := parsePurl(c.Purl)
	if !ok {
		return Evidence{}
	}
	p.once.Do(p.build)
	dir, ok := p.index[normalizePythonName(purl.Name)+"@"+purl.Version]
	if !ok {
		return Evidence{}
	}
	evidence := Evidence{Found: true, Location: dir}
	// PEP 639 puts licence files under licenses/; older wheels at the top.
	evidence.Files, evidence.Notice, evidence.Issues = readDirEvidence(dir, "licenses", "license_files")
	if data, err := readEvidenceFile(filepath.Join(dir, "METADATA")); err == nil {
		header := string(data)
		if blank := strings.Index(header, "\n\n"); blank >= 0 {
			header = header[:blank]
		}
		for _, pattern := range []*regexp.Regexp{metadataLicenseExpression, metadataLicense} {
			if match := pattern.FindStringSubmatch(header); match != nil && spdxLike(match[1]) {
				evidence.Declared = strings.TrimSpace(match[1])
				break
			}
		}
	} else {
		evidence.Issues = append(evidence.Issues, "cannot read Python metadata: "+evidenceError(err))
	}
	return evidence
}

// ---- Cargo: registry sources, then vendor/ ----

type cargoCollector struct{ opts CacheOptions }

func (g *cargoCollector) Handles(c Component) bool { return ecosystemIs(c, "cargo") }

func (g *cargoCollector) home() string {
	if g.opts.CargoHome != "" {
		return g.opts.CargoHome
	}
	if dir := os.Getenv("CARGO_HOME"); dir != "" {
		return dir
	}
	return filepath.Join(homeDir(), ".cargo")
}

func (g *cargoCollector) Collect(c Component) Evidence {
	purl, ok := parsePurl(c.Purl)
	if !ok {
		return Evidence{}
	}
	crate := purl.Name + "-" + purl.Version
	candidates, _ := filepath.Glob(filepath.Join(g.home(), "registry", "src", "*", crate))
	candidates = append(candidates,
		filepath.Join(g.opts.Root, "vendor", crate),
		filepath.Join(g.opts.Root, "vendor", purl.Name))
	for _, dir := range candidates {
		data, err := readEvidenceFile(filepath.Join(dir, "Cargo.toml"))
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return Evidence{Found: true, Issues: []string{"cannot read Cargo metadata: " + evidenceError(err)}}
			}
			continue
		}
		var metadata struct {
			Package struct {
				Name, Version, License string
			}
		}
		if err := toml.Unmarshal(data, &metadata); err != nil {
			return Evidence{Found: true, Issues: []string{"invalid Cargo package metadata"}}
		}
		if metadata.Package.Name != purl.Name || metadata.Package.Version != purl.Version {
			continue
		}
		evidence := Evidence{Found: true, Location: dir}
		evidence.Files, evidence.Notice, evidence.Issues = readDirEvidence(dir)
		if metadata.Package.License != "" {
			// Cargo allows "MIT/Apache-2.0" as a legacy spelling of OR.
			declared := strings.ReplaceAll(metadata.Package.License, "/", " OR ")
			if spdxLike(declared) {
				evidence.Declared = declared
			}
		}
		return evidence
	}
	return Evidence{}
}
