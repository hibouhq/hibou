package depinventory

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	toml "github.com/pelletier/go-toml/v2"
	"golang.org/x/mod/modfile"
	"gopkg.in/yaml.v3"
)

// Relationship rules (ADR-045 §5.1): a source with a graph decides, and the
// decision is per module. Each rule reads the module's own files again,
// cheaply, because SCALIBR does not expose the root's declared set. A
// module no rule covers stays "unknown".

// directInfo is what a module's own files say about its roots: the
// directly declared names with the scopes the manifest gives them, and the
// module's own packages (a local crate, an editable root), which are the
// subject of the inventory, not dependencies in it.
type directInfo struct {
	names map[string][]string
	roots map[string]struct{}
}

func newDirectInfo() directInfo {
	return directInfo{names: make(map[string][]string), roots: make(map[string]struct{})}
}

func (d directInfo) add(name string, scopes ...string) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return
	}
	existing := d.names[name]
	for _, scope := range scopes {
		if scope != "" && !contains(existing, scope) {
			existing = append(existing, scope)
		}
	}
	d.names[name] = existing
}

func annotateRelationships(root string, components []Component) []Component {
	infoByModule := make(map[string]directInfo)
	modules := make(map[string]struct{})
	for _, component := range components {
		modules[component.Module] = struct{}{}
	}
	for module := range modules {
		dir := filepath.Join(root, filepath.FromSlash(module))
		if info, ok := directNamesFor(dir); ok {
			infoByModule[module] = info
		}
	}
	out := make([]Component, 0, len(components))
	for _, component := range components {
		info, resolved := infoByModule[component.Module]
		key := strings.ToLower(component.Name)
		if resolved {
			if _, isRoot := info.roots[key]; isRoot {
				continue
			}
		}
		switch {
		case component.Ecosystem == "go" && component.Name == "stdlib":
			// The toolchain the go directive names: a direct dependency of
			// every Go module, and one that carries advisories.
			component.Relationship = RelationshipDirect
		case component.Resolution == ResolutionDeclared:
			// A manifest lists direct dependencies by definition.
			component.Relationship = RelationshipDirect
		case !resolved:
			// No rule for this module: unknown stays unknown.
		default:
			if scopes, ok := info.names[key]; ok {
				component.Relationship = RelationshipDirect
				for _, scope := range scopes {
					if !contains(component.Scopes, scope) {
						component.Scopes = append(component.Scopes, scope)
					}
				}
				sort.Strings(component.Scopes)
			} else {
				component.Relationship = RelationshipIndirect
			}
		}
		out = append(out, component)
	}
	return out
}

// directNamesFor returns what the module declares directly, from the first
// recognised source in priority order, and whether any applied.
func directNamesFor(dir string) (directInfo, bool) {
	rules := []func(string) (directInfo, bool){
		goModDirect,
		packageLockDirect,
		pnpmLockDirect,
		packageJSONDirect, // yarn.lock and bun.lock have no root block; the manifest gives the roots
		uvLockDirect,
		cargoLockDirect,
		pyprojectDirect, // poetry.lock, pdm.lock, pylock.toml
		pipfileDirect,
		requirementsDirect,
	}
	for _, rule := range rules {
		if info, ok := rule(dir); ok {
			return info, true
		}
	}
	return directInfo{}, false
}

func readIfExists(dir, name string) ([]byte, bool) {
	data, err := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- dir is the extraction root the caller owns
	if err != nil {
		return nil, false
	}
	return data, true
}

// goModDirect: `// indirect` marks the rest.
func goModDirect(dir string) (directInfo, bool) {
	data, ok := readIfExists(dir, "go.mod")
	if !ok {
		return directInfo{}, false
	}
	parsed, err := modfile.ParseLax("go.mod", data, nil)
	if err != nil {
		return directInfo{}, false
	}
	info := newDirectInfo()
	for _, require := range parsed.Require {
		if !require.Indirect {
			info.add(require.Mod.Path)
		}
	}
	return info, true
}

// packageLockDirect: lockfile v2/v3 root entry lists the direct set; v1
// has no root block, so the manifest rule takes over.
func packageLockDirect(dir string) (directInfo, bool) {
	data, ok := readIfExists(dir, "package-lock.json")
	if !ok {
		data, ok = readIfExists(dir, "npm-shrinkwrap.json")
	}
	if !ok {
		return directInfo{}, false
	}
	var lock struct {
		Packages map[string]struct {
			Dependencies         map[string]string `json:"dependencies"`
			DevDependencies      map[string]string `json:"devDependencies"`
			OptionalDependencies map[string]string `json:"optionalDependencies"`
			PeerDependencies     map[string]string `json:"peerDependencies"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return directInfo{}, false
	}
	root, ok := lock.Packages[""]
	if !ok {
		return packageJSONDirect(dir)
	}
	info := newDirectInfo()
	addNamed(info, root.Dependencies, "")
	addNamed(info, root.DevDependencies, "dev")
	addNamed(info, root.OptionalDependencies, "optional")
	addNamed(info, root.PeerDependencies, "peer")
	return info, true
}

func addNamed[V any](info directInfo, set map[string]V, scope string) {
	for name := range set {
		info.add(name, scope)
	}
}

// pnpmLockDirect: importers (v6+) or the top-level blocks (v5).
func pnpmLockDirect(dir string) (directInfo, bool) {
	data, ok := readIfExists(dir, "pnpm-lock.yaml")
	if !ok {
		return directInfo{}, false
	}
	var lock struct {
		Importers map[string]struct {
			Dependencies         map[string]any `yaml:"dependencies"`
			DevDependencies      map[string]any `yaml:"devDependencies"`
			OptionalDependencies map[string]any `yaml:"optionalDependencies"`
		} `yaml:"importers"`
		Dependencies    map[string]any `yaml:"dependencies"`
		DevDependencies map[string]any `yaml:"devDependencies"`
	}
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return directInfo{}, false
	}
	info := newDirectInfo()
	if len(lock.Importers) > 0 {
		for _, importer := range lock.Importers {
			addNamed(info, importer.Dependencies, "")
			addNamed(info, importer.DevDependencies, "dev")
			addNamed(info, importer.OptionalDependencies, "optional")
		}
		return info, true
	}
	addNamed(info, lock.Dependencies, "")
	addNamed(info, lock.DevDependencies, "dev")
	return info, true
}

func packageJSONDirect(dir string) (directInfo, bool) {
	data, ok := readIfExists(dir, "package.json")
	if !ok {
		return directInfo{}, false
	}
	var manifest struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return directInfo{}, false
	}
	info := newDirectInfo()
	addNamed(info, manifest.Dependencies, "")
	addNamed(info, manifest.DevDependencies, "dev")
	addNamed(info, manifest.OptionalDependencies, "optional")
	addNamed(info, manifest.PeerDependencies, "peer")
	return info, true
}

// uvLockDirect: the workspace members are the packages with a local
// source; their dependency lists are the direct set.
func uvLockDirect(dir string) (directInfo, bool) {
	data, ok := readIfExists(dir, "uv.lock")
	if !ok {
		return directInfo{}, false
	}
	var lock struct {
		Package []struct {
			Name   string `toml:"name"`
			Source struct {
				Editable string `toml:"editable"`
				Virtual  string `toml:"virtual"`
			} `toml:"source"`
			Dependencies []struct {
				Name string `toml:"name"`
			} `toml:"dependencies"`
			DevDependencies map[string][]struct {
				Name string `toml:"name"`
			} `toml:"dev-dependencies"`
		} `toml:"package"`
	}
	if err := toml.Unmarshal(data, &lock); err != nil {
		return directInfo{}, false
	}
	info := newDirectInfo()
	found := false
	for _, pkg := range lock.Package {
		if pkg.Source.Editable == "" && pkg.Source.Virtual == "" {
			continue
		}
		found = true
		info.roots[normalizePython(pkg.Name)] = struct{}{}
		for _, dep := range pkg.Dependencies {
			info.add(normalizePython(dep.Name))
		}
		for group, deps := range pkg.DevDependencies {
			for _, dep := range deps {
				info.add(normalizePython(dep.Name), group)
			}
		}
	}
	if !found {
		return pyprojectDirect(dir)
	}
	return info, true
}

// cargoLockDirect: the local crates are the packages without a source;
// their dependency lists are the direct set.
func cargoLockDirect(dir string) (directInfo, bool) {
	data, ok := readIfExists(dir, "Cargo.lock")
	if !ok {
		return directInfo{}, false
	}
	var lock struct {
		Package []struct {
			Name         string   `toml:"name"`
			Source       string   `toml:"source"`
			Dependencies []string `toml:"dependencies"`
		} `toml:"package"`
	}
	if err := toml.Unmarshal(data, &lock); err != nil {
		return directInfo{}, false
	}
	info := newDirectInfo()
	found := false
	for _, pkg := range lock.Package {
		if pkg.Source != "" {
			continue
		}
		found = true
		info.roots[strings.ToLower(pkg.Name)] = struct{}{}
		for _, dep := range pkg.Dependencies {
			// "name", or "name version", or "name version (source)".
			name, _, _ := strings.Cut(dep, " ")
			info.add(name)
		}
	}
	if found {
		// Cargo.toml says which direct entries are dev or build only.
		if data, ok := readIfExists(dir, "Cargo.toml"); ok {
			var manifest struct {
				DevDependencies   map[string]any `toml:"dev-dependencies"`
				BuildDependencies map[string]any `toml:"build-dependencies"`
			}
			if toml.Unmarshal(data, &manifest) == nil {
				addNamed(info, manifest.DevDependencies, "dev")
				addNamed(info, manifest.BuildDependencies, "build")
			}
		}
	}
	return info, found
}

var requirementNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*`)

// pyprojectDirect: PEP 621 and Poetry declarations; the root of
// poetry.lock, pdm.lock and pylock.toml.
func pyprojectDirect(dir string) (directInfo, bool) {
	data, ok := readIfExists(dir, "pyproject.toml")
	if !ok {
		return directInfo{}, false
	}
	var manifest struct {
		Project struct {
			Dependencies         []string            `toml:"dependencies"`
			OptionalDependencies map[string][]string `toml:"optional-dependencies"`
		} `toml:"project"`
		DependencyGroups map[string][]any `toml:"dependency-groups"`
		Tool             struct {
			Poetry struct {
				Dependencies    map[string]any `toml:"dependencies"`
				DevDependencies map[string]any `toml:"dev-dependencies"`
				Group           map[string]struct {
					Dependencies map[string]any `toml:"dependencies"`
				} `toml:"group"`
			} `toml:"poetry"`
		} `toml:"tool"`
	}
	if err := toml.Unmarshal(data, &manifest); err != nil {
		return directInfo{}, false
	}
	info := newDirectInfo()
	addSpec := func(spec, scope string) {
		if match := requirementNamePattern.FindString(strings.TrimSpace(spec)); match != "" {
			info.add(normalizePython(match), scope)
		}
	}
	for _, spec := range manifest.Project.Dependencies {
		addSpec(spec, "")
	}
	for extra, specs := range manifest.Project.OptionalDependencies {
		for _, spec := range specs {
			addSpec(spec, extra)
		}
	}
	for group, entries := range manifest.DependencyGroups {
		for _, entry := range entries {
			if spec, ok := entry.(string); ok {
				addSpec(spec, group)
			}
		}
	}
	for name := range manifest.Tool.Poetry.Dependencies {
		if !strings.EqualFold(name, "python") {
			info.add(normalizePython(name))
		}
	}
	for name := range manifest.Tool.Poetry.DevDependencies {
		info.add(normalizePython(name), "dev")
	}
	for group, entries := range manifest.Tool.Poetry.Group {
		for name := range entries.Dependencies {
			info.add(normalizePython(name), group)
		}
	}
	return info, len(info.names) > 0
}

func pipfileDirect(dir string) (directInfo, bool) {
	data, ok := readIfExists(dir, "Pipfile")
	if !ok {
		return directInfo{}, false
	}
	var manifest struct {
		Packages    map[string]any `toml:"packages"`
		DevPackages map[string]any `toml:"dev-packages"`
	}
	if err := toml.Unmarshal(data, &manifest); err != nil {
		return directInfo{}, false
	}
	info := newDirectInfo()
	for name := range manifest.Packages {
		info.add(normalizePython(name))
	}
	for name := range manifest.DevPackages {
		info.add(normalizePython(name), "dev")
	}
	return info, true
}

// requirementsDirect: pip-compile output says "# via -r requirements.in"
// for direct entries and "# via <package>" for the rest. Without those
// comments the file has no graph, so the module stays unknown.
func requirementsDirect(dir string) (directInfo, bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return directInfo{}, false
	}
	info := newDirectInfo()
	sawVia := false
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "requirements") || !strings.HasSuffix(entry.Name(), ".txt") {
			continue
		}
		file, err := os.Open(filepath.Join(dir, entry.Name())) // #nosec G304 -- inside the extraction root
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		current := ""
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			switch {
			case line == "" || strings.HasPrefix(line, "-"):
				current = ""
			case strings.HasPrefix(line, "#"):
				comment := strings.TrimSpace(strings.TrimPrefix(line, "#"))
				if strings.HasPrefix(comment, "via") {
					sawVia = true
					target := strings.TrimSpace(strings.TrimPrefix(comment, "via"))
					if current != "" && (strings.HasPrefix(target, "-r ") || strings.HasPrefix(target, "-c ") || strings.HasSuffix(target, ".in") || strings.HasSuffix(target, "pyproject.toml")) {
						info.add(current)
					}
				}
			default:
				if match := requirementNamePattern.FindString(line); match != "" {
					current = normalizePython(match)
					if strings.Contains(line, "# via -r") || strings.Contains(line, "# via -c") {
						sawVia = true
						info.add(current)
					}
				}
			}
		}
		_ = file.Close()
	}
	if !sawVia {
		return directInfo{}, false
	}
	return info, true
}

// normalizePython applies PEP 503 so names compare the way the index keys
// them.
func normalizePython(name string) string {
	var b strings.Builder
	pendingDash := false
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		if r == '-' || r == '_' || r == '.' {
			pendingDash = true
			continue
		}
		if pendingDash && b.Len() > 0 {
			b.WriteByte('-')
		}
		pendingDash = false
		b.WriteRune(r)
	}
	return b.String()
}
