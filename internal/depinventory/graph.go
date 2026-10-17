package depinventory

import (
	"encoding/json"
	"path"
	"regexp"
	"sort"
	"strings"

	toml "github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

// Parent edges (ADR-045 §5, "where is it used"). The engine lists what a
// lockfile contains; the lockfile also says which package pulled in which,
// so an indirect dependency can be traced to the direct one that needs it.
// Each format is read for that one fact; anything the lockfile does not
// state is not invented.

// Edge says From depends on To, both as purls.
type Edge struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// extractEdges reads every module's lockfile for parent edges and keeps
// those whose ends are components of the inventory.
func extractEdges(root string, components []Component) []Edge {
	byModule := map[string][]Component{}
	for _, c := range components {
		byModule[c.Module] = append(byModule[c.Module], c)
	}
	var out []Edge
	seen := map[Edge]bool{}
	for module, list := range byModule {
		dir := root
		if module != "." && module != "" {
			dir = path.Join(root, module)
		}
		index := newPurlIndex(list)
		for _, edge := range moduleEdges(dir, index) {
			if !seen[edge] {
				seen[edge] = true
				out = append(out, edge)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].From != out[j].From {
			return out[i].From < out[j].From
		}
		return out[i].To < out[j].To
	})
	return out
}

// purlIndex resolves (ecosystem, name[, version]) to a component purl.
type purlIndex struct {
	byNameVersion map[string]string
	byName        map[string][]string
}

func newPurlIndex(components []Component) purlIndex {
	index := purlIndex{byNameVersion: map[string]string{}, byName: map[string][]string{}}
	for _, c := range components {
		if c.Version == "" {
			continue
		}
		key := c.Ecosystem + "|" + strings.ToLower(c.Name)
		index.byNameVersion[key+"|"+c.Version] = c.Purl
		index.byName[key] = append(index.byName[key], c.Purl)
	}
	return index
}

// resolve returns the purl of a name at a version, or the only purl of the
// name when no version is given and exactly one exists.
func (i purlIndex) resolve(ecosystem, name, version string) (string, bool) {
	key := ecosystem + "|" + strings.ToLower(name)
	if version != "" {
		purl, ok := i.byNameVersion[key+"|"+version]
		return purl, ok
	}
	if purls := i.byName[key]; len(purls) == 1 {
		return purls[0], true
	}
	return "", false
}

func moduleEdges(dir string, index purlIndex) []Edge {
	var out []Edge
	out = append(out, packageLockEdges(dir, index)...)
	out = append(out, pnpmLockEdges(dir, index)...)
	out = append(out, yarnLockEdges(dir, index)...)
	out = append(out, cargoLockEdges(dir, index)...)
	out = append(out, uvLockEdges(dir, index)...)
	out = append(out, poetryLockEdges(dir, index)...)
	return out
}

// packageLockEdges: lockfile v2/v3 "packages" map. A dependency resolves to
// the nearest node_modules entry up the path, as npm does.
func packageLockEdges(dir string, index purlIndex) []Edge {
	data, ok := readIfExists(dir, "package-lock.json")
	if !ok {
		data, ok = readIfExists(dir, "npm-shrinkwrap.json")
	}
	if !ok {
		return nil
	}
	var lock struct {
		Packages map[string]struct {
			Version              string            `json:"version"`
			Dependencies         map[string]string `json:"dependencies"`
			OptionalDependencies map[string]string `json:"optionalDependencies"`
			PeerDependencies     map[string]string `json:"peerDependencies"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &lock); err != nil || len(lock.Packages) == 0 {
		return nil
	}
	nameOf := func(entry string) string {
		idx := strings.LastIndex(entry, "node_modules/")
		if idx < 0 {
			return ""
		}
		return entry[idx+len("node_modules/"):]
	}
	resolveChild := func(from, child string) (string, bool) {
		// Walk up: a/node_modules/b/node_modules/c → a/node_modules/b/node_modules/child, a/node_modules/child, node_modules/child.
		base := from
		for {
			candidate := strings.TrimPrefix(base+"/node_modules/"+child, "/")
			if pkg, ok := lock.Packages[candidate]; ok {
				return index.resolve("npm", child, pkg.Version)
			}
			idx := strings.LastIndex(base, "/node_modules/")
			if idx < 0 {
				if base == "" {
					return "", false
				}
				base = ""
				continue
			}
			base = base[:idx]
		}
	}
	var out []Edge
	for entry, pkg := range lock.Packages {
		name := nameOf(entry)
		if name == "" {
			continue
		}
		from, ok := index.resolve("npm", name, pkg.Version)
		if !ok {
			continue
		}
		for _, set := range []map[string]string{pkg.Dependencies, pkg.OptionalDependencies, pkg.PeerDependencies} {
			for child := range set {
				if to, ok := resolveChild(entry, child); ok && to != from {
					out = append(out, Edge{From: from, To: to})
				}
			}
		}
	}
	return out
}

var pnpmKeyPattern = regexp.MustCompile(`^/?((?:@[^/]+/)?[^@/]+)@([^(]+)`)

// pnpmLockEdges: v9 "snapshots" (or v6 "packages") entries "name@version"
// with a dependencies map of name → version.
func pnpmLockEdges(dir string, index purlIndex) []Edge {
	data, ok := readIfExists(dir, "pnpm-lock.yaml")
	if !ok {
		return nil
	}
	var lock struct {
		Snapshots map[string]struct {
			Dependencies         map[string]string `yaml:"dependencies"`
			OptionalDependencies map[string]string `yaml:"optionalDependencies"`
		} `yaml:"snapshots"`
		Packages map[string]struct {
			Dependencies         map[string]string `yaml:"dependencies"`
			OptionalDependencies map[string]string `yaml:"optionalDependencies"`
		} `yaml:"packages"`
	}
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return nil
	}
	entries := map[string]map[string]string{}
	for key, snapshot := range lock.Snapshots {
		merged := map[string]string{}
		for k, v := range snapshot.Dependencies {
			merged[k] = v
		}
		for k, v := range snapshot.OptionalDependencies {
			merged[k] = v
		}
		entries[key] = merged
	}
	if len(entries) == 0 {
		for key, pkg := range lock.Packages {
			merged := map[string]string{}
			for k, v := range pkg.Dependencies {
				merged[k] = v
			}
			for k, v := range pkg.OptionalDependencies {
				merged[k] = v
			}
			entries[key] = merged
		}
	}
	var out []Edge
	for key, deps := range entries {
		m := pnpmKeyPattern.FindStringSubmatch(key)
		if m == nil {
			continue
		}
		from, ok := index.resolve("npm", m[1], m[2])
		if !ok {
			continue
		}
		for child, version := range deps {
			version, _, _ = strings.Cut(version, "(")
			if to, ok := index.resolve("npm", child, version); ok && to != from {
				out = append(out, Edge{From: from, To: to})
			}
		}
	}
	return out
}

var yarnEntryPattern = regexp.MustCompile(`^"?((?:@[^/@]+/)?[^@"]+)@`)

// yarnLockEdges: v1 entries "name@range[, name@range]:" with a version and
// a dependencies block of name → range; a child resolves through the entry
// whose key carries that name@range.
func yarnLockEdges(dir string, index purlIndex) []Edge {
	data, ok := readIfExists(dir, "yarn.lock")
	if !ok || !strings.Contains(string(data), "yarn lockfile v1") {
		return nil
	}
	type entry struct {
		version string
		deps    map[string]string
	}
	entries := map[string]*entry{}   // "name@range" → entry
	byVersion := map[string]*entry{} // name@version → entry (for v1 keys)
	var current *entry
	inDeps := false
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimRight(line, "\r")
		switch {
		case trimmed == "" || strings.HasPrefix(trimmed, "#"):
			continue
		case !strings.HasPrefix(trimmed, " ") && strings.HasSuffix(trimmed, ":"):
			current = &entry{deps: map[string]string{}}
			inDeps = false
			for _, key := range strings.Split(strings.TrimSuffix(trimmed, ":"), ",") {
				entries[strings.Trim(strings.TrimSpace(key), `"`)] = current
			}
		case current == nil:
			continue
		case strings.HasPrefix(trimmed, "  version "):
			current.version = strings.Trim(strings.TrimSpace(strings.TrimPrefix(trimmed, "  version")), `"`)
			for key, e := range entries {
				if e == current {
					if m := yarnEntryPattern.FindStringSubmatch(key); m != nil {
						byVersion[m[1]+"@"+current.version] = current
					}
				}
			}
		case trimmed == "  dependencies:" || trimmed == "  optionalDependencies:":
			inDeps = true
		case strings.HasPrefix(trimmed, "    ") && inDeps:
			fields := strings.Fields(trimmed)
			if len(fields) >= 2 {
				current.deps[strings.Trim(fields[0], `"`)] = strings.Trim(strings.Join(fields[1:], " "), `"`)
			}
		case strings.HasPrefix(trimmed, "  "):
			inDeps = false
		}
	}
	var out []Edge
	seenEntry := map[*entry]bool{}
	for key, e := range entries {
		if seenEntry[e] || e.version == "" {
			continue
		}
		seenEntry[e] = true
		m := yarnEntryPattern.FindStringSubmatch(key)
		if m == nil {
			continue
		}
		from, ok := index.resolve("npm", m[1], e.version)
		if !ok {
			continue
		}
		for child, rng := range e.deps {
			target := entries[child+"@"+rng]
			if target == nil || target.version == "" {
				continue
			}
			if to, ok := index.resolve("npm", child, target.version); ok && to != from {
				out = append(out, Edge{From: from, To: to})
			}
		}
	}
	return out
}

// cargoLockEdges: each package's dependency list, "name" or "name version".
func cargoLockEdges(dir string, index purlIndex) []Edge {
	data, ok := readIfExists(dir, "Cargo.lock")
	if !ok {
		return nil
	}
	var lock struct {
		Package []struct {
			Name         string   `toml:"name"`
			Version      string   `toml:"version"`
			Source       string   `toml:"source"`
			Dependencies []string `toml:"dependencies"`
		} `toml:"package"`
	}
	if err := toml.Unmarshal(data, &lock); err != nil {
		return nil
	}
	var out []Edge
	for _, pkg := range lock.Package {
		if pkg.Source == "" {
			continue // the local crate: its edges are the module's direct set
		}
		from, ok := index.resolve("cargo", pkg.Name, pkg.Version)
		if !ok {
			continue
		}
		for _, dep := range pkg.Dependencies {
			name, rest, _ := strings.Cut(dep, " ")
			version, _, _ := strings.Cut(rest, " ")
			if to, ok := index.resolve("cargo", name, version); ok && to != from {
				out = append(out, Edge{From: from, To: to})
			}
		}
	}
	return out
}

// uvLockEdges: each registry package's dependencies list of names; uv locks
// one version per name per environment, so the name resolves.
func uvLockEdges(dir string, index purlIndex) []Edge {
	data, ok := readIfExists(dir, "uv.lock")
	if !ok {
		return nil
	}
	var lock struct {
		Package []struct {
			Name    string `toml:"name"`
			Version string `toml:"version"`
			Source  struct {
				Editable string `toml:"editable"`
				Virtual  string `toml:"virtual"`
			} `toml:"source"`
			Dependencies []struct {
				Name string `toml:"name"`
			} `toml:"dependencies"`
		} `toml:"package"`
	}
	if err := toml.Unmarshal(data, &lock); err != nil {
		return nil
	}
	var out []Edge
	for _, pkg := range lock.Package {
		if pkg.Source.Editable != "" || pkg.Source.Virtual != "" {
			continue
		}
		from, ok := index.resolve("pypi", normalizePython(pkg.Name), pkg.Version)
		if !ok {
			continue
		}
		for _, dep := range pkg.Dependencies {
			if to, ok := index.resolve("pypi", normalizePython(dep.Name), ""); ok && to != from {
				out = append(out, Edge{From: from, To: to})
			}
		}
	}
	return out
}

// poetryLockEdges: [package.dependencies] of each package, names only.
func poetryLockEdges(dir string, index purlIndex) []Edge {
	data, ok := readIfExists(dir, "poetry.lock")
	if !ok {
		return nil
	}
	var lock struct {
		Package []struct {
			Name         string         `toml:"name"`
			Version      string         `toml:"version"`
			Dependencies map[string]any `toml:"dependencies"`
		} `toml:"package"`
	}
	if err := toml.Unmarshal(data, &lock); err != nil {
		return nil
	}
	var out []Edge
	for _, pkg := range lock.Package {
		from, ok := index.resolve("pypi", normalizePython(pkg.Name), pkg.Version)
		if !ok {
			continue
		}
		for dep := range pkg.Dependencies {
			if to, ok := index.resolve("pypi", normalizePython(dep), ""); ok && to != from {
				out = append(out, Edge{From: from, To: to})
			}
		}
	}
	return out
}
