package depinventory

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Resolve mode (ADR-045 §4.2): for ecosystems without a recorded graph
// (Maven, unlocked Gradle), the repository's own build tool resolves the
// full set. It runs in the repository's CI, never on the server.

// CommandRunner runs a program in a directory; never a shell.
type CommandRunner func(ctx context.Context, dir, name string, args ...string) ([]byte, int, error)

// Resolve runs the named build tool and returns the resolved components.
func Resolve(ctx context.Context, root, tool string, run CommandRunner) ([]Component, error) {
	if run == nil {
		return nil, errors.New("no command runner")
	}
	switch strings.ToLower(strings.TrimSpace(tool)) {
	case "maven":
		return resolveMaven(ctx, root, run)
	case "gradle":
		return resolveGradle(ctx, root, run)
	}
	return nil, fmt.Errorf("unsupported resolve tool %q", tool)
}

func resolveMaven(ctx context.Context, root string, run CommandRunner) ([]Component, error) {
	outDir, err := os.MkdirTemp("", "hibou-deps-maven-*")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(outDir) }()
	outFile := filepath.Join(outDir, "dependencies.txt")
	binary := "mvn"
	if _, err := os.Stat(filepath.Join(root, "mvnw")); err == nil {
		binary = filepath.Join(root, "mvnw")
	}
	output, code, err := run(ctx, root, binary, "-q", "-B", "-DoutputFile="+outFile, "-DappendOutput=true", "-DincludeScope=runtime", "dependency:list")
	if err != nil && code < 0 {
		return nil, err
	}
	if code != 0 {
		return nil, fmt.Errorf("%s exited %d: %s", binary, code, lastLines(string(output), 5))
	}
	data, err := os.ReadFile(outFile) // #nosec G304 -- a temp file this process created
	if err != nil {
		return nil, fmt.Errorf("read dependency list: %w", err)
	}
	return parseMavenList(string(data), "pom.xml"), nil
}

func resolveGradle(ctx context.Context, root string, run CommandRunner) ([]Component, error) {
	binary := "gradle"
	if _, err := os.Stat(filepath.Join(root, "gradlew")); err == nil {
		binary = filepath.Join(root, "gradlew")
	}
	output, code, err := run(ctx, root, binary, "-q", "--console=plain", "dependencies", "--configuration", "runtimeClasspath")
	if err != nil && code < 0 {
		return nil, err
	}
	if code != 0 {
		return nil, fmt.Errorf("%s exited %d: %s", binary, code, lastLines(string(output), 5))
	}
	return parseGradleTree(string(output), "build.gradle"), nil
}

// ReadGraphExport reads a graph export produced by the build (T6): Maven
// dependency:list or dependency:tree output, Gradle dependencies output,
// or pip freeze. The format is detected from the content.
func ReadGraphExport(path string) ([]Component, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- a file the CI step names on purpose
	if err != nil {
		return nil, err
	}
	content := string(data)
	switch {
	case gradleTreeLine.MatchString(content):
		return parseGradleTree(content, filepath.Base(path)), nil
	case mavenTreeLine.MatchString(content) || mavenListLine.MatchString(content):
		return parseMavenList(content, filepath.Base(path)), nil
	case pipFreezeLine.MatchString(content):
		return parsePipFreeze(content, filepath.Base(path)), nil
	}
	return nil, errors.New("unrecognised graph export: want Maven dependency:list or dependency:tree, Gradle dependencies, or pip freeze output")
}

var (
	// "   org.slf4j:slf4j-api:jar:2.0.9:compile" (list) and
	// "[INFO] +- org.slf4j:slf4j-api:jar:2.0.9:compile" (tree).
	mavenListLine = regexp.MustCompile(`(?m)^\s*([A-Za-z0-9_.\-]+):([A-Za-z0-9_.\-]+):[a-z\-]+(?::[A-Za-z0-9_.\-]+)?:([A-Za-z0-9_.\-]+):(compile|runtime|provided|test|system)\b`)
	mavenTreeLine = regexp.MustCompile(`(?m)^(?:\[INFO\]\s*)?((?:[|\s]*)(?:\+-|\\-))\s*([A-Za-z0-9_.\-]+):([A-Za-z0-9_.\-]+):[a-z\-]+(?::[A-Za-z0-9_.\-]+)?:([A-Za-z0-9_.\-]+):(compile|runtime|provided|test|system)`)
	// "+--- org.x:y:1.0" / "|    \--- org.x:z:2.0 -> 2.1 (*)".
	gradleTreeLine = regexp.MustCompile(`(?m)^([|\s]*)(\+---|\\---)\s+([A-Za-z0-9_.\-]+):([A-Za-z0-9_.\-]+)(?::([A-Za-z0-9_.\-]+))?(?:\s+->\s+([A-Za-z0-9_.\-]+))?`)
	pipFreezeLine  = regexp.MustCompile(`(?m)^([A-Za-z0-9_.\-]+)==([A-Za-z0-9_.!+\-]+)\s*$`)
)

func parseMavenList(content, path string) []Component {
	seen := make(map[string]Component)
	for _, line := range strings.Split(content, "\n") {
		relationship := RelationshipUnknown
		var group, artifact, version, scope string
		if m := mavenTreeLine.FindStringSubmatch(line); m != nil {
			group, artifact, version, scope = m[2], m[3], m[4], m[5]
			if !strings.ContainsAny(m[1], "|") && !strings.HasPrefix(strings.TrimLeft(m[1], " "), " ") && len(strings.TrimRight(m[1], "+\\-")) == 0 {
				relationship = RelationshipDirect
			} else {
				relationship = RelationshipIndirect
			}
		} else if m := mavenListLine.FindStringSubmatch(line); m != nil {
			group, artifact, version, scope = m[1], m[2], m[3], m[4]
		} else {
			continue
		}
		if scope == "test" || scope == "provided" || scope == "system" {
			// Not at runtime; the declared pom already carries test scopes.
			continue
		}
		purl := "pkg:maven/" + group + "/" + artifact + "@" + version
		if _, dup := seen[purl]; dup {
			continue
		}
		seen[purl] = Component{
			Purl:         purl,
			Name:         group + ":" + artifact,
			Version:      version,
			Ecosystem:    "maven",
			Relationship: relationship,
			Resolution:   ResolutionRecorded,
			Path:         path,
			Module:       moduleOf(path),
			Extractor:    "hibou/resolve:maven",
			Scopes:       []string{scope},
		}
	}
	return sortedComponents(seen)
}

func parseGradleTree(content, path string) []Component {
	seen := make(map[string]Component)
	for _, line := range strings.Split(content, "\n") {
		m := gradleTreeLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		prefix, group, artifact, version, resolved := m[1], m[3], m[4], m[5], m[6]
		if resolved != "" {
			version = resolved
		}
		if version == "" || strings.Contains(line, "(n)") {
			continue // a constraint or an unresolved declaration
		}
		relationship := RelationshipIndirect
		if strings.TrimSpace(prefix) == "" {
			relationship = RelationshipDirect
		}
		purl := "pkg:maven/" + group + "/" + artifact + "@" + version
		if existing, dup := seen[purl]; dup {
			if existing.Relationship == RelationshipIndirect && relationship == RelationshipDirect {
				existing.Relationship = relationship
				seen[purl] = existing
			}
			continue
		}
		seen[purl] = Component{
			Purl:         purl,
			Name:         group + ":" + artifact,
			Version:      version,
			Ecosystem:    "maven",
			Relationship: relationship,
			Resolution:   ResolutionRecorded,
			Path:         path,
			Module:       moduleOf(path),
			Extractor:    "hibou/resolve:gradle",
		}
	}
	return sortedComponents(seen)
}

func parsePipFreeze(content, path string) []Component {
	seen := make(map[string]Component)
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		m := pipFreezeLine.FindStringSubmatch(scanner.Text())
		if m == nil {
			continue
		}
		name := normalizePyPIName(m[1])
		purl := "pkg:pypi/" + name + "@" + m[2]
		if _, dup := seen[purl]; dup {
			continue
		}
		seen[purl] = Component{
			Purl:         purl,
			Name:         name,
			Version:      m[2],
			Ecosystem:    "pypi",
			Relationship: RelationshipUnknown,
			Resolution:   ResolutionRecorded,
			Path:         path,
			Module:       moduleOf(path),
			Extractor:    "hibou/resolve:pip",
		}
	}
	return sortedComponents(seen)
}

// normalizePyPIName applies PEP 503: lower case, runs of -_. collapse to -.
func normalizePyPIName(name string) string {
	var b strings.Builder
	prevSep := false
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		if r == '-' || r == '_' || r == '.' {
			if !prevSep {
				b.WriteRune('-')
			}
			prevSep = true
			continue
		}
		prevSep = false
		b.WriteRune(r)
	}
	return b.String()
}

func sortedComponents(seen map[string]Component) []Component {
	out := make([]Component, 0, len(seen))
	for _, c := range seen {
		out = append(out, c)
	}
	sortComponents(out)
	return out
}

// MergeResolved adds resolved components to an extraction (ADR-045 §5.3):
// additive only. A version the manifest declared stays as declared; a
// resolved entry for the same package at the same version upgrades the
// resolution to recorded and keeps the stronger relationship; an
// unresolved range is replaced by what the build resolved.
func MergeResolved(components, resolved []Component) []Component {
	if len(resolved) == 0 {
		return components
	}
	byIdentity := make(map[string]int, len(components))
	for i, c := range components {
		byIdentity[c.Ecosystem+"|"+strings.ToLower(c.Name)] = i
	}
	out := append([]Component{}, components...)
	for _, r := range resolved {
		key := r.Ecosystem + "|" + strings.ToLower(r.Name)
		i, known := byIdentity[key]
		if !known {
			out = append(out, r)
			continue
		}
		existing := &out[i]
		switch {
		case existing.Resolution == ResolutionUnresolved:
			existing.Version, existing.Purl, existing.Constraint, existing.Resolution = r.Version, r.Purl, "", ResolutionRecorded
			existing.Extractor = r.Extractor
		case existing.Version == r.Version:
			existing.Resolution = ResolutionRecorded
			if existing.Relationship == RelationshipUnknown {
				existing.Relationship = r.Relationship
			}
		default:
			// The build resolved another version than the manifest literal
			// (a BOM or a parent decided): both are kept, both sources are
			// visible, the discrepancy shows (ADR-045 §5.3).
			out = append(out, r)
		}
	}
	return out
}

// FilterModules keeps the components of the given module roots.
func FilterModules(components []Component, roots []string) []Component {
	out := components[:0:0]
	for _, c := range components {
		for _, root := range roots {
			root = strings.TrimSuffix(strings.TrimPrefix(root, "./"), "/")
			if root == "." || root == "" || c.Module == root || strings.HasPrefix(c.Module, root+"/") {
				out = append(out, c)
				break
			}
		}
	}
	return out
}

// RebuildModules recomputes the module list after a merge.
func RebuildModules(components []Component) []Module {
	sortComponents(components)
	return buildModules(components)
}

func lastLines(output string, n int) string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}
