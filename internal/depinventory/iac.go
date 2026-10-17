package depinventory

import (
	"bufio"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Infrastructure-as-code and CI dependencies (ADR-045 §9): versioned
// third-party code referenced by Terraform, Helm, container files, CI
// workflows and Ansible. Each source is its own ecosystem, so the existing
// ecosystem filter isolates them, and the built-in not-shipped defaults
// keep them out of client deliverables unless a repository says otherwise.
// Advisory coverage is thin here; the value is inventory, pinning hygiene
// and the link to container images, and the extractor says so through the
// resolution level: a SHA pin or a lockfile is recorded, a tag is declared.

const (
	EcosystemTerraform     = "terraform"
	EcosystemHelm          = "helm"
	EcosystemGitHubActions = "githubactions"
	EcosystemGitLabCI      = "gitlabci"
	EcosystemOCI           = "oci"
	EcosystemAnsible       = "ansible"
)

// iacFile reports whether a repository path is an IaC or CI file the
// inventory reads.
func iacFile(repoPath string) (kind string, ok bool) {
	base := path.Base(repoPath)
	dir := path.Dir(repoPath)
	switch {
	case base == ".terraform.lock.hcl":
		return "terraform-lock", true
	case base == "Chart.lock":
		return "helm-lock", true
	case base == "Chart.yaml" || base == "Chart.yml":
		return "helm-chart", true
	case base == ".gitlab-ci.yml":
		return "gitlab-ci", true
	case (strings.HasSuffix(dir, ".github/workflows") || dir == ".github/workflows") && (strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml")):
		return "github-workflow", true
	case base == "action.yml" || base == "action.yaml":
		return "github-workflow", true
	case base == "requirements.yml" || base == "requirements.yaml":
		return "ansible", true
	case base == "Dockerfile" || strings.HasPrefix(base, "Dockerfile.") || strings.HasSuffix(base, ".Dockerfile") || base == "Containerfile":
		return "dockerfile", true
	case base == "docker-compose.yml" || base == "docker-compose.yaml" || base == "compose.yml" || base == "compose.yaml":
		return "compose", true
	}
	return "", false
}

// IsIaCPath is the sparse-checkout selector for IaC and CI files.
func IsIaCPath(repoPath string) bool {
	repoPath = strings.TrimPrefix(strings.TrimSpace(repoPath), "./")
	if repoPath == "" {
		return false
	}
	for _, segment := range strings.Split(path.Dir(repoPath), "/") {
		if segment != "" && segment != ".github" && segment != ".gitlab" && skipDirPattern.MatchString(segment) {
			return false
		}
	}
	_, ok := iacFile(repoPath)
	return ok
}

// extractIaC walks the root for IaC and CI files and parses them.
func extractIaC(root string, exclude []string, warn func(string)) []Component {
	var out []Component
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel != "." && skipDirPattern.MatchString(d.Name()) && d.Name() != ".github" && d.Name() != ".gitlab" {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || IsExcludedPath(rel, exclude) {
			return nil
		}
		kind, ok := iacFile(rel)
		if !ok {
			return nil
		}
		data, readErr := os.ReadFile(p) // #nosec G304 G122 -- inside the extraction root; the checkout follows no symlinks
		if readErr != nil {
			warn(rel + ": " + readErr.Error())
			return nil
		}
		var components []Component
		switch kind {
		case "terraform-lock":
			components = parseTerraformLock(string(data), rel)
		case "helm-lock":
			components = parseHelmDependencies(data, rel, ResolutionRecorded)
		case "helm-chart":
			components = parseHelmDependencies(data, rel, ResolutionDeclared)
		case "gitlab-ci":
			components = parseGitLabCI(data, rel)
		case "github-workflow":
			components = parseGitHubWorkflow(string(data), rel)
		case "ansible":
			components = parseAnsibleRequirements(data, rel)
		case "dockerfile":
			components = parseDockerfile(string(data), rel)
		case "compose":
			components = parseCompose(data, rel)
		}
		out = append(out, components...)
		return nil
	})
	return out
}

func iacComponent(ecosystem, purl, name, version, rel string, resolution Resolution) Component {
	return Component{
		Purl:         purl,
		Name:         name,
		Version:      version,
		Ecosystem:    ecosystem,
		Relationship: RelationshipDirect,
		Resolution:   resolution,
		Path:         rel,
		Module:       moduleOf(rel),
		Extractor:    "hibou/iac:" + ecosystem,
	}
}

var shaPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

// ---- Terraform ----

var (
	tfProviderBlock = regexp.MustCompile(`(?s)provider\s+"([^"]+)"\s*\{(.*?)\n\}`)
	tfVersionLine   = regexp.MustCompile(`(?m)^\s*version\s*=\s*"([^"]+)"`)
)

// parseTerraformLock reads provider versions (and their hashes exist for
// integrity) from .terraform.lock.hcl.
func parseTerraformLock(content, rel string) []Component {
	var out []Component
	for _, m := range tfProviderBlock.FindAllStringSubmatch(content, -1) {
		source, body := m[1], m[2]
		version := ""
		if v := tfVersionLine.FindStringSubmatch(body); v != nil {
			version = v[1]
		}
		if version == "" {
			continue
		}
		name := strings.TrimPrefix(source, "registry.terraform.io/")
		out = append(out, iacComponent(EcosystemTerraform, "pkg:generic/"+source+"@"+version+"?type=terraform-provider", name, version, rel, ResolutionRecorded))
	}
	return out
}

// ---- Helm ----

func parseHelmDependencies(data []byte, rel string, resolution Resolution) []Component {
	var chart struct {
		Dependencies []struct {
			Name       string `yaml:"name"`
			Version    string `yaml:"version"`
			Repository string `yaml:"repository"`
		} `yaml:"dependencies"`
	}
	if err := yaml.Unmarshal(data, &chart); err != nil {
		return nil
	}
	var out []Component
	for _, dep := range chart.Dependencies {
		if dep.Name == "" || dep.Version == "" {
			continue
		}
		host := strings.TrimPrefix(strings.TrimPrefix(dep.Repository, "https://"), "oci://")
		host = strings.TrimSuffix(host, "/")
		if host == "" {
			host = "local"
		}
		res := resolution
		if strings.ContainsAny(dep.Version, "^~*<>x") || strings.Contains(dep.Version, " ") {
			res = ResolutionUnresolved
		}
		c := iacComponent(EcosystemHelm, "pkg:generic/"+host+"/"+dep.Name+"@"+dep.Version+"?type=helm-chart", dep.Name, dep.Version, rel, res)
		if res == ResolutionUnresolved {
			c.markUnresolved(dep.Version)
		}
		out = append(out, c)
	}
	return out
}

// ---- GitHub Actions ----

var usesLine = regexp.MustCompile(`(?m)^\s*-?\s*uses:\s*["']?([^\s"'#]+)["']?`)

// parseGitHubWorkflow reads every `uses:` reference: owner/repo[/path]@ref.
// A full commit SHA is recorded; a tag or branch is declared, the pinning
// hygiene finding of ADR-045 §9.
func parseGitHubWorkflow(content, rel string) []Component {
	seen := map[string]bool{}
	var out []Component
	for _, m := range usesLine.FindAllStringSubmatch(content, -1) {
		ref := m[1]
		if strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "docker://") {
			continue
		}
		repo, version, ok := strings.Cut(ref, "@")
		if !ok || version == "" {
			continue
		}
		parts := strings.SplitN(repo, "/", 3)
		if len(parts) < 2 {
			continue
		}
		name := parts[0] + "/" + parts[1]
		purl := "pkg:github/" + strings.ToLower(parts[0]) + "/" + strings.ToLower(parts[1]) + "@" + version
		if len(parts) == 3 {
			purl += "#" + parts[2]
			name += "/" + parts[2]
		}
		if seen[purl] {
			continue
		}
		seen[purl] = true
		resolution := ResolutionDeclared
		if shaPattern.MatchString(version) {
			resolution = ResolutionRecorded
		}
		out = append(out, iacComponent(EcosystemGitHubActions, purl, name, version, rel, resolution))
	}
	return out
}

// ---- GitLab CI ----

func parseGitLabCI(data []byte, rel string) []Component {
	var doc struct {
		Include any `yaml:"include"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil
	}
	var includes []map[string]any
	switch v := doc.Include.(type) {
	case []any:
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				includes = append(includes, m)
			}
		}
	case map[string]any:
		includes = append(includes, v)
	}
	var out []Component
	for _, include := range includes {
		if component, ok := include["component"].(string); ok {
			// registry.example/group/component@1.2.3
			name, version, found := strings.Cut(component, "@")
			if !found {
				continue
			}
			resolution := ResolutionDeclared
			if shaPattern.MatchString(version) {
				resolution = ResolutionRecorded
			}
			out = append(out, iacComponent(EcosystemGitLabCI, "pkg:generic/"+name+"@"+version+"?type=gitlab-component", name, version, rel, resolution))
			continue
		}
		project, _ := include["project"].(string)
		if project == "" {
			continue
		}
		ref, _ := include["ref"].(string)
		if ref == "" {
			ref = "HEAD"
		}
		resolution := ResolutionDeclared
		if shaPattern.MatchString(ref) {
			resolution = ResolutionRecorded
		}
		out = append(out, iacComponent(EcosystemGitLabCI, "pkg:generic/gitlab/"+project+"@"+ref+"?type=gitlab-include", project, ref, rel, resolution))
	}
	return out
}

// ---- Ansible ----

func parseAnsibleRequirements(data []byte, rel string) []Component {
	var doc struct {
		Collections []any `yaml:"collections"`
		Roles       []any `yaml:"roles"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		// A bare list is a list of roles.
		var roles []any
		if yaml.Unmarshal(data, &roles) != nil {
			return nil
		}
		doc.Roles = roles
	}
	var out []Component
	entry := func(item any, kind string) {
		name, version := "", ""
		switch v := item.(type) {
		case string:
			name = v
		case map[string]any:
			name, _ = v["name"].(string)
			if name == "" {
				name, _ = v["src"].(string)
			}
			version, _ = v["version"].(string)
		}
		if name == "" {
			return
		}
		resolution := ResolutionDeclared
		if version == "" {
			version = "latest"
		}
		out = append(out, iacComponent(EcosystemAnsible, "pkg:generic/ansible/"+name+"@"+version+"?type="+kind, name, version, rel, resolution))
	}
	for _, item := range doc.Collections {
		entry(item, "ansible-collection")
	}
	for _, item := range doc.Roles {
		entry(item, "ansible-role")
	}
	return out
}

// ---- Container images (C1 metadata, ADR-045 §10) ----

var fromLine = regexp.MustCompile(`(?mi)^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)`)

func parseDockerfile(content, rel string) []Component {
	stages := map[string]bool{}
	scanner := bufio.NewScanner(strings.NewReader(content))
	var out []Component
	for scanner.Scan() {
		line := scanner.Text()
		m := fromLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if idx := strings.Index(strings.ToUpper(line), " AS "); idx >= 0 {
			stages[strings.TrimSpace(line[idx+4:])] = true
		}
		image := m[1]
		if stages[image] || image == "scratch" || strings.HasPrefix(image, "$") {
			continue
		}
		if c, ok := imageComponent(image, rel); ok {
			out = append(out, c)
		}
	}
	return out
}

func parseCompose(data []byte, rel string) []Component {
	var doc struct {
		Services map[string]struct {
			Image string `yaml:"image"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil
	}
	names := make([]string, 0, len(doc.Services))
	for name := range doc.Services {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []Component
	for _, name := range names {
		if image := doc.Services[name].Image; image != "" && !strings.Contains(image, "${") {
			if c, ok := imageComponent(image, rel); ok {
				out = append(out, c)
			}
		}
	}
	return out
}

// imageComponent turns "registry/repo:tag@sha256:…" into an OCI purl: a
// digest is recorded, a tag declared, no tag means "latest", declared.
func imageComponent(image, rel string) (Component, bool) {
	image = strings.TrimSpace(image)
	if image == "" {
		return Component{}, false
	}
	digest := ""
	if idx := strings.Index(image, "@sha256:"); idx >= 0 {
		digest = image[idx+1:]
		image = image[:idx]
	}
	tag := ""
	if idx := strings.LastIndex(image, ":"); idx > strings.LastIndex(image, "/") {
		tag = image[idx+1:]
		image = image[:idx]
	}
	name := image
	version := tag
	resolution := ResolutionDeclared
	if digest != "" {
		version = digest
		resolution = ResolutionRecorded
	}
	if version == "" {
		version = "latest"
	}
	repository := name
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		repository = name[idx+1:]
	}
	purl := "pkg:oci/" + repository + "@" + strings.ReplaceAll(version, ":", "%3A") + "?repository_url=" + name
	if tag != "" && digest != "" {
		purl += "&tag=" + tag
	}
	return iacComponent(EcosystemOCI, purl, name, version, rel, resolution), true
}
