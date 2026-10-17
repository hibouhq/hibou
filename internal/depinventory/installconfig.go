package depinventory

import (
	"bufio"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	toml "github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

// Install-time cooldown verification (ADR-048 §3.1). The gate blocks a
// merge, not a download: the only thing that keeps a fresh version off a
// developer's machine and off CI is the package manager's own setting,
// committed in the repository. Hibou reads those settings next to the
// lockfiles it extracts and reports, per module, whether one exists and
// how long its window is.

// InstallConfig is one install-time cooldown setting found (or missing)
// for a module.
type InstallConfig struct {
	// Tool is the package manager: npm, pnpm, yarn, bun, uv, pip.
	Tool string `json:"tool"`
	// Path of the file the setting lives in (or should), relative to the
	// root.
	Path string `json:"path"`
	// Setting is the key name in that file.
	Setting string `json:"setting"`
	// Present is true when the setting was found with a positive value.
	Present bool `json:"present"`
	// Window is the configured duration, normalised, when present.
	Window time.Duration `json:"window,omitempty"`
	// Value is the raw value as written, for the message.
	Value string `json:"value,omitempty"`
	// Note explains a nuance: loose mode, zero, unparsable.
	Note string `json:"note,omitempty"`
}

// UpdaterConfig is the dependency updater's own cooldown, read so a
// mismatch with the install setting can be reported: an updater that waits
// less than the install does opens PRs the install refuses.
type UpdaterConfig struct {
	Tool    string        `json:"tool"` // renovate | dependabot
	Path    string        `json:"path"`
	Present bool          `json:"present"`
	Window  time.Duration `json:"window,omitempty"`
	Value   string        `json:"value,omitempty"`
}

// installConfigPaths are the files read in addition to manifests.
var installConfigNames = map[string]struct{}{
	".npmrc": {}, "pnpm-workspace.yaml": {}, ".yarnrc.yml": {}, "bunfig.toml": {},
	"pip.conf": {}, "pip.ini": {},
	"renovate.json": {}, "renovate.json5": {}, ".renovaterc": {}, ".renovaterc.json": {}, "dependabot.yml": {}, "dependabot.yaml": {},
}

// IsInstallConfigPath reports whether a repository path is an install-time
// or updater cooldown setting file worth checking out.
func IsInstallConfigPath(repoPath string) bool {
	repoPath = strings.TrimPrefix(strings.TrimSpace(repoPath), "./")
	if repoPath == "" {
		return false
	}
	dir, base := path.Split(repoPath)
	for _, segment := range strings.Split(strings.Trim(dir, "/"), "/") {
		if segment != "" && segment != ".github" && segment != ".gitlab" && skipDirPattern.MatchString(segment) {
			return false
		}
	}
	_, ok := installConfigNames[base]
	return ok
}

// IsExtractionPath is the sparse checkout selector: manifests plus install
// and updater settings.
func IsExtractionPath(repoPath string) bool {
	return IsManifestPath(repoPath) || IsInstallConfigPath(repoPath) || IsIaCPath(repoPath)
}

// ecosystemTools lists the package managers a module's files imply.
func moduleTools(module Module) []string {
	var tools []string
	add := func(tool string) {
		if !contains(tools, tool) {
			tools = append(tools, tool)
		}
	}
	for _, file := range module.Files {
		switch path.Base(file) {
		case "package-lock.json", "npm-shrinkwrap.json":
			add("npm")
		case "pnpm-lock.yaml":
			add("pnpm")
		case "yarn.lock":
			add("yarn")
		case "bun.lock":
			add("bun")
		case "uv.lock":
			add("uv")
		case "poetry.lock", "pdm.lock", "Pipfile.lock", "pylock.toml":
			add("pip")
		default:
			if strings.HasPrefix(path.Base(file), "requirements") {
				add("pip")
			}
		}
	}
	return tools
}

// DetectInstallConfig reads, for every module, the install-time cooldown
// setting of each package manager it uses. Settings are looked up in the
// module directory first, then at the root, which is where monorepos keep
// them.
func DetectInstallConfig(root string, modules []Module) map[string][]InstallConfig {
	out := make(map[string][]InstallConfig, len(modules))
	for _, module := range modules {
		var configs []InstallConfig
		for _, tool := range moduleTools(module) {
			configs = append(configs, detectTool(root, module.Path, tool))
		}
		if len(configs) > 0 {
			out[module.Path] = configs
		}
	}
	return out
}

func detectTool(root, modulePath, tool string) InstallConfig {
	switch tool {
	case "npm":
		return detectKeyValue(root, modulePath, "npm", ".npmrc", "min-release-age", 24*time.Hour, "=")
	case "pnpm":
		return detectPnpm(root, modulePath)
	case "yarn":
		return detectYarn(root, modulePath)
	case "bun":
		return detectBun(root, modulePath)
	case "uv":
		return detectUV(root, modulePath)
	case "pip":
		return detectKeyValue(root, modulePath, "pip", "pip.conf", "uploaded-prior-to", 0, "=")
	}
	return InstallConfig{Tool: tool}
}

// findUp returns the first existing file named name in the module dir or
// the root, with its repository-relative path.
func findUp(root, modulePath, name string) (string, string, bool) {
	candidates := []string{modulePath}
	if modulePath != "." {
		candidates = append(candidates, ".")
	}
	for _, dir := range candidates {
		rel := name
		if dir != "." {
			rel = path.Join(dir, name)
		}
		full := filepath.Join(root, filepath.FromSlash(rel))
		if _, err := os.Stat(full); err == nil {
			return full, rel, true
		}
	}
	return "", "", false
}

var durationUnits = regexp.MustCompile(`^(\d+)\s*(d|days?|h|hours?|m|min|minutes?|s|secs?|seconds?|w|weeks?)?$`)

// parseHumanDuration reads "7", "7d", "7 days", "168h", "10080" with the
// given unit for bare numbers.
func parseHumanDuration(value string, bareUnit time.Duration) (time.Duration, bool) {
	value = strings.ToLower(strings.TrimSpace(strings.Trim(value, `"'`)))
	m := durationUnits.FindStringSubmatch(value)
	if m == nil {
		if d, err := time.ParseDuration(value); err == nil {
			return d, d > 0
		}
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, false
	}
	unit := bareUnit
	switch {
	case m[2] == "":
	case strings.HasPrefix(m[2], "w"):
		unit = 7 * 24 * time.Hour
	case strings.HasPrefix(m[2], "d"):
		unit = 24 * time.Hour
	case strings.HasPrefix(m[2], "h"):
		unit = time.Hour
	case strings.HasPrefix(m[2], "m"):
		unit = time.Minute
	case strings.HasPrefix(m[2], "s"):
		unit = time.Second
	}
	d := time.Duration(n) * unit
	return d, d > 0
}

// detectKeyValue handles ini-style files (.npmrc, pip.conf).
func detectKeyValue(root, modulePath, tool, file, key string, bareUnit time.Duration, sep string) InstallConfig {
	cfg := InstallConfig{Tool: tool, Path: path.Join(modulePath, file), Setting: key}
	if modulePath == "." {
		cfg.Path = file
	}
	full, rel, ok := findUp(root, modulePath, file)
	if !ok {
		return cfg
	}
	cfg.Path = rel
	f, err := os.Open(full) // #nosec G304 -- inside the extraction root
	if err != nil {
		return cfg
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		k, v, found := strings.Cut(line, sep)
		if !found || strings.TrimSpace(k) != key {
			continue
		}
		cfg.Value = strings.TrimSpace(v)
		if d, ok := parseHumanDuration(cfg.Value, bareUnit); ok {
			cfg.Present = true
			cfg.Window = d
		} else {
			cfg.Note = "set to zero or unparsable: no cooldown"
		}
		return cfg
	}
	return cfg
}

func detectPnpm(root, modulePath string) InstallConfig {
	cfg := InstallConfig{Tool: "pnpm", Path: "pnpm-workspace.yaml", Setting: "minimumReleaseAge"}
	full, rel, ok := findUp(root, modulePath, "pnpm-workspace.yaml")
	if !ok {
		// .npmrc is pnpm's other home for settings.
		if alt := detectKeyValue(root, modulePath, "pnpm", ".npmrc", "minimum-release-age", time.Minute, "="); alt.Present || alt.Value != "" {
			alt.Setting = "minimum-release-age"
			return alt
		}
		cfg.Note = "pnpm 11 holds versions for a day by default; set minimumReleaseAge explicitly to make it strict"
		return cfg
	}
	cfg.Path = rel
	data, err := os.ReadFile(full) // #nosec G304 -- inside the extraction root
	if err != nil {
		return cfg
	}
	var ws struct {
		MinimumReleaseAge       any  `yaml:"minimumReleaseAge"`
		MinimumReleaseAgeStrict bool `yaml:"minimumReleaseAgeStrict"`
	}
	if yaml.Unmarshal(data, &ws) != nil || ws.MinimumReleaseAge == nil {
		cfg.Note = "pnpm 11 holds versions for a day by default; set minimumReleaseAge explicitly to make it strict"
		return cfg
	}
	cfg.Value = strings.TrimSpace(strings.Trim(anyString(ws.MinimumReleaseAge), `"`))
	if d, ok := parseHumanDuration(cfg.Value, time.Minute); ok {
		cfg.Present = true
		cfg.Window = d
	} else {
		cfg.Note = "set to zero or unparsable: no cooldown"
	}
	return cfg
}

func detectYarn(root, modulePath string) InstallConfig {
	cfg := InstallConfig{Tool: "yarn", Path: ".yarnrc.yml", Setting: "npmMinimalAgeGate"}
	full, rel, ok := findUp(root, modulePath, ".yarnrc.yml")
	if !ok {
		return cfg
	}
	cfg.Path = rel
	data, err := os.ReadFile(full) // #nosec G304 -- inside the extraction root
	if err != nil {
		return cfg
	}
	var rc struct {
		NpmMinimalAgeGate any `yaml:"npmMinimalAgeGate"`
	}
	if yaml.Unmarshal(data, &rc) != nil || rc.NpmMinimalAgeGate == nil {
		return cfg
	}
	cfg.Value = strings.TrimSpace(anyString(rc.NpmMinimalAgeGate))
	// Minutes when bare; day suffixes were silently ignored by early 4.x.
	if d, ok := parseHumanDuration(cfg.Value, time.Minute); ok {
		cfg.Present = true
		cfg.Window = d
		if strings.HasSuffix(strings.ToLower(cfg.Value), "d") {
			cfg.Note = "day suffix: early Yarn 4.x ignored it; prefer a number of minutes"
		}
	} else {
		cfg.Note = "set to zero or unparsable: no cooldown"
	}
	return cfg
}

func detectBun(root, modulePath string) InstallConfig {
	cfg := InstallConfig{Tool: "bun", Path: "bunfig.toml", Setting: "install.minimumReleaseAge"}
	full, rel, ok := findUp(root, modulePath, "bunfig.toml")
	if !ok {
		return cfg
	}
	cfg.Path = rel
	data, err := os.ReadFile(full) // #nosec G304 -- inside the extraction root
	if err != nil {
		return cfg
	}
	var bf struct {
		Install struct {
			MinimumReleaseAge any `toml:"minimumReleaseAge"`
		} `toml:"install"`
	}
	if toml.Unmarshal(data, &bf) != nil || bf.Install.MinimumReleaseAge == nil {
		return cfg
	}
	cfg.Value = strings.TrimSpace(anyString(bf.Install.MinimumReleaseAge))
	if d, ok := parseHumanDuration(cfg.Value, time.Second); ok {
		cfg.Present = true
		cfg.Window = d
	} else {
		cfg.Note = "set to zero or unparsable: no cooldown"
	}
	return cfg
}

func detectUV(root, modulePath string) InstallConfig {
	cfg := InstallConfig{Tool: "uv", Path: "pyproject.toml", Setting: "tool.uv.exclude-newer"}
	full, rel, ok := findUp(root, modulePath, "pyproject.toml")
	if !ok {
		if alt := detectUVToml(root, modulePath); alt.Present || alt.Value != "" {
			return alt
		}
		return cfg
	}
	cfg.Path = rel
	data, err := os.ReadFile(full) // #nosec G304 -- inside the extraction root
	if err != nil {
		return cfg
	}
	var py struct {
		Tool struct {
			UV struct {
				ExcludeNewer any `toml:"exclude-newer"`
			} `toml:"uv"`
		} `toml:"tool"`
	}
	if toml.Unmarshal(data, &py) != nil || py.Tool.UV.ExcludeNewer == nil {
		if alt := detectUVToml(root, modulePath); alt.Present || alt.Value != "" {
			return alt
		}
		return cfg
	}
	cfg.Value = strings.TrimSpace(anyString(py.Tool.UV.ExcludeNewer))
	if d, ok := parseHumanDuration(cfg.Value, 24*time.Hour); ok {
		cfg.Present = true
		cfg.Window = d
	} else if cfg.Value != "" {
		// A timestamp freezes resolution at a date rather than a window.
		cfg.Present = true
		cfg.Note = "an absolute date, not a rolling window"
	}
	return cfg
}

func detectUVToml(root, modulePath string) InstallConfig {
	cfg := InstallConfig{Tool: "uv", Path: "uv.toml", Setting: "exclude-newer"}
	full, rel, ok := findUp(root, modulePath, "uv.toml")
	if !ok {
		return cfg
	}
	cfg.Path = rel
	data, err := os.ReadFile(full) // #nosec G304 -- inside the extraction root
	if err != nil {
		return cfg
	}
	var uvcfg struct {
		ExcludeNewer any `toml:"exclude-newer"`
	}
	if toml.Unmarshal(data, &uvcfg) != nil || uvcfg.ExcludeNewer == nil {
		return cfg
	}
	cfg.Value = strings.TrimSpace(anyString(uvcfg.ExcludeNewer))
	if d, ok := parseHumanDuration(cfg.Value, 24*time.Hour); ok {
		cfg.Present = true
		cfg.Window = d
	} else if cfg.Value != "" {
		cfg.Present = true
		cfg.Note = "an absolute date, not a rolling window"
	}
	return cfg
}

func anyString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	default:
		return ""
	}
}

// DetectUpdaterConfig reads the dependency updater's cooldown at the
// repository root: Renovate's minimumReleaseAge (top level) or
// Dependabot's cooldown.default-days.
func DetectUpdaterConfig(root string) []UpdaterConfig {
	var out []UpdaterConfig
	for _, rel := range []string{"renovate.json", "renovate.json5", ".renovaterc", ".renovaterc.json", ".github/renovate.json", ".github/renovate.json5", ".gitlab/renovate.json"} {
		full := filepath.Join(root, filepath.FromSlash(rel))
		data, err := os.ReadFile(full) // #nosec G304 -- inside the extraction root
		if err != nil {
			continue
		}
		cfg := UpdaterConfig{Tool: "renovate", Path: rel}
		if value, ok := renovateMinimumReleaseAge(string(data)); ok {
			cfg.Value = value
			if d, parsed := parseHumanDuration(value, 24*time.Hour); parsed {
				cfg.Present = true
				cfg.Window = d
			}
		}
		out = append(out, cfg)
		break
	}
	for _, rel := range []string{".github/dependabot.yml", ".github/dependabot.yaml"} {
		full := filepath.Join(root, filepath.FromSlash(rel))
		data, err := os.ReadFile(full) // #nosec G304 -- inside the extraction root
		if err != nil {
			continue
		}
		cfg := UpdaterConfig{Tool: "dependabot", Path: rel}
		var doc struct {
			Updates []struct {
				Cooldown struct {
					DefaultDays int `yaml:"default-days"`
				} `yaml:"cooldown"`
			} `yaml:"updates"`
		}
		if yaml.Unmarshal(data, &doc) == nil {
			minDays := 0
			for _, update := range doc.Updates {
				if update.Cooldown.DefaultDays > 0 && (minDays == 0 || update.Cooldown.DefaultDays < minDays) {
					minDays = update.Cooldown.DefaultDays
				}
			}
			if minDays > 0 {
				cfg.Present = true
				cfg.Window = time.Duration(minDays) * 24 * time.Hour
				cfg.Value = strconv.Itoa(minDays) + "d"
			}
		}
		out = append(out, cfg)
		break
	}
	return out
}

var renovateAgePattern = regexp.MustCompile(`"minimumReleaseAge"\s*:\s*"([^"]+)"`)

// renovateMinimumReleaseAge finds the first minimumReleaseAge in a Renovate
// config without a JSON5 parser: presets and comments make strict parsing
// fail, and the value's text is what matters.
func renovateMinimumReleaseAge(data string) (string, bool) {
	m := renovateAgePattern.FindStringSubmatch(data)
	if m == nil {
		return "", false
	}
	return m[1], true
}
