package depinventory

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The install-config generator (ADR-048 §3.1): writes the setting each
// package manager needs so a freshly published version waits the window
// on every machine and runner. Existing settings are kept when they wait
// at least as long; anything else in the files is untouched.

// InstallConfigChange is one file written by the generator.
type InstallConfigChange struct {
	Path   string
	Tool   string
	Change string
}

// GenerateInstallConfig writes the settings for the tools the modules use
// (or the tools named), with the window in days, plus the updater's
// cooldown when one is named. With dryRun nothing is written.
func GenerateInstallConfig(root string, modules []Module, days int, onlyTools []string, updater string, dryRun bool) ([]InstallConfigChange, error) {
	window := time.Duration(days) * 24 * time.Hour
	wanted := map[string]bool{}
	for _, tool := range onlyTools {
		wanted[strings.ToLower(strings.TrimSpace(tool))] = true
	}
	type target struct{ module, tool string }
	seen := map[target]bool{}
	var targets []target
	for _, module := range modules {
		for _, tool := range moduleTools(module) {
			if len(wanted) > 0 && !wanted[tool] {
				continue
			}
			t := target{module: module.Path, tool: tool}
			if !seen[t] {
				seen[t] = true
				targets = append(targets, t)
			}
		}
	}
	if len(modules) == 0 && len(wanted) > 0 {
		for tool := range wanted {
			targets = append(targets, target{module: ".", tool: tool})
		}
	}
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].module != targets[j].module {
			return targets[i].module < targets[j].module
		}
		return targets[i].tool < targets[j].tool
	})
	var changes []InstallConfigChange
	for _, t := range targets {
		current := detectTool(root, t.module, t.tool)
		if current.Present && current.Window >= window {
			continue
		}
		change, err := writeToolSetting(root, t.module, t.tool, days, current, dryRun)
		if err != nil {
			return changes, err
		}
		if change != nil {
			changes = append(changes, *change)
		}
	}
	if updater != "" {
		change, err := writeUpdaterSetting(root, strings.ToLower(strings.TrimSpace(updater)), days, dryRun)
		if err != nil {
			return changes, err
		}
		if change != nil {
			changes = append(changes, *change)
		}
	}
	return changes, nil
}

func writeToolSetting(root, module, tool string, days int, current InstallConfig, dryRun bool) (*InstallConfigChange, error) {
	rel := func(name string) string {
		if module == "." || module == "" {
			return name
		}
		return module + "/" + name
	}
	// The detector names a default path when nothing exists; only a file
	// that is really there is reused (a root-level file covers the module).
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(current.Path))); err != nil {
		current.Path = ""
	}
	switch tool {
	case "npm":
		return upsertKeyValue(root, rel(".npmrc"), "min-release-age", strconv.Itoa(days), "=", tool, dryRun)
	case "pnpm":
		path := rel("pnpm-workspace.yaml")
		if current.Path != "" && strings.HasSuffix(current.Path, "pnpm-workspace.yaml") {
			path = current.Path
		}
		return upsertYAMLKey(root, path, "minimumReleaseAge", strconv.Itoa(days*24*60), tool, dryRun, "minimumReleaseAgeStrict: true")
	case "yarn":
		path := rel(".yarnrc.yml")
		if current.Path != "" && strings.HasSuffix(current.Path, ".yarnrc.yml") {
			path = current.Path
		}
		// Minutes: early Yarn 4.x ignored day suffixes.
		return upsertYAMLKey(root, path, "npmMinimalAgeGate", strconv.Itoa(days*24*60), tool, dryRun, "")
	case "bun":
		path := rel("bunfig.toml")
		if current.Path != "" && strings.HasSuffix(current.Path, "bunfig.toml") {
			path = current.Path
		}
		return upsertTOMLSection(root, path, "install", "minimumReleaseAge", strconv.Itoa(days*86400), tool, dryRun)
	case "uv":
		path := rel("pyproject.toml")
		if current.Path != "" && strings.HasSuffix(current.Path, "pyproject.toml") {
			path = current.Path
		}
		return upsertTOMLSection(root, path, "tool.uv", "exclude-newer", strconv.Quote(fmt.Sprintf("%d days", days)), tool, dryRun)
	case "pip":
		return upsertKeyValue(root, rel("pip.conf"), "uploaded-prior-to", fmt.Sprintf("%dd", days), "=", tool, dryRun)
	}
	return nil, nil
}

func writeUpdaterSetting(root, updater string, days int, dryRun bool) (*InstallConfigChange, error) {
	switch updater {
	case "renovate":
		for _, rel := range []string{"renovate.json", "renovate.json5", ".renovaterc", ".renovaterc.json", ".github/renovate.json", ".github/renovate.json5"} {
			if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel))); err == nil {
				return upsertRenovate(root, rel, days, dryRun)
			}
		}
		return upsertRenovate(root, "renovate.json", days, dryRun)
	case "dependabot":
		for _, rel := range []string{".github/dependabot.yml", ".github/dependabot.yaml"} {
			if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel))); err == nil {
				return upsertDependabot(root, rel, days, dryRun)
			}
		}
		return upsertDependabot(root, ".github/dependabot.yml", days, dryRun)
	}
	return nil, fmt.Errorf("unknown updater %q: renovate or dependabot", updater)
}

func readOrEmpty(root, rel string) (string, bool) {
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel))) // #nosec G304 -- inside the repository root
	if err != nil {
		return "", false
	}
	return string(data), true
}

func writeChange(root, rel, content, tool, change string, dryRun bool) (*InstallConfigChange, error) {
	if !dryRun {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			return nil, err
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			return nil, err
		}
	}
	return &InstallConfigChange{Path: rel, Tool: tool, Change: change}, nil
}

// upsertKeyValue handles ini-style files (.npmrc, pip.conf).
func upsertKeyValue(root, rel, key, value, sep, tool string, dryRun bool) (*InstallConfigChange, error) {
	content, exists := readOrEmpty(root, rel)
	lines := []string{}
	if exists {
		lines = strings.Split(strings.TrimRight(content, "\n"), "\n")
	}
	replaced := false
	for i, line := range lines {
		k, _, found := strings.Cut(strings.TrimSpace(line), sep)
		if found && strings.TrimSpace(k) == key {
			lines[i] = key + sep + value
			replaced = true
		}
	}
	if !replaced {
		if rel == "pip.conf" || strings.HasSuffix(rel, "/pip.conf") {
			if !strings.Contains(content, "[install]") {
				lines = append(lines, "[install]")
			}
		}
		lines = append(lines, key+sep+value)
	}
	out := strings.Join(lines, "\n") + "\n"
	if out == content {
		return nil, nil
	}
	change := "set " + key + sep + value
	if !exists {
		change = "created with " + key + sep + value
	}
	return writeChange(root, rel, out, tool, change, dryRun)
}

// upsertYAMLKey sets a top-level scalar in a YAML file, textually, so
// comments and ordering survive.
func upsertYAMLKey(root, rel, key, value, tool string, dryRun bool, extraLine string) (*InstallConfigChange, error) {
	content, exists := readOrEmpty(root, rel)
	pattern := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(key) + `\s*:.*$`)
	var out string
	switch {
	case pattern.MatchString(content):
		out = pattern.ReplaceAllString(content, key+": "+value)
	default:
		out = strings.TrimRight(content, "\n")
		if out != "" {
			out += "\n"
		}
		out += key + ": " + value + "\n"
		if extraLine != "" && !strings.Contains(content, strings.SplitN(extraLine, ":", 2)[0]) {
			out += extraLine + "\n"
		}
	}
	if out == content {
		return nil, nil
	}
	change := "set " + key + ": " + value
	if !exists {
		change = "created with " + key + ": " + value
	}
	return writeChange(root, rel, out, tool, change, dryRun)
}

// upsertTOMLSection sets key = value under [section], creating the
// section at the end when absent.
func upsertTOMLSection(root, rel, section, key, value, tool string, dryRun bool) (*InstallConfigChange, error) {
	content, exists := readOrEmpty(root, rel)
	lines := strings.Split(strings.TrimRight(content, "\n"), "\n")
	if content == "" {
		lines = nil
	}
	header := "[" + section + "]"
	start := -1
	for i, line := range lines {
		if strings.TrimSpace(line) == header {
			start = i
			break
		}
	}
	keyPattern := regexp.MustCompile(`^\s*` + regexp.QuoteMeta(key) + `\s*=`)
	if start >= 0 {
		for i := start + 1; i < len(lines); i++ {
			if strings.HasPrefix(strings.TrimSpace(lines[i]), "[") {
				lines = append(lines[:i], append([]string{key + " = " + value}, lines[i:]...)...)
				start = -2
				break
			}
			if keyPattern.MatchString(lines[i]) {
				lines[i] = key + " = " + value
				start = -2
				break
			}
		}
		if start >= 0 {
			lines = append(lines, key+" = "+value)
		}
	} else {
		if len(lines) > 0 {
			lines = append(lines, "")
		}
		lines = append(lines, header, key+" = "+value)
	}
	out := strings.Join(lines, "\n") + "\n"
	if out == content {
		return nil, nil
	}
	change := "set " + header + " " + key + " = " + value
	if !exists {
		change = "created with " + header + " " + key + " = " + value
	}
	return writeChange(root, rel, out, tool, change, dryRun)
}

func upsertRenovate(root, rel string, days int, dryRun bool) (*InstallConfigChange, error) {
	content, exists := readOrEmpty(root, rel)
	value := fmt.Sprintf("%d days", days)
	if exists {
		if current, ok := renovateMinimumReleaseAge(content); ok {
			if d, parsed := parseHumanDuration(current, 24*time.Hour); parsed && d >= time.Duration(days)*24*time.Hour {
				return nil, nil
			}
			out := renovateAgePattern.ReplaceAllString(content, `"minimumReleaseAge": "`+value+`"`)
			return writeChange(root, rel, out, "renovate", "set minimumReleaseAge "+value, dryRun)
		}
		// Insert after the opening brace: presets and comments make a
		// strict JSON round trip unsafe.
		idx := strings.Index(content, "{")
		if idx < 0 {
			return nil, fmt.Errorf("%s: not a JSON object", rel)
		}
		out := content[:idx+1] + "\n  \"minimumReleaseAge\": \"" + value + "\"," + content[idx+1:]
		return writeChange(root, rel, out, "renovate", "set minimumReleaseAge "+value, dryRun)
	}
	doc := map[string]any{"$schema": "https://docs.renovatebot.com/renovate-schema.json", "extends": []string{"config:recommended"}, "minimumReleaseAge": value}
	data, _ := json.MarshalIndent(doc, "", "  ")
	return writeChange(root, rel, string(data)+"\n", "renovate", "created with minimumReleaseAge "+value, dryRun)
}

func upsertDependabot(root, rel string, days int, dryRun bool) (*InstallConfigChange, error) {
	content, exists := readOrEmpty(root, rel)
	if !exists {
		out := fmt.Sprintf("version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n    schedule:\n      interval: weekly\n    cooldown:\n      default-days: %d\n", days)
		return writeChange(root, rel, out, "dependabot", fmt.Sprintf("created with cooldown.default-days %d", days), dryRun)
	}
	pattern := regexp.MustCompile(`(?m)^(\s*)default-days:\s*(\d+)\s*$`)
	if pattern.MatchString(content) {
		out := pattern.ReplaceAllStringFunc(content, func(line string) string {
			m := pattern.FindStringSubmatch(line)
			if current, err := strconv.Atoi(m[2]); err == nil && current >= days {
				return line
			}
			return m[1] + "default-days: " + strconv.Itoa(days)
		})
		if out == content {
			return nil, nil
		}
		return writeChange(root, rel, out, "dependabot", fmt.Sprintf("set cooldown.default-days %d", days), dryRun)
	}
	// Add a cooldown block under every update entry's directory line.
	dirPattern := regexp.MustCompile(`(?m)^(\s*)directory:.*$`)
	out := dirPattern.ReplaceAllStringFunc(content, func(line string) string {
		indent := dirPattern.FindStringSubmatch(line)[1]
		return line + "\n" + indent + "cooldown:\n" + indent + "  default-days: " + strconv.Itoa(days)
	})
	if out == content {
		return nil, nil
	}
	return writeChange(root, rel, out, "dependabot", fmt.Sprintf("set cooldown.default-days %d", days), dryRun)
}
