// Package shipped decides whether a component reaches clients (ADR-045 §6).
// Everything is shipped unless evidence or a maintained list says
// otherwise; the attribute filters, it never hides.
package shipped

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/hibouhq/hibou/internal/provider/depsdev"
)

// List is a parsed not-shipped list: purl globs ("pkg:npm/@types/*"),
// regular expressions ("re:^pkg:npm/eslint(-.*)?$"), whole ecosystems
// ("ecosystem:terraform") and repository path globs ("tools/**", matched
// against the module and manifest paths that declare the component).
type List struct {
	entries []entry
}

type entry struct {
	raw       string
	regex     *regexp.Regexp
	path      bool
	ecosystem string
}

// Parse validates the patterns; an invalid regular expression or path glob
// is an error naming the pattern.
func Parse(patterns []string) (*List, error) {
	list := &List{}
	for i, raw := range patterns {
		raw = strings.TrimSpace(raw)
		switch {
		case raw == "":
			return nil, fmt.Errorf("not_shipped[%d]: empty pattern", i)
		case strings.HasPrefix(raw, "re:"):
			re, err := regexp.Compile(strings.TrimPrefix(raw, "re:"))
			if err != nil {
				return nil, fmt.Errorf("not_shipped[%d]: %w", i, err)
			}
			list.entries = append(list.entries, entry{raw: raw, regex: re})
		case strings.HasPrefix(raw, "ecosystem:"):
			name := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(raw, "ecosystem:")))
			if name == "" {
				return nil, fmt.Errorf("not_shipped[%d]: empty ecosystem", i)
			}
			list.entries = append(list.entries, entry{raw: raw, ecosystem: name})
		case strings.HasPrefix(raw, "pkg:"):
			list.entries = append(list.entries, entry{raw: raw})
		default:
			if !doublestar.ValidatePattern(raw) {
				return nil, fmt.Errorf("not_shipped[%d]: invalid path pattern %q", i, raw)
			}
			list.entries = append(list.entries, entry{raw: strings.TrimPrefix(raw, "./"), path: true})
		}
	}
	return list, nil
}

// ValidPattern reports whether one pattern parses.
func ValidPattern(pattern string) error {
	_, err := Parse([]string{pattern})
	return err
}

// Empty reports whether the list has no entry.
func (l *List) Empty() bool {
	return l == nil || len(l.entries) == 0
}

// Patterns returns the raw patterns in order.
func (l *List) Patterns() []string {
	if l == nil {
		return nil
	}
	out := make([]string, 0, len(l.entries))
	for _, e := range l.entries {
		out = append(out, e.raw)
	}
	return out
}

// Match returns the first pattern that marks the component not shipped:
// its purl, its ecosystem, or one of the paths (modules, manifests) that
// declare it.
func (l *List) Match(purl, ecosystem string, paths []string) (string, bool) {
	if l == nil {
		return "", false
	}
	ecosystem = strings.ToLower(strings.TrimSpace(ecosystem))
	for _, e := range l.entries {
		switch {
		case e.regex != nil:
			if e.regex.MatchString(purl) {
				return e.raw, true
			}
		case e.ecosystem != "":
			if e.ecosystem == ecosystem {
				return e.raw, true
			}
		case e.path:
			for _, p := range paths {
				p = strings.TrimPrefix(strings.TrimSpace(p), "./")
				if p == "" || p == "." {
					continue
				}
				if ok, _ := doublestar.Match(e.raw, p); ok {
					return e.raw, true
				}
				// "tools/**" also covers the module directory itself.
				if ok, _ := doublestar.Match(e.raw, p+"/"); ok {
					return e.raw, true
				}
			}
		default:
			if depsdev.MatchesNamespace(purl, e.raw) || purlMatches(purl, e.raw) {
				return e.raw, true
			}
		}
	}
	return "", false
}

// purlMatches handles a versioned pattern ("pkg:npm/lodash@4.17.20"),
// which MatchesNamespace strips.
func purlMatches(purl, pattern string) bool {
	if !strings.Contains(pattern, "@") || strings.Contains(pattern, "*") {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(purl), pattern)
}

// DefaultPatterns is the built-in org list (ADR-045 §9): a software vendor
// does not ship its Terraform, Helm charts, CI workflows or Ansible roles
// to clients. A repository whose deliverable is IaC lists the ecosystem
// under `dependencies.shipped` to cancel the entry.
var DefaultPatterns = []string{
	"ecosystem:terraform",
	"ecosystem:helm",
	"ecosystem:githubactions",
	"ecosystem:gitlabci",
	"ecosystem:oci",
	"ecosystem:ansible",
}

// Source names, in precedence order for the reason text.
const (
	SourceDefault      = "default"
	SourceOrganization = "organization"
	SourceRepository   = "repository"
	SourceConfig       = ".hibou.yaml"
	SourceSBOM         = "uploaded SBOM"
	SourceScope        = "declared scope"
)

// Source is one not-shipped list with where it comes from.
type Source struct {
	Name string
	List *List
}

// DevScopes are the declared scopes that mean "not at runtime" in their
// ecosystems: npm devDependencies, Maven test, Cargo dev-dependencies,
// Poetry and uv dev groups.
var DevScopes = map[string]bool{
	"dev": true, "devdependencies": true, "dev-dependencies": true, "development": true,
	"test": true, "build-dependencies": true, "docs": true, "lint": true,
}

// IsDevScope reports whether a declared scope is a dev or test scope.
func IsDevScope(scope string) bool {
	return DevScopes[strings.ToLower(strings.TrimSpace(scope))]
}

// Policy decides the shipped attribute for one snapshot (ADR-045 §6).
type Policy struct {
	// Sources are the not-shipped lists in precedence order: default,
	// organization, repository (UI-managed), .hibou.yaml.
	Sources []Source
	// Overrides are the repository's `dependencies.shipped` patterns: a
	// match cancels any list entry.
	Overrides *List
	// UploadedSBOM is true when the snapshot has an SBOM from the team's
	// own build; what it lists ships, what it omits does not, inside the
	// paths Covers declares (all of them when Covers is empty).
	UploadedSBOM bool
	Covers       []string
	// ExtractorSource is the file name of the built-in extractor's document
	// among a component's inventory sources.
	ExtractorSource string
	// TrustedScopes lists the ecosystems whose declared dev and test scopes
	// are trusted as not shipped (an org opt-in; default off).
	TrustedScopes map[string]bool
}

// Candidate is one component with what the inventory says about it.
type Candidate struct {
	Purl      string
	Ecosystem string
	// Sources are the artifacts that reported the component.
	Sources []string
	Modules []string
	Paths   []string
	Scopes  []string
}

// Decision is the policy's answer.
type Decision struct {
	Shipped bool
	// Reason is empty when shipped by default; otherwise it says which
	// evidence or pattern decided, e.g. "organization: pkg:npm/@types/*".
	Reason string
	// Ignored names a list pattern that matched a component an uploaded
	// SBOM reports anyway: the evidence says it ships.
	Ignored string
}

// Decide applies the rules of ADR-045 §6 in order: evidence (an uploaded
// SBOM), then overrides, then the lists, then trusted declared scopes,
// then shipped.
func (p *Policy) Decide(c Candidate) Decision {
	if p == nil {
		return Decision{Shipped: true}
	}
	paths := append(append([]string{}, c.Modules...), c.Paths...)
	listMatch, listSource := p.matchLists(c, paths)

	if p.UploadedSBOM {
		fromUpload := false
		for _, source := range c.Sources {
			if source != p.ExtractorSource {
				fromUpload = true
				break
			}
		}
		if fromUpload {
			decision := Decision{Shipped: true}
			if listMatch != "" {
				decision.Ignored = listSource + ": " + listMatch
			}
			return decision
		}
		if len(c.Sources) > 0 && p.covers(c.Modules) {
			return Decision{Shipped: false, Reason: "not in " + SourceSBOM}
		}
	}
	if p.Overrides != nil {
		if pattern, ok := p.Overrides.Match(c.Purl, c.Ecosystem, paths); ok {
			return Decision{Shipped: true, Reason: "shipped: " + pattern + " in " + SourceConfig}
		}
	}
	if listMatch != "" {
		return Decision{Shipped: false, Reason: listSource + ": " + listMatch}
	}
	if p.TrustedScopes[strings.ToLower(strings.TrimSpace(c.Ecosystem))] {
		for _, scope := range c.Scopes {
			if IsDevScope(scope) {
				return Decision{Shipped: false, Reason: SourceScope + ": " + scope + " (trusted for " + c.Ecosystem + ")"}
			}
		}
	}
	return Decision{Shipped: true}
}

func (p *Policy) matchLists(c Candidate, paths []string) (string, string) {
	for _, source := range p.Sources {
		if pattern, ok := source.List.Match(c.Purl, c.Ecosystem, paths); ok {
			return pattern, source.Name
		}
	}
	return "", ""
}

// covers reports whether the uploaded SBOM is declared to cover the
// component's modules: every module when nothing is declared, else any
// module under a declared path.
func (p *Policy) covers(modules []string) bool {
	if len(p.Covers) == 0 {
		return true
	}
	for _, module := range modules {
		module = strings.TrimPrefix(strings.TrimSpace(module), "./")
		for _, pattern := range p.Covers {
			pattern = strings.TrimPrefix(strings.TrimSpace(pattern), "./")
			if module == "." || module == "" {
				if pattern == "." || pattern == "**" {
					return true
				}
				continue
			}
			if ok, _ := doublestar.Match(pattern, module); ok {
				return true
			}
			if ok, _ := doublestar.Match(pattern, module+"/"); ok {
				return true
			}
		}
	}
	return false
}

// UndeclaredModules lists extraction modules an uploaded SBOM does not
// mention when the repository declares no sbom_covers: the UI asks
// "shipped or not?" instead of guessing (ADR-045 §6).
func UndeclaredModules(policy *Policy, modulesWithUpload map[string]bool, modules []string) []string {
	if policy == nil || !policy.UploadedSBOM || len(policy.Covers) > 0 {
		return nil
	}
	var out []string
	for _, module := range modules {
		if !modulesWithUpload[module] {
			out = append(out, module)
		}
	}
	return out
}
