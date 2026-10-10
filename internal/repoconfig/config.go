package repoconfig

import (
	"bytes"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/hibouhq/hibou/internal/cwe"
)

const CurrentVersion = 1

type RepoConfig struct {
	Version      int             `yaml:"version" json:"version"`
	QualityGates []QualityGate   `yaml:"quality_gates,omitempty" json:"quality_gates,omitempty"`
	Coverage     *CoverageConfig `yaml:"coverage,omitempty" json:"coverage,omitempty"`
	Upload       *UploadConfig   `yaml:"upload,omitempty" json:"upload,omitempty"`
	Releases     *ReleasesConfig `yaml:"releases,omitempty" json:"releases,omitempty"`
}

type QualityGate struct {
	Branches []string `yaml:"branches" json:"branches"`
	// Code caps NEW first-party code findings (sast, dast, fuzzing, manual,
	// generic) by severity. It replaced `weaknesses` (ADR-037 §8), which also
	// counted dependency and secret findings the other sections own.
	Code            *CodeThresholds          `yaml:"code,omitempty" json:"code,omitempty"`
	Vulnerabilities *VulnerabilityThresholds `yaml:"vulnerabilities,omitempty" json:"vulnerabilities,omitempty"`
	Licenses        *LicensePolicy           `yaml:"licenses,omitempty" json:"licenses,omitempty"`
	Secrets         *SecretThresholds        `yaml:"secrets,omitempty" json:"secrets,omitempty"`
	Coverage        *CoverageThresholds      `yaml:"coverage,omitempty" json:"coverage,omitempty"`
	// CWE denies NEW findings of any type that carry a listed CWE (ADR-037 §7).
	CWE *CWEPolicy `yaml:"cwe,omitempty" json:"cwe,omitempty"`
	// Enforcement controls whether a failing gate blocks the PR. "advisory"
	// (default) publishes an informational, non-blocking forge check — hibou never
	// breaks the build; "blocking" posts a real failure so a required check blocks.
	// See ADR-018.
	Enforcement string `yaml:"enforcement,omitempty" json:"enforcement,omitempty"`
}

const (
	EnforcementAdvisory = "advisory"
	EnforcementBlocking = "blocking"
)

// EnforcementValue returns the gate's enforcement mode, defaulting to advisory.
func (g *QualityGate) EnforcementValue() string {
	if g == nil || strings.TrimSpace(g.Enforcement) == "" {
		return EnforcementAdvisory
	}
	return strings.ToLower(strings.TrimSpace(g.Enforcement))
}

type CoverageThresholds struct {
	MinCoverage *float64 `yaml:"min_coverage,omitempty" json:"min_coverage,omitempty"`
	Grace       *float64 `yaml:"grace,omitempty" json:"grace,omitempty"`
	DiffMinimum *float64 `yaml:"diff_minimum,omitempty" json:"diff_minimum,omitempty"`
}

// CodeThresholds caps NEW code findings by severity.
type CodeThresholds struct {
	Enabled     *bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	MaxCritical *int  `yaml:"max_critical,omitempty" json:"max_critical,omitempty"`
	MaxHigh     *int  `yaml:"max_high,omitempty" json:"max_high,omitempty"`
	MaxMedium   *int  `yaml:"max_medium,omitempty" json:"max_medium,omitempty"`
}

// VulnerabilityThresholds caps NEW dependency vulnerabilities introduced by a
// PR (evaluated against the delta, not the whole snapshot).
type VulnerabilityThresholds struct {
	MaxCritical *int `yaml:"max_critical,omitempty" json:"max_critical,omitempty"`
	MaxHigh     *int `yaml:"max_high,omitempty" json:"max_high,omitempty"`
	MaxMedium   *int `yaml:"max_medium,omitempty" json:"max_medium,omitempty"`
	// MaxUnknown caps new vulnerabilities no source rates yet (ADR-038 §3).
	// Severity thresholds ignore them; KEV still blocks exploited ones.
	MaxUnknown *int `yaml:"max_unknown,omitempty" json:"max_unknown,omitempty"`
	// MaxNewTotal caps new vulnerabilities of any severity.
	MaxNewTotal *int `yaml:"max_new_total,omitempty" json:"max_new_total,omitempty"`
}

// SecretThresholds caps NEW secret findings introduced by a PR. MaxNew: 0 is
// the expected setting — one leaked credential is one too many.
type SecretThresholds struct {
	MaxNew *int `yaml:"max_new,omitempty" json:"max_new,omitempty"`
}

// LicensePolicy denies license categories and/or SPDX id globs; explicit
// allow entries override everything.
type LicensePolicy struct {
	DenyCategories []string `yaml:"deny_categories,omitempty" json:"deny_categories,omitempty"`
	Deny           []string `yaml:"deny,omitempty" json:"deny,omitempty"`
	Allow          []string `yaml:"allow,omitempty" json:"allow,omitempty"`
	// DenyUnknown defaults to TRUE: an unknown/missing license is an
	// unreviewed legal risk. Set false explicitly to allow unknowns through.
	DenyUnknown *bool `yaml:"deny_unknown,omitempty" json:"deny_unknown,omitempty"`
	// ExemptPurls exempts specific packages (purl globs) from the policy. A
	// license allow-list cannot express "this one dev tool is fine" because it
	// matches license ids, not packages, so without this the only way to unblock
	// a single dependency is to weaken the policy for everything.
	ExemptPurls []string `yaml:"exempt_purls,omitempty" json:"exempt_purls,omitempty"`
	// Evaluate scopes the gate: "new" (default) fails only on components this
	// PR introduces, "all" fails on the whole head snapshot. Whole-tree was the
	// original behaviour and it makes enabling a policy on an existing repo
	// report years-old dependencies as if the PR had introduced them.
	Evaluate string `yaml:"evaluate,omitempty" json:"evaluate,omitempty"`
}

const (
	// LicenseEvaluateNew gates only components introduced by the change.
	LicenseEvaluateNew = "new"
	// LicenseEvaluateAll gates every component in the head snapshot.
	LicenseEvaluateAll = "all"
)

// DenyUnknownValue applies the fail-closed default.
func (p *LicensePolicy) DenyUnknownValue() bool {
	if p == nil || p.DenyUnknown == nil {
		return true
	}
	return *p.DenyUnknown
}

// EvaluateValue applies the delta-scoped default.
func (p *LicensePolicy) EvaluateValue() string {
	if p == nil {
		return LicenseEvaluateNew
	}
	switch strings.ToLower(strings.TrimSpace(p.Evaluate)) {
	case LicenseEvaluateAll:
		return LicenseEvaluateAll
	default:
		return LicenseEvaluateNew
	}
}

type CoverageConfig struct {
	Exclude []string `yaml:"exclude,omitempty" json:"exclude,omitempty"`
}

type UploadConfig struct {
	Window string `yaml:"window,omitempty" json:"window,omitempty"`
}

// ReleasesConfig tunes release derivation (ADR-024 §5): which tags count as
// releases when they carry an analysis snapshot.
type ReleasesConfig struct {
	// TagPattern is a Go regular expression a tag name must match to derive a
	// release. Empty means the platform default (v-prefixed semver-ish tags).
	TagPattern string `yaml:"tag_pattern,omitempty" json:"tag_pattern,omitempty"`
}

// CompiledTagPattern returns the configured tag pattern, nil when unset.
// Parse validated it, so a compile failure here cannot happen for configs
// that came through Parse.
func (r *ReleasesConfig) CompiledTagPattern() *regexp.Regexp {
	if r == nil || strings.TrimSpace(r.TagPattern) == "" {
		return nil
	}
	compiled, err := regexp.Compile(r.TagPattern)
	if err != nil {
		return nil
	}
	return compiled
}

func Parse(data []byte) (*RepoConfig, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)

	var cfg RepoConfig
	if err := decoder.Decode(&cfg); err != nil {
		if strings.Contains(err.Error(), "field weaknesses not found") {
			return nil, fmt.Errorf("decode repo config: quality_gates[].weaknesses was renamed to code, which counts code findings only (ADR-037): %w", err)
		}
		return nil, fmt.Errorf("decode repo config: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func Default() *RepoConfig {
	return &RepoConfig{
		Version: CurrentVersion,
		QualityGates: []QualityGate{{
			Branches: []string{"main"},
			Code: &CodeThresholds{
				MaxCritical: intPtr(0),
				MaxHigh:     intPtr(0),
			},
		}},
	}
}

func DefaultYAML() []byte {
	return []byte(strings.Join([]string{
		"# yaml-language-server: $schema=https://hibou.dev/schemas/v1/hibou-config.schema.json",
		"version: 1",
		"",
		"# Configure branch-aware quality gates. `code` caps new first-party code",
		"# findings (SAST, DAST, manual); dependency (CVE) gates stay managed in Hibou.",
		"quality_gates:",
		"  - branches: [\"main\"]",
		"    # enforcement: advisory   # advisory (default, informational/non-blocking) | blocking",
		"    code:",
		"      max_critical: 0",
		"      max_high: 0",
		"    # cwe:                            # deny new findings of any type by CWE (ADR-037)",
		"    #   deny: [CWE-89, CWE-78]        # exact CWEs",
		"    #   deny_tree: [CWE-74]           # a CWE and everything under it (all injection)",
		"    #   deny_sets: [top25]            # CWE Top 25, owasp-top10, owasp-a01..a10",
		"    #   deny_categories: [injection]  # MITRE View 1400 categories",
		"    #   min_severity: medium          # optional; default: any severity",
		"    # coverage:",
		"    #   min_coverage: 60",
		"    #   grace: 2",
		"    #   diff_minimum: 80",
		"",
		"# Exclude files from coverage metrics:",
		"# coverage:",
		"#   exclude:",
		"#     - \"*_test.go\"",
		"#     - \"testutil/**\"",
		"",
		"# Safety-net timeout: force-close snapshot if --complete/--expect never triggers (default: 10m):",
		"# upload:",
		"#   window: 10m",
		"",
		"# Which tags derive releases when their analysis is uploaded (ADR-024).",
		"# Default matches v-prefixed semver-ish tags (v1.2.3, 1.2, v2.0.0-rc.1):",
		"# releases:",
		"#   tag_pattern: \"^payments-v\\\\d+\\\\.\\\\d+\\\\.\\\\d+$\"",
		"",
	}, "\n"))
}

func (c *RepoConfig) MatchGate(targetBranch string) *QualityGate {
	if c == nil {
		return nil
	}

	targetBranch = strings.TrimSpace(targetBranch)
	best := gateMatchCandidate{index: -1, score: -1}
	for index := range c.QualityGates {
		best = selectBetterGateMatch(best, gateMatchForBranches(c.QualityGates[index].Branches, targetBranch, index))
	}

	if best.index == -1 {
		return nil
	}

	return &c.QualityGates[best.index]
}

func (w *CodeThresholds) EnabledValue() bool {
	if w == nil || w.Enabled == nil {
		return true
	}
	return *w.Enabled
}

func (c *RepoConfig) validate() error {
	if c.Version != CurrentVersion {
		return fmt.Errorf("repo config version must be %d", CurrentVersion)
	}

	for index := range c.QualityGates {
		if err := validateQualityGate(&c.QualityGates[index], index); err != nil {
			return err
		}
	}

	if err := validateUploadConfig(c.Upload); err != nil {
		return err
	}

	if err := validateReleasesConfig(c.Releases); err != nil {
		return err
	}

	return nil
}

func validateReleasesConfig(releases *ReleasesConfig) error {
	if releases == nil || strings.TrimSpace(releases.TagPattern) == "" {
		return nil
	}
	if _, err := regexp.Compile(releases.TagPattern); err != nil {
		return fmt.Errorf("releases.tag_pattern is not a valid regular expression: %w", err)
	}
	return nil
}

type gateMatchCandidate struct {
	index int
	score int
	exact bool
}

func gateMatchForBranches(branches []string, targetBranch string, index int) gateMatchCandidate {
	best := gateMatchCandidate{index: -1, score: -1}
	for _, branch := range branches {
		candidate, ok := branchMatchCandidate(branch, targetBranch, index)
		if !ok {
			continue
		}
		best = selectBetterGateMatch(best, candidate)
	}
	return best
}

func branchMatchCandidate(branch, targetBranch string, index int) (gateMatchCandidate, bool) {
	trimmed := strings.TrimSpace(branch)
	if trimmed == "" {
		return gateMatchCandidate{}, false
	}
	exact := trimmed == targetBranch
	matched := exact
	if !matched {
		globMatch, err := path.Match(trimmed, targetBranch)
		if err != nil {
			return gateMatchCandidate{}, false
		}
		matched = globMatch
	}
	if !matched {
		return gateMatchCandidate{}, false
	}
	return gateMatchCandidate{index: index, score: branchSpecificity(trimmed), exact: exact}, true
}

func selectBetterGateMatch(current, candidate gateMatchCandidate) gateMatchCandidate {
	if candidate.index == -1 {
		return current
	}
	if current.index == -1 || (candidate.exact && !current.exact) || (candidate.exact == current.exact && candidate.score > current.score) {
		return candidate
	}
	return current
}

func validateQualityGate(gate *QualityGate, index int) error {
	if err := validateGateBranches(gate, index); err != nil {
		return err
	}
	if err := validateGateEnforcement(gate, index); err != nil {
		return err
	}
	if err := validateCodeThresholds(gate.Code, index); err != nil {
		return err
	}
	if err := validateCWEPolicy(gate.CWE, index); err != nil {
		return err
	}
	if err := validateVulnerabilityThresholds(gate.Vulnerabilities, index); err != nil {
		return err
	}
	if err := validateLicensePolicy(gate.Licenses, index); err != nil {
		return err
	}
	if err := validateSecretThresholds(gate.Secrets, index); err != nil {
		return err
	}
	return validateCoverageThresholds(gate.Coverage, index)
}

func validateSecretThresholds(thresholds *SecretThresholds, index int) error {
	if thresholds == nil {
		return nil
	}
	if thresholds.MaxNew != nil && *thresholds.MaxNew < 0 {
		return fmt.Errorf("quality_gates[%d].secrets.max_new must be >= 0", index)
	}
	return nil
}

func validateVulnerabilityThresholds(thresholds *VulnerabilityThresholds, index int) error {
	if thresholds == nil {
		return nil
	}
	for fieldName, value := range map[string]*int{
		"max_critical":  thresholds.MaxCritical,
		"max_high":      thresholds.MaxHigh,
		"max_medium":    thresholds.MaxMedium,
		"max_unknown":   thresholds.MaxUnknown,
		"max_new_total": thresholds.MaxNewTotal,
	} {
		if value != nil && *value < 0 {
			return fmt.Errorf("quality_gates[%d].vulnerabilities.%s must be >= 0", index, fieldName)
		}
	}
	return nil
}

func validateLicensePolicy(policy *LicensePolicy, index int) error {
	if policy == nil {
		return nil
	}
	for _, category := range policy.DenyCategories {
		switch strings.ToLower(strings.TrimSpace(category)) {
		case "permissive", "weak-copyleft", "copyleft", "network-copyleft", "source-available", "public-domain", "unknown":
		default:
			return fmt.Errorf("quality_gates[%d].licenses.deny_categories: unknown category %q", index, category)
		}
	}
	if value := strings.TrimSpace(policy.Evaluate); value != "" {
		switch strings.ToLower(value) {
		case LicenseEvaluateNew, LicenseEvaluateAll:
		default:
			return fmt.Errorf("quality_gates[%d].licenses.evaluate: must be %q or %q, got %q", index, LicenseEvaluateNew, LicenseEvaluateAll, value)
		}
	}
	return nil
}

func validateGateEnforcement(gate *QualityGate, index int) error {
	value := strings.TrimSpace(gate.Enforcement)
	if value == "" {
		return nil
	}
	switch strings.ToLower(value) {
	case EnforcementAdvisory, EnforcementBlocking:
		return nil
	default:
		return fmt.Errorf("quality_gates[%d].enforcement must be %q or %q", index, EnforcementAdvisory, EnforcementBlocking)
	}
}

func validateGateBranches(gate *QualityGate, index int) error {
	if len(gate.Branches) == 0 {
		return fmt.Errorf("quality_gates[%d].branches must not be empty", index)
	}
	for branchIndex, branch := range gate.Branches {
		gate.Branches[branchIndex] = strings.TrimSpace(branch)
		if gate.Branches[branchIndex] == "" {
			return fmt.Errorf("quality_gates[%d].branches[%d] must not be empty", index, branchIndex)
		}
	}
	return nil
}

func validateCodeThresholds(thresholds *CodeThresholds, index int) error {
	if thresholds == nil {
		return nil
	}
	for fieldName, value := range map[string]*int{
		"max_critical": thresholds.MaxCritical,
		"max_high":     thresholds.MaxHigh,
		"max_medium":   thresholds.MaxMedium,
	} {
		if value != nil && *value < 0 {
			return fmt.Errorf("quality_gates[%d].code.%s must be >= 0", index, fieldName)
		}
	}
	return nil
}

func validateCoverageThresholds(thresholds *CoverageThresholds, index int) error {
	if thresholds == nil {
		return nil
	}
	for fieldName, value := range map[string]*float64{
		"min_coverage": thresholds.MinCoverage,
		"grace":        thresholds.Grace,
		"diff_minimum": thresholds.DiffMinimum,
	} {
		if value != nil && (*value < 0 || *value > 100) {
			return fmt.Errorf("quality_gates[%d].coverage.%s must be between 0 and 100", index, fieldName)
		}
	}
	return nil
}

func validateUploadConfig(upload *UploadConfig) error {
	if upload == nil || strings.TrimSpace(upload.Window) == "" {
		return nil
	}
	d, err := time.ParseDuration(upload.Window)
	if err != nil {
		return fmt.Errorf("upload.window must be a valid duration: %w", err)
	}
	if d <= 0 {
		return errors.New("upload.window must be a positive duration")
	}
	return nil
}

func branchSpecificity(pattern string) int {
	return len(strings.ReplaceAll(pattern, "*", ""))
}

func intPtr(value int) *int {
	return &value
}

// CWEPolicy denies NEW findings that carry a listed CWE, whatever their type
// (ADR-037 §7). Every list goes through the filter grammar's selector
// compiler, so a gate rule and the filter reproducing it match the same
// findings.
type CWEPolicy struct {
	// Deny lists exact CWEs ("CWE-89" or 89).
	Deny []string `yaml:"deny,omitempty" json:"deny,omitempty"`
	// DenyTree lists CWEs denied together with every View 1000 descendant.
	DenyTree []string `yaml:"deny_tree,omitempty" json:"deny_tree,omitempty"`
	// DenySets lists named sets: top25, owasp-top10, owasp-a01 … owasp-a10.
	DenySets []string `yaml:"deny_sets,omitempty" json:"deny_sets,omitempty"`
	// DenyCategories lists MITRE View 1400 categories (injection, encryption, …).
	DenyCategories []string `yaml:"deny_categories,omitempty" json:"deny_categories,omitempty"`
	// Types restricts the rule to finding types; empty means every type.
	Types []string `yaml:"types,omitempty" json:"types,omitempty"`
	// MinSeverity ignores findings below it; empty means any severity.
	MinSeverity string `yaml:"min_severity,omitempty" json:"min_severity,omitempty"`
}

// CWESelectorRule is one deny list compiled into a selector, keeping the
// config path it came from for the gate reason.
type CWESelectorRule struct {
	Path     string
	Selector cwe.Selector
}

// Selectors compiles the policy's deny lists. Config validation already ran
// this, so an error here means the policy was built in code, not parsed.
func (p *CWEPolicy) Selectors() ([]CWESelectorRule, error) {
	if p == nil {
		return nil, nil
	}
	rules := make([]CWESelectorRule, 0, 4)
	for _, list := range []struct {
		field  string
		kind   string
		values []string
	}{
		{"deny", cwe.KindExact, p.Deny},
		{"deny_tree", cwe.KindTree, p.DenyTree},
		{"deny_sets", cwe.KindSet, p.DenySets},
		{"deny_categories", cwe.KindCategory, p.DenyCategories},
	} {
		for _, value := range list.values {
			selector, err := cwe.ParseSelector(list.kind, []string{value})
			if err != nil {
				return nil, fmt.Errorf("cwe.%s: %w", list.field, err)
			}
			rules = append(rules, CWESelectorRule{Path: "cwe." + list.field + " " + strings.TrimSpace(value), Selector: selector})
		}
	}
	return rules, nil
}

var cweGateTypes = map[string]struct{}{
	"sast": {}, "dast": {}, "fuzzing": {}, "manual": {}, "generic": {},
	"dependency": {}, "container": {}, "malware": {}, "secret": {},
}

var cweGateSeverities = map[string]struct{}{"critical": {}, "high": {}, "medium": {}, "unknown": {}, "low": {}, "info": {}}

// validateCWEPolicy rejects anything that would make the gate silently
// inert: a malformed id, an id or set the catalog does not know (a typo must
// not become a rule that never fires), an unknown type or severity, or a
// policy that denies nothing.
func validateCWEPolicy(policy *CWEPolicy, index int) error {
	if policy == nil {
		return nil
	}
	prefix := fmt.Sprintf("quality_gates[%d].", index)
	rules, err := policy.Selectors()
	if err != nil {
		return fmt.Errorf("%s%w", prefix, err)
	}
	if len(rules) == 0 {
		return fmt.Errorf("%scwe must list at least one of deny, deny_tree, deny_sets, deny_categories", prefix)
	}
	catalog := cwe.Default()
	for field, values := range map[string][]string{"deny": policy.Deny, "deny_tree": policy.DenyTree} {
		for _, value := range values {
			if strings.EqualFold(strings.TrimSpace(value), "none") || strings.EqualFold(strings.TrimSpace(value), "any") {
				return fmt.Errorf("%scwe.%s: %q is a filter test, not a CWE", prefix, field, value)
			}
			id, _ := cwe.Parse(value)
			if _, known := catalog.Lookup(id); !known {
				return fmt.Errorf("%scwe.%s: %s is not in the CWE catalog (version %s)", prefix, field, cwe.Format(id), catalog.Version)
			}
		}
	}
	for _, kind := range policy.Types {
		if _, ok := cweGateTypes[strings.ToLower(strings.TrimSpace(kind))]; !ok {
			return fmt.Errorf("%scwe.types: unknown finding type %q", prefix, kind)
		}
	}
	if value := strings.TrimSpace(policy.MinSeverity); value != "" {
		if _, ok := cweGateSeverities[strings.ToLower(value)]; !ok {
			return fmt.Errorf("%scwe.min_severity: unknown severity %q", prefix, value)
		}
	}
	return nil
}
