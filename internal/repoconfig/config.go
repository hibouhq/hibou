package repoconfig

import (
	"bytes"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

const CurrentVersion = 1

type RepoConfig struct {
	Version      int             `yaml:"version" json:"version"`
	QualityGates []QualityGate   `yaml:"quality_gates,omitempty" json:"quality_gates,omitempty"`
	Coverage     *CoverageConfig `yaml:"coverage,omitempty" json:"coverage,omitempty"`
	Upload       *UploadConfig   `yaml:"upload,omitempty" json:"upload,omitempty"`
}

type QualityGate struct {
	Branches        []string                 `yaml:"branches" json:"branches"`
	Weaknesses      *WeaknessThresholds      `yaml:"weaknesses,omitempty" json:"weaknesses,omitempty"`
	Vulnerabilities *VulnerabilityThresholds `yaml:"vulnerabilities,omitempty" json:"vulnerabilities,omitempty"`
	Licenses        *LicensePolicy           `yaml:"licenses,omitempty" json:"licenses,omitempty"`
	Coverage        *CoverageThresholds      `yaml:"coverage,omitempty" json:"coverage,omitempty"`
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

type WeaknessThresholds struct {
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
	// MaxNewTotal caps new vulnerabilities of any severity.
	MaxNewTotal *int `yaml:"max_new_total,omitempty" json:"max_new_total,omitempty"`
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
}

// DenyUnknownValue applies the fail-closed default.
func (p *LicensePolicy) DenyUnknownValue() bool {
	if p == nil || p.DenyUnknown == nil {
		return true
	}
	return *p.DenyUnknown
}

type CoverageConfig struct {
	Exclude []string `yaml:"exclude,omitempty" json:"exclude,omitempty"`
}

type UploadConfig struct {
	Window string `yaml:"window,omitempty" json:"window,omitempty"`
}

func Parse(data []byte) (*RepoConfig, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)

	var cfg RepoConfig
	if err := decoder.Decode(&cfg); err != nil {
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
			Weaknesses: &WeaknessThresholds{
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
		"# Configure branch-aware weakness quality gates for code findings.",
		"# Vulnerability (CVE) gates stay managed in Hibou itself.",
		"quality_gates:",
		"  - branches: [\"main\"]",
		"    # enforcement: advisory   # advisory (default, informational/non-blocking) | blocking",
		"    weaknesses:",
		"      max_critical: 0",
		"      max_high: 0",
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

func (w *WeaknessThresholds) EnabledValue() bool {
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
	if err := validateWeaknessThresholds(gate.Weaknesses, index); err != nil {
		return err
	}
	if err := validateVulnerabilityThresholds(gate.Vulnerabilities, index); err != nil {
		return err
	}
	if err := validateLicensePolicy(gate.Licenses, index); err != nil {
		return err
	}
	return validateCoverageThresholds(gate.Coverage, index)
}

func validateVulnerabilityThresholds(thresholds *VulnerabilityThresholds, index int) error {
	if thresholds == nil {
		return nil
	}
	for fieldName, value := range map[string]*int{
		"max_critical":  thresholds.MaxCritical,
		"max_high":      thresholds.MaxHigh,
		"max_medium":    thresholds.MaxMedium,
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

func validateWeaknessThresholds(thresholds *WeaknessThresholds, index int) error {
	if thresholds == nil {
		return nil
	}
	for fieldName, value := range map[string]*int{
		"max_critical": thresholds.MaxCritical,
		"max_high":     thresholds.MaxHigh,
		"max_medium":   thresholds.MaxMedium,
	} {
		if value != nil && *value < 0 {
			return fmt.Errorf("quality_gates[%d].weaknesses.%s must be >= 0", index, fieldName)
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
