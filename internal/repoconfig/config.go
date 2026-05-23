package repoconfig

import (
	"bytes"
	"fmt"
	"path"
	"strings"

	"go.yaml.in/yaml/v3"
)

const CurrentVersion = 1

type RepoConfig struct {
	Version      int           `yaml:"version" json:"version"`
	QualityGates []QualityGate `yaml:"quality_gates,omitempty" json:"quality_gates,omitempty"`
}

type QualityGate struct {
	Branches   []string            `yaml:"branches" json:"branches"`
	Weaknesses *WeaknessThresholds `yaml:"weaknesses,omitempty" json:"weaknesses,omitempty"`
}

type WeaknessThresholds struct {
	Enabled     *bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	MaxCritical *int  `yaml:"max_critical,omitempty" json:"max_critical,omitempty"`
	MaxHigh     *int  `yaml:"max_high,omitempty" json:"max_high,omitempty"`
	MaxMedium   *int  `yaml:"max_medium,omitempty" json:"max_medium,omitempty"`
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
	return []byte(`# yaml-language-server: $schema=https://hibou.dev/schemas/v1/hibou-config.schema.json
version: 1

# Configure branch-aware weakness quality gates for code findings.
# Vulnerability (CVE) gates stay managed in Hibou itself.
quality_gates:
  - branches: ["main"]
    weaknesses:
      max_critical: 0
      max_high: 0
`)
}

func (c *RepoConfig) MatchGate(targetBranch string) *QualityGate {
	if c == nil {
		return nil
	}

	targetBranch = strings.TrimSpace(targetBranch)
	bestIndex := -1
	bestScore := -1
	bestExact := false

	for index := range c.QualityGates {
		gate := &c.QualityGates[index]
		for _, branch := range gate.Branches {
			trimmed := strings.TrimSpace(branch)
			if trimmed == "" {
				continue
			}

			exact := trimmed == targetBranch
			matched := exact
			if !matched {
				globMatch, err := path.Match(trimmed, targetBranch)
				if err != nil {
					continue
				}
				matched = globMatch
			}
			if !matched {
				continue
			}

			score := branchSpecificity(trimmed)
			if bestIndex == -1 || (exact && !bestExact) || (exact == bestExact && score > bestScore) {
				bestIndex = index
				bestScore = score
				bestExact = exact
			}
		}
	}

	if bestIndex == -1 {
		return nil
	}

	return &c.QualityGates[bestIndex]
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
		gate := &c.QualityGates[index]
		if len(gate.Branches) == 0 {
			return fmt.Errorf("quality_gates[%d].branches must not be empty", index)
		}
		for branchIndex, branch := range gate.Branches {
			gate.Branches[branchIndex] = strings.TrimSpace(branch)
			if gate.Branches[branchIndex] == "" {
				return fmt.Errorf("quality_gates[%d].branches[%d] must not be empty", index, branchIndex)
			}
		}
		if gate.Weaknesses != nil {
			for fieldName, value := range map[string]*int{
				"max_critical": gate.Weaknesses.MaxCritical,
				"max_high":     gate.Weaknesses.MaxHigh,
				"max_medium":   gate.Weaknesses.MaxMedium,
			} {
				if value != nil && *value < 0 {
					return fmt.Errorf("quality_gates[%d].weaknesses.%s must be >= 0", index, fieldName)
				}
			}
		}
	}

	return nil
}

func branchSpecificity(pattern string) int {
	return len(strings.ReplaceAll(pattern, "*", ""))
}

func intPtr(value int) *int {
	return &value
}
