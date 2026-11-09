package repoconfig

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/hibouhq/hibou/internal/filterquery"
)

// ProductConfig names the product a repository ships (ADR-053 §4a): the
// identity VEX statements and advisories use for its releases. The purl is
// version-less; release versions are appended. Without it hibou uses
// pkg:generic/<org>/<repo>.
type ProductConfig struct {
	Name string `yaml:"name,omitempty" json:"name,omitempty"`
	PURL string `yaml:"purl,omitempty" json:"purl,omitempty"`
	// CPE is an optional alias, for NVD and CPE-based consumers, with the
	// version field left as "*" or "-" (filled per release).
	CPE string `yaml:"cpe,omitempty" json:"cpe,omitempty"`
}

// IncidentsConfig is the `incidents` section (ADR-053 §1).
type IncidentsConfig struct {
	// Owner receives signals and countdowns: "user:<login>" or "team:<slug>".
	Owner string `yaml:"owner,omitempty" json:"owner,omitempty"`
	// Rules, when present, replace the organisation defaults (locked
	// organisation rules always apply first). An explicit empty list turns
	// every unlocked rule off; an absent key keeps the defaults.
	Rules []IncidentRule `yaml:"rules,omitempty" json:"rules,omitempty"`
	// RulesSet records whether `rules` was written, so an explicit empty
	// list differs from an absent one.
	RulesSet bool `yaml:"-" json:"rules_set,omitempty"`
}

// UnmarshalYAML records whether `rules` was present.
func (c *IncidentsConfig) UnmarshalYAML(node *yaml.Node) error {
	type plain IncidentsConfig
	var decoded plain
	if err := node.Decode(&decoded); err != nil {
		return err
	}
	*c = IncidentsConfig(decoded)
	for index := 0; index+1 < len(node.Content); index += 2 {
		if node.Content[index].Value == "rules" {
			c.RulesSet = true
		}
	}
	return nil
}

// IncidentRule opens an incident when a finding matches (ADR-053 §1).
type IncidentRule struct {
	// Match is a filter expression in the search grammar (ADR-013).
	Match string `yaml:"match" json:"match"`
	// Kind overrides the kind derived from what matched.
	Kind string `yaml:"kind,omitempty" json:"kind,omitempty"`
	// Refs selects where the finding must be seen: default, all, released,
	// or branch globs. Empty: the kind's default.
	Refs RefSelector `yaml:"refs,omitempty" json:"refs,omitempty"`
	// Regimes attach external obligations; empty means [internal].
	Regimes []string `yaml:"regimes,omitempty" json:"regimes,omitempty"`
	// Priority is the team's P1–P3 order; empty means P2.
	Priority string `yaml:"priority,omitempty" json:"priority,omitempty"`
	// Due is an internal deadline for policy breaches, e.g. 7d or 48h.
	Due string `yaml:"due,omitempty" json:"due,omitempty"`
	// Locked marks an organisation rule repositories cannot remove; ignored
	// in .hibou.yaml.
	Locked bool `yaml:"-" json:"locked,omitempty"`
}

// RefSelector accepts a single string or a list in YAML and JSON.
type RefSelector []string

func (r *RefSelector) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		*r = RefSelector{node.Value}
		return nil
	}
	var values []string
	if err := node.Decode(&values); err != nil {
		return err
	}
	*r = values
	return nil
}

func (r *RefSelector) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*r = RefSelector{single}
		return nil
	}
	var values []string
	if err := json.Unmarshal(data, &values); err != nil {
		return err
	}
	*r = values
	return nil
}

// Reserved ref keywords (ADR-053 §1).
const (
	RefsDefault  = "default"
	RefsAll      = "all"
	RefsReleased = "released"
)

var (
	incidentKinds = map[string]struct{}{
		"exploited_vulnerability": {}, "severe_incident": {}, "secret_leak": {}, "malware": {}, "policy_breach": {},
	}
	nationalRegimePattern = regexp.MustCompile(`^national:[a-z0-9][a-z0-9_-]{0,31}$`)
	ownerPattern          = regexp.MustCompile(`^(user|team):[A-Za-z0-9._-]+$`)
	duePattern            = regexp.MustCompile(`^(\d+)(h|d)$`)
)

// IncidentKindKnown reports whether kind is a registered incident kind.
func IncidentKindKnown(kind string) bool {
	_, ok := incidentKinds[kind]
	return ok
}

// RegimeKnown reports whether a regime name is well-formed: a built-in, or a
// national regime the organisation configures.
func RegimeKnown(regime string) bool {
	switch regime {
	case "cra-article-14", "nis2-article-23", "internal":
		return true
	}
	return nationalRegimePattern.MatchString(regime)
}

// ParseDue parses an internal deadline such as "7d" or "48h".
func ParseDue(value string) (time.Duration, error) {
	match := duePattern.FindStringSubmatch(strings.TrimSpace(value))
	if match == nil {
		return 0, fmt.Errorf("due must look like 7d or 48h (got %q)", value)
	}
	var amount int
	_, _ = fmt.Sscanf(match[1], "%d", &amount)
	if amount <= 0 || amount > 3650 {
		return 0, fmt.Errorf("due out of range (got %q)", value)
	}
	if match[2] == "d" {
		return time.Duration(amount) * 24 * time.Hour, nil
	}
	return time.Duration(amount) * time.Hour, nil
}

// ValidateIncidentRule checks one rule; index names it in errors.
func ValidateIncidentRule(rule IncidentRule, index int) error {
	match := strings.TrimSpace(rule.Match)
	if match == "" {
		return fmt.Errorf("incidents.rules[%d].match is required", index)
	}
	node, err := filterquery.Parse(match)
	if err != nil {
		return fmt.Errorf("incidents.rules[%d].match: %w", index, err)
	}
	if _, err := filterquery.ToSQL(node, 2); err != nil {
		return fmt.Errorf("incidents.rules[%d].match: %w", index, err)
	}
	if rule.Kind != "" && !IncidentKindKnown(rule.Kind) {
		return fmt.Errorf("incidents.rules[%d].kind %q is not a known kind", index, rule.Kind)
	}
	for _, ref := range rule.Refs {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			return fmt.Errorf("incidents.rules[%d].refs has an empty entry", index)
		}
		if ref == RefsDefault || ref == RefsAll || ref == RefsReleased {
			continue
		}
		if _, err := path.Match(ref, "x"); err != nil {
			return fmt.Errorf("incidents.rules[%d].refs %q is not a valid glob: %w", index, ref, err)
		}
	}
	for _, regime := range rule.Regimes {
		if !RegimeKnown(regime) {
			return fmt.Errorf("incidents.rules[%d].regimes: unknown regime %q", index, regime)
		}
	}
	switch rule.Priority {
	case "", "P1", "P2", "P3":
	default:
		return fmt.Errorf("incidents.rules[%d].priority must be P1, P2 or P3", index)
	}
	if rule.Due != "" {
		if _, err := ParseDue(rule.Due); err != nil {
			return fmt.Errorf("incidents.rules[%d].%w", index, err)
		}
	}
	return nil
}

func validateIncidentsConfig(cfg *IncidentsConfig) error {
	if cfg == nil {
		return nil
	}
	if owner := strings.TrimSpace(cfg.Owner); owner != "" && !ownerPattern.MatchString(owner) {
		return fmt.Errorf("incidents.owner must be user:<login> or team:<slug> (got %q)", cfg.Owner)
	}
	for index, rule := range cfg.Rules {
		if err := ValidateIncidentRule(rule, index); err != nil {
			return err
		}
	}
	return nil
}

func validateProductConfig(cfg *ProductConfig) error {
	if cfg == nil {
		return nil
	}
	if purl := strings.TrimSpace(cfg.PURL); purl != "" {
		if !strings.HasPrefix(purl, "pkg:") || !strings.Contains(purl, "/") {
			return fmt.Errorf("product.purl must be a package URL such as pkg:generic/<vendor>/<product> (got %q)", purl)
		}
		if strings.Contains(purl[strings.LastIndex(purl, "/"):], "@") {
			return fmt.Errorf("product.purl must not carry a version; release versions are appended (got %q)", purl)
		}
	}
	if cpe := strings.TrimSpace(cfg.CPE); cpe != "" && !strings.HasPrefix(cpe, "cpe:2.3:") {
		return fmt.Errorf("product.cpe must be a CPE 2.3 name (got %q)", cpe)
	}
	return nil
}
