package incident

import (
	"path"
	"strings"
	"time"

	"github.com/hibouhq/hibou/internal/filterquery"
	"github.com/hibouhq/hibou/internal/repoconfig"
)

// Rule is an incident rule after resolution: defaults filled, the source it
// came from recorded (ADR-053 §1).
type Rule struct {
	Match    string        `json:"match"`
	Kind     string        `json:"kind,omitempty"`
	Refs     []string      `json:"refs,omitempty"`
	Regimes  []string      `json:"regimes"`
	Priority string        `json:"priority"`
	Due      time.Duration `json:"-"`
	DueText  string        `json:"due,omitempty"`
	Locked   bool          `json:"locked,omitempty"`
	// Source: org-locked, repo, org, or builtin.
	Source string `json:"source"`
}

// Rule sources.
const (
	SourceOrgLocked = "org-locked"
	SourceRepo      = "repo"
	SourceOrg       = "org"
	SourceBuiltin   = "builtin"
)

// BuiltinRules are the defaults a repository gets when neither it nor its
// organisation writes rules: exploited, verified-secret and malware findings.
func BuiltinRules() []repoconfig.IncidentRule {
	return []repoconfig.IncidentRule{
		{Match: "exploited:true", Regimes: []string{RegimeCRA}, Priority: "P1"},
		{Match: "type:secret verified:true", Priority: "P1"},
		{Match: "type:malware", Priority: "P1"},
	}
}

// EffectiveRules resolves the rules a repository runs: locked organisation
// rules first, then the repository's own rules when it wrote any, else the
// organisation defaults when set, else the built-ins.
func EffectiveRules(locked []repoconfig.IncidentRule, orgDefaults []repoconfig.IncidentRule, orgDefaultsSet bool, repo *repoconfig.IncidentsConfig) []Rule {
	out := []Rule{}
	for _, rule := range locked {
		out = append(out, resolveRule(rule, SourceOrgLocked, true))
	}
	switch {
	case repo != nil && repo.RulesSet:
		for _, rule := range repo.Rules {
			out = append(out, resolveRule(rule, SourceRepo, false))
		}
	case orgDefaultsSet:
		for _, rule := range orgDefaults {
			out = append(out, resolveRule(rule, SourceOrg, false))
		}
	default:
		for _, rule := range BuiltinRules() {
			out = append(out, resolveRule(rule, SourceBuiltin, false))
		}
	}
	return out
}

func resolveRule(rule repoconfig.IncidentRule, source string, locked bool) Rule {
	out := Rule{
		Match:    strings.TrimSpace(rule.Match),
		Kind:     rule.Kind,
		Refs:     append([]string(nil), rule.Refs...),
		Regimes:  append([]string(nil), rule.Regimes...),
		Priority: rule.Priority,
		DueText:  rule.Due,
		Locked:   locked,
		Source:   source,
	}
	if len(out.Regimes) == 0 {
		out.Regimes = []string{RegimeInternal}
	}
	if out.Priority == "" {
		out.Priority = "P2"
	}
	if rule.Due != "" {
		if due, err := repoconfig.ParseDue(rule.Due); err == nil {
			out.Due = due
		}
	}
	return out
}

// FindingFacts is what a rule needs to know about a matched finding.
type FindingFacts struct {
	Type      string
	Exploited bool
}

// DeriveKind is the kind a matched finding opens (ADR-053 §1): secrets open
// secret leaks, malware opens malware, an exploited dependency matched by a
// rule that asks for exploitation opens an exploited vulnerability, anything
// else a policy breach. An explicit kind wins when the finding can carry it.
func DeriveKind(rule Rule, finding FindingFacts) string {
	derived := KindPolicyBreach
	switch {
	case finding.Type == "secret":
		derived = KindSecretLeak
	case finding.Type == "malware":
		derived = KindMalware
	case finding.Exploited && MatchAsksForExploitation(rule.Match) && componentType(finding.Type):
		derived = KindExploitedVulnerability
	}
	if rule.Kind != "" && KindFits(rule.Kind, finding.Type) {
		return rule.Kind
	}
	return derived
}

func componentType(findingType string) bool {
	return findingType == "dependency" || findingType == "container"
}

// KindFits reports whether a finding of this type can carry the kind.
func KindFits(kind, findingType string) bool {
	switch kind {
	case KindSecretLeak:
		return findingType == "secret"
	case KindMalware:
		return findingType == "malware"
	case KindExploitedVulnerability:
		return componentType(findingType)
	case KindPolicyBreach:
		return true
	}
	return false
}

// MatchAsksForExploitation reports whether a match expression requires
// exploitation positively (exploited:true outside a negation).
func MatchAsksForExploitation(match string) bool {
	node, err := filterquery.Parse(match)
	if err != nil {
		return false
	}
	return asksForExploitation(node)
}

func asksForExploitation(node filterquery.Node) bool {
	switch n := node.(type) {
	case filterquery.QualifierNode:
		value := strings.ToLower(n.Value)
		return n.Key == "exploited" && !n.Negated && (value == "true" || value == "yes")
	case filterquery.AndNode:
		return asksForExploitation(n.Left) || asksForExploitation(n.Right)
	case filterquery.OrNode:
		return asksForExploitation(n.Left) && asksForExploitation(n.Right)
	case filterquery.GroupNode:
		return asksForExploitation(n.Child)
	}
	return false
}

// DefaultRefs is where a kind's findings must be seen when a rule says
// nothing: everywhere for credentials and malicious packages, which are a
// problem the moment they exist; released snapshots otherwise, since the gate
// already stops new ones and the incident is about what shipped.
func DefaultRefs(kind string) []string {
	switch kind {
	case KindSecretLeak, KindMalware:
		return []string{repoconfig.RefsAll}
	default:
		return []string{repoconfig.RefsReleased}
	}
}

// RefInfo describes a snapshot's ref for selector matching.
type RefInfo struct {
	Name      string
	Type      string // branch | tag | pull_request
	IsDefault bool
	Released  bool // pinned by a release
}

// RefSelected reports whether a snapshot of this ref is in a rule's scope.
func RefSelected(selectors []string, ref RefInfo) bool {
	for _, selector := range selectors {
		switch selector {
		case repoconfig.RefsAll:
			return true
		case repoconfig.RefsDefault:
			if ref.IsDefault {
				return true
			}
		case repoconfig.RefsReleased:
			if ref.Released {
				return true
			}
		default:
			if ref.Type == "branch" {
				if matched, err := path.Match(selector, ref.Name); err == nil && matched {
					return true
				}
			}
		}
	}
	return false
}

// RefsFor returns a rule's selectors, falling back to the kind's default.
func RefsFor(rule Rule, kind string) []string {
	if len(rule.Refs) > 0 {
		return rule.Refs
	}
	return DefaultRefs(kind)
}

// SubjectFor is what an incident opened by a finding is about: the advisory
// row for an exploited vulnerability (aliases never split it, ADR-053 §3),
// the finding otherwise.
func SubjectFor(kind, fingerprint, advisoryID string) (string, string) {
	if kind == KindExploitedVulnerability && advisoryID != "" {
		return SubjectAdvisory, advisoryID
	}
	return SubjectFinding, fingerprint
}
