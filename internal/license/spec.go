package license

import (
	"sort"
	"strings"
)

// Spec is a declared license policy — what an organization or a repository
// writes down. Policy is the evaluation-time subset used to judge one
// component's licenses; Spec additionally carries the knobs that shape HOW the
// gate runs (package exemptions, delta scope).
//
// It exists because three places now produce the same policy — an org row in
// `license_policies`, a repository's `.hibou.yaml`, and the built-in defaults —
// and they must be comparable to each other. Without a single type, "is this
// repo's override looser than the org's policy?" cannot be answered at all.
type Spec struct {
	DenyCategories []string
	Deny           []string
	Allow          []string
	ExemptPurls    []string
	DenyUnknown    bool
	// Evaluate is EvaluateNew or EvaluateAll.
	Evaluate string
}

const (
	// EvaluateNew gates only components a change introduces.
	EvaluateNew = "new"
	// EvaluateAll gates every component in the snapshot.
	EvaluateAll = "all"
)

// Policy narrows a Spec to the evaluation-time rules.
func (s Spec) Policy() Policy {
	return Policy{
		DenyCategories: s.DenyCategories,
		Deny:           s.Deny,
		Allow:          s.Allow,
		DenyUnknown:    s.DenyUnknown,
	}
}

// Empty reports whether the spec denies nothing, in which case the gate is
// skipped rather than evaluated as a pass.
func (s Spec) Empty() bool {
	return s.Policy().Empty()
}

// EvaluateValue applies the delta-scoped default.
func (s Spec) EvaluateValue() string {
	if strings.EqualFold(strings.TrimSpace(s.Evaluate), EvaluateAll) {
		return EvaluateAll
	}
	return EvaluateNew
}

// Relation describes how one spec compares to another in strictness. Mixed is a
// first-class answer, not a failure to decide: a policy can genuinely deny more
// categories while also allowing more unknowns, and collapsing that into a single
// verdict would hide the half a compliance reader cares about.
type Relation string

const (
	RelationEquivalent Relation = "equivalent"
	RelationStricter   Relation = "stricter"
	RelationLooser     Relation = "looser"
	RelationMixed      Relation = "mixed"
)

// Difference is one axis on which two specs disagree. Added and Removed carry
// the DELTA for set-valued axes, because the whole-set values are unreadable on
// any real policy — a reader needs "gained network-copyleft", not two
// twelve-element lists to diff by eye.
type Difference struct {
	Field     string
	Direction Relation
	Base      string
	Override  string
	Added     []string
	Removed   []string
}

// Compare reports how override relates to base, plus the axis-by-axis detail.
//
// Only Looser and Mixed matter for compliance: a repository tightening its own
// policy needs no oversight, whereas one loosening the org's needs to be
// findable. That asymmetry is why the differences are returned rather than just
// the verdict.
func Compare(base, override Spec) (Relation, []Difference) {
	differences := make([]Difference, 0, 6)

	// Denial sets: a superset denies more, so it is stricter.
	differences = appendSetDifference(differences, "deny_categories", base.DenyCategories, override.DenyCategories, true)
	differences = appendSetDifference(differences, "deny", base.Deny, override.Deny, true)
	// Permission sets invert: allowing or exempting more is looser.
	differences = appendSetDifference(differences, "allow", base.Allow, override.Allow, false)
	differences = appendSetDifference(differences, "exempt_purls", base.ExemptPurls, override.ExemptPurls, false)

	if base.DenyUnknown != override.DenyUnknown {
		direction := RelationLooser
		if override.DenyUnknown {
			direction = RelationStricter
		}
		differences = append(differences, Difference{
			Field:     "deny_unknown",
			Direction: direction,
			Base:      boolText(base.DenyUnknown),
			Override:  boolText(override.DenyUnknown),
		})
	}

	if base.EvaluateValue() != override.EvaluateValue() {
		// Judging the whole tree is stricter than judging only what a change adds.
		direction := RelationLooser
		if override.EvaluateValue() == EvaluateAll {
			direction = RelationStricter
		}
		differences = append(differences, Difference{
			Field:     "evaluate",
			Direction: direction,
			Base:      base.EvaluateValue(),
			Override:  override.EvaluateValue(),
		})
	}

	return combineRelations(differences), differences
}

// appendSetDifference records how two sets differ. supersetIsStricter says which
// way the axis points: adding to a deny list tightens, adding to an allow list
// loosens.
func appendSetDifference(into []Difference, field string, base, override []string, supersetIsStricter bool) []Difference {
	baseSet, overrideSet := normalizedSet(base), normalizedSet(override)
	added, removed := setDelta(baseSet, overrideSet)
	if len(added) == 0 && len(removed) == 0 {
		return into
	}

	var direction Relation
	switch {
	case len(added) > 0 && len(removed) > 0:
		direction = RelationMixed
	case len(added) > 0:
		direction = relationFor(supersetIsStricter)
	default:
		direction = relationFor(!supersetIsStricter)
	}

	return append(into, Difference{
		Field:     field,
		Direction: direction,
		Base:      strings.Join(sortedKeys(baseSet), ", "),
		Override:  strings.Join(sortedKeys(overrideSet), ", "),
		Added:     added,
		Removed:   removed,
	})
}

func relationFor(stricter bool) Relation {
	if stricter {
		return RelationStricter
	}
	return RelationLooser
}

// combineRelations reduces per-axis directions to one verdict. Any pairing of
// stricter and looser is Mixed, because there is no honest way to net them off.
func combineRelations(differences []Difference) Relation {
	stricter, looser := false, false
	for _, difference := range differences {
		switch difference.Direction {
		case RelationMixed:
			return RelationMixed
		case RelationStricter:
			stricter = true
		case RelationLooser:
			looser = true
		}
	}
	switch {
	case stricter && looser:
		return RelationMixed
	case stricter:
		return RelationStricter
	case looser:
		return RelationLooser
	default:
		return RelationEquivalent
	}
}

// normalizedSet keys entries so casing, padding and wrapping parens cannot make
// two spellings of one rule look like a policy difference.
func normalizedSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		key := strings.ToLower(NormalizeID(value))
		if key == "" {
			continue
		}
		set[key] = struct{}{}
	}
	return set
}

func setDelta(base, override map[string]struct{}) (added, removed []string) {
	for key := range override {
		if _, ok := base[key]; !ok {
			added = append(added, key)
		}
	}
	for key := range base {
		if _, ok := override[key]; !ok {
			removed = append(removed, key)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

func sortedKeys(set map[string]struct{}) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func boolText(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

// MatchesPurlGlob reports whether a package purl matches any exemption glob.
// Matching is case-insensitive and `*` crosses `/`: purls are not paths, and
// path.Match refuses to let a wildcard span a separator, so `pkg:npm/@types/*`
// would never match a scoped name.
//
// It lives here rather than in the gate because both the gate and the policy
// simulator must answer "is this package exempt?" identically — a second copy
// would let the preview disagree with the check it is previewing.
func MatchesPurlGlob(purl string, globs []string) bool {
	if len(globs) == 0 {
		return false
	}
	normalized := strings.ToLower(strings.TrimSpace(purl))
	if normalized == "" {
		return false
	}
	for _, glob := range globs {
		pattern := strings.ToLower(strings.TrimSpace(glob))
		if pattern == "" {
			continue
		}
		if pattern == normalized || globMatch(pattern, normalized) {
			return true
		}
	}
	return false
}

// globMatch is a minimal `*`-only matcher.
func globMatch(pattern, value string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == value
	}
	if !strings.HasPrefix(value, parts[0]) {
		return false
	}
	value = value[len(parts[0]):]
	last := parts[len(parts)-1]
	for _, part := range parts[1 : len(parts)-1] {
		index := strings.Index(value, part)
		if index < 0 {
			return false
		}
		value = value[index+len(part):]
	}
	return strings.HasSuffix(value, last)
}
