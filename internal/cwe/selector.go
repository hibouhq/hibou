package cwe

import (
	"fmt"
	"strings"
)

// Selector kinds, as they appear in the filter grammar and in .hibou.yaml.
const (
	// KindExact matches the listed ids ("cwe:79,89").
	KindExact = "cwe"
	// KindTree matches an id or any View 1000 descendant ("cwe-tree:74").
	KindTree = "cwe-tree"
	// KindSet matches the members of a named set ("cwe-set:top25").
	KindSet = "cwe-set"
	// KindCategory matches the weaknesses of a View 1400 category
	// ("cwe-category:injection").
	KindCategory = "cwe-category"
)

// Selector is one CWE condition, already expanded against the catalog: a
// finding matches when it carries any of IDs, or — for the coverage tests —
// carries no CWE at all (None) or at least one (Any). The filter compiler and
// the quality gate both evaluate selectors, so a gate rule and the filter that
// reproduces it always match the same findings.
type Selector struct {
	Kind   string
	Values []string
	IDs    []int
	None   bool
	Any    bool
}

// SetLookup resolves a named-set slug to its members. The embedded MITRE
// catalog is the default; an org-scoped lookup (custom CWE lists stored like
// search presets) can wrap it without touching the compiler or the gate.
type SetLookup interface {
	LookupSet(slug string) (Set, bool)
	SetSlugs() []string
}

// LookupSet implements SetLookup over the catalog's MITRE sets.
func (c *Catalog) LookupSet(slug string) (Set, bool) { return c.Set(slug) }

// ParseSelector validates and expands one qualifier against the embedded
// catalog's sets. Ids are accepted in any normalizer spelling; an id the
// catalog does not know is still valid (a scanner may report it), while an
// unknown set slug is an error.
func ParseSelector(kind string, values []string) (Selector, error) {
	return ParseSelectorWith(kind, values, Default())
}

// ParseSelectorWith is ParseSelector with an explicit set lookup.
func ParseSelectorWith(kind string, values []string, sets SetLookup) (Selector, error) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	selector := Selector{Kind: kind}
	if len(values) == 0 {
		return Selector{}, fmt.Errorf("%s requires a value", kind)
	}
	catalog := Default()
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		selector.Values = append(selector.Values, value)
		switch kind {
		case KindExact:
			switch strings.ToLower(value) {
			case "none":
				selector.None = true
				continue
			case "any":
				selector.Any = true
				continue
			}
			id, ok := Parse(value)
			if !ok {
				return Selector{}, fmt.Errorf("%s: %q is not a CWE id", kind, value)
			}
			selector.IDs = append(selector.IDs, id)
		case KindTree:
			id, ok := Parse(value)
			if !ok {
				return Selector{}, fmt.Errorf("%s: %q is not a CWE id", kind, value)
			}
			selector.IDs = append(selector.IDs, catalog.Descendants(id)...)
		case KindSet:
			set, ok := sets.LookupSet(value)
			if !ok {
				return Selector{}, fmt.Errorf("%s: unknown set %q (try %s)", kind, value, strings.Join(sets.SetSlugs(), ", "))
			}
			selector.IDs = append(selector.IDs, set.Members...)
		case KindCategory:
			category, ok := catalog.Category(value)
			if !ok {
				return Selector{}, fmt.Errorf("%s: unknown category %q (try %s)", kind, value, strings.Join(catalog.CategorySlugs()[:5], ", ")+", …")
			}
			selector.IDs = append(selector.IDs, category.Members...)
		default:
			return Selector{}, fmt.Errorf("unknown CWE selector %q", kind)
		}
	}
	selector.IDs = Dedupe(selector.IDs)
	return selector, nil
}

// Matches reports whether a finding carrying ids satisfies the selector.
func (s Selector) Matches(ids []int) bool {
	if len(ids) == 0 {
		return s.None
	}
	if s.Any {
		return true
	}
	for _, id := range ids {
		for _, wanted := range s.IDs {
			if id == wanted {
				return true
			}
		}
	}
	return false
}

// Match returns the first of ids the selector matches, for explaining why
// (a gate reason names the CWE that tripped it).
func (s Selector) Match(ids []int) (int, bool) {
	if s.Any && len(ids) > 0 {
		return ids[0], true
	}
	for _, id := range ids {
		for _, wanted := range s.IDs {
			if id == wanted {
				return id, true
			}
		}
	}
	return 0, false
}

// String renders the selector in filter-grammar form ("cwe-tree:74").
func (s Selector) String() string {
	return s.Kind + ":" + strings.Join(s.Values, ",")
}
