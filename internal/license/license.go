// Package license categorizes SPDX license identifiers and evaluates license
// policies. Categories exist because deny-lists of individual ids are
// unmaintainable: what a policy means is "no copyleft", not a race to
// enumerate every GPL variant.
package license

import (
	"path"
	"strings"
)

type Category string

const (
	CategoryPermissive      Category = "permissive"
	CategoryWeakCopyleft    Category = "weak-copyleft"
	CategoryCopyleft        Category = "copyleft"
	CategoryNetworkCopyleft Category = "network-copyleft"
	CategorySourceAvailable Category = "source-available"
	CategoryPublicDomain    Category = "public-domain"
	CategoryUnknown         Category = "unknown"
)

// categoryByPrefix maps SPDX id prefixes (case-insensitive, longest match
// wins) to categories. Derived from the ScanCode/ClearlyDefined
// categorization of the SPDX license list.
var categoryByPrefix = map[string]Category{
	// permissive
	"mit":        CategoryPermissive,
	"mit-0":      CategoryPermissive,
	"apache-":    CategoryPermissive,
	"bsd-":       CategoryPermissive,
	"isc":        CategoryPermissive,
	"zlib":       CategoryPermissive,
	"x11":        CategoryPermissive,
	"curl":       CategoryPermissive,
	"openssl":    CategoryPermissive,
	"python-":    CategoryPermissive,
	"psf-":       CategoryPermissive,
	"ruby":       CategoryPermissive,
	"artistic-":  CategoryPermissive,
	"boost":      CategoryPermissive,
	"bsl-1.0":    CategoryPermissive, // Boost Software License, NOT BUSL
	"ftl":        CategoryPermissive,
	"icu":        CategoryPermissive,
	"ijg":        CategoryPermissive,
	"ofl-":       CategoryPermissive,
	"postgresql": CategoryPermissive,
	"w3c":        CategoryPermissive,
	"ncsa":       CategoryPermissive,
	"php-":       CategoryPermissive,
	"beerware":   CategoryPermissive,
	"blueoak-":   CategoryPermissive,
	"0bsd":       CategoryPermissive,

	// public domain
	"cc0-":      CategoryPublicDomain,
	"unlicense": CategoryPublicDomain,
	"wtfpl":     CategoryPublicDomain,

	// weak copyleft
	"lgpl-":  CategoryWeakCopyleft,
	"mpl-":   CategoryWeakCopyleft,
	"epl-":   CategoryWeakCopyleft,
	"eupl-":  CategoryWeakCopyleft,
	"cddl-":  CategoryWeakCopyleft,
	"cpl-":   CategoryWeakCopyleft,
	"ms-rl":  CategoryWeakCopyleft,
	"osl-":   CategoryWeakCopyleft,
	"cecill": CategoryWeakCopyleft,

	// copyleft
	"gpl-": CategoryCopyleft,

	// network copyleft
	"agpl-": CategoryNetworkCopyleft,
	"sspl-": CategoryNetworkCopyleft,

	// source-available (not open source)
	"busl-":          CategorySourceAvailable,
	"elastic-":       CategorySourceAvailable,
	"commons-clause": CategorySourceAvailable,
}

// Categorize maps one license identifier (SPDX id, expression fragment, or
// free-form name) to a category. Anything unrecognized is CategoryUnknown —
// unreviewed is a state, not a pass.
func Categorize(id string) Category {
	normalized := strings.ToLower(strings.TrimSpace(id))
	if normalized == "" {
		return CategoryUnknown
	}
	// GPL with linking exceptions behaves weak ("GPL-2.0-with-classpath-exception",
	// "GPL-2.0-only WITH Classpath-exception-2.0").
	if strings.HasPrefix(normalized, "gpl-") && strings.Contains(normalized, "exception") {
		return CategoryWeakCopyleft
	}
	best := CategoryUnknown
	bestLen := 0
	for prefix, category := range categoryByPrefix {
		if strings.HasPrefix(normalized, prefix) && len(prefix) > bestLen {
			best = category
			bestLen = len(prefix)
		}
	}
	return best
}

// CategorizeAll reduces a component's license list to its most restrictive
// category; an empty list is unknown.
func CategorizeAll(ids []string) Category {
	if len(ids) == 0 {
		return CategoryUnknown
	}
	best := CategoryPermissive
	seen := false
	for _, id := range ids {
		for _, part := range splitExpression(id) {
			category := Categorize(part)
			seen = true
			if rank(category) > rank(best) {
				best = category
			}
		}
	}
	if !seen {
		return CategoryUnknown
	}
	return best
}

// splitExpression breaks an SPDX expression ("MIT OR GPL-2.0-only") into
// atomic ids; WITH-exception clauses stay attached to their license.
func splitExpression(expression string) []string {
	normalized := strings.ReplaceAll(expression, "(", " ")
	normalized = strings.ReplaceAll(normalized, ")", " ")
	fields := strings.Fields(normalized)
	out := make([]string, 0, len(fields))
	for i := 0; i < len(fields); i++ {
		field := fields[i]
		upper := strings.ToUpper(field)
		if upper == "AND" || upper == "OR" {
			continue
		}
		if upper == "WITH" && len(out) > 0 && i+1 < len(fields) {
			out[len(out)-1] += " WITH " + fields[i+1]
			i++
			continue
		}
		out = append(out, field)
	}
	if len(out) == 0 {
		return []string{expression}
	}
	return out
}

func rank(category Category) int {
	switch category {
	case CategoryPublicDomain:
		return 0
	case CategoryPermissive:
		return 1
	case CategoryWeakCopyleft:
		return 2
	case CategoryCopyleft:
		return 3
	case CategoryNetworkCopyleft:
		return 4
	case CategorySourceAvailable:
		return 5
	default:
		return 6 // unknown ranks most restrictive: unreviewed legal risk
	}
}

// Policy is a license gate: denied categories, denied ids (SPDX globs), and
// explicitly allowed ids that override everything else.
type Policy struct {
	DenyCategories []string
	Deny           []string
	Allow          []string
	// DenyUnknown defaults to true at the config layer: an unknown license is
	// an unreviewed legal risk and must be approved, not ignored.
	DenyUnknown bool
}

// Violation names the license (or category) that made a component fail.
type Violation struct {
	License  string
	Category Category
}

// Evaluate checks one component's licenses against the policy. A nil result
// means allowed. Semantics: atoms inside one expression are alternatives the
// consumer may choose between ("MIT OR GPL-3.0-only" passes on MIT), while
// separate list entries all apply — every entry must pass.
func (p Policy) Evaluate(licenses []string) *Violation {
	if len(licenses) == 0 {
		if p.DenyUnknown {
			return &Violation{License: "", Category: CategoryUnknown}
		}
		return nil
	}

	var worst *Violation
	for _, entry := range licenses {
		violation := p.evaluateExpression(entry)
		if violation == nil {
			continue
		}
		if worst == nil || rank(violation.Category) > rank(worst.Category) {
			worst = violation
		}
	}
	return worst
}

// evaluateExpression applies OR semantics across an expression's atoms:
// explicit allow wins, one passing alternative clears the expression.
func (p Policy) evaluateExpression(expression string) *Violation {
	var worst *Violation
	for _, atom := range splitExpression(expression) {
		if matchesAny(atom, p.Allow) {
			return nil
		}
		violation := p.evaluateAtom(atom)
		if violation == nil {
			return nil
		}
		if worst == nil || rank(violation.Category) > rank(worst.Category) {
			worst = violation
		}
	}
	return worst
}

func (p Policy) evaluateAtom(atom string) *Violation {
	category := Categorize(atom)
	if matchesAny(atom, p.Deny) {
		return &Violation{License: atom, Category: category}
	}
	if category == CategoryUnknown {
		if p.DenyUnknown {
			return &Violation{License: atom, Category: CategoryUnknown}
		}
		return nil
	}
	for _, denied := range p.DenyCategories {
		if strings.EqualFold(strings.TrimSpace(denied), string(category)) {
			return &Violation{License: atom, Category: category}
		}
	}
	return nil
}

func matchesAny(id string, globs []string) bool {
	normalized := strings.ToLower(strings.TrimSpace(id))
	for _, glob := range globs {
		pattern := strings.ToLower(strings.TrimSpace(glob))
		if pattern == "" {
			continue
		}
		if matched, err := path.Match(pattern, normalized); err == nil && matched {
			return true
		}
	}
	return false
}

// Empty reports whether the policy denies nothing.
func (p Policy) Empty() bool {
	return len(p.DenyCategories) == 0 && len(p.Deny) == 0 && !p.DenyUnknown
}
