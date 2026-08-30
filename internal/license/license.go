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
	"unicode-":   CategoryPermissive,
	"zpl-":       CategoryPermissive,
	"ms-pl":      CategoryPermissive, // Microsoft Public License, NOT Ms-RL
	"afl-":       CategoryPermissive,
	"upl-":       CategoryPermissive,
	"libpng":     CategoryPermissive,
	"bzip2-":     CategoryPermissive,
	"openldap":   CategoryPermissive,
	// Creative Commons: attribution alone is permissive; share-alike is
	// copyleft; non-commercial and no-derivatives are not open source at
	// all. Longest-prefix matching keeps the family ordered correctly.
	"cc-by-": CategoryPermissive,

	// public domain
	"cc0-":      CategoryPublicDomain,
	"cc-pddc":   CategoryPublicDomain,
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
	"apsl-":  CategoryWeakCopyleft,

	// copyleft
	"gpl-":      CategoryCopyleft,
	"gfdl-":     CategoryCopyleft,
	"cc-by-sa-": CategoryCopyleft,
	"qpl-":      CategoryCopyleft,
	"sleepycat": CategoryCopyleft,

	// network copyleft
	"agpl-": CategoryNetworkCopyleft,
	"sspl-": CategoryNetworkCopyleft,
	"cal-":  CategoryNetworkCopyleft,

	// source-available (not open source)
	"busl-":          CategorySourceAvailable,
	"elastic-":       CategorySourceAvailable,
	"commons-clause": CategorySourceAvailable,
	"cc-by-nc":       CategorySourceAvailable,
	"cc-by-nd":       CategorySourceAvailable,
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

// CategorizeAll reduces a component's license list to its effective category.
// Separate list entries are conjunctive — every entry's obligations apply — so
// the list takes the most restrictive entry. Within one entry, OR and AND are
// resolved by CategorizeExpression.
func CategorizeAll(ids []string) Category {
	if len(ids) == 0 {
		return CategoryUnknown
	}
	worst := CategoryPublicDomain
	for _, id := range ids {
		if category := CategorizeExpression(id); rank(category) > rank(worst) {
			worst = category
		}
	}
	return worst
}

// CategorizeExpression resolves one SPDX expression to the category a consumer
// actually ends up under. OR takes the LEAST restrictive alternative (dual
// licensing is a choice: "MIT OR GPL-3.0-only" is permissive in practice), AND
// takes the most restrictive (both sets of obligations apply at once).
func CategorizeExpression(expression string) Category {
	return categorizeNode(parseExpression(expression))
}

func categorizeNode(node exprNode) Category {
	switch typed := node.(type) {
	case exprID:
		return Categorize(typed.raw)
	case exprUnparsed:
		// An expression we could not read tells us nothing about its licences.
		return CategoryUnknown
	case exprOp:
		if len(typed.children) == 0 {
			return CategoryUnknown
		}
		if typed.op == opOr {
			best := categorizeNode(typed.children[0])
			for _, child := range typed.children[1:] {
				if category := categorizeNode(child); rank(category) < rank(best) {
					best = category
				}
			}
			return best
		}
		worst := categorizeNode(typed.children[0])
		for _, child := range typed.children[1:] {
			if category := categorizeNode(child); rank(category) > rank(worst) {
				worst = category
			}
		}
		return worst
	}
	return CategoryUnknown
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
// means allowed. Semantics follow SPDX: separate list entries are conjunctive
// (every entry must pass), and within an entry OR is a choice while AND applies
// both. Returns the most restrictive violation found, so the reported reason
// names the worst problem rather than the first one seen.
func (p Policy) Evaluate(licenses []string) *Violation {
	if len(licenses) == 0 {
		if p.DenyUnknown || p.deniesCategory(CategoryUnknown) {
			return &Violation{License: "", Category: CategoryUnknown}
		}
		return nil
	}

	var worst *Violation
	for _, entry := range licenses {
		worst = worseOf(worst, p.evaluateNode(parseExpression(entry)))
	}
	return worst
}

// evaluateNode walks the expression tree. OR clears as soon as one alternative
// passes; AND fails if any operand fails.
func (p Policy) evaluateNode(node exprNode) *Violation {
	switch typed := node.(type) {
	case exprID:
		return p.evaluateAtom(typed.raw)
	case exprUnparsed:
		// An explicit allow still clears it — an operator can name the exact
		// string — but otherwise it is unknown and fails closed.
		if matchesAny(typed.raw, p.Allow) {
			return nil
		}
		if p.DenyUnknown || p.deniesCategory(CategoryUnknown) {
			return &Violation{License: typed.raw, Category: CategoryUnknown}
		}
		return nil
	case exprOp:
		var worst *Violation
		if typed.op == opOr {
			for _, child := range typed.children {
				violation := p.evaluateNode(child)
				if violation == nil {
					return nil // one acceptable alternative clears the expression
				}
				worst = worseOf(worst, violation)
			}
			return worst
		}
		for _, child := range typed.children {
			worst = worseOf(worst, p.evaluateNode(child))
		}
		return worst
	}
	return nil
}

func (p Policy) evaluateAtom(atom string) *Violation {
	atom = NormalizeID(atom)
	if matchesAny(atom, p.Allow) {
		return nil
	}
	// An allow entry may name the bare license ("GPL-2.0-only") while the SBOM
	// carries it with its linking exception attached.
	if base, _, found := strings.Cut(atom, " WITH "); found && matchesAny(base, p.Allow) {
		return nil
	}
	if atom == "" {
		if p.DenyUnknown || p.deniesCategory(CategoryUnknown) {
			return &Violation{Category: CategoryUnknown}
		}
		return nil
	}
	category := Categorize(atom)
	// Deny gets the same bare-id fallback as Allow: the schema's own example is
	// `deny: ["GPL-3.0-only"]`, and SBOMs routinely carry that licence with its
	// linking exception attached. Without this, the documented form silently
	// fails to match.
	if matchesAny(atom, p.Deny) {
		return &Violation{License: atom, Category: category}
	}
	if base, _, found := strings.Cut(atom, " WITH "); found && matchesAny(base, p.Deny) {
		return &Violation{License: atom, Category: category}
	}
	if category == CategoryUnknown {
		// deny_unknown is the ergonomic switch, but naming "unknown" in
		// deny_categories must work too — it validates and it is in the schema
		// enum, so silently ignoring it would be a config that lies.
		if p.DenyUnknown || p.deniesCategory(CategoryUnknown) {
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

// worseOf keeps the more restrictive of two violations; nil counts as no
// violation and never wins.
func worseOf(current, candidate *Violation) *Violation {
	if candidate == nil {
		return current
	}
	if current == nil || rank(candidate.Category) > rank(current.Category) {
		return candidate
	}
	return current
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

// deniesCategory reports whether the category is named in DenyCategories.
func (p Policy) deniesCategory(category Category) bool {
	for _, denied := range p.DenyCategories {
		if strings.EqualFold(strings.TrimSpace(denied), string(category)) {
			return true
		}
	}
	return false
}

// Empty reports whether the policy denies nothing.
func (p Policy) Empty() bool {
	return len(p.DenyCategories) == 0 && len(p.Deny) == 0 && !p.DenyUnknown
}

// Categories lists every category from least to most restrictive. Callers that
// render a partition of an inventory need a stable order that is not
// alphabetical, and duplicating this ordering in a frontend would let the two
// drift.
func Categories() []Category {
	return []Category{
		CategoryPublicDomain,
		CategoryPermissive,
		CategoryWeakCopyleft,
		CategoryCopyleft,
		CategoryNetworkCopyleft,
		CategorySourceAvailable,
		CategoryUnknown,
	}
}
