package license

import "testing"

// The bug this file exists for: AND-expressions used to be flattened into OR
// alternatives, so "GPL-3.0-only AND MIT" passed a copyleft-denying policy
// because MIT passed. Real SBOMs emit AND (this repo's apko SBOM has
// "MPL-2.0 AND MIT"), so the gate was silently under-blocking.
func TestPolicyEvaluateExpressionOperators(t *testing.T) {
	policy := Policy{
		DenyCategories: []string{"copyleft", "network-copyleft"},
		DenyUnknown:    true,
	}

	cases := []struct {
		expression string
		violates   bool
		category   Category
		why        string
	}{
		{"MIT", false, "", "plain permissive"},
		{"MIT OR GPL-3.0-only", false, "", "dual-licensed: consumer picks MIT"},
		{"GPL-3.0-only OR MIT", false, "", "OR is order-independent"},
		{"GPL-3.0-only AND MIT", true, CategoryCopyleft, "AND applies both obligations"},
		{"MIT AND GPL-3.0-only", true, CategoryCopyleft, "AND is order-independent"},
		{"(MPL-2.0 AND MIT)", false, "", "weak copyleft is not denied here"},
		{"MIT AND WeirdCorpThing", true, CategoryUnknown, "unknown operand fails under deny_unknown"},
		{"MIT OR WeirdCorpThing", false, "", "OR clears via the known-good side"},
		{"AGPL-3.0-only AND MIT", true, CategoryNetworkCopyleft, "worst operand is reported"},
		// AND binds tighter than OR: this is "MIT" OR "(GPL AND AGPL)", so the
		// MIT alternative clears it.
		{"MIT OR GPL-3.0-only AND AGPL-3.0-only", false, "", "AND binds tighter than OR"},
		// ...and with the grouping made explicit the other way, it must fail.
		{"(MIT OR GPL-3.0-only) AND AGPL-3.0-only", true, CategoryNetworkCopyleft, "explicit parens override precedence"},
		{"GPL-2.0-only WITH Classpath-exception-2.0", false, "", "linking exception behaves weak"},
	}

	for _, tc := range cases {
		violation := policy.Evaluate([]string{tc.expression})
		if tc.violates {
			if violation == nil {
				t.Errorf("Evaluate(%q) = allowed, want violation (%s)", tc.expression, tc.why)
				continue
			}
			if violation.Category != tc.category {
				t.Errorf("Evaluate(%q) category = %s, want %s (%s)", tc.expression, violation.Category, tc.category, tc.why)
			}
			continue
		}
		if violation != nil {
			t.Errorf("Evaluate(%q) = violation %+v, want allowed (%s)", tc.expression, violation, tc.why)
		}
	}
}

func TestPolicyAllowAppliesInsideExpressions(t *testing.T) {
	policy := Policy{
		DenyCategories: []string{"copyleft"},
		Allow:          []string{"GPL-2.0-only"},
		DenyUnknown:    true,
	}
	// An allow entry naming the bare id must also clear the id carrying its
	// linking exception, which is how SBOMs usually spell it.
	if v := policy.Evaluate([]string{"GPL-2.0-only WITH Classpath-exception-2.0"}); v != nil {
		t.Errorf("allowed id with exception should pass, got %+v", v)
	}
	// Allow must survive being one operand of an AND.
	if v := policy.Evaluate([]string{"GPL-2.0-only AND MIT"}); v != nil {
		t.Errorf("allowed operand should clear the AND, got %+v", v)
	}
	// Glob allow.
	globPolicy := Policy{DenyCategories: []string{"copyleft"}, Allow: []string{"GPL-*"}}
	if v := globPolicy.Evaluate([]string{"GPL-3.0-or-later AND MIT"}); v != nil {
		t.Errorf("glob allow should clear it, got %+v", v)
	}
}

func TestCategorizeExpression(t *testing.T) {
	cases := map[string]Category{
		"MIT":                        CategoryPermissive,
		"MIT OR GPL-3.0-only":        CategoryPermissive, // choice: least restrictive
		"MIT AND GPL-3.0-only":       CategoryCopyleft,   // both apply: most restrictive
		"(MPL-2.0 AND MIT)":          CategoryWeakCopyleft,
		"AGPL-3.0-only OR BUSL-1.1":  CategoryNetworkCopyleft, // network-copyleft ranks below source-available
		"SEE LICENSE IN LICENSE.txt": CategoryUnknown,
		"":                           CategoryUnknown,
	}
	for expression, want := range cases {
		if got := CategorizeExpression(expression); got != want {
			t.Errorf("CategorizeExpression(%q) = %s, want %s", expression, got, want)
		}
	}
}

func TestCategorizeAllEntriesAreConjunctive(t *testing.T) {
	// Two entries = two independent license grants that both apply.
	if got := CategorizeAll([]string{"MIT", "GPL-3.0-only"}); got != CategoryCopyleft {
		t.Errorf("separate entries = %s, want copyleft", got)
	}
	// One entry that is a choice resolves to the alternative you'd pick.
	if got := CategorizeAll([]string{"MIT OR GPL-3.0-only"}); got != CategoryPermissive {
		t.Errorf("single OR entry = %s, want permissive", got)
	}
}

func TestNormalizeID(t *testing.T) {
	cases := map[string]string{
		"MIT":                   "MIT",
		"  MIT  ":               "MIT",
		"(MIT)":                 "MIT",
		"((MIT))":               "MIT",
		"(MPL-2.0 AND MIT)":     "MPL-2.0 AND MIT",
		"MPL-2.0  and   MIT":    "MPL-2.0 AND MIT",
		"GPL-2.0-only with Foo": "GPL-2.0-only WITH Foo",
		"(MIT OR (Apache-2.0))": "MIT OR (Apache-2.0)",
		"":                      "",
	}
	for input, want := range cases {
		if got := NormalizeID(input); got != want {
			t.Errorf("NormalizeID(%q) = %q, want %q", input, got, want)
		}
	}
}

// Malformed input must terminate rather than spin, and must not be silently
// treated as permissive.
func TestParseExpressionMalformed(t *testing.T) {
	policy := Policy{DenyCategories: []string{"copyleft"}, DenyUnknown: true}
	for _, expression := range []string{"(", ")", "((", "))", "AND", "OR", "MIT AND", "AND MIT", "(MIT", "MIT)", "WITH", "MIT WITH"} {
		// The assertion that matters is that this returns at all.
		_ = policy.Evaluate([]string{expression})
		_ = CategorizeExpression(expression)
	}
}

// Catalog gaps found by categorizing every distinct license string in this
// repo's own SBOMs (its apko SPDX output plus trivy CycloneDX runs over the Go,
// npm, Maven and container trees). CC-PDDC is a public-domain dedication and
// CC-BY-4.0 is attribution-only; both used to fall through to `unknown`, which
// ranks most restrictive, so deny_unknown's true default blocked them.
func TestCatalogCoversRealWorldIdentifiers(t *testing.T) {
	cases := map[string]Category{
		"CC-PDDC":         CategoryPublicDomain,
		"CC-BY-4.0":       CategoryPermissive,
		"CC-BY-SA-4.0":    CategoryCopyleft,        // share-alike is copyleft
		"CC-BY-NC-4.0":    CategorySourceAvailable, // non-commercial is not open source
		"CC-BY-ND-4.0":    CategorySourceAvailable,
		"CC-BY-NC-SA-4.0": CategorySourceAvailable,
		"CC0-1.0":         CategoryPublicDomain,
		"Unicode-3.0":     CategoryPermissive,
		"ZPL-2.1":         CategoryPermissive,
		"Ms-PL":           CategoryPermissive, // distinct from Ms-RL below
		"Ms-RL":           CategoryWeakCopyleft,
		"AFL-3.0":         CategoryPermissive,
		"UPL-1.0":         CategoryPermissive,
		"GFDL-1.3-only":   CategoryCopyleft,
		"CAL-1.0":         CategoryNetworkCopyleft,
		"BlueOak-1.0.0":   CategoryPermissive,
		"Python-2.0":      CategoryPermissive,
	}
	for id, want := range cases {
		if got := Categorize(id); got != want {
			t.Errorf("Categorize(%q) = %s, want %s", id, got, want)
		}
	}
}

// Every surface that shows licenses funnels through NormalizeIDs, so the same
// component cannot render different pills on the compare view, the dependency
// table and the org overview.
func TestNormalizeIDs(t *testing.T) {
	cases := []struct {
		name  string
		input []string
		want  []string
	}{
		{"empty stays empty", nil, []string{}},
		{"blanks dropped", []string{"", "   ", "MIT"}, []string{"MIT"}},
		{"parens stripped", []string{"(MIT)"}, []string{"MIT"}},
		{"whitespace collapsed", []string{"  MPL-2.0   AND   MIT  "}, []string{"MPL-2.0 AND MIT"}},
		// Case-insensitive dedup, first spelling wins so the SBOM's own casing
		// is what gets displayed.
		{"case-insensitive dedup keeps the first spelling", []string{"MIT", "mit", "(MIT)"}, []string{"MIT"}},
		{"order preserved", []string{"Apache-2.0", "MIT", "ISC"}, []string{"Apache-2.0", "MIT", "ISC"}},
		{"distinct licenses all kept", []string{"MIT", "GPL-3.0-only"}, []string{"MIT", "GPL-3.0-only"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := NormalizeIDs(tc.input)
			if got == nil {
				t.Fatal("must never return nil")
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// deny_categories accepts "unknown" (it is in the schema enum and passes
// validation), so it must actually deny. It used to be inert whenever
// deny_unknown was false, which is a config that silently lies.
func TestDenyCategoriesUnknownIsNotInert(t *testing.T) {
	policy := Policy{DenyCategories: []string{"unknown"}}

	if v := policy.Evaluate(nil); v == nil {
		t.Error("no license metadata must violate deny_categories: [unknown]")
	}
	if v := policy.Evaluate([]string{"Acme-Internal-1.0"}); v == nil {
		t.Error("unrecognized id must violate deny_categories: [unknown]")
	}
	if v := policy.Evaluate([]string{"MIT"}); v != nil {
		t.Errorf("a recognized permissive license must still pass, got %+v", v)
	}
	// An explicit allow still wins, as everywhere else.
	allowed := Policy{DenyCategories: []string{"unknown"}, Allow: []string{"Acme-Internal-1.0"}}
	if v := allowed.Evaluate([]string{"Acme-Internal-1.0"}); v != nil {
		t.Errorf("allow must override the category deny, got %+v", v)
	}
	// And deny_unknown:false alone no longer disables the category form.
	explicitFalse := Policy{DenyCategories: []string{"unknown"}, DenyUnknown: false}
	if v := explicitFalse.Evaluate(nil); v == nil {
		t.Error("deny_categories: [unknown] must hold even with deny_unknown false")
	}
}

// Free-text license names are reachable from production ingest: CycloneDX
// falls back to `license.name` and SPDX to `licenseDeclared`, neither of which
// is an SPDX id. When such text precedes an AND, the parser used to stop at the
// first term and DISCARD the rest — so a copyleft operand vanished and the
// component passed a policy that denies copyleft.
func TestPolicyEvaluateDoesNotDropOperandsAfterFreeText(t *testing.T) {
	policy := Policy{DenyCategories: []string{"copyleft", "network-copyleft"}, DenyUnknown: true}

	for _, expression := range []string{
		"MIT License AND GPL-3.0-only",
		"zlib acknowledgement AND AGPL-3.0-only",
		"MIT (see LICENSE) AND AGPL-3.0-only",
		"ISC / MIT AND GPL-3.0-only",
	} {
		if violation := policy.Evaluate([]string{expression}); violation == nil {
			t.Errorf("Evaluate(%q) = allowed; an unreadable expression must fail closed, not be truncated to its first term", expression)
		}
		if category := CategorizeExpression(expression); category != CategoryUnknown {
			t.Errorf("CategorizeExpression(%q) = %s, want unknown", expression, category)
		}
	}

	// Well-formed input is unaffected in both directions. `WITH` is a real SPDX
	// operator, so an exception clause parses fully and must keep resolving on
	// its operands rather than degrading to unknown.
	if violation := policy.Evaluate([]string{"MIT AND GPL-3.0-only"}); violation == nil {
		t.Error("a well-formed AND must still deny")
	}
	if category := CategorizeExpression("Apache-2.0 WITH LLVM-exception AND GPL-3.0-only"); category != CategoryCopyleft {
		t.Errorf("a WITH clause beside an AND operand = %s, want copyleft", category)
	}
	if violation := policy.Evaluate([]string{"Apache-2.0 with LLVM-exception AND GPL-3.0-only"}); violation == nil {
		t.Error("lowercase `with` is still the SPDX operator and the GPL operand must deny")
	}
	if violation := policy.Evaluate([]string{"MIT OR GPL-3.0-only"}); violation != nil {
		t.Errorf("a well-formed OR must still pass, got %+v", violation)
	}
	// And free text with no operator keeps its existing lenient handling.
	if violation := policy.Evaluate([]string{"MIT License"}); violation != nil {
		t.Errorf("plain free text must not regress, got %+v", violation)
	}
}

// An explicit allow can still clear an expression we cannot parse — the operator
// may name the exact string — but nothing else may.
func TestUnparsedExpressionRespectsAllow(t *testing.T) {
	allowed := Policy{
		DenyCategories: []string{"copyleft"},
		Allow:          []string{"MIT License AND GPL-3.0-only"},
		DenyUnknown:    true,
	}
	if violation := allowed.Evaluate([]string{"MIT License AND GPL-3.0-only"}); violation != nil {
		t.Errorf("an explicitly allowed string must pass, got %+v", violation)
	}
	// deny_unknown:false also lets it through, as for any other unknown.
	lenient := Policy{DenyCategories: []string{"copyleft"}}
	if violation := lenient.Evaluate([]string{"MIT License AND GPL-3.0-only"}); violation != nil {
		t.Errorf("deny_unknown:false should not deny an unknown, got %+v", violation)
	}
}

// Sibling groups are a legal SPDX shape. Stripping the outer characters of
// "(A) AND (B)" produces unbalanced text that reparses to A alone, so the denied
// operand disappears — and because the gate reads raw licenses while the org
// overview and simulator read normalized ones, the two disagreed in BOTH
// directions on exactly these strings.
func TestNormalizeIDKeepsSiblingGroupsIntact(t *testing.T) {
	cases := map[string]string{
		"(MIT OR Apache-2.0) AND (AGPL-3.0-only)": "(MIT OR Apache-2.0) AND (AGPL-3.0-only)",
		"(MIT) AND (GPL-3.0-only)":                "(MIT) AND (GPL-3.0-only)",
		"(AGPL-3.0-only) OR (MIT)":                "(AGPL-3.0-only) OR (MIT)",
		// Genuine wrappers are still unwrapped.
		"(MPL-2.0 AND MIT)":     "MPL-2.0 AND MIT",
		"((MIT))":               "MIT",
		"(MIT OR (Apache-2.0))": "MIT OR (Apache-2.0)",
	}
	for input, want := range cases {
		if got := NormalizeID(input); got != want {
			t.Errorf("NormalizeID(%q) = %q, want %q", input, got, want)
		}
	}

	// The point of the fix: normalizing must not change the verdict.
	policy := Policy{DenyCategories: []string{"copyleft", "network-copyleft"}, DenyUnknown: true}
	for _, expression := range []string{
		"(MIT OR Apache-2.0) AND (AGPL-3.0-only)",
		"(MIT) AND (GPL-3.0-only)",
		"(AGPL-3.0-only) OR (MIT)",
	} {
		raw := policy.Evaluate([]string{expression})
		normalized := policy.Evaluate(NormalizeIDs([]string{expression}))
		if (raw == nil) != (normalized == nil) {
			t.Errorf("%q: gate(raw)=%v but simulator(normalized)=%v — the two must agree", expression, raw, normalized)
		}
	}
}

// "unknown ranks most restrictive" is load-bearing: it is why an unrecognized
// license in a list dominates the rest. Nothing pinned it, so inverting rank()
// left the whole suite green.
func TestUnknownRanksMostRestrictive(t *testing.T) {
	for _, other := range []Category{
		CategoryPublicDomain, CategoryPermissive, CategoryWeakCopyleft,
		CategoryCopyleft, CategoryNetworkCopyleft, CategorySourceAvailable,
	} {
		if rank(CategoryUnknown) <= rank(other) {
			t.Errorf("rank(unknown)=%d must exceed rank(%s)=%d", rank(CategoryUnknown), other, rank(other))
		}
	}
	// The observable consequence, which is what actually matters.
	if got := CategorizeAll([]string{"MIT", "Acme-Internal-1.0"}); got != CategoryUnknown {
		t.Errorf("CategorizeAll(MIT + unrecognized) = %s, want unknown", got)
	}
}

// The schema's own example for `deny` is a bare SPDX id, and SBOMs routinely
// carry that licence with a linking exception attached. `Allow` had the fallback
// and `Deny` did not, so the documented form silently matched nothing — and
// `deny_categories` could not reach it either, because a GPL-with-exception
// categorizes as weak-copyleft.
func TestDenyMatchesLicenseCarryingAnException(t *testing.T) {
	policy := Policy{Deny: []string{"GPL-2.0-only"}, DenyUnknown: false}

	if violation := policy.Evaluate([]string{"GPL-2.0-only WITH Classpath-exception-2.0"}); violation == nil {
		t.Error("a bare deny id must match the same licence carried with its exception")
	}
	// The bare form still matches, and unrelated licences still pass.
	if violation := policy.Evaluate([]string{"GPL-2.0-only"}); violation == nil {
		t.Error("the bare form must still match")
	}
	if violation := policy.Evaluate([]string{"MIT"}); violation != nil {
		t.Errorf("MIT must still pass, got %+v", violation)
	}
	// Allow still wins over deny, exception or not.
	allowed := Policy{
		Deny:  []string{"GPL-2.0-only"},
		Allow: []string{"GPL-2.0-only WITH Classpath-exception-2.0"},
	}
	if violation := allowed.Evaluate([]string{"GPL-2.0-only WITH Classpath-exception-2.0"}); violation != nil {
		t.Errorf("an explicit allow must still win, got %+v", violation)
	}
	// A glob deny reaches the exception form too.
	glob := Policy{Deny: []string{"GPL-*"}}
	if violation := glob.Evaluate([]string{"GPL-3.0-or-later WITH Autoconf-exception-3.0"}); violation == nil {
		t.Error("a glob deny must reach the exception form")
	}
}
