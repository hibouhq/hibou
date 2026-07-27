package license

import "testing"

func TestCategorize(t *testing.T) {
	cases := map[string]Category{
		"MIT":                              CategoryPermissive,
		"Apache-2.0":                       CategoryPermissive,
		"BSD-3-Clause":                     CategoryPermissive,
		"BSL-1.0":                          CategoryPermissive, // Boost, not BUSL
		"BUSL-1.1":                         CategorySourceAvailable,
		"LGPL-2.1-only":                    CategoryWeakCopyleft,
		"MPL-2.0":                          CategoryWeakCopyleft,
		"GPL-2.0-only":                     CategoryCopyleft,
		"GPL-3.0-or-later":                 CategoryCopyleft,
		"GPL-2.0-with-classpath-exception": CategoryWeakCopyleft,
		"AGPL-3.0-only":                    CategoryNetworkCopyleft,
		"SSPL-1.0":                         CategoryNetworkCopyleft,
		"CC0-1.0":                          CategoryPublicDomain,
		"Unlicense":                        CategoryPublicDomain,
		"SEE LICENSE IN LICENSE.txt":       CategoryUnknown,
		"":                                 CategoryUnknown,
	}
	for id, want := range cases {
		if got := Categorize(id); got != want {
			t.Errorf("Categorize(%q) = %s, want %s", id, got, want)
		}
	}
}

func TestCategorizeAllMostRestrictive(t *testing.T) {
	if got := CategorizeAll([]string{"MIT", "GPL-3.0-only"}); got != CategoryCopyleft {
		t.Fatalf("got %s", got)
	}
	if got := CategorizeAll(nil); got != CategoryUnknown {
		t.Fatalf("empty = %s", got)
	}
}

func TestPolicyEvaluate(t *testing.T) {
	policy := Policy{
		DenyCategories: []string{"copyleft", "network-copyleft"},
		Deny:           []string{"BUSL-1.1"},
		Allow:          []string{"GPL-2.0-only"},
		DenyUnknown:    true,
	}

	if v := policy.Evaluate([]string{"MIT"}); v != nil {
		t.Fatalf("MIT should pass, got %+v", v)
	}
	if v := policy.Evaluate([]string{"GPL-3.0-only"}); v == nil || v.Category != CategoryCopyleft {
		t.Fatalf("GPL-3.0 should fail as copyleft, got %+v", v)
	}
	// explicit allow beats its denied category
	if v := policy.Evaluate([]string{"GPL-2.0-only"}); v != nil {
		t.Fatalf("allowed GPL-2.0-only should pass, got %+v", v)
	}
	if v := policy.Evaluate([]string{"BUSL-1.1"}); v == nil {
		t.Fatal("denied id should fail")
	}
	// unknown breaks by default
	if v := policy.Evaluate(nil); v == nil || v.Category != CategoryUnknown {
		t.Fatalf("unlicensed should fail as unknown, got %+v", v)
	}
	if v := policy.Evaluate([]string{"Custom-Corp-License"}); v == nil || v.Category != CategoryUnknown {
		t.Fatalf("unrecognized should fail as unknown, got %+v", v)
	}
	// OR expression: one acceptable choice clears the component
	if v := policy.Evaluate([]string{"MIT OR GPL-3.0-only"}); v != nil {
		t.Fatalf("dual-licensed MIT OR GPL should pass, got %+v", v)
	}
	// Separate entries are conjunctive: every entry must pass on its own.
	if v := policy.Evaluate([]string{"MIT", "GPL-3.0-only"}); v == nil || v.Category != CategoryCopyleft {
		t.Fatalf("list entry GPL-3.0-only must fail even next to MIT, got %+v", v)
	}
	// AND-only copyleft still fails
	if v := policy.Evaluate([]string{"AGPL-3.0-only"}); v == nil || v.Category != CategoryNetworkCopyleft {
		t.Fatalf("AGPL should fail, got %+v", v)
	}
}

func TestPolicyDenyUnknownFalse(t *testing.T) {
	policy := Policy{DenyCategories: []string{"copyleft"}}
	if v := policy.Evaluate(nil); v != nil {
		t.Fatalf("unknown allowed when DenyUnknown=false, got %+v", v)
	}
}
