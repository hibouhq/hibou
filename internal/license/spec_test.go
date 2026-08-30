package license

import "testing"

func specWith(mutate func(*Spec)) Spec {
	spec := Spec{
		DenyCategories: []string{"copyleft", "network-copyleft"},
		DenyUnknown:    true,
		Evaluate:       EvaluateNew,
	}
	if mutate != nil {
		mutate(&spec)
	}
	return spec
}

// The compliance question is "did this repository loosen the org's policy?", so
// direction matters far more than difference.
func TestCompareDirection(t *testing.T) {
	base := specWith(nil)

	cases := []struct {
		name     string
		override Spec
		want     Relation
		why      string
	}{
		{
			name:     "identical",
			override: specWith(nil),
			want:     RelationEquivalent,
		},
		{
			// Spelling is not a policy change.
			name: "same rules spelled differently",
			override: specWith(func(s *Spec) {
				s.DenyCategories = []string{"COPYLEFT", " network-copyleft "}
			}),
			want: RelationEquivalent,
			why:  "casing and padding must not read as a difference",
		},
		{
			name: "denies an extra category",
			override: specWith(func(s *Spec) {
				s.DenyCategories = append(s.DenyCategories, "source-available")
			}),
			want: RelationStricter,
		},
		{
			name: "drops a denied category",
			override: specWith(func(s *Spec) {
				s.DenyCategories = []string{"copyleft"}
			}),
			want: RelationLooser,
			why:  "no longer denying network-copyleft is a loosening",
		},
		{
			name: "swaps one denied category for another",
			override: specWith(func(s *Spec) {
				s.DenyCategories = []string{"copyleft", "source-available"}
			}),
			want: RelationMixed,
			why:  "added and removed on the same axis cannot be netted off",
		},
		{
			name: "allows more ids",
			override: specWith(func(s *Spec) {
				s.Allow = []string{"GPL-2.0-only"}
			}),
			want: RelationLooser,
			why:  "allow entries override denials, so adding one loosens",
		},
		{
			name: "exempts a package",
			override: specWith(func(s *Spec) {
				s.ExemptPurls = []string{"pkg:npm/eslint-*"}
			}),
			want: RelationLooser,
		},
		{
			name: "stops denying unknown licenses",
			override: specWith(func(s *Spec) {
				s.DenyUnknown = false
			}),
			want: RelationLooser,
		},
		{
			name: "widens the scope to the whole tree",
			override: specWith(func(s *Spec) {
				s.Evaluate = EvaluateAll
			}),
			want: RelationStricter,
			why:  "judging every component is stricter than judging only new ones",
		},
		{
			// The case a single verdict would hide: tighter on one axis, looser
			// on another.
			name: "tighter categories, looser unknowns",
			override: specWith(func(s *Spec) {
				s.DenyCategories = append(s.DenyCategories, "source-available")
				s.DenyUnknown = false
			}),
			want: RelationMixed,
			why:  "a compliance reader must still see the loosening",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			relation, differences := Compare(base, tc.override)
			if relation != tc.want {
				t.Errorf("Compare = %s, want %s (%s); differences=%+v", relation, tc.want, tc.why, differences)
			}
			if tc.want == RelationEquivalent && len(differences) != 0 {
				t.Errorf("equivalent specs must report no differences, got %+v", differences)
			}
			if tc.want != RelationEquivalent && len(differences) == 0 {
				t.Error("a non-equivalent verdict must name the axis that changed")
			}
		})
	}
}

// The differences drive the compliance table, so they must name the field and
// carry both sides.
func TestCompareReportsActionableDifferences(t *testing.T) {
	base := specWith(nil)
	override := specWith(func(s *Spec) {
		s.DenyUnknown = false
		s.ExemptPurls = []string{"pkg:npm/eslint-*"}
	})

	relation, differences := Compare(base, override)
	if relation != RelationLooser {
		t.Fatalf("relation = %s, want looser", relation)
	}

	byField := make(map[string]Difference, len(differences))
	for _, difference := range differences {
		byField[difference.Field] = difference
	}

	unknown, ok := byField["deny_unknown"]
	if !ok {
		t.Fatalf("deny_unknown difference missing from %+v", differences)
	}
	if unknown.Base != "true" || unknown.Override != "false" || unknown.Direction != RelationLooser {
		t.Errorf("deny_unknown difference = %+v, want true→false looser", unknown)
	}

	exempt, ok := byField["exempt_purls"]
	if !ok {
		t.Fatalf("exempt_purls difference missing from %+v", differences)
	}
	if exempt.Base != "" || exempt.Override != "pkg:npm/eslint-*" {
		t.Errorf("exempt_purls difference = %+v, want ''→the glob", exempt)
	}
}

func TestSpecPolicyAndDefaults(t *testing.T) {
	spec := Spec{DenyCategories: []string{"copyleft"}, DenyUnknown: true}

	if got := spec.EvaluateValue(); got != EvaluateNew {
		t.Errorf("EvaluateValue = %q, want the delta-scoped default", got)
	}
	if got := (Spec{Evaluate: "ALL"}).EvaluateValue(); got != EvaluateAll {
		t.Errorf("EvaluateValue(ALL) = %q, want all", got)
	}
	if got := (Spec{Evaluate: "nonsense"}).EvaluateValue(); got != EvaluateNew {
		t.Errorf("an unrecognized scope must fall back to %q, got %q", EvaluateNew, got)
	}

	// The evaluation-time policy must carry the rules and nothing else.
	policy := spec.Policy()
	if v := policy.Evaluate([]string{"GPL-3.0-only"}); v == nil {
		t.Error("spec policy should deny copyleft")
	}
	if (Spec{}).Empty() != true {
		t.Error("a spec denying nothing must report Empty")
	}
	if spec.Empty() {
		t.Error("a spec denying copyleft is not empty")
	}
}

// The whole-set values are unreadable on a real policy, so a difference must
// also say what actually changed.
func TestCompareReportsSetDelta(t *testing.T) {
	base := Spec{DenyCategories: []string{"copyleft", "network-copyleft"}, DenyUnknown: true}
	override := Spec{DenyCategories: []string{"copyleft", "source-available"}, DenyUnknown: true}

	relation, differences := Compare(base, override)
	if relation != RelationMixed {
		t.Fatalf("relation = %s, want mixed", relation)
	}
	if len(differences) != 1 {
		t.Fatalf("differences = %+v, want one axis", differences)
	}

	difference := differences[0]
	if len(difference.Added) != 1 || difference.Added[0] != "source-available" {
		t.Errorf("added = %v, want [source-available]", difference.Added)
	}
	if len(difference.Removed) != 1 || difference.Removed[0] != "network-copyleft" {
		t.Errorf("removed = %v, want [network-copyleft]", difference.Removed)
	}
	// The full sets are still available for anyone who wants them.
	if difference.Base == "" || difference.Override == "" {
		t.Error("the full sets should still be reported")
	}

	// A scalar axis has no delta lists, and must not fabricate empty ones that
	// render as "changed nothing".
	_, scalarDifferences := Compare(Spec{DenyUnknown: true}, Spec{DenyUnknown: false})
	if len(scalarDifferences) != 1 {
		t.Fatalf("scalar differences = %+v", scalarDifferences)
	}
	if len(scalarDifferences[0].Added) != 0 || len(scalarDifferences[0].Removed) != 0 {
		t.Errorf("a scalar axis must not report set deltas: %+v", scalarDifferences[0])
	}
}
