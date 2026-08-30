package delta

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/license"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// The false positive this whole change exists for: a copyleft dependency that
// has been on the target branch for a year must not be reported as something
// this PR introduced.
func TestLicenseGateIsDeltaScopedByDefault(t *testing.T) {
	headID, baseID := uuid.New(), uuid.New()
	inherited := dbgen.Component{Purl: "pkg:npm/old-gpl", Name: "old-gpl", Version: "1.0.0", Licenses: []string{"GPL-3.0-only"}}
	introduced := dbgen.Component{Purl: "pkg:npm/new-gpl", Name: "new-gpl", Version: "2.0.0", Licenses: []string{"GPL-3.0-only"}}
	clean := dbgen.Component{Purl: "pkg:npm/lodash", Name: "lodash", Version: "4.17.21", Licenses: []string{"MIT"}}

	mock := &licenseTestStore{mockStore: newMockStore(), components: map[uuid.UUID][]dbgen.Component{
		baseID: {inherited, clean},
		headID: {inherited, introduced, clean},
	}}
	service := NewService(mock, zerolog.Nop())

	gate, err := service.EvaluateGatesWithConfig(context.Background(), uuid.New(), uuid.New(), &DeltaResult{}, &GateConfig{
		Licenses:       &LicenseGate{DenyCategories: []string{"copyleft"}},
		HeadSnapshotID: headID,
		BaseSnapshotID: baseID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if gate.Passed {
		t.Fatalf("gate should fail on the introduced component, reasons=%v", gate.Reasons)
	}

	joined := strings.Join(gate.Reasons, "\n")
	if !strings.Contains(joined, "new-gpl@2.0.0") {
		t.Errorf("introduced component missing from reasons: %v", gate.Reasons)
	}
	if strings.Contains(joined, "old-gpl@1.0.0 introduces") {
		t.Errorf("pre-existing component reported as introduced: %v", gate.Reasons)
	}
	// Not counted as a failure, but still reported — silently dropping it would
	// hide real exposure. Disclosures live in Notes so they cannot flip Passed.
	if !strings.Contains(strings.Join(gate.Notes, "\n"), "1 pre-existing license violation(s)") {
		t.Errorf("inherited violation not disclosed: notes=%v", gate.Notes)
	}
	for _, reason := range gate.Reasons {
		if strings.Contains(reason, "pre-existing") {
			t.Errorf("disclosure leaked into Reasons, which would fail the gate: %q", reason)
		}
	}
}

// A version bump is a new decision: the new version may carry a different
// license, so an upgraded dependency must not inherit the old one's pass.
func TestLicenseGateTreatsVersionBumpAsIntroduced(t *testing.T) {
	headID, baseID := uuid.New(), uuid.New()
	mock := &licenseTestStore{mockStore: newMockStore(), components: map[uuid.UUID][]dbgen.Component{
		baseID: {{Purl: "pkg:npm/thing", Name: "thing", Version: "1.0.0", Licenses: []string{"MIT"}}},
		headID: {{Purl: "pkg:npm/thing", Name: "thing", Version: "2.0.0", Licenses: []string{"GPL-3.0-only"}}},
	}}
	service := NewService(mock, zerolog.Nop())

	gate, err := service.EvaluateGatesWithConfig(context.Background(), uuid.New(), uuid.New(), &DeltaResult{}, &GateConfig{
		Licenses:       &LicenseGate{DenyCategories: []string{"copyleft"}},
		HeadSnapshotID: headID,
		BaseSnapshotID: baseID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if gate.Passed {
		t.Fatalf("relicensed upgrade must fail, reasons=%v", gate.Reasons)
	}
	if !strings.Contains(strings.Join(gate.Reasons, "\n"), "thing@2.0.0 introduces") {
		t.Errorf("reasons = %v", gate.Reasons)
	}
}

// Whole-tree mode stays available, and must word itself honestly: nothing is
// being "introduced" when the entire snapshot is judged.
func TestLicenseGateWholeTreeModeAndWording(t *testing.T) {
	headID, baseID := uuid.New(), uuid.New()
	mock := &licenseTestStore{mockStore: newMockStore(), components: map[uuid.UUID][]dbgen.Component{
		baseID: {{Purl: "pkg:npm/old-gpl", Name: "old-gpl", Version: "1.0.0", Licenses: []string{"GPL-3.0-only"}}},
		headID: {{Purl: "pkg:npm/old-gpl", Name: "old-gpl", Version: "1.0.0", Licenses: []string{"GPL-3.0-only"}}},
	}}
	service := NewService(mock, zerolog.Nop())

	gate, err := service.EvaluateGatesWithConfig(context.Background(), uuid.New(), uuid.New(), &DeltaResult{}, &GateConfig{
		Licenses:       &LicenseGate{DenyCategories: []string{"copyleft"}, Evaluate: "all"},
		HeadSnapshotID: headID,
		BaseSnapshotID: baseID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if gate.Passed {
		t.Fatal("whole-tree mode must fail on the pre-existing component")
	}
	joined := strings.Join(gate.Reasons, "\n")
	if !strings.Contains(joined, "carries denied license") {
		t.Errorf("whole-tree reason should say \"carries\", got %v", gate.Reasons)
	}
	if strings.Contains(joined, "introduces") {
		t.Errorf("whole-tree reason must not claim introduction: %v", gate.Reasons)
	}
}

// No base snapshot means new-vs-old is unknowable. Fail closed to whole-tree
// rather than passing everything.
func TestLicenseGateFailsClosedWithoutBaseSnapshot(t *testing.T) {
	headID := uuid.New()
	mock := &licenseTestStore{mockStore: newMockStore(), components: map[uuid.UUID][]dbgen.Component{
		headID: {{Purl: "pkg:npm/gpl", Name: "gpl", Version: "1.0.0", Licenses: []string{"GPL-3.0-only"}}},
	}}
	service := NewService(mock, zerolog.Nop())

	gate, err := service.EvaluateGatesWithConfig(context.Background(), uuid.New(), uuid.New(), &DeltaResult{}, &GateConfig{
		Licenses:       &LicenseGate{DenyCategories: []string{"copyleft"}},
		HeadSnapshotID: headID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if gate.Passed {
		t.Fatalf("must not pass when the delta is unknowable, reasons=%v", gate.Reasons)
	}
}

func TestLicenseGateExemptPurls(t *testing.T) {
	headID, baseID := uuid.New(), uuid.New()
	mock := &licenseTestStore{mockStore: newMockStore(), components: map[uuid.UUID][]dbgen.Component{
		baseID: {},
		headID: {
			{Purl: "pkg:npm/eslint-plugin-thing", Name: "eslint-plugin-thing", Version: "1.0.0", Licenses: []string{"GPL-3.0-only"}},
			{Purl: "pkg:npm/@types/node", Name: "node", Version: "20.0.0", Licenses: []string{"GPL-3.0-only"}},
		},
	}}
	service := NewService(mock, zerolog.Nop())

	// Both exempted: the gate passes, but says so out loud.
	gate, err := service.EvaluateGatesWithConfig(context.Background(), uuid.New(), uuid.New(), &DeltaResult{}, &GateConfig{
		Licenses: &LicenseGate{
			DenyCategories: []string{"copyleft"},
			ExemptPurls:    []string{"pkg:npm/eslint-*", "pkg:npm/@types/*"},
		},
		HeadSnapshotID: headID,
		BaseSnapshotID: baseID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !gate.Passed {
		t.Fatalf("exempted components must not fail the gate, reasons=%v", gate.Reasons)
	}

	// One exempted: the remaining violation fails, and the exemption is
	// disclosed rather than silently applied.
	gate, err = service.EvaluateGatesWithConfig(context.Background(), uuid.New(), uuid.New(), &DeltaResult{}, &GateConfig{
		Licenses: &LicenseGate{
			DenyCategories: []string{"copyleft"},
			ExemptPurls:    []string{"pkg:npm/eslint-*"},
		},
		HeadSnapshotID: headID,
		BaseSnapshotID: baseID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if gate.Passed {
		t.Fatal("non-exempted violation must still fail")
	}
	if !strings.Contains(strings.Join(gate.Notes, "\n"), "1 component(s) exempted by policy") {
		t.Errorf("exemption not disclosed: notes=%v", gate.Notes)
	}
	if strings.Contains(strings.Join(gate.Reasons, "\n"), "eslint-plugin-thing") {
		t.Errorf("exempted component should not be a reason: %v", gate.Reasons)
	}
}

// Undeclared and unrecognized both land in CategoryUnknown but have different
// owners — the SBOM generator versus the license catalog — so the reason must
// distinguish them.
func TestLicenseGateDistinguishesUndeclaredFromUnrecognized(t *testing.T) {
	headID, baseID := uuid.New(), uuid.New()
	mock := &licenseTestStore{mockStore: newMockStore(), components: map[uuid.UUID][]dbgen.Component{
		baseID: {},
		headID: {
			{Purl: "pkg:npm/nometa", Name: "nometa", Version: "1.0.0", Licenses: []string{}},
			{Purl: "pkg:npm/weird", Name: "weird", Version: "1.0.0", Licenses: []string{"Acme-Internal-1.0"}},
		},
	}}
	service := NewService(mock, zerolog.Nop())

	gate, err := service.EvaluateGatesWithConfig(context.Background(), uuid.New(), uuid.New(), &DeltaResult{}, &GateConfig{
		Licenses:       &LicenseGate{DenyUnknown: true},
		HeadSnapshotID: headID,
		BaseSnapshotID: baseID,
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(gate.Reasons, "\n")
	if !strings.Contains(joined, "nometa@1.0.0 introduces no license metadata") {
		t.Errorf("undeclared reason wrong: %v", gate.Reasons)
	}
	if !strings.Contains(joined, "weird@1.0.0 introduces unrecognized license Acme-Internal-1.0") {
		t.Errorf("unrecognized reason wrong: %v", gate.Reasons)
	}
	// The old wording claimed a license literally named "" was denied.
	if strings.Contains(joined, "denied license  ") {
		t.Errorf("empty license name leaked into a reason: %v", gate.Reasons)
	}
}

func TestMatchesPurlGlob(t *testing.T) {
	cases := []struct {
		purl  string
		globs []string
		want  bool
	}{
		{"pkg:npm/eslint", []string{"pkg:npm/eslint"}, true},
		{"pkg:npm/eslint", []string{"pkg:npm/*"}, true},
		{"pkg:npm/@types/node", []string{"pkg:npm/@types/*"}, true},
		{"pkg:npm/@types/node", []string{"pkg:npm/@babel/*"}, false},
		// Purls contain slashes; a matcher that refuses to cross them is useless.
		{"pkg:golang/github.com/foo/bar", []string{"pkg:golang/github.com/foo/*"}, true},
		{"pkg:npm/ESLint", []string{"pkg:npm/eslint"}, true}, // case-insensitive
		{"pkg:npm/eslint", nil, false},
		{"pkg:npm/eslint", []string{""}, false},
		{"", []string{"*"}, false}, // an empty purl must not be swept up by a wildcard
		{"pkg:npm/a-b-c", []string{"pkg:npm/a-*-c"}, true},
		{"pkg:npm/a-b-d", []string{"pkg:npm/a-*-c"}, false},
	}
	for _, tc := range cases {
		if got := matchesPurlGlob(tc.purl, tc.globs); got != tc.want {
			t.Errorf("matchesPurlGlob(%q, %v) = %t, want %t", tc.purl, tc.globs, got, tc.want)
		}
	}
}

// waivableLicenseStore adds waiver support to the license mock. Kept separate so
// the tests above still exercise the no-acceptance-support path.
type waivableLicenseStore struct {
	*licenseTestStore
	acceptances []store.FindingAcceptance
}

func (m *waivableLicenseStore) ListActiveFindingAcceptancesByRepo(_ context.Context, _ uuid.UUID) ([]store.FindingAcceptance, error) {
	return m.acceptances, nil
}

// A waiver is the sanctioned way to unblock one package. It must clear the gate
// while still being visible, and it must be keyed so an unrelated version bump
// does not revoke it.
func TestLicenseGateHonoursWaivers(t *testing.T) {
	headID, baseID := uuid.New(), uuid.New()
	repoID := uuid.New()
	base := &licenseTestStore{mockStore: newMockStore(), components: map[uuid.UUID][]dbgen.Component{
		baseID: {},
		headID: {{Purl: "pkg:npm/readline", Name: "readline", Version: "8.2", Licenses: []string{"GPL-3.0-only"}}},
	}}

	// Without a waiver: fails.
	service := NewService(&waivableLicenseStore{licenseTestStore: base}, zerolog.Nop())
	gate, err := service.EvaluateGatesWithConfig(context.Background(), repoID, uuid.New(), &DeltaResult{}, &GateConfig{
		Licenses:       &LicenseGate{DenyCategories: []string{"copyleft"}},
		HeadSnapshotID: headID,
		BaseSnapshotID: baseID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if gate.Passed {
		t.Fatal("unwaived copyleft component must fail")
	}

	// With a waiver on (purl, license): passes, and says so.
	waived := &waivableLicenseStore{
		licenseTestStore: base,
		acceptances: []store.FindingAcceptance{
			{Fingerprint: license.Fingerprint("pkg:npm/readline", "GPL-3.0-only"), Reason: "vendored, not distributed"},
		},
	}
	service = NewService(waived, zerolog.Nop())
	gate, err = service.EvaluateGatesWithConfig(context.Background(), repoID, uuid.New(), &DeltaResult{}, &GateConfig{
		Licenses:       &LicenseGate{DenyCategories: []string{"copyleft"}},
		HeadSnapshotID: headID,
		BaseSnapshotID: baseID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !gate.Passed {
		t.Fatalf("waived violation must not fail the gate, reasons=%v", gate.Reasons)
	}

	// A waiver for a DIFFERENT license on the same package must not apply.
	wrong := &waivableLicenseStore{
		licenseTestStore: base,
		acceptances: []store.FindingAcceptance{
			{Fingerprint: license.Fingerprint("pkg:npm/readline", "AGPL-3.0-only")},
		},
	}
	service = NewService(wrong, zerolog.Nop())
	gate, err = service.EvaluateGatesWithConfig(context.Background(), repoID, uuid.New(), &DeltaResult{}, &GateConfig{
		Licenses:       &LicenseGate{DenyCategories: []string{"copyleft"}},
		HeadSnapshotID: headID,
		BaseSnapshotID: baseID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if gate.Passed {
		t.Fatal("a waiver for another license must not clear this violation")
	}
}

// Version is excluded from the fingerprint on purpose: a patch bump must not
// revoke a waiver someone deliberately granted.
func TestLicenseFingerprintIsVersionIndependent(t *testing.T) {
	a := license.Fingerprint("pkg:npm/readline", "GPL-3.0-only")
	if a == "" {
		t.Fatal("fingerprint should be non-empty")
	}
	// Same package + license → same fingerprint regardless of case or padding.
	if a != license.Fingerprint("  pkg:npm/readline  ", "gpl-3.0-only") {
		t.Error("fingerprint must be case- and whitespace-insensitive")
	}
	// Normalized expressions collapse too.
	if license.Fingerprint("pkg:npm/x", "(MIT)") != license.Fingerprint("pkg:npm/x", "MIT") {
		t.Error("fingerprint must use the normalized license id")
	}
	// Different package or different license → different fingerprint.
	if a == license.Fingerprint("pkg:npm/other", "GPL-3.0-only") {
		t.Error("different packages must not share a fingerprint")
	}
	if a == license.Fingerprint("pkg:npm/readline", "AGPL-3.0-only") {
		t.Error("different licenses must not share a fingerprint")
	}
}

// The disclosure matters MOST when the gate passes: that is precisely when a
// reader would otherwise conclude there is no license exposure at all. It used
// to be suppressed in exactly that case.
func TestLicenseGateDisclosesBacklogEvenWhenPassing(t *testing.T) {
	headID, baseID := uuid.New(), uuid.New()
	inherited := dbgen.Component{Purl: "pkg:npm/old-gpl", Name: "old-gpl", Version: "1.0.0", Licenses: []string{"GPL-3.0-only"}}
	exempted := dbgen.Component{Purl: "pkg:npm/eslint-thing", Name: "eslint-thing", Version: "1.0.0", Licenses: []string{"GPL-3.0-only"}}

	base := &licenseTestStore{mockStore: newMockStore(), components: map[uuid.UUID][]dbgen.Component{
		baseID: {inherited},
		headID: {inherited, exempted},
	}}
	waived := &waivableLicenseStore{
		licenseTestStore: base,
		acceptances: []store.FindingAcceptance{
			{Fingerprint: license.Fingerprint("pkg:npm/waived", "GPL-3.0-only")},
		},
	}
	service := NewService(waived, zerolog.Nop())

	gate, err := service.EvaluateGatesWithConfig(context.Background(), uuid.New(), uuid.New(), &DeltaResult{}, &GateConfig{
		Licenses: &LicenseGate{
			DenyCategories: []string{"copyleft"},
			ExemptPurls:    []string{"pkg:npm/eslint-*"},
		},
		HeadSnapshotID: headID,
		BaseSnapshotID: baseID,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Nothing left to fail on: one violation is inherited, the other exempted.
	if !gate.Passed {
		t.Fatalf("gate should pass, reasons=%v", gate.Reasons)
	}
	notes := strings.Join(gate.Notes, "\n")
	if !strings.Contains(notes, "1 pre-existing license violation(s)") {
		t.Errorf("passing gate hid the inherited backlog: notes=%v", gate.Notes)
	}
	if !strings.Contains(notes, "1 component(s) exempted by policy") {
		t.Errorf("passing gate hid the exemption: notes=%v", gate.Notes)
	}
	if len(gate.Reasons) != 0 {
		t.Errorf("a passing gate must have no reasons, got %v", gate.Reasons)
	}
}

// orgPolicyStore adds an org-level license policy to the license mock.
type orgPolicyStore struct {
	*licenseTestStore
	policy *license.Spec
}

func (m *orgPolicyStore) GetOrgLicensePolicy(_ context.Context, _ uuid.UUID) (*license.Spec, error) {
	return m.policy, nil
}

func licenseFixture(t *testing.T) (*licenseTestStore, uuid.UUID, uuid.UUID) {
	t.Helper()
	headID, baseID := uuid.New(), uuid.New()
	return &licenseTestStore{mockStore: newMockStore(), components: map[uuid.UUID][]dbgen.Component{
		baseID: {},
		headID: {{Purl: "pkg:npm/gpl-thing", Name: "gpl-thing", Version: "1.0.0", Licenses: []string{"GPL-3.0-only"}}},
	}}, headID, baseID
}

// The whole point of an org policy: it applies to a repository whose
// .hibou.yaml says nothing about licenses at all.
func TestOrgLicensePolicyAppliesWithoutRepoConfig(t *testing.T) {
	base, headID, baseID := licenseFixture(t)
	store := &orgPolicyStore{
		licenseTestStore: base,
		policy:           &license.Spec{DenyCategories: []string{"copyleft"}, Evaluate: license.EvaluateNew},
	}
	service := NewService(store, zerolog.Nop())

	gate, err := service.EvaluateGatesWithConfig(context.Background(), uuid.New(), uuid.New(), &DeltaResult{}, &GateConfig{
		// No Licenses section — the repository declares no policy.
		HeadSnapshotID: headID,
		BaseSnapshotID: baseID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if gate.Passed {
		t.Fatalf("the org policy must apply with no repo config, reasons=%v", gate.Reasons)
	}
	// And the check must say whose policy failed it, or the author has nowhere
	// to go.
	if !strings.Contains(strings.Join(gate.Notes, "\n"), "organization's") {
		t.Errorf("the org policy's provenance must be disclosed: notes=%v", gate.Notes)
	}
}

// A repository override REPLACES the org policy rather than merging with it —
// merging two partial policies produces a result neither side wrote.
func TestRepoLicensePolicyOverridesOrg(t *testing.T) {
	base, headID, baseID := licenseFixture(t)
	store := &orgPolicyStore{
		licenseTestStore: base,
		policy:           &license.Spec{DenyCategories: []string{"copyleft"}, DenyUnknown: true},
	}
	service := NewService(store, zerolog.Nop())

	// The repo's own policy denies nothing relevant, so the copyleft component
	// passes despite the org denying copyleft.
	gate, err := service.EvaluateGatesWithConfig(context.Background(), uuid.New(), uuid.New(), &DeltaResult{}, &GateConfig{
		Licenses:       &LicenseGate{DenyCategories: []string{"network-copyleft"}},
		HeadSnapshotID: headID,
		BaseSnapshotID: baseID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !gate.Passed {
		t.Fatalf("the repo override should replace the org policy, reasons=%v", gate.Reasons)
	}

	// But loosening must be visible on the check itself, not only in a dashboard.
	notes := strings.Join(gate.Notes, "\n")
	if !strings.Contains(notes, "overrides the organization's") {
		t.Errorf("the override must be disclosed: notes=%v", gate.Notes)
	}
	if !strings.Contains(notes, "deny_categories") && !strings.Contains(notes, "deny_unknown") {
		t.Errorf("the loosened axis must be named: notes=%v", gate.Notes)
	}
}

// A stricter override needs no chasing, so it is disclosed without being
// flagged as a loosening.
func TestStricterRepoOverrideIsNotFlaggedAsLoosening(t *testing.T) {
	base, headID, baseID := licenseFixture(t)
	store := &orgPolicyStore{
		licenseTestStore: base,
		policy:           &license.Spec{DenyCategories: []string{"copyleft"}, DenyUnknown: true},
	}
	service := NewService(store, zerolog.Nop())

	gate, err := service.EvaluateGatesWithConfig(context.Background(), uuid.New(), uuid.New(), &DeltaResult{}, &GateConfig{
		Licenses: &LicenseGate{
			DenyCategories: []string{"copyleft", "network-copyleft"},
			DenyUnknown:    true,
		},
		HeadSnapshotID: headID,
		BaseSnapshotID: baseID,
	})
	if err != nil {
		t.Fatal(err)
	}
	notes := strings.Join(gate.Notes, "\n")
	if !strings.Contains(notes, "stricter") {
		t.Errorf("a stricter override should still be disclosed: notes=%v", gate.Notes)
	}
	if strings.Contains(notes, "looser") || strings.Contains(notes, "mixed") {
		t.Errorf("a stricter override must not be reported as loosening: notes=%v", gate.Notes)
	}
}

// No org policy and no repo policy means the license gate is not configured, and
// must not be invented from defaults the org never chose.
func TestNoLicensePolicyAnywhereSkipsTheGate(t *testing.T) {
	base, headID, baseID := licenseFixture(t)
	service := NewService(&orgPolicyStore{licenseTestStore: base, policy: nil}, zerolog.Nop())

	gate, err := service.EvaluateGatesWithConfig(context.Background(), uuid.New(), uuid.New(), &DeltaResult{}, &GateConfig{
		HeadSnapshotID: headID,
		BaseSnapshotID: baseID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !gate.Passed {
		t.Fatalf("no policy anywhere must not fail anything, reasons=%v", gate.Reasons)
	}
	if len(gate.Notes) != 0 {
		t.Errorf("nothing to disclose when no policy exists, got %v", gate.Notes)
	}
}

// An org policy that denies nothing is not a policy; it must not switch the
// gate on.
func TestEmptyOrgLicensePolicyIsNotAPolicy(t *testing.T) {
	base, headID, baseID := licenseFixture(t)
	service := NewService(&orgPolicyStore{
		licenseTestStore: base,
		policy:           &license.Spec{DenyUnknown: false},
	}, zerolog.Nop())

	gate, err := service.EvaluateGatesWithConfig(context.Background(), uuid.New(), uuid.New(), &DeltaResult{}, &GateConfig{
		HeadSnapshotID: headID,
		BaseSnapshotID: baseID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !gate.Passed {
		t.Fatalf("an empty org policy must not fail anything, reasons=%v", gate.Reasons)
	}
}

// `Configured` is what the compare view uses to tell "passed" from "nothing was
// checked". A repository governed solely by the org policy has a real threshold,
// so Configured=false renders "no thresholds configured" over an enforcing gate.
func TestOrgPolicyCountsAsConfigured(t *testing.T) {
	base, headID, baseID := licenseFixture(t)
	service := NewService(&orgPolicyStore{
		licenseTestStore: base,
		policy:           &license.Spec{DenyCategories: []string{"copyleft"}},
	}, zerolog.Nop())

	gate, err := service.EvaluateGatesWithConfig(context.Background(), uuid.New(), uuid.New(), &DeltaResult{}, &GateConfig{
		HeadSnapshotID: headID,
		BaseSnapshotID: baseID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !gate.Configured {
		t.Error("an org license policy is a configured threshold")
	}

	// A policy that denies nothing governs nothing and must not claim otherwise.
	empty := NewService(&orgPolicyStore{
		licenseTestStore: base,
		policy:           &license.Spec{DenyUnknown: false},
	}, zerolog.Nop())
	gate, err = empty.EvaluateGatesWithConfig(context.Background(), uuid.New(), uuid.New(), &DeltaResult{}, &GateConfig{
		HeadSnapshotID: headID,
		BaseSnapshotID: baseID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if gate.Configured {
		t.Error("a policy that denies nothing is not a configured threshold")
	}
}

type failingPolicyStore struct {
	*licenseTestStore
}

func (m *failingPolicyStore) GetOrgLicensePolicy(_ context.Context, _ uuid.UUID) (*license.Spec, error) {
	return nil, errors.New("database unavailable")
}

// A failed org-policy read must FAIL the evaluation, not skip the gate and
// report green. This was the fail-open path for any repo inheriting the policy.
func TestOrgPolicyReadErrorFailsClosed(t *testing.T) {
	base, headID, baseID := licenseFixture(t)
	service := NewService(&failingPolicyStore{licenseTestStore: base}, zerolog.Nop())

	gate, err := service.EvaluateGatesWithConfig(context.Background(), uuid.New(), uuid.New(), &DeltaResult{}, &GateConfig{
		HeadSnapshotID: headID,
		BaseSnapshotID: baseID,
	})
	if err == nil {
		t.Fatalf("an unreadable org policy must error rather than pass, got gate=%+v", gate)
	}
	if gate != nil {
		t.Errorf("no gate result may accompany the error, got %+v", gate)
	}
}

// Regression for the production outage in alpha.79: commit 6a8efc6 added
// GetOrganizationByID to GateStore without forwarding it on StoreAdapter, the
// `store.(GateStore)` assertion in NewService silently went nil, and every gate
// evaluation — PR compare and forge check publisher alike — returned
// "gate store is not configured". The compile-time pin in adapter.go is the real
// guard; this test documents the failure mode where someone will find it.
func TestRealStoreAdapterSatisfiesEveryServiceInterface(t *testing.T) {
	adapter := NewStoreAdapter(nil)

	if _, ok := interface{}(adapter).(GateStore); !ok {
		t.Fatal("StoreAdapter no longer satisfies GateStore; NewService will silently disable ALL gate evaluation")
	}
	service := NewService(adapter, zerolog.Nop())
	if service.gateStore == nil {
		t.Fatal("NewService dropped the gate store for the production adapter")
	}
	for name, ok := range map[string]bool{
		"componentLister":     func() bool { _, ok := interface{}(adapter).(componentLister); return ok }(),
		"acceptanceLister":    func() bool { _, ok := interface{}(adapter).(acceptanceLister); return ok }(),
		"licensePolicyReader": func() bool { _, ok := interface{}(adapter).(licensePolicyReader); return ok }(),
	} {
		if !ok {
			t.Errorf("StoreAdapter no longer satisfies %s; that feature silently degrades", name)
		}
	}
}
