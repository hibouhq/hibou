package server

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/hibouhq/hibou/internal/license"
	"github.com/hibouhq/hibou/internal/repoconfig"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

func intPtr(v int) *int    { return &v }
func boolPtr(v bool) *bool { return &v }

func sectionByName(t *testing.T, response effectiveConfigResponse, name string) effectiveSection {
	t.Helper()
	for _, section := range response.Sections {
		if section.Name == name {
			return section
		}
	}
	t.Fatalf("section %q missing from %+v", name, response.Sections)
	return effectiveSection{}
}

func ruleByLabel(t *testing.T, section effectiveSection, label string) effectiveRule {
	t.Helper()
	for _, rule := range section.Rules {
		if rule.Label == label {
			return rule
		}
	}
	t.Fatalf("rule %q missing from section %q: %+v", label, section.Name, section.Rules)
	return effectiveRule{}
}

// Every section must be present even when nothing is configured: a page that
// omits unconfigured axes reads as "this is everything", when the truth is
// "nothing guards that axis".
func TestBuildEffectiveConfigAlwaysReportsEverySection(t *testing.T) {
	t.Parallel()

	response := buildEffectiveConfig("main", nil, nil, sourceRepoGate, false, nil)

	for _, name := range []string{"Dependency vulnerabilities", "Code findings", "Licenses", "Coverage", "Secrets", "Always applied"} {
		section := sectionByName(t, response, name)
		if name == "Always applied" {
			continue
		}
		if section.Status != sectionNotConfigured {
			t.Errorf("%s status = %q, want %q", name, section.Status, sectionNotConfigured)
		}
	}

	// A repo with no gates at all is still not defenceless, and must not read
	// as if it were.
	always := sectionByName(t, response, "Always applied")
	malware := ruleByLabel(t, always, "Malicious packages")
	if malware.Source != sourceUnconditional {
		t.Errorf("malware block source = %q, want %q", malware.Source, sourceUnconditional)
	}

	if len(response.Warnings) == 0 {
		t.Error("a repo with no gates at all must be warned about it")
	}
	if response.Enforcement != repoconfig.EnforcementAdvisory || response.EnforcementSource != sourceDefault {
		t.Errorf("enforcement = %q/%q, want advisory/default", response.Enforcement, response.EnforcementSource)
	}
}

// Defaults are the whole point of the screen: deny_unknown and evaluate apply
// whether or not anyone wrote them down.
func TestBuildEffectiveConfigLabelsLicenseDefaults(t *testing.T) {
	t.Parallel()

	cfg := &repoconfig.RepoConfig{QualityGates: []repoconfig.QualityGate{{
		Branches: []string{"main"},
		Licenses: &repoconfig.LicensePolicy{DenyCategories: []string{"copyleft"}},
	}}}
	section := sectionByName(t, buildEffectiveConfig("main", cfg, nil, sourceRepoGate, false, nil), "Licenses")

	if section.Status != sectionEnforced {
		t.Fatalf("status = %q, want enforced", section.Status)
	}
	unknown := ruleByLabel(t, section, "Unknown licenses")
	if unknown.Value != "denied" || unknown.Source != sourceDefault {
		t.Errorf("deny_unknown = %q from %q, want denied/default", unknown.Value, unknown.Source)
	}
	scope := ruleByLabel(t, section, "Scope")
	if scope.Value != repoconfig.LicenseEvaluateNew || scope.Source != sourceDefault {
		t.Errorf("evaluate = %q from %q, want new/default", scope.Value, scope.Source)
	}

	// Written explicitly, the same values must be attributed to the file.
	cfg.QualityGates[0].Licenses.DenyUnknown = boolPtr(false)
	cfg.QualityGates[0].Licenses.Evaluate = repoconfig.LicenseEvaluateAll
	section = sectionByName(t, buildEffectiveConfig("main", cfg, nil, sourceRepoGate, false, nil), "Licenses")
	unknown = ruleByLabel(t, section, "Unknown licenses")
	if unknown.Value != "allowed" || unknown.Source != sourceFile {
		t.Errorf("deny_unknown = %q from %q, want allowed/file", unknown.Value, unknown.Source)
	}
	if scope := ruleByLabel(t, section, "Scope"); scope.Source != sourceFile {
		t.Errorf("evaluate source = %q, want file", scope.Source)
	}
}

// A license policy that denies nothing is skipped by the gate, not passed, so
// rendering it as enforced would be a lie.
func TestBuildEffectiveConfigMarksEmptyLicensePolicyDisabled(t *testing.T) {
	t.Parallel()

	cfg := &repoconfig.RepoConfig{QualityGates: []repoconfig.QualityGate{{
		Branches: []string{"main"},
		Licenses: &repoconfig.LicensePolicy{DenyUnknown: boolPtr(false)},
	}}}
	section := sectionByName(t, buildEffectiveConfig("main", cfg, nil, sourceRepoGate, false, nil), "Licenses")
	if section.Status != sectionDisabled {
		t.Errorf("status = %q, want disabled", section.Status)
	}
	if section.Note == "" {
		t.Error("a skipped policy must say why")
	}
}

// The interaction nobody expects, mirroring evaluateConfiguredCodeGates: a
// file weakness section replaces the stored findings gates, and an explicitly
// disabled one switches the axis off entirely — stored gates included.
func TestBuildEffectiveConfigWeaknessFileGateOverridesStoredGates(t *testing.T) {
	t.Parallel()

	stored := []dbgen.QualityGate{{
		Name:              "org default",
		Enabled:           true,
		MaxNewFindings:    sql.NullInt32{Int32: 5, Valid: true},
		FindingSeverities: []string{"critical", "high"},
	}}

	// No file section: the stored findings gate is what applies.
	section := sectionByName(t, buildEffectiveConfig("main", nil, stored, sourceOrgGate, false, nil), "Code findings")
	if section.Status != sectionEnforced {
		t.Fatalf("status = %q, want enforced from the stored gate", section.Status)
	}
	rule := ruleByLabel(t, section, "Max new findings")
	if rule.Value != "5" || rule.Source != sourceOrgGate {
		t.Errorf("stored rule = %q from %q, want 5/org-gate", rule.Value, rule.Source)
	}

	// File section present: it replaces the stored gate, and says so.
	cfg := &repoconfig.RepoConfig{QualityGates: []repoconfig.QualityGate{{
		Branches: []string{"main"},
		Code:     &repoconfig.CodeThresholds{MaxHigh: intPtr(3)},
	}}}
	response := buildEffectiveConfig("main", cfg, stored, sourceOrgGate, false, nil)
	section = sectionByName(t, response, "Code findings")
	if section.Note == "" {
		t.Error("the replace-not-add behaviour must be stated")
	}
	for _, rule := range section.Rules {
		if rule.Label == "Max new findings" {
			t.Error("stored findings gate must not appear once a file section exists")
		}
	}

	// File section explicitly disabled: the whole axis is off, including the
	// stored gate, and that must be warned about rather than silently applied.
	cfg.QualityGates[0].Code.Enabled = boolPtr(false)
	response = buildEffectiveConfig("main", cfg, stored, sourceOrgGate, false, nil)
	section = sectionByName(t, response, "Code findings")
	if section.Status != sectionDisabled {
		t.Errorf("status = %q, want disabled", section.Status)
	}
	found := false
	for _, warning := range response.Warnings {
		if strings.Contains(warning, "max-new-findings") {
			found = true
		}
	}
	if !found {
		t.Errorf("disabling the code section must warn that it skips the stored gate: %v", response.Warnings)
	}
}

// Inheriting the org's gates looks identical to having your own until someone
// says so, and "adding one replaces the inherited set" is the trap.
func TestBuildEffectiveConfigWarnsAboutInheritedOrgGates(t *testing.T) {
	t.Parallel()

	stored := []dbgen.QualityGate{{Name: "org default", Enabled: true, MaxCritical: 0, MaxHigh: 2}}
	response := buildEffectiveConfig("main", nil, stored, sourceOrgGate, false, nil)

	if response.GateSource != sourceOrgGate {
		t.Errorf("gate_source = %q, want org-gate", response.GateSource)
	}
	found := false
	for _, warning := range response.Warnings {
		if strings.Contains(warning, "inherited from the organization") {
			found = true
		}
	}
	if !found {
		t.Errorf("inheritance must be disclosed: %v", response.Warnings)
	}

	section := sectionByName(t, response, "Dependency vulnerabilities")
	if rule := ruleByLabel(t, section, "Max new high"); rule.Value != "2" || rule.Source != sourceOrgGate {
		t.Errorf("rule = %q from %q, want 2/org-gate", rule.Value, rule.Source)
	}
	// The gate's name is the only way to tell two stored gates apart.
	if rule := ruleByLabel(t, section, "Max new critical"); rule.Detail != "org default" {
		t.Errorf("detail = %q, want the gate name", rule.Detail)
	}
}

// Disabled stored gates must not be rendered as if they applied.
func TestBuildEffectiveConfigSkipsDisabledStoredGates(t *testing.T) {
	t.Parallel()

	stored := []dbgen.QualityGate{{Name: "switched off", Enabled: false, MaxCritical: 0, MaxHigh: 0}}
	response := buildEffectiveConfig("main", nil, stored, sourceRepoGate, false, nil)

	section := sectionByName(t, response, "Dependency vulnerabilities")
	if section.Status != sectionNotConfigured {
		t.Errorf("status = %q, want not-configured — the only gate is disabled", section.Status)
	}
	if response.GateSource != "" {
		t.Errorf("gate_source = %q, want empty when no gate is enabled", response.GateSource)
	}
}

// Gate selection is per branch, so a branch no gate covers must be called out
// rather than showing another branch's thresholds.
func TestBuildEffectiveConfigReportsUnmatchedBranch(t *testing.T) {
	t.Parallel()

	cfg := &repoconfig.RepoConfig{QualityGates: []repoconfig.QualityGate{{
		Branches: []string{"main"},
		Code:     &repoconfig.CodeThresholds{MaxHigh: intPtr(0)},
	}}}
	response := buildEffectiveConfig("release/2.0", cfg, nil, sourceRepoGate, false, nil)

	if response.FileGateMatched {
		t.Error("no gate covers release/2.0")
	}
	if section := sectionByName(t, response, "Code findings"); section.Status != sectionNotConfigured {
		t.Errorf("weaknesses = %q, want not-configured on an unmatched branch", section.Status)
	}
	found := false
	for _, warning := range response.Warnings {
		if strings.Contains(warning, "release/2.0") {
			found = true
		}
	}
	if !found {
		t.Errorf("the unmatched branch must be named: %v", response.Warnings)
	}

	// And the matching branch does get them.
	response = buildEffectiveConfig("main", cfg, nil, sourceRepoGate, false, nil)
	if !response.FileGateMatched {
		t.Error("main must match")
	}
	if section := sectionByName(t, response, "Code findings"); section.Status != sectionEnforced {
		t.Errorf("weaknesses on main = %q, want enforced", section.Status)
	}
}

// Advisory is the default and means failures do not block, which is the single
// most consequential thing to misunderstand about a gate.
func TestBuildEffectiveConfigDisclosesAdvisoryEnforcement(t *testing.T) {
	t.Parallel()

	cfg := &repoconfig.RepoConfig{QualityGates: []repoconfig.QualityGate{{
		Branches: []string{"main"},
		Code:     &repoconfig.CodeThresholds{MaxHigh: intPtr(0)},
	}}}
	response := buildEffectiveConfig("main", cfg, nil, sourceRepoGate, false, nil)
	found := false
	for _, warning := range response.Warnings {
		if strings.Contains(warning, "advisory") {
			found = true
		}
	}
	if !found {
		t.Errorf("advisory enforcement must be disclosed: %v", response.Warnings)
	}

	cfg.QualityGates[0].Enforcement = repoconfig.EnforcementBlocking
	response = buildEffectiveConfig("main", cfg, nil, sourceRepoGate, false, nil)
	if response.Enforcement != repoconfig.EnforcementBlocking || response.EnforcementSource != sourceFile {
		t.Errorf("enforcement = %q/%q, want blocking/file", response.Enforcement, response.EnforcementSource)
	}
	for _, warning := range response.Warnings {
		if strings.Contains(warning, "advisory") {
			t.Errorf("a blocking gate must not be described as advisory: %v", response.Warnings)
		}
	}
}

// The org opt-in silently changes what every gate counts, so it belongs on this
// page even though it is configured elsewhere.
func TestBuildEffectiveConfigShowsReachabilityFiltering(t *testing.T) {
	t.Parallel()

	off := sectionByName(t, buildEffectiveConfig("main", nil, nil, sourceRepoGate, false, nil), "Always applied")
	for _, rule := range off.Rules {
		if rule.Label == "Unreachable findings" {
			t.Error("reachability filtering must not be listed when the org has not opted in")
		}
	}

	on := sectionByName(t, buildEffectiveConfig("main", nil, nil, sourceRepoGate, true, nil), "Always applied")
	if rule := ruleByLabel(t, on, "Unreachable findings"); rule.Value != "excluded" {
		t.Errorf("rule = %+v, want excluded", rule)
	}
}

// Both the stored gate and the file section are evaluated for dependency
// vulnerabilities — unlike the code section, where the file replaces the stored gate.
func TestBuildEffectiveConfigDependencySectionIsAdditive(t *testing.T) {
	t.Parallel()

	stored := []dbgen.QualityGate{{Name: "stored", Enabled: true, MaxCritical: 0, MaxHigh: 5}}
	cfg := &repoconfig.RepoConfig{QualityGates: []repoconfig.QualityGate{{
		Branches:        []string{"main"},
		Vulnerabilities: &repoconfig.VulnerabilityThresholds{MaxHigh: intPtr(1)},
	}}}

	section := sectionByName(t, buildEffectiveConfig("main", cfg, stored, sourceRepoGate, false, nil), "Dependency vulnerabilities")

	// Both must be present, each attributed to its own source.
	if rule := ruleByLabel(t, section, "Max new high"); rule.Value != "5" || rule.Source != sourceRepoGate {
		t.Errorf("stored rule = %q from %q, want 5/repo-gate", rule.Value, rule.Source)
	}
	if rule := ruleByLabel(t, section, "Max new high (file)"); rule.Value != "1" || rule.Source != sourceFile {
		t.Errorf("file rule = %q from %q, want 1/file", rule.Value, rule.Source)
	}
	if section.Note == "" {
		t.Error("the additive interaction must be stated when both sources apply")
	}
}

// "The file could not be read" and "the file has no gates" produce very
// different truths, and the more dangerous error is reporting the first as the
// second — it reads as "nothing is enforced".
func TestBuildEffectiveConfigDistinguishesMissingFileFromEmptyFile(t *testing.T) {
	t.Parallel()

	stored := []dbgen.QualityGate{{Name: "stored", Enabled: true, MaxCritical: 0, MaxHigh: 1}}

	// nil cfg is what the handler passes when the forge read failed. The stored
	// thresholds must still be reported rather than lost with the error.
	response := buildEffectiveConfig("main", nil, stored, sourceRepoGate, false, nil)
	section := sectionByName(t, response, "Dependency vulnerabilities")
	if section.Status != sectionEnforced {
		t.Errorf("stored gate must still be reported without the file, got %q", section.Status)
	}
	if response.FileUnavailable {
		t.Error("buildEffectiveConfig must not guess at file availability; the handler sets it")
	}
	if response.ConfigPresent {
		t.Error("config_present must be false when there are no file gates")
	}
}

// A repository that declares no license section is governed by the org policy.
// Reporting that as "not configured" would tell the reader nothing is enforced
// when something is.
func TestEffectiveLicenseSectionResolvesOrgPolicy(t *testing.T) {
	t.Parallel()

	orgPolicy := &license.Spec{
		DenyCategories: []string{"copyleft"},
		DenyUnknown:    true,
		Evaluate:       license.EvaluateNew,
	}

	// No file gate at all: the org policy applies and is attributed to the org.
	section := sectionByName(t, buildEffectiveConfig("main", nil, nil, sourceRepoGate, false, orgPolicy), "Licenses")
	if section.Status != sectionEnforced {
		t.Fatalf("status = %q, want enforced from the org policy", section.Status)
	}
	if rule := ruleByLabel(t, section, "Denied categories"); rule.Source != sourceOrgPolicy {
		t.Errorf("source = %q, want %q", rule.Source, sourceOrgPolicy)
	}
	if !strings.Contains(section.Note, "Inherited from the organization") {
		t.Errorf("note must say where the policy came from: %q", section.Note)
	}

	// A file gate with no licenses section still inherits.
	cfg := &repoconfig.RepoConfig{QualityGates: []repoconfig.QualityGate{{
		Branches: []string{"main"},
		Code:     &repoconfig.CodeThresholds{MaxHigh: intPtr(0)},
	}}}
	section = sectionByName(t, buildEffectiveConfig("main", cfg, nil, sourceRepoGate, false, orgPolicy), "Licenses")
	if section.Status != sectionEnforced {
		t.Errorf("a gate without a licenses section must still inherit, got %q", section.Status)
	}
}

// The override must be stated here too — this page is where someone comes to ask
// why the repository and the org disagree.
func TestEffectiveLicenseSectionReportsOverrideRelation(t *testing.T) {
	t.Parallel()

	orgPolicy := &license.Spec{DenyCategories: []string{"copyleft"}, DenyUnknown: true}

	looser := &repoconfig.RepoConfig{QualityGates: []repoconfig.QualityGate{{
		Branches: []string{"main"},
		Licenses: &repoconfig.LicensePolicy{
			DenyCategories: []string{"copyleft"},
			DenyUnknown:    boolPtr(false),
		},
	}}}
	section := sectionByName(t, buildEffectiveConfig("main", looser, nil, sourceRepoGate, false, orgPolicy), "Licenses")
	if !strings.Contains(section.Note, "replaces the organization's") {
		t.Errorf("the override must be stated: %q", section.Note)
	}
	if !strings.Contains(section.Note, string(license.RelationLooser)) {
		t.Errorf("the direction must be named: %q", section.Note)
	}
	if !strings.Contains(section.Note, "deny_unknown") {
		t.Errorf("the changed axis must be named: %q", section.Note)
	}
	// The repository's own value is what applies, attributed to the file.
	if rule := ruleByLabel(t, section, "Unknown licenses"); rule.Value != "allowed" || rule.Source != sourceFile {
		t.Errorf("rule = %q from %q, want allowed/file", rule.Value, rule.Source)
	}

	// An identical override is not a departure and must not read like one.
	same := &repoconfig.RepoConfig{QualityGates: []repoconfig.QualityGate{{
		Branches: []string{"main"},
		Licenses: &repoconfig.LicensePolicy{DenyCategories: []string{"copyleft"}, DenyUnknown: boolPtr(true)},
	}}}
	section = sectionByName(t, buildEffectiveConfig("main", same, nil, sourceRepoGate, false, orgPolicy), "Licenses")
	if !strings.Contains(section.Note, "identical") {
		t.Errorf("an equivalent override should say so: %q", section.Note)
	}
	for _, word := range []string{"looser", "stricter", "mixed"} {
		if strings.Contains(section.Note, word) {
			t.Errorf("an identical policy must not be described as %q: %q", word, section.Note)
		}
	}
}

// No policy in either place means no license gate, and the page must not invent
// one from defaults nobody chose.
func TestEffectiveLicenseSectionNoPolicyAnywhere(t *testing.T) {
	t.Parallel()

	section := sectionByName(t, buildEffectiveConfig("main", nil, nil, sourceRepoGate, false, nil), "Licenses")
	if section.Status != sectionNotConfigured {
		t.Errorf("status = %q, want not-configured", section.Status)
	}
	if len(section.Rules) != 0 {
		t.Errorf("no rules should be invented, got %+v", section.Rules)
	}

	// An org policy that denies nothing is not a policy.
	empty := &license.Spec{DenyUnknown: false}
	section = sectionByName(t, buildEffectiveConfig("main", nil, nil, sourceRepoGate, false, empty), "Licenses")
	if section.Status != sectionNotConfigured {
		t.Errorf("an empty org policy must not switch the section on, got %q", section.Status)
	}
}

// An org license policy IS an enforcing gate. Warning that "nothing can fail a
// pull request" while the Licenses section directly above says "enforced" is a
// contradiction on one screen, and the screen exists to be trusted.
func TestEffectiveConfigWarningsAccountForOrgLicensePolicy(t *testing.T) {
	t.Parallel()

	orgPolicy := &license.Spec{DenyCategories: []string{"copyleft"}, DenyUnknown: true}

	// No repo config, no stored gates, but an org policy in force.
	response := buildEffectiveConfig("main", nil, nil, sourceRepoGate, false, orgPolicy)

	if section := sectionByName(t, response, "Licenses"); section.Status != sectionEnforced {
		t.Fatalf("premise wrong: licenses = %q, want enforced", section.Status)
	}
	joined := strings.Join(response.Warnings, "\n")
	if strings.Contains(joined, "No quality gates at all") {
		t.Errorf("must not claim no gates while the license policy is enforced: %v", response.Warnings)
	}
	if !strings.Contains(joined, "license policy") {
		t.Errorf("the warning should name the org license policy as the exception: %v", response.Warnings)
	}

	// With no policy anywhere, the blunt warning is correct and must remain.
	bare := buildEffectiveConfig("main", nil, nil, sourceRepoGate, false, nil)
	if !strings.Contains(strings.Join(bare.Warnings, "\n"), "No quality gates at all") {
		t.Errorf("a genuinely ungated repo must still be warned bluntly: %v", bare.Warnings)
	}

	// An org policy that denies nothing is not a gate, so it must not soften the
	// warning either.
	empty := buildEffectiveConfig("main", nil, nil, sourceRepoGate, false, &license.Spec{DenyUnknown: false})
	if !strings.Contains(strings.Join(empty.Warnings, "\n"), "No quality gates at all") {
		t.Errorf("an empty policy must not count as a gate: %v", empty.Warnings)
	}
}
