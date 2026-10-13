package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/cwe"
	"github.com/hibouhq/hibou/internal/license"
	"github.com/hibouhq/hibou/internal/repoconfig"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// The effective-config view answers one question: "why did my gate do that?".
//
// Gate behaviour is assembled from four sources that no single screen showed
// before — the branch-matched `.hibou.yaml` gate, `quality_gates` rows (the
// repo's own, or the org's when the repo has none), fail-closed defaults applied
// in code, and rules that run unconditionally. The settings page was already
// titled "Effective configuration" while rendering only the raw YAML, so
// DB-managed thresholds, inherited org gates, and every default were invisible.
//
// Each rule therefore carries its SOURCE. A value with no provenance is exactly
// the thing that makes a gate feel arbitrary.

const (
	sourceFile     = "file"
	sourceRepoGate = "repo-gate"
	sourceOrgGate  = "org-gate"
	// sourceOrgPolicy is the org-wide license policy, which is a different
	// object from an org-wide quality gate row.
	sourceOrgPolicy     = "org-policy"
	sourceDefault       = "default"
	sourceUnconditional = "always"
)

type effectiveRule struct {
	Label  string `json:"label"`
	Value  string `json:"value"`
	Source string `json:"source"`
	Detail string `json:"detail,omitempty"`
}

const (
	sectionEnforced      = "enforced"
	sectionNotConfigured = "not-configured"
	sectionDisabled      = "disabled"
)

type effectiveSection struct {
	Name   string          `json:"name"`
	Status string          `json:"status"`
	Rules  []effectiveRule `json:"rules"`
	Note   string          `json:"note,omitempty"`
}

type effectiveConfigResponse struct {
	// Branch the resolution was done for. Gate selection is branch-dependent, so
	// an effective config without a branch is meaningless.
	Branch string `json:"branch"`
	// FileGateMatched is false when no `.hibou.yaml` gate covers this branch —
	// in which case only DB gates and unconditional rules apply.
	FileGateMatched  bool     `json:"file_gate_matched"`
	FileGateBranches []string `json:"file_gate_branches,omitempty"`
	ConfigPresent    bool     `json:"config_present"`
	// FileUnavailable distinguishes "the file has no gates" from "we could not
	// read the file" — collapsing those two would report an unknown as an
	// absence.
	FileUnavailable   bool   `json:"file_unavailable"`
	Enforcement       string `json:"enforcement"`
	EnforcementSource string `json:"enforcement_source"`
	// GateSource says where the DB thresholds came from, since inheriting the
	// org's gates is indistinguishable from having your own until you are told.
	GateSource string             `json:"gate_source,omitempty"`
	Sections   []effectiveSection `json:"sections"`
	// Warnings call out interactions that surprise people — most of all a file
	// weakness gate switching off DB findings gates it never mentions.
	Warnings []string `json:"warnings"`
}

// @Summary      Effective repository gate configuration
// @Description  What actually applies to a branch: the matched .hibou.yaml gate, DB-managed quality gates (the repo's own or inherited from the org), defaults filled in by the server, and unconditional rules — each labelled with its source.
// @Tags         repositories
// @Produce      json
// @Param        provider  path   string  true   "Forge provider"
// @Param        slug      path   string  true   "Organization slug"
// @Param        repoSlug  path   string  true   "Repository slug"
// @Param        branch    query  string  false  "Branch to resolve for (defaults to the repository's default branch)"
// @Success      200  {object}  effectiveConfigResponse
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/config/effective [get]
func (s *Server) handleGetEffectiveRepoConfig(w http.ResponseWriter, r *http.Request) {
	org, repo, _, ok := s.loadAuthorizedRepoWithUser(w, r, false)
	if !ok {
		return
	}
	if !s.enforceTokenCapability(w, r, apitoken.CapAdmin, apitoken.AccessRead, org.Slug, repo.Slug) {
		return
	}

	branch := strings.TrimSpace(r.URL.Query().Get("branch"))
	if branch == "" {
		branch = repo.DefaultBranch
	}

	// A forge hiccup must not make the page claim "no config" — that reads as
	// "nothing is enforced", which is both false and the more dangerous of the
	// two errors. Degrade instead: report the stored gates and defaults, and say
	// plainly that the file could not be read.
	var cfg *repoconfig.RepoConfig
	fileUnavailable := false
	if s.repoConfigLoader == nil {
		fileUnavailable = true
	} else {
		owner, name, resolved := s.boundRepoCoordinates(r.Context(), repo)
		if !resolved {
			fileUnavailable = true
		} else if loaded, loadErr := s.repoConfigLoader.Load(forgeOwnerContext(r.Context(), owner), repo.Provider, owner, name, repo.DefaultBranch); loadErr != nil {
			s.log.Warn().Err(loadErr).Str("repo_id", repo.ID.String()).Msg("load repo config for effective view")
			fileUnavailable = true
		} else {
			cfg = loaded
		}
	}

	repoGates, err := s.queries.ListQualityGatesByRepo(r.Context(), uuid.NullUUID{UUID: repo.ID, Valid: true})
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list repository quality gates")
		return
	}
	gateSource := sourceRepoGate
	gates := repoGates
	if len(gates) == 0 {
		orgGates, orgErr := s.queries.ListOrgWideQualityGates(r.Context(), org.ID)
		if orgErr != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to list organization quality gates")
			return
		}
		gates = orgGates
		gateSource = sourceOrgGate
	}

	orgPolicy, err := s.queries.GetOrgLicensePolicy(r.Context(), org.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load the organization license policy")
		return
	}

	response := buildEffectiveConfig(branch, cfg, gates, gateSource, reachabilityGatingEnabled(org), orgPolicy)
	if fileUnavailable {
		response.FileUnavailable = true
		// Prepended: everything below it is incomplete, so this has to be read
		// first.
		response.Warnings = append([]string{
			".hibou.yml could not be read from the forge, so no file-managed thresholds are shown. Only the stored gates and defaults below are certain.",
		}, response.Warnings...)
	}
	api.JSON(w, http.StatusOK, response)
}

// reachabilityGatingEnabled mirrors delta.reachabilityGateEnabled. Duplicated
// rather than exported because the delta service reads it from its own store
// interface, and this view must report the same flag it actually applies.
func reachabilityGatingEnabled(org *store.Organization) bool {
	if org == nil || len(org.Settings) == 0 {
		return false
	}
	var settings struct {
		VEXReachabilityAnalysis bool `json:"vex_reachability_analysis"`
	}
	if err := json.Unmarshal(org.Settings, &settings); err != nil {
		return false
	}
	return settings.VEXReachabilityAnalysis
}

// buildEffectiveConfig is pure so the merge rules — which are the part users get
// wrong and the part that must not drift from internal/delta — are testable
// without a forge or a database.
func buildEffectiveConfig(
	branch string,
	cfg *repoconfig.RepoConfig,
	gates []dbgen.QualityGate,
	gateSource string,
	reachabilityFiltering bool,
	orgLicensePolicy *license.Spec,
) effectiveConfigResponse {
	matched := cfg.MatchGate(branch)
	response := effectiveConfigResponse{
		Branch:            branch,
		ConfigPresent:     cfg != nil && len(cfg.QualityGates) > 0,
		FileGateMatched:   matched != nil,
		Enforcement:       repoconfig.EnforcementAdvisory,
		EnforcementSource: sourceDefault,
		Sections:          []effectiveSection{},
		Warnings:          []string{},
	}
	if matched != nil {
		response.FileGateBranches = matched.Branches
		response.Enforcement = matched.EnforcementValue()
		if strings.TrimSpace(matched.Enforcement) != "" {
			response.EnforcementSource = sourceFile
		}
	}

	enabledGates := make([]dbgen.QualityGate, 0, len(gates))
	for _, gate := range gates {
		if gate.Enabled {
			enabledGates = append(enabledGates, gate)
		}
	}
	if len(enabledGates) > 0 {
		response.GateSource = gateSource
	}

	response.Sections = append(response.Sections,
		effectiveDependencyVulnerabilitySection(matched, enabledGates, gateSource),
		effectiveCodeSection(matched, enabledGates, gateSource),
		effectiveCWESection(matched),
		effectiveLicenseSection(matched, orgLicensePolicy),
		effectiveCoverageSection(matched, cfg),
		effectiveSecretsSection(matched),
		effectiveUnconditionalSection(reachabilityFiltering),
	)

	// An org license policy is itself an enforcing gate, so the warnings must
	// know about it or they will contradict the Licenses section above them.
	response.Warnings = effectiveConfigWarnings(cfg, matched, enabledGates, gateSource, branch,
		orgLicensePolicy != nil && !orgLicensePolicy.Empty())
	return response
}

func effectiveDependencyVulnerabilitySection(matched *repoconfig.QualityGate, gates []dbgen.QualityGate, gateSource string) effectiveSection {
	section := effectiveSection{Name: "Dependency vulnerabilities", Status: sectionNotConfigured, Rules: []effectiveRule{}}

	// DB rows and the file section are additive here: both are evaluated, so a
	// repo can be held to whichever is stricter without either being visible in
	// the other's UI.
	for _, gate := range gates {
		section.Rules = append(section.Rules,
			effectiveRule{Label: "Max new critical", Value: strconv.Itoa(int(gate.MaxCritical)), Source: gateSource, Detail: gate.Name},
			effectiveRule{Label: "Max new high", Value: strconv.Itoa(int(gate.MaxHigh)), Source: gateSource, Detail: gate.Name},
		)
		if gate.MaxMedium.Valid {
			section.Rules = append(section.Rules,
				effectiveRule{Label: "Max new medium", Value: strconv.Itoa(int(gate.MaxMedium.Int32)), Source: gateSource, Detail: gate.Name})
		}
	}

	if matched != nil && matched.Vulnerabilities != nil {
		thresholds := matched.Vulnerabilities
		section.Rules = append(section.Rules, optionalIntRules(sourceFile, "", map[string]*int{
			"Max new critical (file)": thresholds.MaxCritical,
			"Max new high (file)":     thresholds.MaxHigh,
			"Max new medium (file)":   thresholds.MaxMedium,
			"Max new unknown (file)":  thresholds.MaxUnknown,
			"Max new total (file)":    thresholds.MaxNewTotal,
		})...)
	}

	if len(section.Rules) > 0 {
		section.Status = sectionEnforced
		if len(gates) > 0 && matched != nil && matched.Vulnerabilities != nil {
			section.Note = "Both the stored gate and the file section apply; the stricter one fails first."
		}
	}
	return section
}

func effectiveCodeSection(matched *repoconfig.QualityGate, gates []dbgen.QualityGate, gateSource string) effectiveSection {
	section := effectiveSection{Name: "Code findings", Status: sectionNotConfigured, Rules: []effectiveRule{}}

	// The interaction that surprises everyone: a file code section REPLACES
	// the stored max_new_findings gates rather than adding to them, and an
	// explicitly disabled one switches the whole axis off — stored gates
	// included. Mirrors evaluateConfiguredCodeGates.
	if matched != nil && matched.Code != nil {
		if !matched.Code.EnabledValue() {
			section.Status = sectionDisabled
			section.Note = "Disabled in .hibou.yaml. Stored max-new-findings gates are skipped too."
			return section
		}
		thresholds := matched.Code
		section.Rules = append(section.Rules, optionalIntRules(sourceFile, "", map[string]*int{
			"Max critical": thresholds.MaxCritical,
			"Max high":     thresholds.MaxHigh,
			"Max medium":   thresholds.MaxMedium,
		})...)
		if len(section.Rules) > 0 {
			section.Status = sectionEnforced
			section.Note = "Replaces the stored max-new-findings gates rather than adding to them."
		}
		return section
	}

	for _, gate := range gates {
		if !gate.MaxNewFindings.Valid {
			continue
		}
		severities := "critical, high"
		if len(gate.FindingSeverities) > 0 {
			severities = strings.Join(gate.FindingSeverities, ", ")
		}
		section.Rules = append(section.Rules, effectiveRule{
			Label:  "Max new findings",
			Value:  strconv.Itoa(int(gate.MaxNewFindings.Int32)),
			Source: gateSource,
			Detail: fmt.Sprintf("%s · counts %s", gate.Name, severities),
		})
	}
	if len(section.Rules) > 0 {
		section.Status = sectionEnforced
	}
	return section
}

// effectiveCWESection lists the CWE deny rules with their titles, so the
// settings page says what is blocked in words, not only ids.
func effectiveCWESection(matched *repoconfig.QualityGate) effectiveSection {
	section := effectiveSection{Name: "CWE deny list", Status: sectionNotConfigured, Rules: []effectiveRule{}}
	if matched == nil || matched.CWE == nil {
		return section
	}
	policy := matched.CWE
	catalog := cwe.Default()
	add := func(label string, values []string, describe func(string) string) {
		for _, value := range values {
			section.Rules = append(section.Rules, effectiveRule{Label: label, Value: strings.TrimSpace(value), Source: sourceFile, Detail: describe(value)})
		}
	}
	title := func(value string) string {
		id, _ := cwe.Parse(value)
		return catalog.Name(id)
	}
	add("Deny", policy.Deny, title)
	add("Deny with descendants", policy.DenyTree, func(value string) string {
		id, _ := cwe.Parse(value)
		return fmt.Sprintf("%s · %d CWEs", catalog.Name(id), len(catalog.Descendants(id)))
	})
	add("Deny set", policy.DenySets, func(value string) string {
		set, _ := catalog.Set(value)
		return fmt.Sprintf("%s · %d CWEs", set.Name, len(set.Members))
	})
	add("Deny category", policy.DenyCategories, func(value string) string {
		category, _ := catalog.Category(value)
		return fmt.Sprintf("%s · %d CWEs", category.Name, len(category.Members))
	})
	if len(section.Rules) > 0 {
		section.Status = sectionEnforced
		scope := "every finding type"
		if len(policy.Types) > 0 {
			scope = strings.Join(policy.Types, ", ")
		}
		if policy.MinSeverity != "" {
			scope += ", severity " + policy.MinSeverity + " and above"
		}
		section.Note = "Applies to new findings of " + scope + ". Accepting a finding (risk or false positive) is the way past a denied CWE."
	}
	return section
}

// effectiveLicenseSection reflects RESOLUTION, not just the file: a repository
// that declares no license section is governed by the org policy, and the page
// must say so rather than reporting "not configured".
func effectiveLicenseSection(matched *repoconfig.QualityGate, orgPolicy *license.Spec) effectiveSection {
	section := effectiveSection{Name: "Licenses", Status: sectionNotConfigured, Rules: []effectiveRule{}}

	orgConfigured := orgPolicy != nil && !orgPolicy.Empty()
	declared := matched != nil && matched.Licenses != nil

	var spec license.Spec
	source := sourceFile
	switch {
	case declared:
		spec = license.Spec{
			DenyCategories: matched.Licenses.DenyCategories,
			Deny:           matched.Licenses.Deny,
			Allow:          matched.Licenses.Allow,
			ExemptPurls:    matched.Licenses.ExemptPurls,
			DenyUnknown:    matched.Licenses.DenyUnknownValue(),
			Evaluate:       matched.Licenses.EvaluateValue(),
		}
	case orgConfigured:
		spec = *orgPolicy
		source = sourceOrgPolicy
	default:
		return section
	}

	if len(spec.DenyCategories) > 0 {
		section.Rules = append(section.Rules, effectiveRule{Label: "Denied categories", Value: strings.Join(spec.DenyCategories, ", "), Source: source})
	}
	if len(spec.Deny) > 0 {
		section.Rules = append(section.Rules, effectiveRule{Label: "Denied ids", Value: strings.Join(spec.Deny, ", "), Source: source})
	}
	if len(spec.Allow) > 0 {
		section.Rules = append(section.Rules, effectiveRule{Label: "Allowed ids", Value: strings.Join(spec.Allow, ", "), Source: source})
	}
	if len(spec.ExemptPurls) > 0 {
		section.Rules = append(section.Rules, effectiveRule{Label: "Exempt packages", Value: strings.Join(spec.ExemptPurls, ", "), Source: source})
	}

	// Both of these apply whether or not they appear anywhere, which is precisely
	// why they belong on an effective-config screen.
	denyUnknownSource := source
	if declared && matched.Licenses.DenyUnknown == nil {
		denyUnknownSource = sourceDefault
	}
	section.Rules = append(section.Rules, effectiveRule{
		Label:  "Unknown licenses",
		Value:  boolLabel(spec.DenyUnknown, "denied", "allowed"),
		Source: denyUnknownSource,
		Detail: "a component with no usable license metadata",
	})

	evaluateSource := source
	if declared && strings.TrimSpace(matched.Licenses.Evaluate) == "" {
		evaluateSource = sourceDefault
	}
	scope := "only components this change introduces"
	if spec.EvaluateValue() == license.EvaluateAll {
		scope = "every component in the snapshot"
	}
	section.Rules = append(section.Rules, effectiveRule{
		Label:  "Scope",
		Value:  spec.EvaluateValue(),
		Source: evaluateSource,
		Detail: scope,
	})

	section.Status = sectionEnforced
	// A policy that denies nothing is skipped outright rather than passing, so
	// showing it as "enforced" would be a lie.
	if spec.Empty() {
		section.Status = sectionDisabled
		section.Note = "Denies nothing, so the license gate is skipped entirely."
		return section
	}

	switch {
	case declared && orgConfigured:
		// The override is stated here as well as on the check, because this page
		// is where someone comes to ask why the two differ.
		relation, differences := license.Compare(*orgPolicy, spec)
		if relation == license.RelationEquivalent {
			section.Note = "This repository declares its own policy, identical to the organization's."
			break
		}
		section.Note = fmt.Sprintf("This repository's policy replaces the organization's and is %s (%s).",
			relation, summarizePolicyDifferences(differences))
	case declared:
		section.Note = "Declared by this repository; the organization has no license policy."
	default:
		section.Note = "Inherited from the organization. Adding a `licenses:` section to .hibou.yml replaces it entirely."
	}
	return section
}

// summarizePolicyDifferences names the axes that changed, without dumping both
// policies into a sentence.
func summarizePolicyDifferences(differences []license.Difference) string {
	parts := make([]string, 0, len(differences))
	for _, difference := range differences {
		parts = append(parts, fmt.Sprintf("%s %s", difference.Field, difference.Direction))
	}
	if len(parts) == 0 {
		return "no differences"
	}
	return strings.Join(parts, ", ")
}

func effectiveCoverageSection(matched *repoconfig.QualityGate, cfg *repoconfig.RepoConfig) effectiveSection {
	section := effectiveSection{Name: "Coverage", Status: sectionNotConfigured, Rules: []effectiveRule{}}
	if matched != nil && matched.Coverage != nil {
		coverage := matched.Coverage
		section.Rules = append(section.Rules, optionalFloatRules(sourceFile, map[string]*float64{
			"Min coverage":     coverage.MinCoverage,
			"Diff minimum":     coverage.DiffMinimum,
			"Max drop (grace)": coverage.Grace,
		})...)
	}
	if cfg != nil && cfg.Coverage != nil && len(cfg.Coverage.Exclude) > 0 {
		section.Rules = append(section.Rules, effectiveRule{
			Label:  "Excluded paths",
			Value:  strings.Join(cfg.Coverage.Exclude, ", "),
			Source: sourceFile,
			Detail: "repository-wide, not per branch",
		})
	}
	if len(section.Rules) > 0 {
		section.Status = sectionEnforced
	}
	return section
}

func effectiveSecretsSection(matched *repoconfig.QualityGate) effectiveSection {
	section := effectiveSection{Name: "Secrets", Status: sectionNotConfigured, Rules: []effectiveRule{}}
	if matched != nil && matched.Secrets != nil && matched.Secrets.MaxNew != nil {
		section.Rules = append(section.Rules, effectiveRule{
			Label:  "Max new secrets",
			Value:  strconv.Itoa(*matched.Secrets.MaxNew),
			Source: sourceFile,
			Detail: "accepted findings are already excluded from the delta",
		})
		section.Status = sectionEnforced
	}
	return section
}

// effectiveUnconditionalSection lists what runs no matter what is configured.
// Without it a repo with no gates reads as "nothing is checked", which is wrong.
func effectiveUnconditionalSection(reachabilityFiltering bool) effectiveSection {
	section := effectiveSection{
		Name:   "Always applied",
		Status: sectionEnforced,
		Rules: []effectiveRule{{
			Label:  "Malicious packages",
			Value:  "blocked",
			Source: sourceUnconditional,
			Detail: "runs before any configured gate, whether or not gates exist",
		}},
	}
	if reachabilityFiltering {
		section.Rules = append(section.Rules, effectiveRule{
			Label:  "Unreachable findings",
			Value:  "excluded",
			Source: sourceUnconditional,
			Detail: "organization setting: findings proven unreachable are not counted; unknown still counts",
		})
	}
	return section
}

func effectiveConfigWarnings(
	cfg *repoconfig.RepoConfig,
	matched *repoconfig.QualityGate,
	gates []dbgen.QualityGate,
	gateSource string,
	branch string,
	orgLicensePolicyActive bool,
) []string {
	warnings := []string{}

	if cfg == nil || len(cfg.QualityGates) == 0 {
		switch {
		case len(gates) == 0 && orgLicensePolicyActive:
			// The org license policy is a gate in its own right, so claiming
			// nothing can fail a pull request would contradict the Licenses
			// section rendered directly above it.
			warnings = append(warnings, "No repository or stored quality gates: apart from the organization's license policy and the malicious-package block, nothing can fail a pull request.")
		case len(gates) == 0:
			warnings = append(warnings, "No quality gates at all: scans are recorded, but nothing can fail a pull request except the malicious-package block.")
		default:
			warnings = append(warnings, "No .hibou.yaml quality gates. Only the stored gates below apply, so code, CWE, coverage, secret and license thresholds are unset.")
		}
	} else if matched == nil {
		warnings = append(warnings, fmt.Sprintf("No .hibou.yaml gate matches %q, so none of its thresholds apply to this branch.", branch))
	}

	if len(gates) > 0 && gateSource == sourceOrgGate {
		warnings = append(warnings, "The stored thresholds are inherited from the organization; this repository has no gate rows of its own. Adding one replaces the inherited set entirely.")
	}

	if matched != nil && matched.Code != nil && !matched.Code.EnabledValue() {
		for _, gate := range gates {
			if gate.MaxNewFindings.Valid {
				warnings = append(warnings, fmt.Sprintf("The code section is disabled in .hibou.yaml, which also skips the stored max-new-findings threshold on gate %q.", gate.Name))
				break
			}
		}
	}

	if matched != nil && matched.EnforcementValue() == repoconfig.EnforcementAdvisory {
		warnings = append(warnings, "Enforcement is advisory: failures are reported on the pull request but the check does not block a merge.")
	}

	return warnings
}

func optionalIntRules(source, detail string, values map[string]*int) []effectiveRule {
	// Map iteration is random, so emit in a fixed order for a stable response.
	order := []string{
		"Max critical", "Max high", "Max medium", "Max new",
		"Max new critical (file)", "Max new high (file)", "Max new medium (file)", "Max new total (file)",
	}
	rules := make([]effectiveRule, 0, len(values))
	for _, label := range order {
		value, ok := values[label]
		if !ok || value == nil {
			continue
		}
		rules = append(rules, effectiveRule{Label: label, Value: strconv.Itoa(*value), Source: source, Detail: detail})
	}
	return rules
}

func optionalFloatRules(source string, values map[string]*float64) []effectiveRule {
	order := []string{"Min coverage", "Diff minimum", "Max drop (grace)"}
	rules := make([]effectiveRule, 0, len(values))
	for _, label := range order {
		value, ok := values[label]
		if !ok || value == nil {
			continue
		}
		rules = append(rules, effectiveRule{Label: label, Value: strings.TrimSuffix(fmt.Sprintf("%.2f", *value), ".00"), Source: source})
	}
	return rules
}

func boolLabel(value bool, whenTrue, whenFalse string) string {
	if value {
		return whenTrue
	}
	return whenFalse
}
