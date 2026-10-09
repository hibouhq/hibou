package delta

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/cwe"
	"github.com/hibouhq/hibou/internal/license"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type GateResult struct {
	Passed bool `json:"passed"`
	// Configured is false when no threshold of any kind applies, so a green
	// "passed" can be told apart from "nothing was checked".
	Configured bool     `json:"configured"`
	Reasons    []string `json:"reasons"`
	// Notes are disclosures that must NOT fail the gate: violations that were
	// waived, exempted, or inherited from the target branch. They cannot live in
	// Reasons because Passed is derived from its length (here and again at
	// internal/server/repos.go when merging a persisted verdict), so an
	// informational line there would turn a green check red.
	Notes []string `json:"notes,omitempty"`
}

type GateStore interface {
	ListQualityGatesByRepo(ctx context.Context, repoID uuid.UUID) ([]dbgen.QualityGate, error)
	ListOrgWideQualityGates(ctx context.Context, orgID uuid.UUID) ([]dbgen.QualityGate, error)
	GetOrganizationByID(ctx context.Context, id uuid.UUID) (*store.Organization, error)
}

// GateConfig carries every file-managed gate section matched for the PR's
// target branch, plus the two snapshots license checks run against. Sections
// are nil when unconfigured.
type GateConfig struct {
	Code            *CodeGate
	CWE             *CWEGate
	Vulnerabilities *VulnerabilityGate
	Licenses        *LicenseGate
	Secrets         *SecretsGate
	HeadSnapshotID  uuid.UUID
	// BaseSnapshotID is the comparison target. Without it the license gate
	// cannot tell an introduced dependency from one that has been on the target
	// branch for a year, so it falls back to whole-tree evaluation.
	BaseSnapshotID uuid.UUID
}

// Configured reports whether any file-managed section carries thresholds.
func (c *GateConfig) Configured() bool {
	return c != nil && (c.Code != nil || c.CWE != nil || c.Vulnerabilities != nil || c.Licenses != nil || c.Secrets != nil)
}

// SecretsGate caps NEW secret findings introduced by the PR. Accepted findings
// are already filtered out of the delta, so a waived rotated key does not fail
// the gate.
type SecretsGate struct {
	MaxNew *int
}

// VulnerabilityGate caps NEW dependency vulnerabilities introduced by the PR.
type VulnerabilityGate struct {
	MaxCritical *int
	MaxHigh     *int
	MaxMedium   *int
	MaxNewTotal *int
}

// LicenseGate is the matched license policy (see internal/license).
type LicenseGate struct {
	DenyCategories []string
	Deny           []string
	Allow          []string
	DenyUnknown    bool
	// ExemptPurls are package globs the policy does not apply to.
	ExemptPurls []string
	// Evaluate is "new" (delta-scoped, the default) or "all" (whole head tree).
	Evaluate string
}

// EvaluatesWholeTree reports whether the gate is configured to judge every
// component in the head snapshot rather than only introduced ones.
func (g *LicenseGate) EvaluatesWholeTree() bool {
	return g != nil && strings.EqualFold(strings.TrimSpace(g.Evaluate), "all")
}

// CodeGate caps NEW first-party code findings by severity (ADR-037 §8).
type CodeGate struct {
	Enabled     *bool
	MaxCritical *int
	MaxHigh     *int
	MaxMedium   *int
}

// CWEGate denies NEW findings that carry a listed CWE (ADR-037 §7).
type CWEGate struct {
	Rules []CWERule
	// Types restricts the gate to finding types; empty means every type.
	Types []string
	// MinSeverity ignores findings below it; empty means any severity.
	MinSeverity string
	// Invalid carries a policy that could not be compiled: evaluating it
	// fails the gate instead of silently skipping the section.
	Invalid error
}

// CWERule is one compiled deny list entry; Path names it in the reason
// ("cwe.deny_tree CWE-74").
type CWERule struct {
	Path     string
	Selector cwe.Selector
}

// cweLister resolves the CWEs of the delta's findings through the same
// finding_cwes definition the filters use.
type cweLister interface {
	ListFindingCWEs(ctx context.Context, vulnerabilityIDs []uuid.UUID) (map[uuid.UUID][]store.FindingCWE, error)
}

// EvaluateGates checks quality gates against a delta result.
func (s *Service) EvaluateGates(ctx context.Context, repoID, orgID uuid.UUID, delta *DeltaResult) (*GateResult, error) {
	return s.EvaluateGatesWithConfig(ctx, repoID, orgID, delta, nil)
}

// EvaluateGatesWithConfig checks DB-managed vulnerability gates plus the
// file-managed weakness / new-vulnerability / license sections.
func (s *Service) EvaluateGatesWithConfig(ctx context.Context, repoID, orgID uuid.UUID, delta *DeltaResult, cfg *GateConfig) (*GateResult, error) {
	if delta == nil {
		delta = &DeltaResult{}
	}
	if s == nil || s.gateStore == nil {
		return nil, errors.New("gate store is not configured")
	}

	gates, err := s.loadQualityGates(ctx, repoID, orgID)
	if err != nil {
		return nil, err
	}

	// Reachability-aware gating (org opt-in): a finding whose vulnerable
	// symbol is provably never called (govulncheck) is not merge-blocking
	// risk. Only `not_reachable` is exempt — unknown stays counted.
	if s.reachabilityGateEnabled(ctx, orgID) {
		filtered := make([]store.Vulnerability, 0, len(delta.New))
		for _, vulnerability := range delta.New {
			if vulnerability.Reachability != nil && *vulnerability.Reachability == "not_reachable" {
				continue
			}
			filtered = append(filtered, vulnerability)
		}
		if len(filtered) != len(delta.New) {
			shallow := *delta
			shallow.New = filtered
			delta = &shallow
		}
	}

	var codeGate *CodeGate
	if cfg != nil {
		codeGate = cfg.Code
	}
	// Malware blocks unconditionally — before any configured gate section: a
	// malicious package is never acceptable, whether or not the repo has a
	// vulnerabilities gate (or any gate) configured.
	var notes []string
	// Set when a license policy (from either source) actually governs this
	// evaluation, so Configured can account for a policy the repo never declared.
	licensePolicyApplied := false
	reasons := evaluateMalwareBlock(delta.New)
	// KEV blocks unconditionally for the same reason malware does: CISA having
	// evidence of active exploitation is a stronger fact than any CVSS score,
	// so a KEV-listed vulnerability is merge-blocking regardless of which gate
	// sections are configured (TODO: "always critical regardless of CVSS").
	// Accepted findings were filtered out of the delta upstream, so a waiver
	// remains the sanctioned way to merge past one.
	kevReasons, err := s.evaluateKEVBlock(ctx, delta.New)
	if err != nil {
		// FAIL CLOSED, like the license policy read: a KEV lookup that errors
		// must not become "nothing is exploited".
		return nil, err
	}
	reasons = append(reasons, kevReasons...)
	reasons = append(reasons, evaluateStoredVulnerabilityGates(gates, delta.New)...)
	reasons = append(reasons, evaluateConfiguredCodeGates(gates, delta.New, codeGate)...)
	if cfg != nil && cfg.CWE != nil {
		cweReasons, err := s.evaluateCWEGate(ctx, delta.New, cfg.CWE)
		if err != nil {
			// FAIL CLOSED like KEV: "could not read CWEs" must not become
			// "no denied CWE was introduced".
			return nil, err
		}
		reasons = append(reasons, cweReasons...)
	}
	if cfg != nil && cfg.Vulnerabilities != nil {
		reasons = append(reasons, evaluateNewVulnerabilityGate(delta.New, cfg.Vulnerabilities)...)
	}
	if cfg != nil && cfg.Secrets != nil {
		reasons = append(reasons, evaluateNewSecretsGate(delta.New, cfg.Secrets)...)
	}
	// Licenses are resolved rather than read straight off the file config: an
	// org-level policy applies even to a repository whose `.hibou.yaml` says
	// nothing about licenses.
	if cfg != nil {
		licensePolicy, policySource, policyNotes, policyErr := s.resolveLicensePolicy(ctx, orgID, cfg.Licenses)
		if policyErr != nil {
			return nil, policyErr
		}
		if licensePolicy != nil {
			licensePolicyApplied = !licensePolicy.Spec().Empty()
			licenseReasons, licenseNotes, licenseErr := s.evaluateLicenseGate(ctx, repoID, cfg.HeadSnapshotID, cfg.BaseSnapshotID, licensePolicy)
			if licenseErr != nil {
				return nil, licenseErr
			}
			reasons = append(reasons, licenseReasons...)
			notes = append(notes, policyNotes...)
			notes = append(notes, licenseNotes...)
			if policySource == LicenseSourceOrganization && len(licenseReasons) > 0 {
				notes = append(notes, "The license policy applied here is the organization's; this repository declares none.")
			}
		}
	}
	return &GateResult{
		Passed: len(reasons) == 0,
		// An org license policy is a configured threshold even though it appears
		// in neither the stored gates nor the repo's file. Without it here, a
		// repo governed solely by the org policy reports Configured=false and
		// the compare view renders "no thresholds configured" over a gate that
		// is enforcing.
		Configured: len(gates) > 0 || cfg.Configured() || licensePolicyApplied,
		Reasons:    reasons,
		Notes:      notes,
	}, nil
}

// evaluateNewVulnerabilityGate caps the vulnerabilities a PR introduces,
// counting only dependency-type rows (weakness gates own SAST findings).
// reachabilityGateEnabled reads the org's vex_reachability_analysis setting.
// Fail closed to counting everything: a settings read error must never make
// the gate more permissive.
func (s *Service) reachabilityGateEnabled(ctx context.Context, orgID uuid.UUID) bool {
	if s.gateStore == nil || orgID == uuid.Nil {
		return false
	}
	org, err := s.gateStore.GetOrganizationByID(ctx, orgID)
	if err != nil || org == nil || len(org.Settings) == 0 {
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

// evaluateMalwareBlock is the unconditional part of malware gating: any new
// malware finding fails the gate, regardless of which gate sections are
// configured or how permissive their limits are. Runs on every evaluation.
func evaluateMalwareBlock(newVulns []store.Vulnerability) []string {
	malware := make([]string, 0, 2)
	for _, vuln := range newVulns {
		if strings.EqualFold(strings.TrimSpace(vuln.Type), "malware") {
			malware = append(malware, vulnLabel(vuln))
		}
	}
	if len(malware) == 0 {
		return nil
	}
	return []string{fmt.Sprintf("%d malicious packages introduced: %s", len(malware), strings.Join(malware, ", "))}
}

// kevLister is satisfied by the store when the local exploited-catalog mirror
// (CISA KEV, ENISA EUVD) is available. A separate optional interface, like
// componentLister: a store that cannot answer simply skips the block rather
// than failing every gate.
type kevLister interface {
	FilterKEVAdvisoryIDs(ctx context.Context, advisoryIDs []uuid.UUID) ([]uuid.UUID, error)
	FilterKEVIdentifiers(ctx context.Context, identifiers []string) ([]string, error)
}

// evaluateKEVBlock fails the gate for every new dependency finding whose
// advisory is on an exploited-vulnerabilities catalog. Matching goes
// through the advisory (canonical id plus aliases) when the finding carries
// one, and falls back to the primary identifier otherwise — a GHSA-canonical
// advisory is KEV-listed when its CVE alias is.
//
// An empty kev_entries table (sync disabled, or never run) matches nothing and
// blocks nothing; only a lookup ERROR propagates.
func (s *Service) evaluateKEVBlock(ctx context.Context, newVulns []store.Vulnerability) ([]string, error) {
	lister, ok := s.store.(kevLister)
	if !ok {
		return nil, nil
	}

	advisoryIDs := make([]uuid.UUID, 0, len(newVulns))
	identifiers := make([]string, 0, len(newVulns))
	for _, vuln := range newVulns {
		if !isAdvisoryBackedFinding(vuln) {
			continue
		}
		if vuln.AdvisoryID != nil {
			advisoryIDs = append(advisoryIDs, *vuln.AdvisoryID)
		} else if id := strings.ToUpper(strings.TrimSpace(vuln.PrimaryIdentifierValue)); id != "" {
			identifiers = append(identifiers, id)
		}
	}
	if len(advisoryIDs) == 0 && len(identifiers) == 0 {
		return nil, nil
	}

	listedAdvisories, err := lister.FilterKEVAdvisoryIDs(ctx, advisoryIDs)
	if err != nil {
		return nil, fmt.Errorf("kev advisory lookup: %w", err)
	}
	listedIdentifiers, err := lister.FilterKEVIdentifiers(ctx, identifiers)
	if err != nil {
		return nil, fmt.Errorf("kev identifier lookup: %w", err)
	}
	if len(listedAdvisories) == 0 && len(listedIdentifiers) == 0 {
		return nil, nil
	}

	advisoryHits := make(map[uuid.UUID]struct{}, len(listedAdvisories))
	for _, id := range listedAdvisories {
		advisoryHits[id] = struct{}{}
	}
	identifierHits := make(map[string]struct{}, len(listedIdentifiers))
	for _, id := range listedIdentifiers {
		identifierHits[id] = struct{}{}
	}

	listed := make([]string, 0, 2)
	for _, vuln := range newVulns {
		if !isAdvisoryBackedFinding(vuln) {
			continue
		}
		var hit bool
		if vuln.AdvisoryID != nil {
			_, hit = advisoryHits[*vuln.AdvisoryID]
		} else {
			_, hit = identifierHits[strings.ToUpper(strings.TrimSpace(vuln.PrimaryIdentifierValue))]
		}
		if hit {
			listed = append(listed, vulnLabel(vuln))
		}
	}
	if len(listed) == 0 {
		return nil, nil
	}
	return []string{fmt.Sprintf("%d known-exploited vulnerabilities introduced (listed on a KEV catalog): %s",
		len(listed), strings.Join(listed, ", "))}, nil
}

// isDependencyFinding limits vulnerability-threshold counting to dependency
// and malware findings — the pre-KEV scope of the stored and file-managed
// gates, kept unchanged so a threshold someone tuned does not silently start
// counting container findings.
func isDependencyFinding(vuln store.Vulnerability) bool {
	vulnType := strings.TrimSpace(vuln.Type)
	return strings.EqualFold(vulnType, "dependency") || strings.EqualFold(vulnType, "malware")
}

// isAdvisoryBackedFinding is the KEV block's scope: every finding type an
// advisory can stand behind. Wider than isDependencyFinding on purpose — a
// KEV-listed CVE in a base image (type "container") is exactly as exploited
// as the same CVE in a manifest, and the finding drawer renders both with the
// same "the gate blocks this" wording.
func isAdvisoryBackedFinding(vuln store.Vulnerability) bool {
	vulnType := strings.TrimSpace(vuln.Type)
	return strings.EqualFold(vulnType, "dependency") ||
		strings.EqualFold(vulnType, "malware") ||
		strings.EqualFold(vulnType, "container")
}

func evaluateNewVulnerabilityGate(newVulns []store.Vulnerability, gate *VulnerabilityGate) []string {
	counts := map[store.SeverityLevel]int{}
	total := 0
	for _, vuln := range newVulns {
		// Malware counts toward the same thresholds as dependency findings; its
		// unconditional block lives in evaluateMalwareBlock.
		if !isDependencyFinding(vuln) {
			continue
		}
		counts[vuln.Severity]++
		total++
	}
	reasons := make([]string, 0, 4)
	check := func(threshold *int, count int, label string) {
		if threshold != nil && count > *threshold {
			reasons = append(reasons, fmt.Sprintf("%d new %s dependency vulnerabilities exceed the maximum %d", count, label, *threshold))
		}
	}
	check(gate.MaxCritical, counts[store.SeverityLevelCritical], "critical")
	check(gate.MaxHigh, counts[store.SeverityLevelHigh], "high")
	check(gate.MaxMedium, counts[store.SeverityLevelMedium], "medium")
	if gate.MaxNewTotal != nil && total > *gate.MaxNewTotal {
		reasons = append(reasons, fmt.Sprintf("%d new dependency vulnerabilities exceed the maximum %d", total, *gate.MaxNewTotal))
	}
	return reasons
}

// vulnLabel names a finding in gate reasons: component@version when known,
// else the primary identifier.
func vulnLabel(vuln store.Vulnerability) string {
	if vuln.ComponentName != nil && *vuln.ComponentName != "" {
		label := *vuln.ComponentName
		if vuln.ComponentVersion != nil && *vuln.ComponentVersion != "" {
			label += "@" + *vuln.ComponentVersion
		}
		return label
	}
	if vuln.PrimaryIdentifierValue != "" {
		return vuln.PrimaryIdentifierValue
	}
	return vuln.Title
}

// evaluateNewSecretsGate caps the secret findings a PR introduces. Only rows of
// type "secret" count; the message names files, never values — only
// secret_hash is ever stored.
func evaluateNewSecretsGate(newVulns []store.Vulnerability, gate *SecretsGate) []string {
	if gate == nil || gate.MaxNew == nil {
		return nil
	}
	count := 0
	files := make([]string, 0, 5)
	for _, vuln := range newVulns {
		if !strings.EqualFold(strings.TrimSpace(vuln.Type), "secret") {
			continue
		}
		count++
		if len(files) < 5 && vuln.FilePath != nil && *vuln.FilePath != "" {
			files = append(files, *vuln.FilePath)
		}
	}
	if count <= *gate.MaxNew {
		return nil
	}
	reason := fmt.Sprintf("%d new secret findings exceed the maximum %d", count, *gate.MaxNew)
	if len(files) > 0 {
		reason += " (in " + strings.Join(files, ", ")
		if count > len(files) {
			reason += ", …"
		}
		reason += ")"
	}
	return []string{reason}
}

// componentLister is satisfied by the store when license gating is available.
type componentLister interface {
	ListComponentsBySnapshot(ctx context.Context, snapshotID uuid.UUID) ([]dbgen.Component, error)
}

// acceptanceLister is satisfied by the store when waivers can be honoured. It is
// a separate optional interface so a store that cannot serve acceptances still
// gates licenses, just without waiver support.
type acceptanceLister interface {
	ListActiveFindingAcceptancesByRepo(ctx context.Context, repoID uuid.UUID) ([]store.FindingAcceptance, error)
}

// licensePolicyReader is satisfied by the store when an org-level license policy
// can be read. Repositories inherit it and may override it in `.hibou.yaml`.
type licensePolicyReader interface {
	GetOrgLicensePolicy(ctx context.Context, orgID uuid.UUID) (*license.Spec, error)
}

// Spec converts the file-declared gate into the shared declarative policy type,
// so an override can be compared against the org's.
func (g *LicenseGate) Spec() license.Spec {
	if g == nil {
		return license.Spec{}
	}
	return license.Spec{
		DenyCategories: g.DenyCategories,
		Deny:           g.Deny,
		Allow:          g.Allow,
		ExemptPurls:    g.ExemptPurls,
		DenyUnknown:    g.DenyUnknown,
		Evaluate:       g.Evaluate,
	}
}

// licenseGateFromSpec is the inverse, used when the org policy applies unchanged.
func licenseGateFromSpec(spec license.Spec) *LicenseGate {
	return &LicenseGate{
		DenyCategories: spec.DenyCategories,
		Deny:           spec.Deny,
		Allow:          spec.Allow,
		ExemptPurls:    spec.ExemptPurls,
		DenyUnknown:    spec.DenyUnknown,
		Evaluate:       spec.EvaluateValue(),
	}
}

// Where the applied license policy came from.
const (
	LicenseSourceRepository   = "repository"
	LicenseSourceOrganization = "organization"
)

// resolveLicensePolicy decides which license policy applies. A repository's
// `.hibou.yaml` section OVERRIDES the organization's policy rather than merging
// with it — merging two partial policies produces a result neither side wrote,
// and nobody could predict it.
//
// The override is deliberately not silent: when it is looser than the org policy,
// the gate says so on the check itself, so loosening is visible at the point of
// use and not only in an org dashboard.
func (s *Service) resolveLicensePolicy(ctx context.Context, orgID uuid.UUID, fileGate *LicenseGate) (*LicenseGate, string, []string, error) {
	var orgSpec *license.Spec
	if reader, ok := s.store.(licensePolicyReader); ok && orgID != uuid.Nil {
		spec, err := reader.GetOrgLicensePolicy(ctx, orgID)
		if err != nil {
			// FAIL CLOSED. A policy that exists but cannot be read must not
			// become "no policy": for a repository that inherits the org policy
			// and declares none of its own, swallowing this error skips the gate
			// entirely and reports a green check. Returning the error makes the
			// whole gate evaluation fail, which every caller surfaces as an
			// error or a pending check rather than a pass.
			return nil, "", nil, fmt.Errorf("read org license policy: %w", err)
		}
		orgSpec = spec
	}

	if fileGate == nil {
		if orgSpec == nil || orgSpec.Empty() {
			return nil, "", nil, nil
		}
		return licenseGateFromSpec(*orgSpec), LicenseSourceOrganization, nil, nil
	}

	notes := []string{}
	if orgSpec != nil && !orgSpec.Empty() {
		relation, differences := license.Compare(*orgSpec, fileGate.Spec())
		switch relation {
		case license.RelationLooser, license.RelationMixed:
			notes = append(notes, fmt.Sprintf(
				"This repository's license policy overrides the organization's and is %s: %s",
				relation, summarizeDifferences(differences)))
		case license.RelationStricter:
			notes = append(notes, "This repository's license policy overrides the organization's and is stricter.")
		}
	}
	return fileGate, LicenseSourceRepository, notes, nil
}

// summarizeDifferences renders the loosened axes for a check note, naming the
// fields rather than dumping both policies.
func summarizeDifferences(differences []license.Difference) string {
	parts := make([]string, 0, len(differences))
	for _, difference := range differences {
		if difference.Direction == license.RelationStricter {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s (%s)", difference.Field, difference.Direction))
	}
	if len(parts) == 0 {
		return "no loosened rules"
	}
	return strings.Join(parts, ", ")
}

// evaluateLicenseGate checks head-snapshot components against the license
// policy. By default only components the change INTRODUCES are judged: gating
// the whole tree means enabling a policy on an existing repo reports
// years-old dependencies as if this PR had added them, which is the fastest way
// to get a license gate switched off for good. Pre-existing violations are
// still counted and reported, just not as a reason to fail.
//
// Capped to 20 reasons so a policy rollout over a large tree cannot produce a
// megabyte check run; the count is included when truncated.
func (s *Service) evaluateLicenseGate(ctx context.Context, repoID, headSnapshotID, baseSnapshotID uuid.UUID, gate *LicenseGate) (reasons, notes []string, err error) {
	if headSnapshotID == uuid.Nil {
		return nil, nil, nil
	}
	lister, ok := s.store.(componentLister)
	if !ok {
		// A configured policy that cannot be evaluated must be loud. Returning
		// nil here silently is what let the license gate ship inert: the check
		// reported "passed" while never looking at a single component.
		s.log.Error().Msg("license gate configured but the delta store cannot list components; policy NOT evaluated")
		return nil, nil, nil
	}
	policy := license.Policy{
		DenyCategories: gate.DenyCategories,
		Deny:           gate.Deny,
		Allow:          gate.Allow,
		DenyUnknown:    gate.DenyUnknown,
	}
	if policy.Empty() {
		return nil, nil, nil
	}

	components, listErr := lister.ListComponentsBySnapshot(ctx, headSnapshotID)
	if listErr != nil {
		return nil, nil, fmt.Errorf("list components for license gate: %w", listErr)
	}

	// Waivers are the sanctioned way to unblock one package, as opposed to
	// loosening the policy for the whole repo. Expired ones are excluded by the
	// query, so a lapsed waiver resurfaces as a failure on its own.
	waived := map[string]struct{}{}
	if accepter, ok := s.store.(acceptanceLister); !ok {
		// Not fatal — the gate still works, waivers just cannot be honoured —
		// but a granted waiver that does nothing is its own trust problem.
		s.log.Warn().Msg("delta store cannot list finding acceptances; license waivers will not be honoured")
	} else {
		acceptances, acceptErr := accepter.ListActiveFindingAcceptancesByRepo(ctx, repoID)
		if acceptErr != nil {
			return nil, nil, fmt.Errorf("list license waivers: %w", acceptErr)
		}
		for _, acceptance := range acceptances {
			waived[acceptance.Fingerprint] = struct{}{}
		}
	}

	// Delta scope. A missing base snapshot means we cannot tell new from old, so
	// we fail closed to whole-tree rather than silently passing everything.
	preExisting := map[string]struct{}{}
	deltaScoped := !gate.EvaluatesWholeTree() && baseSnapshotID != uuid.Nil
	if deltaScoped {
		baseComponents, baseErr := lister.ListComponentsBySnapshot(ctx, baseSnapshotID)
		if baseErr != nil {
			return nil, nil, fmt.Errorf("list base components for license gate: %w", baseErr)
		}
		for _, component := range baseComponents {
			preExisting[componentIdentity(component.Purl, component.Version)] = struct{}{}
		}
	}

	const maxReasons = 20
	reasons = make([]string, 0, maxReasons)
	violations := 0
	inherited := 0
	exempted := 0
	accepted := 0

	for _, component := range components {
		// Normalized, matching the policy simulator and the org overview. Left
		// raw, the gate and its own preview disagreed on any expression whose
		// spelling normalization changes.
		violation := policy.Evaluate(license.NormalizeIDs(component.Licenses))
		if violation == nil {
			continue
		}
		// Exemptions are counted and reported, never silent: a suppression
		// nobody can see is worse than the false positive it hides.
		if matchesPurlGlob(component.Purl, gate.ExemptPurls) {
			exempted++
			continue
		}
		if _, ok := waived[license.Fingerprint(component.Purl, violation.License)]; ok {
			accepted++
			continue
		}
		if deltaScoped {
			if _, existed := preExisting[componentIdentity(component.Purl, component.Version)]; existed {
				inherited++
				continue
			}
		}
		violations++
		if len(reasons) >= maxReasons {
			continue
		}
		reasons = append(reasons, licenseViolationReason(component.Name, component.Version, deltaScoped, violation))
	}

	if violations > len(reasons) {
		reasons = append(reasons, fmt.Sprintf("… and %d more license violations", violations-len(reasons)))
	}
	// Disclosures are unconditional: the backlog a delta-scoped gate chooses not
	// to fail on is exactly the thing a reader needs to see, and it is most
	// relevant when the gate PASSES. They go to Notes so they cannot flip Passed.
	if inherited > 0 {
		notes = append(notes, fmt.Sprintf("%d pre-existing license violation(s) on the target branch were not counted", inherited))
	}
	if exempted > 0 {
		notes = append(notes, fmt.Sprintf("%d component(s) exempted by policy", exempted))
	}
	if accepted > 0 {
		notes = append(notes, fmt.Sprintf("%d license violation(s) accepted with a reason", accepted))
	}
	return reasons, notes, nil
}

// componentIdentity keys a component for delta comparison. Version is part of
// the identity on purpose: a version bump can change the license, so an upgraded
// dependency is a new decision, not an inherited one.
func componentIdentity(purl, version string) string {
	return purl + "@" + version
}

// licenseViolationReason words the failure honestly. "Introduces" is only true
// for a delta-scoped run; whole-tree mode says "carries" instead, and a missing
// license is reported as absent metadata rather than as a license named "".
func licenseViolationReason(name, version string, deltaScoped bool, violation *license.Violation) string {
	verb := "carries"
	if deltaScoped {
		verb = "introduces"
	}
	if violation.License == "" {
		return fmt.Sprintf("%s@%s %s no license metadata (unreviewed)", name, version, verb)
	}
	if violation.Category == license.CategoryUnknown {
		return fmt.Sprintf("%s@%s %s unrecognized license %s (category unknown)", name, version, verb, violation.License)
	}
	return fmt.Sprintf("%s@%s %s denied license %s (category %s)", name, version, verb, violation.License, violation.Category)
}

// matchesPurlGlob delegates to internal/license so the gate and the policy
// simulator cannot disagree about which packages are exempt.
func matchesPurlGlob(purl string, globs []string) bool {
	return license.MatchesPurlGlob(purl, globs)
}

func (s *Service) loadQualityGates(ctx context.Context, repoID, orgID uuid.UUID) ([]dbgen.QualityGate, error) {
	gates, err := s.gateStore.ListQualityGatesByRepo(ctx, repoID)
	if err != nil {
		return nil, fmt.Errorf("list repo quality gates: %w", err)
	}
	if len(gates) > 0 {
		return gates, nil
	}
	gates, err = s.gateStore.ListOrgWideQualityGates(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("list org quality gates: %w", err)
	}
	return gates, nil
}

func evaluateStoredVulnerabilityGates(gates []dbgen.QualityGate, vulns []store.Vulnerability) []string {
	critical, high, medium := countNewVulnerabilitySeverities(vulns)
	reasons := make([]string, 0)
	for _, gate := range gates {
		if !gate.Enabled {
			continue
		}
		reasons = append(reasons, evaluateStoredVulnerabilityGate(gate, critical, high, medium)...)
	}
	return reasons
}

func evaluateStoredVulnerabilityGate(gate dbgen.QualityGate, critical, high, medium int) []string {
	reasons := make([]string, 0, 3)
	if int32(critical) > gate.MaxCritical { // #nosec G115 -- severity counts are bounded by in-memory delta size.
		reasons = append(reasons, fmt.Sprintf("gate %q exceeded max critical vulnerabilities: %d > %d", gate.Name, critical, gate.MaxCritical))
	}
	if int32(high) > gate.MaxHigh { // #nosec G115 -- severity counts are bounded by in-memory delta size.
		reasons = append(reasons, fmt.Sprintf("gate %q exceeded max high vulnerabilities: %d > %d", gate.Name, high, gate.MaxHigh))
	}
	if gate.MaxMedium.Valid && int32(medium) > gate.MaxMedium.Int32 { // #nosec G115 -- severity counts are bounded by in-memory delta size.
		reasons = append(reasons, fmt.Sprintf("gate %q exceeded max medium vulnerabilities: %d > %d", gate.Name, medium, gate.MaxMedium.Int32))
	}
	return reasons
}

// evaluateConfiguredCodeGates applies the repo's `code` section, or the
// stored gates when the file has none — both over code findings only: a
// dependency CVE belongs to the vulnerabilities section and a leaked secret
// to the secrets section, and counting them here too failed one finding
// against two thresholds.
func evaluateConfiguredCodeGates(gates []dbgen.QualityGate, vulns []store.Vulnerability, codeGate *CodeGate) []string {
	code := make([]store.Vulnerability, 0, len(vulns))
	for _, vuln := range vulns {
		if isCodeFinding(vuln) {
			code = append(code, vuln)
		}
	}
	if codeGate == nil {
		return evaluateStoredFindingGates(gates, code)
	}
	if !codeGate.EnabledValue() {
		return nil
	}
	return evaluateRepoCodeThresholds(code, codeGate)
}

// isCodeFinding is the `code` section's scope: first-party findings about the
// repository's own code.
func isCodeFinding(vuln store.Vulnerability) bool {
	switch strings.ToLower(strings.TrimSpace(vuln.Type)) {
	case "sast", "dast", "fuzzing", "manual", "generic":
		return true
	}
	return false
}

// evaluateCWEGate fails the gate for every new finding (of an in-scope type
// and severity) that carries a denied CWE. Reasons name the CWE by title and
// the rule that denied it, so the PR check explains itself.
func (s *Service) evaluateCWEGate(ctx context.Context, newVulns []store.Vulnerability, gate *CWEGate) ([]string, error) {
	if gate == nil {
		return nil, nil
	}
	if gate.Invalid != nil {
		return nil, fmt.Errorf("cwe gate policy is invalid: %w", gate.Invalid)
	}
	if len(gate.Rules) == 0 {
		return nil, nil
	}
	lister, ok := s.store.(cweLister)
	if !ok {
		return nil, errors.New("cwe gate configured but the store cannot resolve finding CWEs")
	}
	types := make(map[string]struct{}, len(gate.Types))
	for _, kind := range gate.Types {
		types[strings.ToLower(strings.TrimSpace(kind))] = struct{}{}
	}
	minRank := severityRank(gate.MinSeverity)
	candidates := make([]store.Vulnerability, 0, len(newVulns))
	ids := make([]uuid.UUID, 0, len(newVulns))
	for _, vuln := range newVulns {
		if _, in := types[strings.ToLower(vuln.Type)]; len(types) > 0 && !in {
			continue
		}
		if severityRank(string(vuln.Severity)) < minRank {
			continue
		}
		candidates = append(candidates, vuln)
		ids = append(ids, vuln.ID)
	}
	if len(ids) == 0 {
		return nil, nil
	}
	byFinding, err := lister.ListFindingCWEs(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("cwe lookup: %w", err)
	}
	reasons := make([]string, 0)
	for _, vuln := range candidates {
		carried := make([]int, 0, len(byFinding[vuln.ID]))
		for _, item := range byFinding[vuln.ID] {
			carried = append(carried, item.ID)
		}
		for _, rule := range gate.Rules {
			id, matched := rule.Selector.Match(carried)
			if !matched {
				continue
			}
			reasons = append(reasons, fmt.Sprintf("new %s finding %s%s carries %s, denied by %s",
				vuln.Type, vulnLabel(vuln), vulnLocation(vuln), describeCWE(id), rule.Path))
			break
		}
	}
	return reasons, nil
}

func describeCWE(id int) string {
	if name := cwe.Default().Name(id); name != "" {
		return fmt.Sprintf("%s (%s)", cwe.Format(id), name)
	}
	return cwe.Format(id)
}

func vulnLocation(vuln store.Vulnerability) string {
	if vuln.FilePath == nil || *vuln.FilePath == "" {
		return ""
	}
	if vuln.StartLine != nil && *vuln.StartLine > 0 {
		return fmt.Sprintf(" in %s:%d", *vuln.FilePath, *vuln.StartLine)
	}
	return " in " + *vuln.FilePath
}

func severityRank(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	}
	return 0
}

func evaluateStoredFindingGates(gates []dbgen.QualityGate, vulns []store.Vulnerability) []string {
	reasons := make([]string, 0)
	for _, gate := range gates {
		if !gate.Enabled || !gate.MaxNewFindings.Valid {
			continue
		}
		newVulnerabilities := countVulnerabilitiesBySeverity(vulns, gate.FindingSeverities)
		if int32(newVulnerabilities) > gate.MaxNewFindings.Int32 { // #nosec G115 -- finding counts are bounded by in-memory delta size.
			reasons = append(reasons, fmt.Sprintf("gate %q exceeded max new vulnerabilities: %d > %d", gate.Name, newVulnerabilities, gate.MaxNewFindings.Int32))
		}
	}
	return reasons
}

func evaluateRepoCodeThresholds(vulns []store.Vulnerability, thresholds *CodeGate) []string {
	if thresholds == nil {
		return nil
	}

	critical, high, medium := countNewVulnerabilitySeverities(vulns)
	reasons := make([]string, 0, 3)
	if thresholds.MaxCritical != nil && critical > *thresholds.MaxCritical {
		reasons = append(reasons, fmt.Sprintf("repo config exceeded max critical code findings: %d > %d", critical, *thresholds.MaxCritical))
	}
	if thresholds.MaxHigh != nil && high > *thresholds.MaxHigh {
		reasons = append(reasons, fmt.Sprintf("repo config exceeded max high code findings: %d > %d", high, *thresholds.MaxHigh))
	}
	if thresholds.MaxMedium != nil && medium > *thresholds.MaxMedium {
		reasons = append(reasons, fmt.Sprintf("repo config exceeded max medium code findings: %d > %d", medium, *thresholds.MaxMedium))
	}
	return reasons
}

func (w *CodeGate) EnabledValue() bool {
	if w == nil || w.Enabled == nil {
		return true
	}
	return *w.Enabled
}

func countNewVulnerabilitySeverities(vulns []store.Vulnerability) (critical, high, medium int) {
	for _, vuln := range vulns {
		switch strings.ToLower(strings.TrimSpace(string(vuln.Severity))) {
		case "critical":
			critical++
		case "high":
			high++
		case "medium":
			medium++
		}
	}
	return critical, high, medium
}

func countVulnerabilitiesBySeverity(vulns []store.Vulnerability, allowed []string) int {
	if len(allowed) == 0 {
		return len(vulns)
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, severity := range allowed {
		allowedSet[strings.ToLower(strings.TrimSpace(severity))] = struct{}{}
	}
	count := 0
	for _, vuln := range vulns {
		if _, ok := allowedSet[strings.ToLower(strings.TrimSpace(string(vuln.Severity)))]; ok {
			count++
		}
	}
	return count
}
