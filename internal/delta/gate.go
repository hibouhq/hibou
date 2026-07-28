package delta

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

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
}

type GateStore interface {
	ListQualityGatesByRepo(ctx context.Context, repoID uuid.UUID) ([]dbgen.QualityGate, error)
	ListOrgWideQualityGates(ctx context.Context, orgID uuid.UUID) ([]dbgen.QualityGate, error)
}

// GateConfig carries every file-managed gate section matched for the PR's
// target branch, plus the head snapshot whose components license checks run
// against. Sections are nil when unconfigured.
type GateConfig struct {
	Weakness        *WeaknessGate
	Vulnerabilities *VulnerabilityGate
	Licenses        *LicenseGate
	Secrets         *SecretsGate
	HeadSnapshotID  uuid.UUID
}

// Configured reports whether any file-managed section carries thresholds.
func (c *GateConfig) Configured() bool {
	return c != nil && (c.Weakness != nil || c.Vulnerabilities != nil || c.Licenses != nil || c.Secrets != nil)
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
}

type WeaknessGate struct {
	Enabled     *bool
	MaxCritical *int
	MaxHigh     *int
	MaxMedium   *int
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
	var weaknessGate *WeaknessGate
	if cfg != nil {
		weaknessGate = cfg.Weakness
	}
	reasons := append(evaluateStoredVulnerabilityGates(gates, delta.New), evaluateConfiguredWeaknessGates(gates, delta.New, weaknessGate)...)
	if cfg != nil && cfg.Vulnerabilities != nil {
		reasons = append(reasons, evaluateNewVulnerabilityGate(delta.New, cfg.Vulnerabilities)...)
	}
	if cfg != nil && cfg.Secrets != nil {
		reasons = append(reasons, evaluateNewSecretsGate(delta.New, cfg.Secrets)...)
	}
	if cfg != nil && cfg.Licenses != nil {
		licenseReasons, licenseErr := s.evaluateLicenseGate(ctx, cfg.HeadSnapshotID, cfg.Licenses)
		if licenseErr != nil {
			return nil, licenseErr
		}
		reasons = append(reasons, licenseReasons...)
	}
	return &GateResult{
		Passed:     len(reasons) == 0,
		Configured: len(gates) > 0 || cfg.Configured(),
		Reasons:    reasons,
	}, nil
}

// evaluateNewVulnerabilityGate caps the vulnerabilities a PR introduces,
// counting only dependency-type rows (weakness gates own SAST findings).
func evaluateNewVulnerabilityGate(newVulns []store.Vulnerability, gate *VulnerabilityGate) []string {
	counts := map[store.SeverityLevel]int{}
	total := 0
	for _, vuln := range newVulns {
		if !strings.EqualFold(strings.TrimSpace(vuln.Type), "dependency") {
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

// evaluateLicenseGate checks every head-snapshot component against the license
// policy. Capped to 20 reasons so a policy rollout over a large tree cannot
// produce a megabyte check run; the count is included when truncated.
func (s *Service) evaluateLicenseGate(ctx context.Context, headSnapshotID uuid.UUID, gate *LicenseGate) ([]string, error) {
	if headSnapshotID == uuid.Nil {
		return nil, nil
	}
	lister, ok := s.store.(componentLister)
	if !ok {
		return nil, nil
	}
	components, err := lister.ListComponentsBySnapshot(ctx, headSnapshotID)
	if err != nil {
		return nil, fmt.Errorf("list components for license gate: %w", err)
	}
	policy := license.Policy{
		DenyCategories: gate.DenyCategories,
		Deny:           gate.Deny,
		Allow:          gate.Allow,
		DenyUnknown:    gate.DenyUnknown,
	}
	if policy.Empty() {
		return nil, nil
	}
	const maxReasons = 20
	reasons := make([]string, 0, maxReasons)
	violations := 0
	for _, component := range components {
		violation := policy.Evaluate(component.Licenses)
		if violation == nil {
			continue
		}
		violations++
		if len(reasons) >= maxReasons {
			continue
		}
		licenseName := violation.License
		if licenseName == "" {
			licenseName = "no license metadata"
		}
		reasons = append(reasons, fmt.Sprintf("%s@%s introduces denied license %s (category %s)", component.Name, component.Version, licenseName, violation.Category))
	}
	if violations > len(reasons) {
		reasons = append(reasons, fmt.Sprintf("… and %d more license violations", violations-len(reasons)))
	}
	return reasons, nil
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
	if int32(critical) > gate.MaxCritical { //nolint:gosec // G115: severity counts are bounded by in-memory delta size.
		reasons = append(reasons, fmt.Sprintf("gate %q exceeded max critical vulnerabilities: %d > %d", gate.Name, critical, gate.MaxCritical))
	}
	if int32(high) > gate.MaxHigh { //nolint:gosec // G115: severity counts are bounded by in-memory delta size.
		reasons = append(reasons, fmt.Sprintf("gate %q exceeded max high vulnerabilities: %d > %d", gate.Name, high, gate.MaxHigh))
	}
	if gate.MaxMedium.Valid && int32(medium) > gate.MaxMedium.Int32 { //nolint:gosec // G115: severity counts are bounded by in-memory delta size.
		reasons = append(reasons, fmt.Sprintf("gate %q exceeded max medium vulnerabilities: %d > %d", gate.Name, medium, gate.MaxMedium.Int32))
	}
	return reasons
}

func evaluateConfiguredWeaknessGates(gates []dbgen.QualityGate, vulns []store.Vulnerability, weaknessGate *WeaknessGate) []string {
	if weaknessGate == nil {
		return evaluateStoredFindingGates(gates, vulns)
	}
	if !weaknessGate.EnabledValue() {
		return nil
	}
	return evaluateRepoWeaknessThresholds(vulns, weaknessGate)
}

func evaluateStoredFindingGates(gates []dbgen.QualityGate, vulns []store.Vulnerability) []string {
	reasons := make([]string, 0)
	for _, gate := range gates {
		if !gate.Enabled || !gate.MaxNewFindings.Valid {
			continue
		}
		newVulnerabilities := countVulnerabilitiesBySeverity(vulns, gate.FindingSeverities)
		if int32(newVulnerabilities) > gate.MaxNewFindings.Int32 { //nolint:gosec // G115: finding counts are bounded by in-memory delta size.
			reasons = append(reasons, fmt.Sprintf("gate %q exceeded max new vulnerabilities: %d > %d", gate.Name, newVulnerabilities, gate.MaxNewFindings.Int32))
		}
	}
	return reasons
}

func evaluateRepoWeaknessThresholds(vulns []store.Vulnerability, thresholds *WeaknessGate) []string {
	if thresholds == nil {
		return nil
	}

	critical, high, medium := countNewVulnerabilitySeverities(vulns)
	reasons := make([]string, 0, 3)
	if thresholds.MaxCritical != nil && critical > *thresholds.MaxCritical {
		reasons = append(reasons, fmt.Sprintf("repo config exceeded max critical weaknesses: %d > %d", critical, *thresholds.MaxCritical))
	}
	if thresholds.MaxHigh != nil && high > *thresholds.MaxHigh {
		reasons = append(reasons, fmt.Sprintf("repo config exceeded max high weaknesses: %d > %d", high, *thresholds.MaxHigh))
	}
	if thresholds.MaxMedium != nil && medium > *thresholds.MaxMedium {
		reasons = append(reasons, fmt.Sprintf("repo config exceeded max medium weaknesses: %d > %d", medium, *thresholds.MaxMedium))
	}
	return reasons
}

func (w *WeaknessGate) EnabledValue() bool {
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
