package delta

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

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

// EvaluateGatesWithConfig checks DB-managed vulnerability gates and optional file-managed weakness gates.
func (s *Service) EvaluateGatesWithConfig(ctx context.Context, repoID, orgID uuid.UUID, delta *DeltaResult, weaknessGate *WeaknessGate) (*GateResult, error) {
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
	reasons := append(evaluateStoredVulnerabilityGates(gates, delta.New), evaluateConfiguredWeaknessGates(gates, delta.New, weaknessGate)...)
	return &GateResult{
		Passed:     len(reasons) == 0,
		Configured: len(gates) > 0 || weaknessGate != nil,
		Reasons:    reasons,
	}, nil
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
