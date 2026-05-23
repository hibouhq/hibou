package delta

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/hibouhq/lehibou/internal/store/dbgen"
)

type GateResult struct {
	Passed  bool     `json:"passed"`
	Reasons []string `json:"reasons"`
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
		return nil, fmt.Errorf("gate store is not configured")
	}

	gates, err := s.gateStore.ListQualityGatesByRepo(ctx, repoID)
	if err != nil {
		return nil, fmt.Errorf("list repo quality gates: %w", err)
	}
	if len(gates) == 0 {
		gates, err = s.gateStore.ListOrgWideQualityGates(ctx, orgID)
		if err != nil {
			return nil, fmt.Errorf("list org quality gates: %w", err)
		}
	}

	critical, high, medium := countNewVulnSeverities(delta.NewVulns)
	reasons := make([]string, 0)
	for _, gate := range gates {
		if !gate.Enabled {
			continue
		}
		if int32(critical) > gate.MaxCritical {
			reasons = append(reasons, fmt.Sprintf("gate %q exceeded max critical vulnerabilities: %d > %d", gate.Name, critical, gate.MaxCritical))
		}
		if int32(high) > gate.MaxHigh {
			reasons = append(reasons, fmt.Sprintf("gate %q exceeded max high vulnerabilities: %d > %d", gate.Name, high, gate.MaxHigh))
		}
		if gate.MaxMedium.Valid && int32(medium) > gate.MaxMedium.Int32 {
			reasons = append(reasons, fmt.Sprintf("gate %q exceeded max medium vulnerabilities: %d > %d", gate.Name, medium, gate.MaxMedium.Int32))
		}
	}

	if weaknessGate == nil {
		for _, gate := range gates {
			if !gate.Enabled || !gate.MaxNewFindings.Valid {
				continue
			}
			newFindings := countFindingsBySeverity(delta.NewFindings, gate.FindingSeverities)
			if int32(newFindings) > gate.MaxNewFindings.Int32 {
				reasons = append(reasons, fmt.Sprintf("gate %q exceeded max new findings: %d > %d", gate.Name, newFindings, gate.MaxNewFindings.Int32))
			}
		}
		return &GateResult{Passed: len(reasons) == 0, Reasons: reasons}, nil
	}

	if weaknessGate.EnabledValue() {
		reasons = append(reasons, evaluateRepoWeaknessThresholds(delta.NewFindings, weaknessGate)...)
	}

	return &GateResult{Passed: len(reasons) == 0, Reasons: reasons}, nil
}

func evaluateRepoWeaknessThresholds(findings []FindingDelta, thresholds *WeaknessGate) []string {
	if thresholds == nil {
		return nil
	}

	critical, high, medium := countFindingSeverities(findings)
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

func countNewVulnSeverities(vulns []VulnDelta) (critical, high, medium int) {
	for _, vuln := range vulns {
		switch strings.ToLower(strings.TrimSpace(vuln.Severity)) {
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

func countFindingsBySeverity(findings []FindingDelta, allowed []string) int {
	if len(allowed) == 0 {
		return len(findings)
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, severity := range allowed {
		allowedSet[strings.ToLower(strings.TrimSpace(severity))] = struct{}{}
	}
	count := 0
	for _, finding := range findings {
		if _, ok := allowedSet[strings.ToLower(strings.TrimSpace(finding.Severity))]; ok {
			count++
		}
	}
	return count
}

func countFindingSeverities(findings []FindingDelta) (critical, high, medium int) {
	for _, finding := range findings {
		switch strings.ToLower(strings.TrimSpace(finding.Severity)) {
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
