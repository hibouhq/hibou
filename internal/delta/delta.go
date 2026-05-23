package delta

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/lehibou/internal/store/dbgen"
)

type DeltaResult struct {
	NewVulns          []VulnDelta    `json:"new_vulns"`
	ResolvedVulns     []VulnDelta    `json:"resolved_vulns"`
	UnchangedVulns    int            `json:"unchanged_vulns"`
	NewFindings       []FindingDelta `json:"new_findings"`
	ResolvedFindings  []FindingDelta `json:"resolved_findings"`
	UnchangedFindings int            `json:"unchanged_findings"`
}

type VulnDelta struct {
	AdvisoryID    uuid.UUID `json:"advisory_id"`
	CanonicalID   string    `json:"canonical_id"`
	Severity      string    `json:"severity"`
	ComponentName string    `json:"component_name"`
}

type FindingDelta struct {
	Fingerprint string `json:"fingerprint"`
	Tool        string `json:"tool"`
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	FilePath    string `json:"file_path"`
	Message     string `json:"message"`
}

type DeltaStore interface {
	ListVulnMatchesBySnapshot(ctx context.Context, snapshotID uuid.UUID) ([]dbgen.VulnMatch, error)
	ListFindingsBySnapshot(ctx context.Context, arg dbgen.ListFindingsBySnapshotParams) ([]dbgen.Finding, error)
	GetAdvisoryByID(ctx context.Context, id uuid.UUID) (dbgen.Advisory, error)
}

type Service struct {
	store     DeltaStore
	gateStore GateStore
	log       zerolog.Logger
}

func NewService(store DeltaStore, log zerolog.Logger) *Service {
	gateStore, _ := store.(GateStore)
	return &Service{store: store, gateStore: gateStore, log: log.With().Str("component", "delta.service").Logger()}
}

// ComputeDelta compares a PR snapshot against its target branch snapshot.
func (s *Service) ComputeDelta(ctx context.Context, prSnapshotID, targetSnapshotID uuid.UUID) (*DeltaResult, error) {
	if s == nil || s.store == nil {
		return nil, fmt.Errorf("delta store is not configured")
	}

	prVulns, err := s.store.ListVulnMatchesBySnapshot(ctx, prSnapshotID)
	if err != nil {
		return nil, fmt.Errorf("list PR vulnerability matches: %w", err)
	}
	targetVulns, err := s.store.ListVulnMatchesBySnapshot(ctx, targetSnapshotID)
	if err != nil {
		return nil, fmt.Errorf("list target vulnerability matches: %w", err)
	}
	prFindings, err := s.listAllFindings(ctx, prSnapshotID)
	if err != nil {
		return nil, err
	}
	targetFindings, err := s.listAllFindings(ctx, targetSnapshotID)
	if err != nil {
		return nil, err
	}

	result := &DeltaResult{}
	advisoryCache := make(map[uuid.UUID]dbgen.Advisory)

	prVulnSet := uniqueVulns(prVulns)
	targetVulnSet := uniqueVulns(targetVulns)
	for advisoryID := range prVulnSet {
		if _, ok := targetVulnSet[advisoryID]; ok {
			result.UnchangedVulns++
			continue
		}
		delta, err := s.vulnDelta(ctx, advisoryCache, advisoryID)
		if err != nil {
			return nil, err
		}
		result.NewVulns = append(result.NewVulns, delta)
	}
	for advisoryID := range targetVulnSet {
		if _, ok := prVulnSet[advisoryID]; ok {
			continue
		}
		delta, err := s.vulnDelta(ctx, advisoryCache, advisoryID)
		if err != nil {
			return nil, err
		}
		result.ResolvedVulns = append(result.ResolvedVulns, delta)
	}

	prFindingSet := uniqueFindings(prFindings)
	targetFindingSet := uniqueFindings(targetFindings)
	for fingerprint, finding := range prFindingSet {
		if _, ok := targetFindingSet[fingerprint]; ok {
			result.UnchangedFindings++
			continue
		}
		result.NewFindings = append(result.NewFindings, findingDelta(fingerprint, finding))
	}
	for fingerprint, finding := range targetFindingSet {
		if _, ok := prFindingSet[fingerprint]; ok {
			continue
		}
		result.ResolvedFindings = append(result.ResolvedFindings, findingDelta(fingerprint, finding))
	}

	return result, nil
}

func (s *Service) listAllFindings(ctx context.Context, snapshotID uuid.UUID) ([]dbgen.Finding, error) {
	const pageSize = 1000
	all := make([]dbgen.Finding, 0)
	for offset := int32(0); ; offset += pageSize {
		rows, err := s.store.ListFindingsBySnapshot(ctx, dbgen.ListFindingsBySnapshotParams{
			SnapshotID: snapshotID,
			Limit:      pageSize,
			Offset:     offset,
		})
		if err != nil {
			return nil, fmt.Errorf("list findings for snapshot %s: %w", snapshotID, err)
		}
		all = append(all, rows...)
		if len(rows) < int(pageSize) {
			break
		}
	}
	return all, nil
}

func (s *Service) vulnDelta(ctx context.Context, cache map[uuid.UUID]dbgen.Advisory, advisoryID uuid.UUID) (VulnDelta, error) {
	advisory, ok := cache[advisoryID]
	if !ok {
		loaded, err := s.store.GetAdvisoryByID(ctx, advisoryID)
		if err != nil {
			return VulnDelta{}, fmt.Errorf("load advisory %s: %w", advisoryID, err)
		}
		advisory = loaded
		cache[advisoryID] = advisory
	}
	return VulnDelta{
		AdvisoryID:  advisory.ID,
		CanonicalID: advisory.CanonicalID,
		Severity:    strings.ToLower(string(advisory.Severity)),
	}, nil
}

func uniqueVulns(matches []dbgen.VulnMatch) map[uuid.UUID]struct{} {
	set := make(map[uuid.UUID]struct{}, len(matches))
	for _, match := range matches {
		set[match.AdvisoryID] = struct{}{}
	}
	return set
}

func uniqueFindings(findings []dbgen.Finding) map[string]dbgen.Finding {
	set := make(map[string]dbgen.Finding, len(findings))
	for _, finding := range findings {
		key := findingKey(finding)
		if key == "" {
			continue
		}
		set[key] = finding
	}
	return set
}

func findingKey(finding dbgen.Finding) string {
	if finding.Fingerprint.Valid && strings.TrimSpace(finding.Fingerprint.String) != "" {
		return strings.TrimSpace(finding.Fingerprint.String)
	}
	return strings.TrimSpace(finding.LocationHash)
}

func findingDelta(fingerprint string, finding dbgen.Finding) FindingDelta {
	return FindingDelta{
		Fingerprint: fingerprint,
		Tool:        finding.Tool,
		RuleID:      finding.RuleID,
		Severity:    strings.ToLower(string(finding.Severity)),
		FilePath:    finding.FilePath,
		Message:     finding.Message,
	}
}
