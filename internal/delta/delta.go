package delta

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/lehibou/internal/store"
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

type vulnMatchKey struct {
	AdvisoryID uuid.UUID
	ComponentID uuid.UUID
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

type VEXStore interface {
	GetEffectiveVEXStatus(ctx context.Context, arg dbgen.GetEffectiveVEXStatusParams) (dbgen.VexStatement, error)
}

type vexScopeStore interface {
	GetSnapshotByID(ctx context.Context, id uuid.UUID) (*store.Snapshot, error)
	GetRefByID(ctx context.Context, id uuid.UUID) (*store.Ref, error)
	GetRepositoryByID(ctx context.Context, id uuid.UUID) (*store.Repository, error)
	GetComponentByID(ctx context.Context, id uuid.UUID) (dbgen.Component, error)
}

type Service struct {
	store     DeltaStore
	gateStore GateStore
	vexStore  VEXStore
	log       zerolog.Logger
}

func NewService(store DeltaStore, log zerolog.Logger, vexStore ...VEXStore) *Service {
	gateStore, _ := store.(GateStore)
	var resolvedVEXStore VEXStore
	if len(vexStore) > 0 {
		resolvedVEXStore = vexStore[0]
	}
	return &Service{store: store, gateStore: gateStore, vexStore: resolvedVEXStore, log: log.With().Str("component", "delta.service").Logger()}
}

// ComputeDelta compares a PR snapshot against its target branch snapshot.
func (s *Service) ComputeDelta(ctx context.Context, prSnapshotID, targetSnapshotID uuid.UUID) (*DeltaResult, error) {
	if s == nil || s.store == nil {
		return nil, errors.New("delta store is not configured")
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
	newMatchesByAdvisory := groupNewVulnMatchesByAdvisory(prVulns, targetVulnSet)
	filteredNewVulns, err := s.filterVEXedNewVulns(ctx, prSnapshotID, advisoryCache, newMatchesByAdvisory)
	if err != nil {
		return nil, err
	}
	result.NewVulns = filteredNewVulns
	for advisoryID := range prVulnSet {
		if _, ok := targetVulnSet[advisoryID]; ok {
			result.UnchangedVulns++
			continue
		}
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

func (s *Service) filterVEXedNewVulns(ctx context.Context, snapshotID uuid.UUID, advisoryCache map[uuid.UUID]dbgen.Advisory, matchesByAdvisory map[uuid.UUID][]dbgen.VulnMatch) ([]VulnDelta, error) {
	if len(matchesByAdvisory) == 0 {
		return nil, nil
	}
	filtered := make([]VulnDelta, 0, len(matchesByAdvisory))
	if s == nil || s.vexStore == nil {
		for advisoryID := range matchesByAdvisory {
			delta, err := s.vulnDelta(ctx, advisoryCache, advisoryID)
			if err != nil {
				return nil, err
			}
			filtered = append(filtered, delta)
		}
		return filtered, nil
	}
	scopeStore, ok := s.store.(vexScopeStore)
	if !ok {
		for advisoryID := range matchesByAdvisory {
			delta, err := s.vulnDelta(ctx, advisoryCache, advisoryID)
			if err != nil {
				return nil, err
			}
			filtered = append(filtered, delta)
		}
		return filtered, nil
	}

	snapshot, err := scopeStore.GetSnapshotByID(ctx, snapshotID)
	if err != nil {
		return nil, fmt.Errorf("load snapshot %s for vex filter: %w", snapshotID, err)
	}
	if snapshot == nil {
		return nil, fmt.Errorf("snapshot %s not found for vex filter", snapshotID)
	}
	ref, err := scopeStore.GetRefByID(ctx, snapshot.RefID)
	if err != nil {
		return nil, fmt.Errorf("load ref %s for vex filter: %w", snapshot.RefID, err)
	}
	if ref == nil {
		return nil, fmt.Errorf("ref %s not found for vex filter", snapshot.RefID)
	}
	repo, err := scopeStore.GetRepositoryByID(ctx, ref.RepoID)
	if err != nil {
		return nil, fmt.Errorf("load repo %s for vex filter: %w", ref.RepoID, err)
	}
	if repo == nil {
		return nil, fmt.Errorf("repo %s not found for vex filter", ref.RepoID)
	}

	componentCache := make(map[uuid.UUID]dbgen.Component)
	for advisoryID, matches := range matchesByAdvisory {
		keepAdvisory := false
		for _, match := range matches {
			arg := dbgen.GetEffectiveVEXStatusParams{
				OrgID:      repo.OrgID,
				AdvisoryID: advisoryID,
				RepoID:     uuid.NullUUID{UUID: repo.ID, Valid: true},
			}
			component, componentErr := componentForMatch(ctx, scopeStore, componentCache, match.ComponentID)
			if componentErr != nil {
				return nil, componentErr
			}
			if strings.TrimSpace(component.Purl) != "" {
				arg.ComponentPurl = sql.NullString{String: strings.TrimSpace(component.Purl), Valid: true}
			}
			statement, vexErr := s.vexStore.GetEffectiveVEXStatus(ctx, arg)
			if errors.Is(vexErr, sql.ErrNoRows) {
				keepAdvisory = true
				break
			}
			if vexErr != nil {
				return nil, fmt.Errorf("load effective vex status for advisory %s component %s: %w", advisoryID, match.ComponentID, vexErr)
			}
			if statement.Status != dbgen.VexStatusNotAffected && statement.Status != dbgen.VexStatusFixed {
				keepAdvisory = true
				break
			}
		}
		if !keepAdvisory {
			continue
		}
		delta, err := s.vulnDelta(ctx, advisoryCache, advisoryID)
		if err != nil {
			return nil, err
		}
		filtered = append(filtered, delta)
	}

	return filtered, nil
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


func groupNewVulnMatchesByAdvisory(matches []dbgen.VulnMatch, target map[uuid.UUID]struct{}) map[uuid.UUID][]dbgen.VulnMatch {
	grouped := make(map[uuid.UUID][]dbgen.VulnMatch)
	seen := make(map[vulnMatchKey]struct{}, len(matches))
	for _, match := range matches {
		if _, ok := target[match.AdvisoryID]; ok {
			continue
		}
		key := vulnMatchKey{AdvisoryID: match.AdvisoryID, ComponentID: match.ComponentID}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		grouped[match.AdvisoryID] = append(grouped[match.AdvisoryID], match)
	}
	return grouped
}

func componentForMatch(ctx context.Context, scopeStore vexScopeStore, cache map[uuid.UUID]dbgen.Component, componentID uuid.UUID) (dbgen.Component, error) {
	if component, ok := cache[componentID]; ok {
		return component, nil
	}
	component, err := scopeStore.GetComponentByID(ctx, componentID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return dbgen.Component{}, fmt.Errorf("load component %s for vex filter: %w", componentID, err)
	}
	if err != nil {
		return dbgen.Component{}, nil
	}
	cache[componentID] = component
	return component, nil
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
