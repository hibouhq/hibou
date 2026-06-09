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
	New       []store.Vulnerability `json:"new_vulnerabilities"`
	Resolved  []store.Vulnerability `json:"resolved_vulnerabilities"`
	Unchanged int                   `json:"unchanged_vulnerabilities"`
}

type DeltaStore interface {
	ListAllVulnerabilitiesBySnapshot(ctx context.Context, snapshotID uuid.UUID) ([]store.Vulnerability, error)
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

	prVulns, err := s.store.ListAllVulnerabilitiesBySnapshot(ctx, prSnapshotID)
	if err != nil {
		return nil, fmt.Errorf("list PR vulnerabilities: %w", err)
	}
	targetVulns, err := s.store.ListAllVulnerabilitiesBySnapshot(ctx, targetSnapshotID)
	if err != nil {
		return nil, fmt.Errorf("list target vulnerabilities: %w", err)
	}

	result := &DeltaResult{}
	prSet := uniqueVulnerabilities(prVulns)
	targetSet := uniqueVulnerabilities(targetVulns)
	newVulns := make([]store.Vulnerability, 0)
	resolved := make([]store.Vulnerability, 0)
	unchanged := 0
	for fingerprint, vuln := range prSet {
		if _, ok := targetSet[fingerprint]; ok {
			unchanged++
			continue
		}
		newVulns = append(newVulns, vuln)
	}
	filteredNewVulns, err := s.filterVEXedNewVulnerabilities(ctx, prSnapshotID, newVulns)
	if err != nil {
		return nil, err
	}
	for fingerprint, vuln := range targetSet {
		if _, ok := prSet[fingerprint]; ok {
			continue
		}
		resolved = append(resolved, vuln)
	}
	result.New = filteredNewVulns
	result.Resolved = resolved
	result.Unchanged = unchanged

	return result, nil
}

func (s *Service) filterVEXedNewVulnerabilities(ctx context.Context, snapshotID uuid.UUID, vulns []store.Vulnerability) ([]store.Vulnerability, error) {
	if len(vulns) == 0 {
		return nil, nil
	}
	filtered, scopeStore, ok := s.prepareVEXFilter(vulns)
	if !ok {
		return filtered, nil
	}
	repo, componentCache, err := s.loadVEXFilterContext(ctx, snapshotID, scopeStore)
	if err != nil {
		return nil, err
	}

	filtered = filtered[:0]
	for _, vuln := range vulns {
		keep, err := s.keepNewVulnerabilityAfterVEX(ctx, scopeStore, repo, componentCache, vuln)
		if err != nil {
			return nil, err
		}
		if keep {
			filtered = append(filtered, vuln)
		}
	}

	return filtered, nil
}

func (s *Service) prepareVEXFilter(vulns []store.Vulnerability) ([]store.Vulnerability, vexScopeStore, bool) {
	filtered := make([]store.Vulnerability, 0, len(vulns))
	if s == nil || s.vexStore == nil {
		return append(filtered, vulns...), nil, false
	}
	scopeStore, ok := s.store.(vexScopeStore)
	if !ok {
		return append(filtered, vulns...), nil, false
	}
	return filtered, scopeStore, true
}

func (s *Service) loadVEXFilterContext(ctx context.Context, snapshotID uuid.UUID, scopeStore vexScopeStore) (*store.Repository, map[uuid.UUID]dbgen.Component, error) {
	snapshot, err := scopeStore.GetSnapshotByID(ctx, snapshotID)
	if err != nil {
		return nil, nil, fmt.Errorf("load snapshot %s for vex filter: %w", snapshotID, err)
	}
	if snapshot == nil {
		return nil, nil, fmt.Errorf("snapshot %s not found for vex filter", snapshotID)
	}
	ref, err := scopeStore.GetRefByID(ctx, snapshot.RefID)
	if err != nil {
		return nil, nil, fmt.Errorf("load ref %s for vex filter: %w", snapshot.RefID, err)
	}
	if ref == nil {
		return nil, nil, fmt.Errorf("ref %s not found for vex filter", snapshot.RefID)
	}
	repo, err := scopeStore.GetRepositoryByID(ctx, ref.RepoID)
	if err != nil {
		return nil, nil, fmt.Errorf("load repo %s for vex filter: %w", ref.RepoID, err)
	}
	if repo == nil {
		return nil, nil, fmt.Errorf("repo %s not found for vex filter", ref.RepoID)
	}
	return repo, make(map[uuid.UUID]dbgen.Component), nil
}

func (s *Service) keepNewVulnerabilityAfterVEX(ctx context.Context, scopeStore vexScopeStore, repo *store.Repository, componentCache map[uuid.UUID]dbgen.Component, vuln store.Vulnerability) (bool, error) {
	if !isVEXFilteredType(vuln) || vuln.AdvisoryID == nil {
		return true, nil
	}
	statement, err := s.loadEffectiveVEXStatus(ctx, scopeStore, repo, componentCache, vuln)
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return statement.Status != dbgen.VexStatusNotAffected && statement.Status != dbgen.VexStatusFixed, nil
}

func isVEXFilteredType(vuln store.Vulnerability) bool {
	return vuln.Type == "dependency" || vuln.Type == "malware"
}

func (s *Service) loadEffectiveVEXStatus(ctx context.Context, scopeStore vexScopeStore, repo *store.Repository, componentCache map[uuid.UUID]dbgen.Component, vuln store.Vulnerability) (dbgen.VexStatement, error) {
	arg := dbgen.GetEffectiveVEXStatusParams{
		OrgID:      repo.OrgID,
		AdvisoryID: *vuln.AdvisoryID,
		RepoID:     uuid.NullUUID{UUID: repo.ID, Valid: true},
	}
	componentPURL, err := resolveVEXComponentPURL(ctx, scopeStore, componentCache, vuln)
	if err != nil {
		return dbgen.VexStatement{}, err
	}
	if componentPURL != "" {
		arg.ComponentPurl = sql.NullString{String: componentPURL, Valid: true}
	}
	statement, vexErr := s.vexStore.GetEffectiveVEXStatus(ctx, arg)
	if vexErr != nil {
		componentID := uuid.Nil
		if vuln.ComponentID != nil {
			componentID = *vuln.ComponentID
		}
		return dbgen.VexStatement{}, fmt.Errorf("load effective vex status for advisory %s component %s: %w", *vuln.AdvisoryID, componentID, vexErr)
	}
	return statement, nil
}

func resolveVEXComponentPURL(ctx context.Context, scopeStore vexScopeStore, componentCache map[uuid.UUID]dbgen.Component, vuln store.Vulnerability) (string, error) {
	if vuln.ComponentPurl != nil {
		if componentPURL := strings.TrimSpace(*vuln.ComponentPurl); componentPURL != "" {
			return componentPURL, nil
		}
	}
	if vuln.ComponentID == nil {
		return "", nil
	}
	component, err := componentForVulnerability(ctx, scopeStore, componentCache, *vuln.ComponentID)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(component.Purl), nil
}

func componentForVulnerability(ctx context.Context, scopeStore vexScopeStore, cache map[uuid.UUID]dbgen.Component, componentID uuid.UUID) (dbgen.Component, error) {
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

func uniqueVulnerabilities(vulns []store.Vulnerability) map[string]store.Vulnerability {
	set := make(map[string]store.Vulnerability, len(vulns))
	for _, vuln := range vulns {
		key := vulnerabilityKey(vuln)
		if key == "" {
			continue
		}
		set[key] = vuln
	}
	return set
}

func vulnerabilityKey(vuln store.Vulnerability) string {
	if trimmed := strings.TrimSpace(vuln.Fingerprint); trimmed != "" {
		return trimmed
	}
	if vuln.ID != uuid.Nil {
		return vuln.ID.String()
	}
	return ""
}
