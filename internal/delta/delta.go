package delta

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/presence"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type DeltaResult struct {
	New      []store.Vulnerability `json:"new_vulnerabilities"`
	Resolved []store.Vulnerability `json:"resolved_vulnerabilities"`
	// NotRechecked are base findings the PR snapshot did not re-check
	// (ADR-034 §6): their producer did not run, failed, or ran without their
	// file. They are not fixed and keep counting; each carries presence
	// "not_rechecked" and the reason.
	NotRechecked []store.Vulnerability `json:"not_rechecked_vulnerabilities"`
	Unchanged    int                   `json:"unchanged_vulnerabilities"`
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
	store           DeltaStore
	gateStore       GateStore
	vexStore        VEXStore
	presenceOptions PresenceOptionsFunc
	log             zerolog.Logger
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
	// A scanner-suppressed finding is never open and never gating (ADR-023),
	// so it must not enter the diff on either side — otherwise a new `#nosec`
	// finding counts against the weakness gate. The exception is a disputed
	// suppression (ADR-026): a human contested the directive, so it keeps
	// counting until the directive is removed or the dispute withdrawn.
	// Filtering the PR side also makes "suppressed in the PR" read as
	// resolved, which is what the suppression meant.
	prVulns, targetVulns, err = s.filterUndisputedSuppressed(ctx, prSnapshotID, prVulns, targetVulns)
	if err != nil {
		return nil, err
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
	filteredNewVulns, err = s.filterAcceptedNewVulnerabilities(ctx, prSnapshotID, filteredNewVulns)
	if err != nil {
		return nil, err
	}
	for fingerprint, vuln := range targetSet {
		if _, ok := prSet[fingerprint]; ok {
			continue
		}
		resolved = append(resolved, vuln)
	}
	filteredNewVulns, resolved = cancelIdentityPairs(filteredNewVulns, resolved)
	filteredNewVulns, resolved = cancelLineDriftPairs(filteredNewVulns, resolved, prSet, targetSet)
	resolved, notRechecked, err := s.splitNotRechecked(ctx, prSnapshotID, targetSnapshotID, resolved)
	if err != nil {
		return nil, err
	}
	// Rows the PR snapshot carried forward are present, hence "unchanged",
	// but nothing looked at them in this build either.
	for key, vuln := range prSet {
		if _, inTarget := targetSet[key]; inTarget && vuln.Presence != "" && vuln.Presence != store.PresenceReported {
			notRechecked = append(notRechecked, vuln)
		}
	}
	// Always emit empty (not nil) slices so the JSON arrays are [] not null.
	if filteredNewVulns == nil {
		filteredNewVulns = []store.Vulnerability{}
	}
	result.New = filteredNewVulns
	result.Resolved = resolved
	result.NotRechecked = notRechecked
	result.Unchanged = unchanged

	return result, nil
}

// coverageStore is satisfied by the real store. Without it the delta keeps
// the pre-ADR-034 reading: everything absent from the PR is resolved.
type coverageStore interface {
	SnapshotProducerRuns(ctx context.Context, snapshotID uuid.UUID) ([]store.ProducerRun, error)
	SnapshotCoverageKnown(ctx context.Context, snapshotID uuid.UUID) (bool, error)
	GetSnapshotByID(ctx context.Context, id uuid.UUID) (*store.Snapshot, error)
}

// PresenceOptionsFunc loads the producer policies and forge change checker
// for a head snapshot. The server provides it; the delta has no forge.
type PresenceOptionsFunc func(ctx context.Context, headSnapshotID uuid.UUID) (presence.Options, error)

// SetPresenceOptions lets PR deltas apply the code-change rule and the org's
// producer policies (ADR-034 §6). Without it coverage alone decides.
func (s *Service) SetPresenceOptions(fn PresenceOptionsFunc) {
	if s != nil {
		s.presenceOptions = fn
	}
}

// splitNotRechecked separates, among base findings absent from the PR
// snapshot, those the PR's producers actually covered (resolved) from those
// nothing re-checked (ADR-034 §6). A PR snapshot is usually the first of its
// ref, so nothing was carried into it: the PR's own producer runs decide. A
// snapshot processed before runs were recorded keeps the old reading.
func (s *Service) splitNotRechecked(ctx context.Context, prSnapshotID, targetSnapshotID uuid.UUID, resolved []store.Vulnerability) ([]store.Vulnerability, []store.Vulnerability, error) {
	notRechecked := make([]store.Vulnerability, 0)
	coverage, ok := s.store.(coverageStore)
	if !ok || len(resolved) == 0 {
		return resolved, notRechecked, nil
	}
	known, err := coverage.SnapshotCoverageKnown(ctx, prSnapshotID)
	if err != nil {
		return nil, nil, fmt.Errorf("load PR snapshot coverage: %w", err)
	}
	if !known {
		return resolved, notRechecked, nil
	}
	prRuns, err := coverage.SnapshotProducerRuns(ctx, prSnapshotID)
	if err != nil {
		return nil, nil, fmt.Errorf("load PR producer runs: %w", err)
	}
	targetRuns, err := coverage.SnapshotProducerRuns(ctx, targetSnapshotID)
	if err != nil {
		return nil, nil, fmt.Errorf("load target producer runs: %w", err)
	}
	targetCommit := ""
	if target, err := coverage.GetSnapshotByID(ctx, targetSnapshotID); err == nil && target != nil {
		targetCommit = target.CommitSHA
	}
	opts := presence.Options{}
	if s.presenceOptions != nil {
		if loaded, err := s.presenceOptions(ctx, prSnapshotID); err != nil {
			s.log.Warn().Err(err).Str("snapshot", prSnapshotID.String()).Msg("presence options unavailable; coverage alone decides")
		} else {
			opts = loaded
		}
	}

	produced := make([]store.Vulnerability, 0, len(resolved))
	// A resolved or retracted assertion was decided: it stays resolved.
	decided := make([]store.Vulnerability, 0)
	for _, vuln := range resolved {
		if presence.ProducerOf(vuln) == "" {
			if vuln.Status == "resolved" {
				decided = append(decided, vuln)
				continue
			}
			// An assertion has no producer to re-check it; ADR-034 §4 keeps
			// it open until a decision (resolve, retract) ends it.
			vuln.Presence = store.PresenceNotRechecked
			reason := presence.ReasonAssertion
			vuln.PresenceReason = &reason
			notRechecked = append(notRechecked, vuln)
			continue
		}
		produced = append(produced, vuln)
	}
	// The PR build against the base, through the same rules as a branch's
	// next snapshot: not covered → not re-checked, covered but unchanged →
	// unconfirmed, both kept on the base side (ADR-034 §6).
	carries, resolutions := presence.Plan(
		presence.Snapshot{ID: targetSnapshotID, CommitSHA: targetCommit, Rows: produced, Runs: targetRuns},
		presence.Snapshot{ID: prSnapshotID, Runs: prRuns},
		opts,
	)
	for _, carry := range carries {
		vuln := carry.Source
		vuln.Presence = carry.Presence
		reason := carry.Reason
		vuln.PresenceReason = &reason
		notRechecked = append(notRechecked, vuln)
	}
	kept := append(make([]store.Vulnerability, 0, len(resolutions)+len(decided)), decided...)
	for _, resolution := range resolutions {
		vuln := resolution.Source
		reason := resolution.Reason
		vuln.ResolutionReason = &reason
		kept = append(kept, vuln)
	}
	return kept, notRechecked, nil
}

// acceptanceStore is satisfied by the real store; acceptance filtering
// degrades to a no-op on test stores that don't implement it.
type acceptanceStore interface {
	GetSnapshotByID(ctx context.Context, id uuid.UUID) (*store.Snapshot, error)
	GetRefByID(ctx context.Context, id uuid.UUID) (*store.Ref, error)
	ListActiveFindingAcceptancesByRepo(ctx context.Context, repoID uuid.UUID) ([]store.FindingAcceptance, error)
}

// disputeStore is satisfied by the real store. On stores that don't implement
// it, every suppressed finding is filtered — the ADR-023 default; disputes are
// simply not honored there.
type disputeStore interface {
	GetSnapshotByID(ctx context.Context, id uuid.UUID) (*store.Snapshot, error)
	GetRefByID(ctx context.Context, id uuid.UUID) (*store.Ref, error)
	ListFindingDisputesByRepo(ctx context.Context, repoID uuid.UUID) ([]store.FindingDispute, error)
}

// filterUndisputedSuppressed drops scanner-suppressed findings from both sides
// of the diff, keeping the disputed ones (ADR-026). Fail-safe direction: when
// disputes cannot be loaded, only the suppression default applies — a dispute
// is merely not surfaced, the gate never wrongly passes on an open finding.
func (s *Service) filterUndisputedSuppressed(ctx context.Context, snapshotID uuid.UUID, prVulns, targetVulns []store.Vulnerability) ([]store.Vulnerability, []store.Vulnerability, error) {
	disputed := map[string]struct{}{}
	if scopeStore, ok := s.store.(disputeStore); ok {
		snapshot, err := scopeStore.GetSnapshotByID(ctx, snapshotID)
		if err != nil {
			return nil, nil, fmt.Errorf("load snapshot for dispute scope: %w", err)
		}
		var ref *store.Ref
		if snapshot != nil {
			ref, err = scopeStore.GetRefByID(ctx, snapshot.RefID)
			if err != nil {
				return nil, nil, fmt.Errorf("load ref for dispute scope: %w", err)
			}
		}
		if ref != nil {
			disputes, err := scopeStore.ListFindingDisputesByRepo(ctx, ref.RepoID)
			if err != nil {
				return nil, nil, fmt.Errorf("list finding disputes: %w", err)
			}
			for _, dispute := range disputes {
				disputed[dispute.Fingerprint] = struct{}{}
			}
		}
	}
	return dropUndisputedSuppressed(prVulns, disputed), dropUndisputedSuppressed(targetVulns, disputed), nil
}

func dropUndisputedSuppressed(vulns []store.Vulnerability, disputed map[string]struct{}) []store.Vulnerability {
	filtered := make([]store.Vulnerability, 0, len(vulns))
	for _, vuln := range vulns {
		if vuln.Status == "suppressed" {
			if _, ok := disputed[strings.TrimSpace(vuln.Fingerprint)]; !ok {
				continue
			}
		}
		filtered = append(filtered, vuln)
	}
	return filtered
}

// filterAcceptedNewVulnerabilities drops findings the repo has accepted (or
// marked false positive), keyed by fingerprint. Sonar-style: accepted issues
// stop failing the gate but remain queryable; unaccepting resurfaces them.
func (s *Service) filterAcceptedNewVulnerabilities(ctx context.Context, snapshotID uuid.UUID, vulns []store.Vulnerability) ([]store.Vulnerability, error) {
	if len(vulns) == 0 {
		return vulns, nil
	}
	scopeStore, ok := s.store.(acceptanceStore)
	if !ok {
		return vulns, nil
	}
	snapshot, err := scopeStore.GetSnapshotByID(ctx, snapshotID)
	if err != nil || snapshot == nil {
		return vulns, err
	}
	ref, err := scopeStore.GetRefByID(ctx, snapshot.RefID)
	if err != nil || ref == nil {
		return vulns, err
	}
	acceptances, err := scopeStore.ListActiveFindingAcceptancesByRepo(ctx, ref.RepoID)
	if err != nil {
		return nil, fmt.Errorf("list finding acceptances: %w", err)
	}
	if len(acceptances) == 0 {
		return vulns, nil
	}
	accepted := make(map[string]struct{}, len(acceptances))
	for _, acceptance := range acceptances {
		accepted[acceptance.Fingerprint] = struct{}{}
	}
	filtered := make([]store.Vulnerability, 0, len(vulns))
	for _, vuln := range vulns {
		if _, ok := accepted[strings.TrimSpace(vuln.Fingerprint)]; ok {
			continue
		}
		filtered = append(filtered, vuln)
	}
	return filtered, nil
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

// vulnerabilityKey derives a key that is stable for the same finding across
// snapshots. A scanner-provided fingerprint wins; otherwise we build one from
// attributes that don't change snapshot-to-snapshot. The per-snapshot ID must
// never be used as the key — it differs every snapshot, which would make every
// finding read as both "new" and "resolved" in a diff.
func vulnerabilityKey(vuln store.Vulnerability) string {
	if trimmed := strings.TrimSpace(vuln.Fingerprint); trimmed != "" {
		return trimmed
	}

	parts := []string{
		strings.TrimSpace(vuln.Type),
		strings.TrimSpace(vuln.ScannerName),
		strings.TrimSpace(vuln.ScannerExternalID),
		strings.TrimSpace(vuln.PrimaryIdentifierValue),
		strings.TrimSpace(ptrString(vuln.ComponentPurl)),
		strings.TrimSpace(ptrString(vuln.FilePath)),
	}
	if vuln.StartLine != nil {
		parts = append(parts, strconv.FormatInt(int64(*vuln.StartLine), 10))
	}

	key := strings.Join(nonEmptyStrings(parts), "|")
	if key != "" {
		return key
	}
	if vuln.ID != uuid.Nil {
		return vuln.ID.String()
	}
	return ""
}

// cancelIdentityPairs drops new/resolved pairs that are the same finding whose
// fingerprint drifted between snapshots (a scanner rename or a fingerprint
// algorithm change re-keys every row). Without this, one ingestion change makes
// every existing finding read as simultaneously "new" and "resolved".
func cancelIdentityPairs(newVulns, resolved []store.Vulnerability) ([]store.Vulnerability, []store.Vulnerability) {
	if len(newVulns) == 0 || len(resolved) == 0 {
		return newVulns, resolved
	}
	resolvedByIdentity := make(map[string][]int, len(resolved))
	for i, vuln := range resolved {
		key := identityKey(vuln)
		resolvedByIdentity[key] = append(resolvedByIdentity[key], i)
	}
	drop := make(map[int]struct{})
	keptNew := newVulns[:0]
	for _, vuln := range newVulns {
		key := identityKey(vuln)
		if indices := resolvedByIdentity[key]; key != "" && len(indices) > 0 {
			drop[indices[0]] = struct{}{}
			resolvedByIdentity[key] = indices[1:]
			continue
		}
		keptNew = append(keptNew, vuln)
	}
	keptResolved := make([]store.Vulnerability, 0, len(resolved))
	for i, vuln := range resolved {
		if _, ok := drop[i]; ok {
			continue
		}
		keptResolved = append(keptResolved, vuln)
	}
	return keptNew, keptResolved
}

// identityKey is presence.IdentityKey, shared with the presence planner so a
// re-keyed finding is recognised the same way in both places.
func identityKey(vuln store.Vulnerability) string {
	return presence.IdentityKey(vuln)
}

// cancelLineDriftPairs drops new/resolved pairs that are the same code finding
// moved to another line (ADR-034 "Identity drift"). Most scanners emit no
// fingerprint, so the fallback identity hashes the start line: adding lines
// above a finding re-keys it, which reads as a new finding (and can fail a
// gate) plus a false fix. A pair cancels only when its line-free key occurs
// exactly once in each whole snapshot — two G101 hits in one file stay
// unpaired, since which one moved cannot be told.
func cancelLineDriftPairs(newVulns, resolved []store.Vulnerability, prSet, targetSet map[string]store.Vulnerability) ([]store.Vulnerability, []store.Vulnerability) {
	if len(newVulns) == 0 || len(resolved) == 0 {
		return newVulns, resolved
	}
	prCounts := driftKeyCounts(prSet)
	targetCounts := driftKeyCounts(targetSet)
	resolvedByKey := make(map[string]int, len(resolved))
	for i, vuln := range resolved {
		if key := driftKey(vuln); key != "" && prCounts[key] == 1 && targetCounts[key] == 1 {
			resolvedByKey[key] = i
		}
	}
	drop := make(map[int]struct{})
	keptNew := newVulns[:0]
	for _, vuln := range newVulns {
		key := driftKey(vuln)
		if i, ok := resolvedByKey[key]; ok && key != "" {
			drop[i] = struct{}{}
			delete(resolvedByKey, key)
			continue
		}
		keptNew = append(keptNew, vuln)
	}
	keptResolved := make([]store.Vulnerability, 0, len(resolved))
	for i, vuln := range resolved {
		if _, ok := drop[i]; ok {
			continue
		}
		keptResolved = append(keptResolved, vuln)
	}
	return keptNew, keptResolved
}

func driftKeyCounts(set map[string]store.Vulnerability) map[string]int {
	counts := make(map[string]int, len(set))
	for _, vuln := range set {
		if key := driftKey(vuln); key != "" {
			counts[key]++
		}
	}
	return counts
}

// driftKey is identityKey without the line, plus the message so two different
// diagnostics of one rule in one file are not confused. Only located code
// findings qualify: dependency and secret rows have no line to drift.
func driftKey(vuln store.Vulnerability) string {
	filePath := strings.TrimSpace(ptrString(vuln.FilePath))
	identifier := strings.TrimSpace(vuln.PrimaryIdentifierValue)
	if filePath == "" || identifier == "" || vuln.StartLine == nil {
		return ""
	}
	return strings.Join([]string{
		strings.ToLower(strings.TrimSpace(vuln.Type)),
		strings.ToLower(strings.TrimSpace(vuln.ScannerName)),
		identifier,
		filePath,
		strings.TrimSpace(vuln.Description),
	}, "|")
}

func ptrString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func nonEmptyStrings(values []string) []string {
	out := values[:0:0]
	for _, v := range values {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// RekeyPair is one finding seen under two fingerprints: Old in the earlier
// snapshot, New in the later one.
type RekeyPair struct {
	Old store.Vulnerability
	New store.Vulnerability
}

// RekeyedPairs finds findings whose fingerprint changed between two snapshots
// of a ref while the finding itself did not: a fallback-key scope change, the
// switch to content fingerprints (ADR-034, D15), or a line move. Same rules as
// the delta's pairing passes — exact identity first, then the one-to-one
// line-free match — so triage follows exactly the pairs the delta cancels.
func RekeyedPairs(older, newer []store.Vulnerability) []RekeyPair {
	olderSet := uniqueVulnerabilities(older)
	newerSet := uniqueVulnerabilities(newer)
	gone := make([]store.Vulnerability, 0)
	for key, vuln := range olderSet {
		if _, ok := newerSet[key]; !ok {
			gone = append(gone, vuln)
		}
	}
	appeared := make([]store.Vulnerability, 0)
	for key, vuln := range newerSet {
		if _, ok := olderSet[key]; !ok {
			appeared = append(appeared, vuln)
		}
	}
	if len(gone) == 0 || len(appeared) == 0 {
		return nil
	}

	pairs := make([]RekeyPair, 0)
	byIdentity := make(map[string][]store.Vulnerability)
	for _, vuln := range gone {
		if key := identityKey(vuln); key != "" {
			byIdentity[key] = append(byIdentity[key], vuln)
		}
	}
	paired := make(map[string]struct{})
	unpaired := make([]store.Vulnerability, 0, len(appeared))
	for _, vuln := range appeared {
		key := identityKey(vuln)
		if candidates := byIdentity[key]; key != "" && len(candidates) > 0 {
			pairs = append(pairs, RekeyPair{Old: candidates[0], New: vuln})
			paired[vulnerabilityKey(candidates[0])] = struct{}{}
			byIdentity[key] = candidates[1:]
			continue
		}
		unpaired = append(unpaired, vuln)
	}

	olderCounts := driftKeyCounts(olderSet)
	newerCounts := driftKeyCounts(newerSet)
	goneByDrift := make(map[string]store.Vulnerability)
	for _, vuln := range gone {
		if _, ok := paired[vulnerabilityKey(vuln)]; ok {
			continue
		}
		if key := driftKey(vuln); key != "" && olderCounts[key] == 1 && newerCounts[key] == 1 {
			goneByDrift[key] = vuln
		}
	}
	for _, vuln := range unpaired {
		key := driftKey(vuln)
		if old, ok := goneByDrift[key]; ok && key != "" {
			pairs = append(pairs, RekeyPair{Old: old, New: vuln})
			delete(goneByDrift, key)
		}
	}
	return pairs
}
