package server

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/events"
	"github.com/hibouhq/hibou/internal/presence"
	"github.com/hibouhq/hibou/internal/store"
)

// reconcileFindingPresence carries forward the previous snapshot's findings
// that this snapshot's producers did not re-check (ADR-034 §3), so a missing,
// failed or partial producer no longer reads as a fix. Idempotent: it diffs
// the planned carries against the carried rows already in the snapshot, so it
// runs again whenever a producer lands late (secret scan, advisory scan).
//
// Two passes keep the forge out of the locked transaction: an unlocked dry
// run learns which comparisons the plan needs and fetches them (cache first,
// bounded); the locked pass reads them from memory only.
//
// Returns whether any row changed. Best effort: on failure the snapshot keeps
// today's behaviour (absent = resolved) and the error is logged.
func (s *Server) reconcileFindingPresence(ctx context.Context, snapshotID uuid.UUID) bool {
	if s.db == nil || s.queries == nil {
		return false
	}
	comparisons, err := s.prefetchPresenceComparisons(ctx, snapshotID)
	if err != nil {
		s.log.Warn().Err(err).Str("snapshot", snapshotID.String()).Msg("finding presence prefetch failed")
	}
	changed, err := s.reconcileFindingPresenceTx(ctx, snapshotID, comparisons)
	if err != nil {
		s.log.Warn().Err(err).Str("snapshot", snapshotID.String()).Msg("finding presence reconcile failed")
		return false
	}
	return changed
}

// presenceInputs is what one planning pass reads.
type presenceInputs struct {
	snapshot *store.Snapshot
	previous *store.Snapshot
	repo     *store.Repository
	before   presence.Snapshot
	after    presence.Snapshot
	opts     presence.Options
}

// loadPresenceInputs reads the two snapshots' lean rows and runs and the
// org's policies. previous is nil when the ref has no earlier finished
// snapshot.
func (s *Server) loadPresenceInputs(ctx context.Context, queries *store.Queries, snapshot *store.Snapshot) (*presenceInputs, error) {
	previous, err := queries.GetPreviousCompleteSnapshotByRef(ctx, snapshot)
	if err != nil {
		return nil, fmt.Errorf("load previous snapshot: %w", err)
	}
	currentRows, err := queries.ListPresenceRowsBySnapshot(ctx, snapshot.ID)
	if err != nil {
		return nil, fmt.Errorf("list findings: %w", err)
	}
	inputs := &presenceInputs{snapshot: snapshot, previous: previous,
		after: presence.Snapshot{ID: snapshot.ID, CommitSHA: snapshot.CommitSHA, Rows: currentRows}}
	if previous == nil {
		return inputs, nil
	}
	if inputs.before.Rows, err = queries.ListPresenceRowsBySnapshot(ctx, previous.ID); err != nil {
		return nil, fmt.Errorf("list previous findings: %w", err)
	}
	if inputs.after.Runs, err = snapshotProducerRuns(ctx, queries, snapshot); err != nil {
		return nil, fmt.Errorf("list producer runs: %w", err)
	}
	if inputs.before.Runs, err = snapshotProducerRuns(ctx, queries, previous); err != nil {
		return nil, fmt.Errorf("list previous producer runs: %w", err)
	}
	inputs.before.ID, inputs.before.CommitSHA = previous.ID, previous.CommitSHA
	if inputs.repo, inputs.opts, err = s.presencePolicies(ctx, queries, snapshot); err != nil {
		return nil, err
	}
	return inputs, nil
}

func (s *Server) reconcileFindingPresenceTx(ctx context.Context, snapshotID uuid.UUID, comparisons map[string]comparisonIndex) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	queries := s.queries.WithTx(tx)

	snapshot, err := queries.GetSnapshotByID(ctx, snapshotID)
	if err != nil || snapshot == nil {
		return false, err
	}
	if err := queries.LockRefForPresence(ctx, snapshot.RefID); err != nil {
		return false, fmt.Errorf("lock ref: %w", err)
	}
	inputs, err := s.loadPresenceInputs(ctx, queries, snapshot)
	if err != nil {
		return false, err
	}
	currentRows := inputs.after.Rows

	var carries []presence.Carry
	var resolutions []presence.Resolution
	if inputs.previous != nil {
		inputs.opts.Changed = prefetchedChangeChecker(snapshot.CommitSHA, comparisons)
		carries, resolutions = presence.Plan(inputs.before, inputs.after, inputs.opts)
	}

	existing := make(map[string]store.Vulnerability)
	for _, row := range currentRows {
		if row.Presence != store.PresenceReported {
			existing[presence.FindingKey(row)] = row
		}
	}
	inserts := make([]store.CarryInput, 0)
	changed := false
	for _, carry := range carries {
		key := presence.FindingKey(carry.Source)
		input := carryInput(carry)
		if row, ok := existing[key]; ok {
			delete(existing, key)
			if carriedRowMatches(row, input) {
				continue
			}
			if err := queries.UpdateCarriedPresence(ctx, row.ID, input); err != nil {
				return false, fmt.Errorf("update carried finding: %w", err)
			}
			changed = true
			continue
		}
		inserts = append(inserts, input)
	}
	inserted, err := queries.CarryVulnerabilitiesForward(ctx, snapshot.ID, inserts)
	if err != nil {
		return false, fmt.Errorf("carry findings forward: %w", err)
	}
	stale := make([]uuid.UUID, 0, len(existing))
	for _, row := range existing {
		stale = append(stale, row.ID)
	}
	deleted, err := queries.DeleteCarriedVulnerabilities(ctx, stale)
	if err != nil {
		return false, fmt.Errorf("delete stale carried findings: %w", err)
	}
	resolutionInputs := make([]store.ResolutionInput, len(resolutions))
	for i, resolution := range resolutions {
		resolutionInputs[i] = store.ResolutionInput{
			Type:        resolution.Source.Type,
			Fingerprint: resolution.Source.Fingerprint,
			Producer:    resolution.Producer,
			Reason:      resolution.Reason,
		}
	}
	if err := queries.ReplaceFindingResolutions(ctx, snapshot.ID, resolutionInputs); err != nil {
		return false, fmt.Errorf("record finding resolutions: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return changed || inserted > 0 || deleted > 0, nil
}

func carryInput(carry presence.Carry) store.CarryInput {
	input := store.CarryInput{
		SourceID:            carry.Source.ID,
		Presence:            carry.Presence,
		Reason:              carry.Reason,
		LastSeenCommit:      carry.LastSeenCommit,
		ConsecutiveAbsences: carry.ConsecutiveAbsences,
	}
	if carry.LastSeenSnapshotID != uuid.Nil {
		id := carry.LastSeenSnapshotID
		input.LastSeenSnapshotID = &id
	}
	return input
}

func carriedRowMatches(row store.Vulnerability, input store.CarryInput) bool {
	return row.Presence == input.Presence &&
		derefString(row.PresenceReason) == input.Reason &&
		derefString(row.LastSeenCommit) == input.LastSeenCommit &&
		row.ConsecutiveAbsences == input.ConsecutiveAbsences &&
		((row.LastSeenSnapshotID == nil && input.LastSeenSnapshotID == nil) ||
			(row.LastSeenSnapshotID != nil && input.LastSeenSnapshotID != nil && *row.LastSeenSnapshotID == *input.LastSeenSnapshotID))
}

// reconcileFindingPresenceLate re-runs presence after a producer landed on a
// snapshot that may already be complete, and asks for a gate recompute when
// carried rows changed: the gate read the snapshot before this producer.
func (s *Server) reconcileFindingPresenceLate(ctx context.Context, snapshotID uuid.UUID) {
	if !s.reconcileFindingPresence(ctx, snapshotID) || s.bus == nil {
		return
	}
	s.bus.Publish(context.WithoutCancel(ctx), events.Event{
		Type:    events.GateRecomputeRequested,
		Payload: map[string]any{"snapshot_id": snapshotID.String()},
	})
}

// presencePolicies loads the repository, the org's producer policies and its
// closed assertions: the presence options except the change checker.
func (s *Server) presencePolicies(ctx context.Context, queries *store.Queries, snapshot *store.Snapshot) (*store.Repository, presence.Options, error) {
	ref, err := queries.GetRefByID(ctx, snapshot.RefID)
	if err != nil || ref == nil {
		return nil, presence.Options{}, fmt.Errorf("load ref: %w", err)
	}
	repo, err := queries.GetRepositoryByID(ctx, ref.RepoID)
	if err != nil || repo == nil {
		return nil, presence.Options{}, fmt.Errorf("load repository: %w", err)
	}
	policies, err := queries.ListProducerPolicies(ctx, repo.OrgID)
	if err != nil {
		return nil, presence.Options{}, fmt.Errorf("load producer policies: %w", err)
	}
	closed, err := queries.ClosedAssertionFingerprints(ctx, repo.ID)
	if err != nil {
		return nil, presence.Options{}, fmt.Errorf("load closed assertions: %w", err)
	}
	return repo, presence.Options{
		Policy:           producerPolicyLookup(policies),
		ClosedAssertions: closed,
		// Location fingerprints were scoped by ref before they were scoped by
		// repository: both identify a location-keyed row (ADR-034 §7 re-keys).
		LocationScopes: []string{repo.ID.String(), ref.ID.String()},
	}, nil
}

// presenceOptions is the PR delta's view (no transaction, no lock): policies
// plus a change checker that fetches on demand within the compare budget.
// PR pairs keep hunks, since the PR's diff view reads the same cache row.
func (s *Server) presenceOptions(ctx context.Context, queries *store.Queries, snapshot *store.Snapshot) (presence.Options, error) {
	repo, opts, err := s.presencePolicies(ctx, queries, snapshot)
	if err != nil {
		return presence.Options{}, err
	}
	opts.Changed = s.lazyChangeChecker(ctx, repo, snapshot.CommitSHA)
	return opts, nil
}

func producerPolicyLookup(policies []store.ProducerPolicy) func(string) presence.Policy {
	byProducer := make(map[string]presence.Policy, len(policies))
	for _, policy := range policies {
		byProducer[policy.Producer] = presence.Policy{Kind: policy.Policy, Threshold: policy.Threshold}
	}
	return func(producer string) presence.Policy {
		if policy, ok := byProducer[producer]; ok {
			return policy
		}
		return presence.DefaultPolicy(producer)
	}
}
