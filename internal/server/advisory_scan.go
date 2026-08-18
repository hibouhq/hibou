package server

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/store"
)

const advisoryScanTimeout = 30 * time.Minute

func (s *Server) runAdvisoryScanLoop(ctx context.Context) {
	if s.advisoryScanner == nil || len(s.advisoryProviders) == 0 || s.cfg.AdvisoryScan.Interval <= 0 {
		return
	}

	s.runAdvisoryScanPass(ctx)

	ticker := time.NewTicker(s.cfg.AdvisoryScan.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runAdvisoryScanPass(ctx)
		}
	}
}

func (s *Server) runAdvisoryScanPass(ctx context.Context) {
	if s.advisoryScanner == nil || len(s.advisoryProviders) == 0 {
		return
	}
	// In-process guard: stops a slow pass overlapping its own next tick.
	if !s.advisoryScanActive.CompareAndSwap(false, true) {
		s.log.Warn().Msg("advisory scan pass already running; skipping overlap")
		return
	}
	defer s.advisoryScanActive.Store(false)

	// Cross-replica guard: without it every replica runs the same full pass and
	// burns N× the advisory-provider quota for one identical result. Not a
	// correctness control — scan writes are idempotent — purely quota.
	ran, err := store.WithLeaderLock(ctx, s.db, store.LockAdvisoryScanPass, s.advisoryScanPass)
	if err != nil {
		s.log.Error().Err(err).Msg("advisory scan leader lock failed")
		return
	}
	if !ran {
		s.log.Debug().Msg("another replica is running the advisory scan pass; skipping this tick")
	}
}

func (s *Server) advisoryScanPass(ctx context.Context) error {
	snapshotIDs, err := s.listLatestSnapshotsForAdvisoryScan(ctx)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			s.log.Error().Err(err).Msg("list snapshots for advisory scan failed")
		}
		return nil
	}

	succeeded := 0
	failed := 0
	s.log.Info().Int("snapshots", len(snapshotIDs)).Strs("providers", s.advisoryProviders).Msg("starting advisory scan pass")
	for _, snapshotID := range snapshotIDs {
		if _, err := s.advisoryScanner.RunScan(ctx, snapshotID, s.advisoryProviders, "system"); err != nil {
			failed++
			s.log.Error().Err(err).Str("snapshot_id", snapshotID.String()).Msg("advisory scan failed")
			continue
		}
		succeeded++
		// Idempotent release reconciliation (ADR-024 §5): heals derivations
		// deferred while the forge (repo config) was unreachable at snapshot
		// completion. Early-exits for non-tag refs before any forge call.
		s.reconcileReleasesForSnapshot(ctx, snapshotID)
	}
	s.log.Info().Int("snapshots", len(snapshotIDs)).Int("succeeded", succeeded).Int("failed", failed).Msg("finished advisory scan pass")
	return nil
}

func (s *Server) listLatestSnapshotsForAdvisoryScan(ctx context.Context) ([]uuid.UUID, error) {
	repos, err := s.queries.ListRepositoriesForRetention(ctx)
	if err != nil {
		return nil, err
	}

	snapshotIDs := make([]uuid.UUID, 0)
	for _, repo := range repos {
		offset := 0
		for {
			refs, total, err := s.queries.ListRefsByRepo(ctx, repo.ID, api.MaxPerPage, offset)
			if err != nil {
				return nil, err
			}
			for _, ref := range refs {
				snapshot, err := s.queries.GetLatestSnapshotWithComponentsByRef(ctx, ref.ID)
				if err != nil {
					return nil, err
				}
				if snapshot != nil {
					snapshotIDs = append(snapshotIDs, snapshot.ID)
				}
			}
			offset += len(refs)
			if offset >= total || len(refs) == 0 {
				break
			}
		}
	}

	// Release-pinned snapshots (ADR-024 §6): a release can pin an older
	// snapshot of its ref than the latest one collected above, and shipped
	// state must keep lighting up when new advisories land. The shared
	// advisory cache dedupes the package queries across all of these, so the
	// marginal provider cost of a release that shares dependencies with a
	// scanned branch is zero.
	pinned, err := s.queries.ListReleasePinnedSnapshotIDs(ctx)
	if err != nil {
		return nil, err
	}
	seen := make(map[uuid.UUID]struct{}, len(snapshotIDs))
	for _, id := range snapshotIDs {
		seen[id] = struct{}{}
	}
	for _, id := range pinned {
		if _, ok := seen[id]; !ok {
			snapshotIDs = append(snapshotIDs, id)
			seen[id] = struct{}{}
		}
	}

	sort.Slice(snapshotIDs, func(i, j int) bool {
		return snapshotIDs[i].String() < snapshotIDs[j].String()
	})
	return snapshotIDs, nil
}

func (s *Server) enqueueAdvisoryScan(snapshotID uuid.UUID, triggeredBy string) {
	if s.advisoryScanner == nil || len(s.advisoryProviders) == 0 {
		return
	}
	baseCtx := s.lifecycleCtx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	providers := append([]string(nil), s.advisoryProviders...)
	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				s.log.Error().Any("panic", recovered).Str("snapshot_id", snapshotID.String()).Msg("advisory scan goroutine panicked")
			}
		}()
		scanCtx, cancel := context.WithTimeout(baseCtx, advisoryScanTimeout)
		defer cancel()
		if _, err := s.advisoryScanner.RunScan(scanCtx, snapshotID, providers, triggeredBy); err != nil && !errors.Is(err, context.Canceled) {
			s.log.Error().Err(err).Str("snapshot_id", snapshotID.String()).Msg("advisory scan failed")
		}
	}()
}
