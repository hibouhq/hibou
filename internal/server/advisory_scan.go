package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/scanner"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
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
	if !s.beginAdvisoryScanTask() {
		return
	}
	defer s.advisoryScanTasks.Done()
	// In-process guard: stops a slow pass overlapping its own next tick.
	if !s.advisoryScanActive.CompareAndSwap(false, true) {
		s.log.Warn().Msg("advisory scan pass already running; skipping overlap")
		return
	}
	defer s.advisoryScanActive.Store(false)

	ctx, cancel := context.WithTimeout(ctx, advisoryScanTimeout)
	defer cancel()
	// Cross-replica guard: without it every replica runs the same full pass and
	// burns N× the advisory-provider quota for one identical result. Not a
	// correctness control — scan writes are idempotent — purely quota.
	ran, err := store.WithLeaderLock(ctx, s.db, store.LockAdvisoryScanPass, s.advisoryScanPass)
	if err != nil {
		s.log.Error().Err(err).Msg("advisory scan pass or leader lock failed")
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
		return err
	}

	var succeeded, failed, skipped, done atomic.Int64
	s.log.Info().Int("snapshots", len(snapshotIDs)).Strs("providers", s.advisoryProviders).Msg("starting advisory scan pass")
	var wg sync.WaitGroup
scanLoop:
	for _, snapshotID := range snapshotIDs {
		if ctx.Err() != nil {
			break
		}
		if s.advisoryScanSlots != nil {
			select {
			case s.advisoryScanSlots <- struct{}{}:
			case <-ctx.Done():
				break scanLoop
			}
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.advisoryScanSlots != nil {
				defer func() { <-s.advisoryScanSlots }()
			}
			_, err := s.advisoryScanner.RunScan(ctx, snapshotID, s.advisoryProviders, "system")
			switch {
			case errors.Is(err, scanner.ErrScanInProgress):
				skipped.Add(1)
			case err != nil:
				failed.Add(1)
				s.log.Error().Err(err).Str("snapshot_id", snapshotID.String()).Msg("advisory scan failed")
			default:
				succeeded.Add(1)
				s.reconcileFindingPresenceLate(ctx, snapshotID)
				s.reconcileReleasesForSnapshot(ctx, snapshotID)
			}
			if n := done.Add(1); n%25 == 0 {
				s.log.Info().Int64("done", n).Int("snapshots", len(snapshotIDs)).Msg("advisory scan pass progress")
			}
		}()
	}
	wg.Wait()
	event := s.log.Info()
	if ctx.Err() != nil {
		event = s.log.Warn().Err(ctx.Err())
	}
	event.Int("snapshots", len(snapshotIDs)).Int64("done", done.Load()).Int64("succeeded", succeeded.Load()).
		Int64("failed", failed.Load()).Int64("skipped_active", skipped.Load()).Msg("finished advisory scan pass")
	return ctx.Err()
}

func (s *Server) listLatestSnapshotsForAdvisoryScan(ctx context.Context) ([]uuid.UUID, error) {
	repos, err := s.queries.ListRepositoriesForRetention(ctx)
	if err != nil {
		return nil, err
	}

	type candidate struct {
		id       uuid.UUID
		priority int
	}
	candidates := make([]candidate, 0)
	for _, repo := range repos {
		offset := 0
		for {
			refs, total, err := s.queries.ListRefsByRepo(ctx, repo.ID, api.MaxPerPage, offset)
			if err != nil {
				return nil, err
			}
			for _, ref := range refs {
				priority, scan := advisoryScanPriority(&ref, repo.DefaultBranch)
				if !scan {
					continue
				}
				snapshot, err := s.queries.GetLatestSnapshotWithComponentsByRef(ctx, ref.ID)
				if err != nil {
					return nil, err
				}
				if snapshot != nil {
					candidates = append(candidates, candidate{id: snapshot.ID, priority: priority})
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
	for _, id := range pinned {
		candidates = append(candidates, candidate{id: id, priority: advisoryPriorityReleasePinned})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].priority != candidates[j].priority {
			return candidates[i].priority < candidates[j].priority
		}
		return candidates[i].id.String() < candidates[j].id.String()
	})
	snapshotIDs := make([]uuid.UUID, 0, len(candidates))
	seen := make(map[uuid.UUID]struct{}, len(candidates))
	for _, c := range candidates {
		if _, ok := seen[c.id]; ok {
			continue
		}
		seen[c.id] = struct{}{}
		snapshotIDs = append(snapshotIDs, c.id)
	}
	return snapshotIDs, nil
}

const (
	advisoryPriorityDefaultBranch = iota
	advisoryPriorityOpenPR
	advisoryPriorityReleasePinned
	advisoryPriorityOtherRef
)

func advisoryScanPriority(ref *store.Ref, defaultBranch string) (int, bool) {
	switch {
	case ref.RefType == store.RefTypePullRequest:
		if ref.PrState != nil && *ref.PrState != "open" {
			return 0, false
		}
		return advisoryPriorityOpenPR, true
	case ref.RefType == store.RefTypeBranch && defaultBranch != "" &&
		(ref.Name == defaultBranch || ref.Name == "refs/heads/"+defaultBranch):
		return advisoryPriorityDefaultBranch, true
	default:
		return advisoryPriorityOtherRef, true
	}
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
	queued, err := s.queries.CreateScan(baseCtx, dbgen.CreateScanParams{
		SnapshotID: snapshotID, Status: "pending", ProvidersRequested: providers, TriggeredBy: triggeredBy,
	})
	if errors.Is(err, sql.ErrNoRows) {
		s.log.Info().Str("snapshot_id", snapshotID.String()).Msg("advisory scan already queued or running")
		return
	}
	if err != nil {
		s.log.Error().Err(err).Str("snapshot_id", snapshotID.String()).Msg("persist queued advisory scan")
		return
	}
	s.runQueuedAdvisoryScanInBackground(queued, func(ctx context.Context) (uuid.UUID, error) {
		return s.advisoryScanner.RunQueuedScan(ctx, queued)
	})
}

func (s *Server) runQueuedAdvisoryScanInBackground(queued dbgen.Scan, run func(context.Context) (uuid.UUID, error)) {
	baseCtx := s.lifecycleCtx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	snapshotID := queued.SnapshotID
	if !s.beginAdvisoryScanTask() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(baseCtx), 10*time.Second)
		defer cancel()
		if err := s.queries.CancelUnfinishedScan(ctx, queued.ID, "cancelled: server draining"); err != nil {
			s.log.Error().Err(err).Str("scan_id", queued.ID.String()).Msg("cancel queued scan during drain")
		}
		return
	}
	go func() {
		defer s.advisoryScanTasks.Done()
		var runErr error
		defer func() {
			if recovered := recover(); recovered != nil {
				runErr = fmt.Errorf("advisory scan worker panicked: %v", recovered)
				s.log.Error().Any("panic", recovered).Str("snapshot_id", snapshotID.String()).Msg("advisory scan goroutine panicked")
			}
			if runErr != nil {
				cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(baseCtx), 10*time.Second)
				defer cancel()
				var err error
				if errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded) {
					err = s.queries.CancelUnfinishedScan(cleanupCtx, queued.ID, truncateSecretScanError(runErr))
				} else {
					err = s.queries.FailUnfinishedScan(cleanupCtx, queued.ID, truncateSecretScanError(runErr))
				}
				if err != nil {
					s.log.Error().Err(err).Str("scan_id", queued.ID.String()).Msg("finalize interrupted advisory scan")
				}
			}
		}()
		scanCtx, cancel := context.WithTimeout(baseCtx, advisoryScanTimeout)
		defer cancel()
		// A burst of builds waits its turn: the first scan of an inventory
		// set matches, the later ones copy it (ADR-049 §4).
		if s.advisoryScanSlots != nil {
			select {
			case s.advisoryScanSlots <- struct{}{}:
				defer func() { <-s.advisoryScanSlots }()
			case <-scanCtx.Done():
				runErr = scanCtx.Err()
				return
			}
		}
		_, runErr = run(scanCtx)
		if runErr != nil && !errors.Is(runErr, context.Canceled) {
			s.log.Error().Err(runErr).Str("snapshot_id", snapshotID.String()).Msg("advisory scan failed")
		}
		// SBOM matching is a producer (ADR-034): its dependency findings were
		// carried as pending until this scan finished.
		s.reconcileFindingPresenceLate(scanCtx, snapshotID)
	}()
}

func (s *Server) beginAdvisoryScanTask() bool {
	s.artifactStateMu.Lock()
	defer s.artifactStateMu.Unlock()
	if s.draining.Load() {
		return false
	}
	s.advisoryScanTasks.Add(1)
	return true
}
