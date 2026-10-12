package server

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sync/singleflight"

	"github.com/hibouhq/hibou/internal/presence"
	"github.com/hibouhq/hibou/internal/store"
)

// Forge budget of the ADR-034 change check. One comparison answers every
// file between two commits, and both SHAs are immutable, so each pair is
// asked of the forge at most once and then served from compare_patch_cache.
const (
	// presenceCompareBudget bounds the distinct base commits compared per
	// snapshot (usually one: the previous snapshot's commit). Questions
	// beyond it are deferred, which keeps findings unconfirmed, never fixed.
	presenceCompareBudget = 3
	// compareFailureBackoff: after a forge error (rate limit, outage) the
	// pair is not asked again for this long, so a struggling forge is not
	// hammered by every reconcile and every PR page view.
	compareFailureBackoff = 10 * time.Minute
)

var errCompareBackoff = errors.New("forge comparison recently failed; backing off")

type comparePair struct {
	repo       uuid.UUID
	base, head string
}

// compareGate de-duplicates concurrent fetches of one pair and remembers
// recent failures, per server process.
type compareGate struct {
	group    singleflight.Group
	mu       sync.Mutex
	failures map[comparePair]time.Time
}

func (g *compareGate) failedRecently(pair comparePair) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	at, ok := g.failures[pair]
	if ok && time.Since(at) > compareFailureBackoff {
		delete(g.failures, pair)
		return false
	}
	return ok
}

func (g *compareGate) recordFailure(pair comparePair) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.failures == nil {
		g.failures = map[comparePair]time.Time{}
	}
	g.failures[pair] = time.Now()
}

// comparisonIndex answers path questions for one base..head comparison.
type comparisonIndex struct {
	files     map[string]presence.Change
	truncated bool
	// unsupported: the forge cannot compare at all; coverage alone decides.
	unsupported bool
}

func indexComparison(files []store.ComparePatchCachedFile, truncated bool) comparisonIndex {
	index := comparisonIndex{files: make(map[string]presence.Change, len(files)), truncated: truncated}
	for _, file := range files {
		switch file.Status {
		case "removed":
			index.files[file.Path] = presence.Change{Known: true, Removed: true}
		case "renamed":
			index.files[file.Path] = presence.Change{Known: true, Changed: true}
			if file.OldPath != "" {
				index.files[file.OldPath] = presence.Change{Known: true, Removed: true}
			}
		default:
			index.files[file.Path] = presence.Change{Known: true, Changed: true}
		}
	}
	return index
}

func (c comparisonIndex) change(path string) presence.Change {
	if c.unsupported {
		return presence.Change{}
	}
	if change, ok := c.files[path]; ok {
		return change
	}
	if c.truncated {
		// Beyond the forge's file cap: not known, so not a fix.
		return presence.Change{Deferred: true}
	}
	return presence.Change{Known: true}
}

// presenceComparison returns the comparison base..head: from the cache,
// else from the forge (deduplicated, failure backoff). pathsOnly caches
// files and status without hunks — branch-to-branch presence compares are
// never shown as a diff, so storing hunks would only cost space.
func (s *Server) presenceComparison(ctx context.Context, repo *store.Repository, base, head string, pathsOnly bool) (comparisonIndex, error) {
	if cached, err := s.queries.GetComparePatchCache(ctx, repo.ID, base, head); err != nil {
		return comparisonIndex{}, err
	} else if cached != nil {
		return indexComparison(cached.Files, cached.Truncated), nil
	}
	provider := s.forges[repo.Provider]
	owner, name, ok := s.boundRepoCoordinates(ctx, repo)
	if provider == nil || !ok {
		return comparisonIndex{unsupported: true}, nil
	}
	pair := comparePair{repo: repo.ID, base: base, head: head}
	if s.compareGate.failedRecently(pair) {
		return comparisonIndex{}, errCompareBackoff
	}
	key := repo.ID.String() + "\x00" + base + "\x00" + head
	value, err, _ := s.compareGate.group.Do(key, func() (any, error) {
		diff, err := provider.ComparePatch(ctx, owner, name, base, head)
		if err != nil {
			// A caller giving up is not the forge failing.
			if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				s.compareGate.recordFailure(pair)
			}
			return nil, err
		}
		if diff == nil {
			return nil, nil // no compare support on this forge
		}
		entry := cacheEntryFromPatchDiff(diff)
		if pathsOnly || diff.PathsOnly {
			entry.PathsOnly = true
			for i := range entry.Files {
				entry.Files[i].AddedLines, entry.Files[i].Hunks = nil, ""
			}
		}
		if err := s.queries.UpsertComparePatchCache(ctx, repo.ID, base, head, entry); err != nil {
			s.log.Warn().Err(err).Str("repo_id", repo.ID.String()).Msg("write compare patch cache")
		}
		return entry, nil
	})
	if err != nil {
		return comparisonIndex{}, err
	}
	entry, ok := value.(store.ComparePatchCacheEntry)
	if !ok {
		return comparisonIndex{unsupported: true}, nil
	}
	return indexComparison(entry.Files, entry.Truncated), nil
}

// prefetchPresenceComparisons is reconcile's unlocked first pass: it plans
// once with a checker that only records which base commits are asked about
// (just the findings their producer covered and no longer reports), then
// fetches the most useful ones within the budget — the previous snapshot's
// commit first, then the most asked.
func (s *Server) prefetchPresenceComparisons(ctx context.Context, snapshotID uuid.UUID) (map[string]comparisonIndex, error) {
	snapshot, err := s.queries.GetSnapshotByID(ctx, snapshotID)
	if err != nil || snapshot == nil {
		return nil, err
	}
	inputs, err := s.loadPresenceInputs(ctx, s.queries, snapshot)
	if err != nil || inputs.previous == nil {
		return nil, err
	}
	asked := map[string]int{}
	inputs.opts.Changed = func(base, path string) presence.Change {
		if base != "" && path != "" && base != snapshot.CommitSHA {
			asked[base]++
		}
		return presence.Change{Deferred: true}
	}
	presence.Plan(inputs.before, inputs.after, inputs.opts)
	if len(asked) == 0 {
		return nil, nil // nothing disappeared under coverage: no forge call
	}
	bases := make([]string, 0, len(asked))
	for base := range asked {
		bases = append(bases, base)
	}
	sort.Slice(bases, func(i, j int) bool {
		if (bases[i] == inputs.previous.CommitSHA) != (bases[j] == inputs.previous.CommitSHA) {
			return bases[i] == inputs.previous.CommitSHA
		}
		if asked[bases[i]] != asked[bases[j]] {
			return asked[bases[i]] > asked[bases[j]]
		}
		return bases[i] < bases[j]
	})
	if len(bases) > presenceCompareBudget {
		bases = bases[:presenceCompareBudget]
	}
	comparisons := make(map[string]comparisonIndex, len(bases))
	for _, base := range bases {
		index, err := s.presenceComparison(ctx, inputs.repo, base, snapshot.CommitSHA, true)
		if err != nil {
			s.log.Debug().Err(err).Str("base", base).Msg("presence comparison deferred")
			continue
		}
		comparisons[base] = index
	}
	return comparisons, nil
}

// prefetchedChangeChecker answers from fetched comparisons only; a base that
// was not fetched is deferred.
func prefetchedChangeChecker(head string, comparisons map[string]comparisonIndex) presence.ChangeChecker {
	return func(base, path string) presence.Change {
		if base == "" || path == "" {
			return presence.Change{}
		}
		if base == head {
			return presence.Change{Known: true}
		}
		index, ok := comparisons[base]
		if !ok {
			return presence.Change{Deferred: true}
		}
		return index.change(path)
	}
}

// lazyChangeChecker fetches on first use, within the budget, for callers
// outside a transaction (the PR delta). PR pairs keep hunks: the PR's diff
// view reads the same cache row.
func (s *Server) lazyChangeChecker(ctx context.Context, repo *store.Repository, head string) presence.ChangeChecker {
	comparisons := map[string]comparisonIndex{}
	deferred := map[string]bool{}
	return func(base, path string) presence.Change {
		if base == "" || path == "" {
			return presence.Change{}
		}
		if base == head {
			return presence.Change{Known: true}
		}
		if index, ok := comparisons[base]; ok {
			return index.change(path)
		}
		if deferred[base] || len(comparisons) >= presenceCompareBudget {
			return presence.Change{Deferred: true}
		}
		index, err := s.presenceComparison(ctx, repo, base, head, false)
		if err != nil {
			deferred[base] = true
			return presence.Change{Deferred: true}
		}
		comparisons[base] = index
		return index.change(path)
	}
}
