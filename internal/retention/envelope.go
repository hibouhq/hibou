package retention

import (
	"sort"
	"time"

	"github.com/google/uuid"
)

// planEviction produces a deterministic, ordered list of snapshot IDs to evict
// so that the repository's artifact usage drops from currentBytes to at most
// targetBytes (the low watermark), per ADR-014 Mechanism A.
//
// Protected snapshots are never evicted: they count against usage but are
// skipped. Eviction stops at the target watermark or when only protected
// snapshots remain (the caller then raises a protected-exceeds-budget alert).
//
// The function is pure and deterministic given the same inputs.
func planEviction(snaps []SnapshotInfo, currentBytes, targetBytes int64, order EvictOrder, now time.Time) []uuid.UUID {
	if currentBytes <= targetBytes {
		return nil
	}

	switch order {
	case EvictOldest:
		return planByStaticRank(snaps, currentBytes, targetBytes, lessOldestFirst)
	case EvictWorstFirst:
		return planByStaticRank(snaps, currentBytes, targetBytes, lessWorstFirst)
	default: // EvictSpread
		return planSpread(snaps, currentBytes, targetBytes, now)
	}
}

// planByStaticRank evicts in a fixed precomputed order (used by oldest and
// worst-first, whose ranking does not change as snapshots are removed).
func planByStaticRank(snaps []SnapshotInfo, currentBytes, targetBytes int64, less func(a, b SnapshotInfo) bool) []uuid.UUID {
	eligible := make([]SnapshotInfo, 0, len(snaps))
	for _, s := range snaps {
		if !s.Protected {
			eligible = append(eligible, s)
		}
	}
	sort.SliceStable(eligible, func(i, j int) bool { return less(eligible[i], eligible[j]) })

	usage := currentBytes
	var plan []uuid.UUID
	for _, s := range eligible {
		if usage <= targetBytes {
			break
		}
		plan = append(plan, s.ID)
		usage -= s.Bytes
	}
	return plan
}

func lessOldestFirst(a, b SnapshotInfo) bool {
	if !a.CreatedAt.Equal(b.CreatedAt) {
		return a.CreatedAt.Before(b.CreatedAt)
	}
	return lessID(a.ID, b.ID)
}

func lessWorstFirst(a, b SnapshotInfo) bool {
	// Least-severe first; ties broken oldest-first then by ID.
	if a.Severity != b.Severity {
		return a.Severity < b.Severity
	}
	if !a.CreatedAt.Equal(b.CreatedAt) {
		return a.CreatedAt.Before(b.CreatedAt)
	}
	return lessID(a.ID, b.ID)
}

// planSpread implements decimation: it repeatedly removes the most temporally
// redundant unprotected snapshot — the one whose removal least damages the
// spread of the retained set — until usage reaches the target. Importance is
// the time span between a snapshot's nearest retained neighbors weighted toward
// recency, so dense, older regions thin before sparse, recent ones. Neighbors
// are recomputed after each removal so survivors stay evenly spread.
func planSpread(snaps []SnapshotInfo, currentBytes, targetBytes int64, now time.Time) []uuid.UUID {
	// Work on a time-sorted copy with an "evicted" marker per element.
	items := make([]SnapshotInfo, len(snaps))
	copy(items, snaps)
	sort.SliceStable(items, func(i, j int) bool { return lessOldestFirst(items[i], items[j]) })

	evicted := make([]bool, len(items))
	usage := currentBytes
	var plan []uuid.UUID

	for usage > targetBytes {
		victim := -1
		var victimImp float64
		for i := range items {
			if evicted[i] || items[i].Protected {
				continue
			}
			imp := spreadImportance(items, evicted, i, now)
			if victim == -1 || imp < victimImp ||
				(imp == victimImp && lessOldestFirst(items[i], items[victim])) {
				victim = i
				victimImp = imp
			}
		}
		if victim == -1 {
			break // only protected snapshots remain
		}
		evicted[victim] = true
		usage -= items[victim].Bytes
		plan = append(plan, items[victim].ID)
	}
	return plan
}

// spreadImportance scores how much keeping items[i] contributes to an evenly
// spread timeline. Higher score = more important = evicted later. It combines
// the time gap to the nearest retained neighbors (a snapshot wedged between two
// close neighbors is redundant) with a recency weight (recent points are more
// valuable, so older regions thin first). Endpoints (missing a neighbor on one
// side) are given a larger effective span so the timeline's extremities are
// preserved longer.
func spreadImportance(items []SnapshotInfo, evicted []bool, i int, now time.Time) float64 {
	self := items[i].CreatedAt

	leftGap, hasLeft := time.Duration(0), false
	for l := i - 1; l >= 0; l-- {
		if evicted[l] {
			continue
		}
		leftGap = self.Sub(items[l].CreatedAt)
		hasLeft = true
		break
	}

	rightGap, hasRight := time.Duration(0), false
	for r := i + 1; r < len(items); r++ {
		if evicted[r] {
			continue
		}
		rightGap = items[r].CreatedAt.Sub(self)
		hasRight = true
		break
	}

	var span time.Duration
	switch {
	case hasLeft && hasRight:
		span = leftGap + rightGap
	case hasLeft:
		span = 2 * leftGap // endpoint: preserve longer
	case hasRight:
		span = 2 * rightGap
	default:
		// Sole survivor in its region; treat as maximally important.
		return float64(^uint(0) >> 1)
	}

	// Recency weight: recent snapshots (small age) score higher, so older,
	// dense regions are decimated first. Age measured in days; +1 avoids a
	// divide-by-zero and damps the weight for very fresh points.
	ageDays := now.Sub(self).Hours() / 24
	if ageDays < 0 {
		ageDays = 0
	}
	return span.Seconds() / (ageDays + 1)
}
