package retention

import (
	"sort"
	"time"

	"github.com/google/uuid"
)

// SnapshotInfo is the minimal projection of a snapshot the retention algorithms
// (GFS selection and envelope eviction) need. The worker builds these from the
// store so the algorithms stay pure and unit-testable.
type SnapshotInfo struct {
	ID        uuid.UUID
	CreatedAt time.Time
	// Bytes is the artifact storage attributed to this snapshot.
	Bytes int64
	// Severity is a numeric severity rollup used by the "worst" representative
	// choice and the "worst-first" eviction order (higher = more severe).
	Severity int
	// Protected is true when the snapshot matches a pin rule or carries a
	// retention hold. Protected snapshots are never thinned or evicted.
	Protected bool
}

// selectTimelineKeep returns the set of snapshot IDs to keep for a single
// (repository, ref) timeline, per ADR-014 Mechanism B. The result is the union
// of: protected snapshots, the recent keep_all window, and one representative
// per GFS bucket for each enabled tier. The computation is pure and
// deterministic given the same inputs and "now".
func selectTimelineKeep(snaps []SnapshotInfo, now time.Time, p RetentionPolicy) map[uuid.UUID]struct{} {
	keep := make(map[uuid.UUID]struct{}, len(snaps))

	for _, s := range snaps {
		if s.Protected {
			keep[s.ID] = struct{}{}
		}
		if p.KeepAll > 0 && now.Sub(s.CreatedAt) <= p.KeepAll {
			keep[s.ID] = struct{}{}
		}
	}

	if p.Tiers.Enabled {
		anchor := p.Tiers.WeekAnchor
		addTierRepresentatives(keep, snaps, dayStart, p.Tiers.Daily.Keep, p.Tiers.Representative)
		addTierRepresentatives(keep, snaps, func(t time.Time) time.Time { return weekStart(t, anchor) }, p.Tiers.Weekly.Keep, p.Tiers.Representative)
		addTierRepresentatives(keep, snaps, monthStart, p.Tiers.Monthly.Keep, p.Tiers.Representative)
		addTierRepresentatives(keep, snaps, yearStart, p.Tiers.Yearly.Keep, p.Tiers.Representative)
	}

	return keep
}

// addTierRepresentatives buckets snapshots by the given period function, keeps
// the most recent keepN buckets that contain data, and marks one representative
// per kept bucket. Mirrors restic's "keep last N periods that have snapshots".
func addTierRepresentatives(keep map[uuid.UUID]struct{}, snaps []SnapshotInfo, period func(time.Time) time.Time, keepN int, rep RepresentativeChoice) {
	if keepN <= 0 || len(snaps) == 0 {
		return
	}

	buckets := make(map[int64][]SnapshotInfo)
	var starts []int64
	for _, s := range snaps {
		k := period(s.CreatedAt).Unix()
		if _, ok := buckets[k]; !ok {
			starts = append(starts, k)
		}
		buckets[k] = append(buckets[k], s)
	}

	// Most recent buckets first.
	sort.Slice(starts, func(i, j int) bool { return starts[i] > starts[j] })
	if len(starts) > keepN {
		starts = starts[:keepN]
	}

	for _, k := range starts {
		r := pickRepresentative(buckets[k], rep)
		keep[r.ID] = struct{}{}
	}
}

// pickRepresentative selects the surviving snapshot within a bucket. Ties are
// broken deterministically (newest CreatedAt, then lexicographically smallest
// ID) so repeated passes are idempotent.
func pickRepresentative(bucket []SnapshotInfo, choice RepresentativeChoice) SnapshotInfo {
	best := bucket[0]
	for _, s := range bucket[1:] {
		if betterRepresentative(s, best, choice) {
			best = s
		}
	}
	return best
}

func betterRepresentative(candidate, current SnapshotInfo, choice RepresentativeChoice) bool {
	switch choice {
	case RepresentativeFirst:
		if !candidate.CreatedAt.Equal(current.CreatedAt) {
			return candidate.CreatedAt.Before(current.CreatedAt)
		}
		return lessID(candidate.ID, current.ID)
	case RepresentativeWorst:
		if candidate.Severity != current.Severity {
			return candidate.Severity > current.Severity
		}
		if !candidate.CreatedAt.Equal(current.CreatedAt) {
			return candidate.CreatedAt.After(current.CreatedAt)
		}
		return lessID(candidate.ID, current.ID)
	default: // RepresentativeLast
		if !candidate.CreatedAt.Equal(current.CreatedAt) {
			return candidate.CreatedAt.After(current.CreatedAt)
		}
		return lessID(candidate.ID, current.ID)
	}
}

func lessID(a, b uuid.UUID) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// --- period boundary helpers (timezone-aware via the snapshot's location) ---

func dayStart(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, t.Location())
}

// weekStart returns the start of the week containing t, where weeks begin on the
// configured anchor weekday.
func weekStart(t time.Time, anchor time.Weekday) time.Time {
	d := dayStart(t)
	delta := (int(d.Weekday()) - int(anchor) + 7) % 7
	return d.AddDate(0, 0, -delta)
}

func monthStart(t time.Time) time.Time {
	y, m, _ := t.Date()
	return time.Date(y, m, 1, 0, 0, 0, 0, t.Location())
}

func yearStart(t time.Time) time.Time {
	return time.Date(t.Year(), 1, 1, 0, 0, 0, 0, t.Location())
}
