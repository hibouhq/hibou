package retention

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func mkSnap(t time.Time, bytes int64, sev int, protected bool) SnapshotInfo {
	return SnapshotInfo{
		ID:        uuid.New(),
		CreatedAt: t,
		Bytes:     bytes,
		Severity:  sev,
		Protected: protected,
	}
}

func TestPresetEnvelopeDefaults(t *testing.T) {
	p := Preset("envelope")
	if p.Storage.Budget != 5*gb {
		t.Errorf("budget = %d, want %d", p.Storage.Budget, 5*gb)
	}
	if p.Storage.EvictOrder != EvictSpread {
		t.Errorf("evict order = %q, want spread", p.Storage.EvictOrder)
	}
	if p.Storage.WarnAt != 0.80 || p.Storage.Target != 0.85 {
		t.Errorf("warn/target = %v/%v, want 0.80/0.85", p.Storage.WarnAt, p.Storage.Target)
	}
	if p.Tiers.Enabled {
		t.Error("tiers should be disabled by default")
	}
	if p.KeepAll != 14*day {
		t.Errorf("keep_all = %v, want 14d", p.KeepAll)
	}
	if p.AutoPurge {
		t.Error("auto_purge must default to false")
	}
	if p.OnThin.Summary != ThinKeep {
		t.Error("summary should default to keep for trend continuity")
	}
	// Empty name falls back to envelope.
	empty := Preset("")
	if empty.Storage != p.Storage || empty.KeepAll != p.KeepAll || empty.Tiers != p.Tiers {
		t.Error("empty preset should equal envelope")
	}
}

func TestPresetLegacy(t *testing.T) {
	p := Preset("legacy")
	if p.Storage.Budget != 0 {
		t.Errorf("legacy budget = %d, want 0 (no envelope)", p.Storage.Budget)
	}
	if p.KeepAll != 90*day {
		t.Errorf("legacy keep_all = %v, want 90d", p.KeepAll)
	}
	if p.Tiers.Enabled {
		t.Error("legacy must not enable tiers")
	}
	if p.AutoPurge {
		t.Error("legacy auto_purge must be false")
	}
}

func TestPresetVariants(t *testing.T) {
	std := Preset("standard")
	if !std.Tiers.Enabled || std.Tiers.Monthly.Keep != 0 || std.Tiers.Yearly.Keep != 0 {
		t.Error("standard should enable daily+weekly tiers only")
	}
	comp := Preset("compliance")
	if comp.Storage.Budget != 0 || !comp.Tiers.Enabled || comp.Tiers.Representative != RepresentativeWorst {
		t.Error("compliance should be unlimited budget, full tiers, worst rep")
	}
	min := Preset("minimal")
	if min.Storage.Budget != 1*gb || min.OnThin.Summary != ThinPurge {
		t.Error("minimal should be 1GB budget with summary purge")
	}
}

func TestSelectKeepAllWindow(t *testing.T) {
	now := time.Date(2024, 1, 3, 18, 0, 0, 0, time.UTC)
	p := Preset("envelope") // keep_all 14d, tiers off
	recent := mkSnap(now.Add(-1*day), 100, 0, false)
	old := mkSnap(now.Add(-100*day), 100, 0, false)

	keep := selectTimelineKeep([]SnapshotInfo{recent, old}, now, p)
	if _, ok := keep[recent.ID]; !ok {
		t.Error("recent snapshot within keep_all should be kept")
	}
	if _, ok := keep[old.ID]; ok {
		t.Error("old snapshot outside keep_all (tiers off) should not be kept")
	}
}

func TestSelectProtectedAlwaysKept(t *testing.T) {
	now := time.Date(2024, 1, 3, 18, 0, 0, 0, time.UTC)
	p := Preset("envelope")
	old := mkSnap(now.Add(-500*day), 100, 0, true) // protected + ancient

	keep := selectTimelineKeep([]SnapshotInfo{old}, now, p)
	if _, ok := keep[old.ID]; !ok {
		t.Error("protected snapshot must always be kept")
	}
}

func TestSelectDailyTier(t *testing.T) {
	now := time.Date(2024, 1, 3, 18, 0, 0, 0, time.UTC)
	p := Preset("envelope")
	p.KeepAll = 0 // isolate the tier behavior
	p.Tiers.Enabled = true
	p.Tiers.Daily = Tier{Keep: 2}
	p.Tiers.Weekly = Tier{Keep: 0}
	p.Tiers.Monthly = Tier{Keep: 0}
	p.Tiers.Yearly = Tier{Keep: 0}

	d1a := mkSnap(time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC), 1, 0, false)
	d1b := mkSnap(time.Date(2024, 1, 1, 15, 0, 0, 0, time.UTC), 1, 0, false)
	d2 := mkSnap(time.Date(2024, 1, 2, 12, 0, 0, 0, time.UTC), 1, 0, false)
	d3 := mkSnap(time.Date(2024, 1, 3, 12, 0, 0, 0, time.UTC), 1, 0, false)

	keep := selectTimelineKeep([]SnapshotInfo{d1a, d1b, d2, d3}, now, p)
	// Two most recent days kept (Jan 2 and Jan 3); Jan 1 dropped entirely.
	if _, ok := keep[d3.ID]; !ok {
		t.Error("Jan 3 should be kept")
	}
	if _, ok := keep[d2.ID]; !ok {
		t.Error("Jan 2 should be kept")
	}
	if _, ok := keep[d1a.ID]; ok {
		t.Error("Jan 1 should be dropped (outside 2 most recent days)")
	}
	if _, ok := keep[d1b.ID]; ok {
		t.Error("Jan 1 should be dropped (outside 2 most recent days)")
	}
}

func TestSelectRepresentativeLastInBucket(t *testing.T) {
	now := time.Date(2024, 1, 3, 18, 0, 0, 0, time.UTC)
	p := Preset("envelope")
	p.KeepAll = 0
	p.Tiers.Enabled = true
	p.Tiers.Daily = Tier{Keep: 3}
	p.Tiers.Weekly = Tier{Keep: 0}
	p.Tiers.Monthly = Tier{Keep: 0}
	p.Tiers.Yearly = Tier{Keep: 0}
	p.Tiers.Representative = RepresentativeLast

	early := mkSnap(time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC), 1, 0, false)
	late := mkSnap(time.Date(2024, 1, 1, 15, 0, 0, 0, time.UTC), 1, 0, false)

	keep := selectTimelineKeep([]SnapshotInfo{early, late}, now, p)
	if _, ok := keep[late.ID]; !ok {
		t.Error("last representative should keep the later snapshot")
	}
	if _, ok := keep[early.ID]; ok {
		t.Error("last representative should drop the earlier snapshot in the bucket")
	}
}

func TestWeekStartAnchor(t *testing.T) {
	// 2024-01-03 is a Wednesday. With a Friday anchor, the week starts on the
	// previous Friday, 2023-12-29.
	wed := time.Date(2024, 1, 3, 12, 0, 0, 0, time.UTC)
	got := weekStart(wed, time.Friday)
	want := time.Date(2023, 12, 29, 0, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("weekStart(wed, friday) = %v, want %v", got, want)
	}

	// On the anchor day itself the week starts that same day.
	fri := time.Date(2024, 1, 5, 9, 0, 0, 0, time.UTC)
	if got := weekStart(fri, time.Friday); !got.Equal(time.Date(2024, 1, 5, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("weekStart on anchor day = %v, want 2024-01-05", got)
	}
}

func TestPlanEvictionNoneUnderTarget(t *testing.T) {
	now := time.Now()
	snaps := []SnapshotInfo{mkSnap(now, 100, 0, false)}
	if plan := planEviction(snaps, 100, 200, EvictSpread, now); plan != nil {
		t.Errorf("expected no eviction under target, got %v", plan)
	}
}

func TestPlanEvictionOldest(t *testing.T) {
	now := time.Date(2024, 1, 21, 0, 0, 0, 0, time.UTC)
	oldest := mkSnap(now.Add(-20*day), 100, 0, false)
	snaps := []SnapshotInfo{
		oldest,
		mkSnap(now.Add(-10*day), 100, 0, false),
		mkSnap(now.Add(-9*day), 100, 0, false),
		mkSnap(now.Add(-1*day), 100, 0, false),
	}
	plan := planEviction(snaps, 400, 300, EvictOldest, now)
	if len(plan) != 1 || plan[0] != oldest.ID {
		t.Errorf("oldest order should evict the oldest snapshot, got %v", plan)
	}
}

func TestPlanEvictionWorstFirst(t *testing.T) {
	now := time.Now()
	leastSevere := mkSnap(now.Add(-5*day), 100, 1, false)
	snaps := []SnapshotInfo{
		mkSnap(now.Add(-1*day), 100, 9, false),
		leastSevere,
		mkSnap(now.Add(-2*day), 100, 5, false),
	}
	plan := planEviction(snaps, 300, 200, EvictWorstFirst, now)
	if len(plan) != 1 || plan[0] != leastSevere.ID {
		t.Errorf("worst-first should evict the least-severe snapshot, got %v", plan)
	}
}

func TestPlanEvictionSpreadThinsDenseMiddle(t *testing.T) {
	now := time.Date(2024, 1, 21, 0, 0, 0, 0, time.UTC)
	tEnd := mkSnap(now.Add(-1*day), 100, 0, false)    // recent endpoint
	tStart := mkSnap(now.Add(-20*day), 100, 0, false) // old endpoint
	dense1 := mkSnap(now.Add(-10*day), 100, 0, false)
	dense2 := mkSnap(now.Add(-9*day), 100, 0, false) // most redundant (between close neighbors, older region)
	snaps := []SnapshotInfo{tStart, dense1, dense2, tEnd}

	plan := planEviction(snaps, 400, 300, EvictSpread, now)
	if len(plan) != 1 || plan[0] != dense2.ID {
		t.Errorf("spread should evict the most redundant middle snapshot, got %v", plan)
	}
}

func TestPlanEvictionSpreadSkipsProtected(t *testing.T) {
	now := time.Date(2024, 1, 21, 0, 0, 0, 0, time.UTC)
	tStart := mkSnap(now.Add(-20*day), 100, 0, false)
	dense1 := mkSnap(now.Add(-10*day), 100, 0, false)
	dense2 := mkSnap(now.Add(-9*day), 100, 0, true) // would be most redundant but protected
	tEnd := mkSnap(now.Add(-1*day), 100, 0, false)
	snaps := []SnapshotInfo{tStart, dense1, dense2, tEnd}

	plan := planEviction(snaps, 400, 300, EvictSpread, now)
	for _, id := range plan {
		if id == dense2.ID {
			t.Fatal("protected snapshot must never be evicted")
		}
	}
	if len(plan) != 1 {
		t.Errorf("expected exactly one eviction, got %v", plan)
	}
}

func TestPlanEvictionProtectedExceedsBudget(t *testing.T) {
	now := time.Now()
	snaps := []SnapshotInfo{
		mkSnap(now.Add(-1*day), 100, 0, true),
		mkSnap(now.Add(-2*day), 100, 0, true),
	}
	plan := planEviction(snaps, 200, 100, EvictSpread, now)
	if len(plan) != 0 {
		t.Errorf("when only protected snapshots remain, nothing is evicted, got %v", plan)
	}
}

func TestPlanEvictionStopsAtTarget(t *testing.T) {
	now := time.Now()
	var snaps []SnapshotInfo
	for i := 0; i < 10; i++ {
		snaps = append(snaps, mkSnap(now.Add(-time.Duration(i+1)*day), 100, 0, false))
	}
	// 1000 bytes -> target 500: must evict exactly 5 to reach <= 500.
	plan := planEviction(snaps, 1000, 500, EvictOldest, now)
	if len(plan) != 5 {
		t.Errorf("expected 5 evictions to reach target, got %d", len(plan))
	}
}
