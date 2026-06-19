package retention

import "time"

// This file implements the resolved retention policy model from ADR-014
// (storage envelopes + tiered downsampling). It is intentionally a pure data
// model with no I/O so it can be unit-tested in isolation and shared by the
// selection (GFS) and envelope (eviction) algorithms.
//
// The legacy three-field Policy type in policy.go is retained until the worker
// and server wiring are migrated to RetentionPolicy (see ADR-014 implementation
// TODO, phases 5-6).

// EvictOrder selects how the storage envelope chooses which unprotected
// snapshot to evict first when a repository is over budget.
type EvictOrder string

const (
	// EvictSpread (default) decimates: it removes the most temporally
	// redundant snapshot first so survivors stay spread across the timeline,
	// preserving a decent decimated history rather than only a recent window.
	EvictSpread EvictOrder = "spread"
	// EvictOldest removes the oldest snapshot first (a recent sliding window).
	EvictOldest EvictOrder = "oldest"
	// EvictWorstFirst removes the least-severe snapshot first.
	EvictWorstFirst EvictOrder = "worst-first"
)

// RepresentativeChoice selects which snapshot survives within a GFS bucket.
type RepresentativeChoice string

const (
	// RepresentativeLast keeps the most recent snapshot in the period.
	RepresentativeLast RepresentativeChoice = "last"
	// RepresentativeFirst keeps the earliest snapshot in the period.
	RepresentativeFirst RepresentativeChoice = "first"
	// RepresentativeWorst keeps the highest-severity snapshot in the period.
	RepresentativeWorst RepresentativeChoice = "worst"
)

// ThinAction describes how a reclaim dimension behaves when thinning.
type ThinAction string

const (
	// ThinPurge removes the dimension (heavy artifacts, or the summary row).
	ThinPurge ThinAction = "purge"
	// ThinKeep retains the dimension.
	ThinKeep ThinAction = "keep"
)

// Tier configures one GFS rotation level: keep one representative per period
// for the most recent Keep periods. Keep == 0 disables the tier.
type Tier struct {
	Keep int
}

// StoragePolicy is Mechanism A: the per-repository storage envelope.
type StoragePolicy struct {
	// Budget is the maximum artifact storage per repo in bytes. 0 means
	// unlimited / disabled.
	Budget int64
	// WarnAt is the fraction of Budget (0..1) at which a warning fires before
	// any eviction.
	WarnAt float64
	// Target is the low watermark (fraction of Budget, 0..1) eviction drains
	// down to once the budget is hit (hysteresis).
	Target float64
	// EvictOrder selects which unprotected snapshot is evicted first.
	EvictOrder EvictOrder
}

// TiersPolicy is Mechanism B: optional GFS tiered downsampling.
type TiersPolicy struct {
	Enabled        bool
	WeekAnchor     time.Weekday
	Representative RepresentativeChoice
	Daily          Tier
	Weekly         Tier
	Monthly        Tier
	Yearly         Tier
}

// OnThinPolicy controls the two reclaim dimensions used by both mechanisms.
type OnThinPolicy struct {
	// Artifacts: purge drops heavy SBOM/SARIF/VEX blobs (status archived).
	Artifacts ThinAction
	// Summary: keep retains the compact severity rollup for trend continuity;
	// purge fully removes the snapshot (status purged).
	Summary ThinAction
}

// PinPolicy lists the protection rules honored by both mechanisms.
type PinPolicy struct {
	Tags                     bool
	LatestPerRef             bool
	ReferencedByOpenFindings bool
	Labels                   []string
}

// PRSnapshotsPolicy treats pull-request snapshots as a short-lived class.
type PRSnapshotsPolicy struct {
	KeepAll    time.Duration
	AfterClose ThinAction
}

// RetentionPolicy is the fully resolved retention configuration covering both
// mechanisms. It is produced by Preset() layered with config overrides.
type RetentionPolicy struct {
	Storage         StoragePolicy
	KeepAll         time.Duration
	Tiers           TiersPolicy
	OnThin          OnThinPolicy
	Pin             PinPolicy
	PRSnapshots     PRSnapshotsPolicy
	FailedRetention time.Duration
	AutoPurge       bool
	DryRun          bool
}

const (
	kb int64 = 1 << 10
	mb int64 = 1 << 20
	gb int64 = 1 << 30
	tb int64 = 1 << 40
)

const day = 24 * time.Hour

// Preset returns the baseline RetentionPolicy for a named preset. An unknown or
// empty name falls back to "envelope" (the default posture). Callers layer
// config overrides on top of the returned value.
func Preset(name string) RetentionPolicy {
	base := RetentionPolicy{
		Storage: StoragePolicy{
			Budget:     5 * gb,
			WarnAt:     0.80,
			Target:     0.85,
			EvictOrder: EvictSpread,
		},
		KeepAll: 14 * day,
		Tiers: TiersPolicy{
			Enabled:        false,
			WeekAnchor:     time.Friday,
			Representative: RepresentativeLast,
			Daily:          Tier{Keep: 30},
			Weekly:         Tier{Keep: 26},
			Monthly:        Tier{Keep: 24},
			Yearly:         Tier{Keep: 7},
		},
		OnThin: OnThinPolicy{
			Artifacts: ThinPurge,
			Summary:   ThinKeep,
		},
		Pin: PinPolicy{
			Tags:                     true,
			LatestPerRef:             true,
			ReferencedByOpenFindings: true,
			Labels:                   []string{"baseline", "audit"},
		},
		PRSnapshots: PRSnapshotsPolicy{
			KeepAll:    7 * day,
			AfterClose: ThinPurge,
		},
		FailedRetention: 7 * day,
		AutoPurge:       false,
		DryRun:          false,
	}

	switch name {
	case "", "envelope":
		return base

	case "standard":
		// Envelope plus light downsampling (daily + weekly only).
		p := base
		p.Tiers.Enabled = true
		p.Tiers.Monthly = Tier{Keep: 0}
		p.Tiers.Yearly = Tier{Keep: 0}
		return p

	case "compliance":
		// Large/unlimited budget, full GFS ladder, summary kept, worst rep.
		p := base
		p.Storage.Budget = 0 // unlimited
		p.Tiers.Enabled = true
		p.Tiers.Representative = RepresentativeWorst
		p.OnThin.Summary = ThinKeep
		return p

	case "minimal":
		// Small budget, aggressive eviction, summary purged.
		p := base
		p.Storage.Budget = 1 * gb
		p.Tiers.Enabled = false
		p.OnThin.Summary = ThinPurge
		return p

	case "legacy":
		// Reproduces pre-ADR-014 behavior: no envelope, 90-day hot window,
		// time-based purge, auto_purge off.
		return RetentionPolicy{
			Storage: StoragePolicy{Budget: 0, EvictOrder: EvictOldest},
			KeepAll: 90 * day,
			Tiers:   TiersPolicy{Enabled: false},
			OnThin: OnThinPolicy{
				Artifacts: ThinPurge,
				Summary:   ThinPurge,
			},
			PRSnapshots:     PRSnapshotsPolicy{KeepAll: 7 * day, AfterClose: ThinPurge},
			FailedRetention: 7 * day,
			AutoPurge:       false,
			DryRun:          false,
		}

	default:
		return base
	}
}

type StoragePolicyOverrides struct {
	Budget     *int64
	WarnAt     *float64
	Target     *float64
	EvictOrder *EvictOrder
}

type TiersPolicyOverrides struct {
	Enabled        *bool
	WeekAnchor     *time.Weekday
	Representative *RepresentativeChoice
	DailyKeep      *int
	WeeklyKeep     *int
	MonthlyKeep    *int
	YearlyKeep     *int
}

type OnThinPolicyOverrides struct {
	Artifacts *ThinAction
	Summary   *ThinAction
}

type PinPolicyOverrides struct {
	Tags                     *bool
	LatestPerRef             *bool
	ReferencedByOpenFindings *bool
	Labels                   *[]string
}

type PRSnapshotsPolicyOverrides struct {
	KeepAll    *time.Duration
	AfterClose *ThinAction
}

type PolicyOverrides struct {
	KeepAll         *time.Duration
	Storage         StoragePolicyOverrides
	Tiers           TiersPolicyOverrides
	OnThin          OnThinPolicyOverrides
	Pin             PinPolicyOverrides
	PRSnapshots     PRSnapshotsPolicyOverrides
	FailedRetention *time.Duration
	AutoPurge       *bool
	DryRun          *bool
}

func Resolve(preset string, overrides PolicyOverrides) RetentionPolicy {
	p := Preset(preset)

	if overrides.Storage.Budget != nil {
		p.Storage.Budget = *overrides.Storage.Budget
	}
	if overrides.Storage.WarnAt != nil {
		p.Storage.WarnAt = *overrides.Storage.WarnAt
	}
	if overrides.Storage.Target != nil {
		p.Storage.Target = *overrides.Storage.Target
	}
	if overrides.Storage.EvictOrder != nil {
		p.Storage.EvictOrder = *overrides.Storage.EvictOrder
	}
	if overrides.KeepAll != nil {
		p.KeepAll = *overrides.KeepAll
	}
	if overrides.Tiers.Enabled != nil {
		p.Tiers.Enabled = *overrides.Tiers.Enabled
	}
	if overrides.Tiers.WeekAnchor != nil {
		p.Tiers.WeekAnchor = *overrides.Tiers.WeekAnchor
	}
	if overrides.Tiers.Representative != nil {
		p.Tiers.Representative = *overrides.Tiers.Representative
	}
	if overrides.Tiers.DailyKeep != nil {
		p.Tiers.Daily.Keep = *overrides.Tiers.DailyKeep
	}
	if overrides.Tiers.WeeklyKeep != nil {
		p.Tiers.Weekly.Keep = *overrides.Tiers.WeeklyKeep
	}
	if overrides.Tiers.MonthlyKeep != nil {
		p.Tiers.Monthly.Keep = *overrides.Tiers.MonthlyKeep
	}
	if overrides.Tiers.YearlyKeep != nil {
		p.Tiers.Yearly.Keep = *overrides.Tiers.YearlyKeep
	}
	if overrides.OnThin.Artifacts != nil {
		p.OnThin.Artifacts = *overrides.OnThin.Artifacts
	}
	if overrides.OnThin.Summary != nil {
		p.OnThin.Summary = *overrides.OnThin.Summary
	}
	if overrides.Pin.Tags != nil {
		p.Pin.Tags = *overrides.Pin.Tags
	}
	if overrides.Pin.LatestPerRef != nil {
		p.Pin.LatestPerRef = *overrides.Pin.LatestPerRef
	}
	if overrides.Pin.ReferencedByOpenFindings != nil {
		p.Pin.ReferencedByOpenFindings = *overrides.Pin.ReferencedByOpenFindings
	}
	if overrides.Pin.Labels != nil {
		p.Pin.Labels = append([]string(nil), (*overrides.Pin.Labels)...)
	}
	if overrides.PRSnapshots.KeepAll != nil {
		p.PRSnapshots.KeepAll = *overrides.PRSnapshots.KeepAll
	}
	if overrides.PRSnapshots.AfterClose != nil {
		p.PRSnapshots.AfterClose = *overrides.PRSnapshots.AfterClose
	}
	if overrides.FailedRetention != nil {
		p.FailedRetention = *overrides.FailedRetention
	}
	if overrides.AutoPurge != nil {
		p.AutoPurge = *overrides.AutoPurge
	}
	if overrides.DryRun != nil {
		p.DryRun = *overrides.DryRun
	}

	return p
}
