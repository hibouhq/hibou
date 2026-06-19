# ADR-014: Snapshot retention — storage envelopes and tiered downsampling

## Status

Proposed

## Context

A snapshot is the unit of build history in Hibou: each one aggregates the SBOM, SARIF,
coverage, and VEX artifacts uploaded for a single CI run, plus the derived findings and
severity rollups. Snapshots are produced on **every** push, pull request, and pipeline retry,
so an active repository generates many snapshots per day.

The current retention model (`internal/retention/policy.go`, wired in
`internal/server/server.go`) is coarse and time-uniform:

- `HotRetention` (default 90 days): `complete`/`active` snapshots older than the cutoff are
  moved to `archived`.
- `ArchiveRetention` (default 7 years): `archived` snapshots older than the cutoff are
  `purged`, and only then are their heavy artifacts deleted from object storage.
- `AutoPurge` (default **false**): the purge phase is disabled out of the box, so artifacts
  are effectively **never reclaimed** by default.

This has three practical problems:

1. **It keeps everything, then deletes everything.** Inside the hot window every snapshot of
   every day is retained at full fidelity. Day-to-day, nobody needs all of Tuesday's
   thirty snapshots — they need *the shape of the trend over time*. The current model offers
   no middle ground between "keep all" and "delete".
2. **Storage grows unbounded in practice.** Because `AutoPurge` defaults off and the policy is
   hardcoded (not configurable), object storage accumulates indefinitely. The 7-year
   `ArchiveRetention` is moot until an operator recompiles to flip `AutoPurge`.
3. **It is uniform and inflexible.** Every company has a different cadence. Teams that do a
   weekly security write-up (for example, reviewing Sonar and Veracode results every Friday)
   want to retain *one representative snapshot per week aligned to that day* for years, while
   discarding the intra-week noise. The current model cannot express this, and there is no
   configuration surface to adapt it per company.
4. **There is no hard ceiling on cost.** A large or busy repository — many branches, heavy PR
   traffic, frequent pipeline retries — can produce thousands of snapshots between any two
   time-based passes. Time-based rules alone cannot guarantee a bounded bill, because storage
   cost is driven by *volume*, not just *age*. Operators want to say "this repo gets at most
   N GB" and have Hibou honor it.

We want two things, expressed as simple configuration: a **hard, predictable ceiling on storage
cost per repository**, and, optionally, **long-lived history that is dense recently and
progressively sparser as it ages**, aligned to how a team actually reviews results.

## Decision

Hibou will provide **two complementary retention mechanisms** that operators can use
independently or together:

- **Mechanism A — Storage envelope (default, always-on).** Each repository is given a storage
  budget (for example, 5 GB). Protected snapshots consume the budget but are never evicted;
  unprotected snapshots are evicted whenever usage exceeds the budget — by default the *most
  redundant* (closest-spaced) points first, so the surviving set stays spread across time and a
  decent history is kept rather than just a recent window. Notifications fire as the repo
  approaches and crosses the limit. This is a *space-based* hard ceiling and is simple enough to
  be the only thing most teams ever configure: "give each repo N GB."
- **Mechanism B — Tiered downsampling (optional).** For teams that want structured long-term
  history, snapshots are downsampled over time using the Grandfather-Father-Son (GFS) rotation
  model used by backup tools such as restic, Borg, and Time Machine, with retained points
  aligned to the team's review cadence. This is a *time-based* shaping layer and is **off by
  default** because it is more than most repositories need.

The two are orthogonal and run in order: time-based shaping (B, if enabled) first reduces volume
structurally; then the space-based envelope (A) enforces the hard ceiling on whatever remains.
Both honor the same protection rules, so a snapshot that matters is never removed by either
mechanism.

### Both mechanisms are computed per timeline and per repository

GFS shaping is evaluated per `(repository, ref)` timeline — comparing a snapshot to its
predecessors only makes sense within the same ref, and this guarantees every branch keeps its
own representative history rather than being crowded out by a busier branch. The storage
envelope is accounted and enforced per **repository** (summing across its refs), since the
budget is a property of the repo's overall footprint.

Pull-request snapshots are treated as a separate, short-lived class (see `pr` below; `pr_snapshots`
is also accepted for compatibility),
since they are ephemeral by nature — important for large repos where PR traffic dominates.

### Mechanism A — Storage envelope (per-repo budget)

The envelope is a hard, space-based ceiling that requires almost no thought to operate: set a
budget and Hibou keeps the repository within it.

- **Budget.** Each repository has a `budget` (default 5 GB; `0` means unlimited/disabled). It is
  the maximum artifact storage Hibou will retain for that repo, configurable globally and — as a
  future extension — per organization and per repository.
- **Accounting.** Hibou tracks the artifact bytes attributed to each repository (the sum of its
  snapshots' object sizes). The running total is updated when uploads complete and when
  snapshots are thinned or evicted, so enforcement never has to scan object storage on a pass.
- **Watermarks with hysteresis.** Eviction uses two thresholds to avoid thrashing: when usage
  crosses the high watermark (the budget), Hibou evicts until usage falls back to a target low
  watermark (default 85% of budget). A `warn_at` threshold (default 80%) raises a notification
  *before* any eviction happens.
- **Eviction order.** Only *unprotected* snapshots are eligible. The default order is `spread`
  (decimation): rather than dropping the oldest snapshots — which would leave only a recent
  sliding window — Hibou removes the *most redundant* snapshot first, i.e. the one closest in
  time to its retained neighbors, weighted so older regions thin before recent ones. This keeps
  the surviving set spread across the whole timeline (dense recent, progressively sparser as it
  ages), so a decent long-term history is preserved at whatever depth the budget allows. The
  alternatives are `oldest` (a simple recent sliding window) and `worst-first` (drop least-severe
  first). When GFS is enabled, its representatives are protected, so eviction only removes the
  in-between noise. Eviction is two-dimensional, mirroring time-based thinning: it drops the
  heavy artifact blobs first (status `archived`, compact summary retained for trend continuity)
  and only purges the summary row if the budget still cannot be met.
- **Protected content is never evicted.** Snapshots matching a protection rule (see *Protection
  rules* below) count against the budget but are never removed. If protected content *alone*
  exceeds the budget, Hibou stops evicting, keeps the protected snapshots intact, and raises a
  high-priority notification asking the operator to raise the budget or unpin. The budget is
  therefore a hard ceiling on *evictable* storage and a best-effort target for protected
  storage — it never deletes something a human marked important to satisfy a number.
- **Notifications.** Through the existing `internal/notify` package, Hibou emits a warning at
  `warn_at`, an alert when the budget is reached and eviction begins, and a distinct
  high-priority alert when protected content exceeds the budget. Notifications are throttled so
  a busy repo does not produce a storm.
- **Triggers.** Enforcement runs on a periodic worker pass and is also nudged after upload
  completion, so a sudden burst on a large repo is bounded promptly rather than only at the next
  scheduled pass.

### Keeping a decent history under a budget

The budget sets *how much* history is kept; the eviction order sets its *shape*. With the
default `spread` order, the envelope behaves like a budget-driven version of GFS: as a
repository fills its budget, Hibou thins the densest regions of the timeline first, so the
points it keeps remain spread out — many in the last days, fewer per week further back, fewer
per month further back still. The result is a continuous, decimated trend reaching as far back
as the budget permits, with no tiers to configure. Where GFS gives *explicit, calendar-aligned*
points (for example, every Friday), `spread` gives an *implicit, self-sizing* distribution that
automatically deepens or shortens as the budget or upload volume changes. Enabling GFS on top
simply pins the calendar points you care about and lets `spread` manage everything in between.

For many teams — especially large repositories with heavy PR and build traffic — Mechanism A
alone is sufficient: there are no tiers or cadences to reason about, just a budget and warnings.

### Mechanism B — Tiered downsampling (optional)

When enabled, GFS shaping reduces volume *structurally over time* so the envelope rarely has to
evict anything. It computes, for each timeline, the set of snapshots to keep and thins the rest.

### Keep-set selection (GFS buckets)

For a timeline, snapshots are ordered newest-to-oldest and a snapshot is **kept** if it
satisfies any of the following:

1. **Recent window** — it falls within `keep_all` (no thinning at all for the most recent
   period; this preserves day-to-day debugging fidelity).
2. **Tiered representatives** — for each configured tier (`daily`, `weekly`, `monthly`,
   `yearly`), the timeline is bucketed by that period and **one representative snapshot is kept
   per period**, for the most recent `keep` periods of that tier. A snapshot kept by a finer
   tier is not double-counted by a coarser one.
3. **Pinned / important** — it matches a protection rule (see `pin` below), regardless of age.

Everything not in the keep-set is **thinned**.

This is intentionally the same mental model as `restic forget --keep-within --keep-daily
--keep-weekly --keep-monthly --keep-yearly`, so operators already familiar with backup
rotation can reason about it immediately.

### Week anchor (maps to a team's review cadence)

The weekly tier honors a configurable `week_anchor` (default `monday`, ISO-8601). The weekly
representative is the snapshot on, or the last one before, the anchor day within each week.

A team that performs its security write-up every **Friday** sets `week_anchor: friday`; the
Friday snapshots — the exact builds they review — become the long-lived weekly history, and
the intra-week snapshots are downsampled away. This directly ties retained history to the way
the team already works, instead of to an arbitrary calendar boundary.

### Representative choice

Within a bucket, `representative` selects which snapshot survives:

- `last` (default): the most recent snapshot in the period — reflects the end-of-period state.
- `first`: the earliest — reflects when the period's state was established.
- `worst`: the snapshot with the highest severity rollup — biases retention toward the most
  security-relevant point in the period.

### Two-dimensional thinning: artifacts vs. summary

The expensive thing to store is the **raw artifact blob** (SBOM/SARIF/VEX) in object storage.
The snapshot's **summary** (per-severity finding counts and metadata) is tiny. Thinning
therefore acts on two independent dimensions:

- `on_thin.artifacts: purge` — delete the heavy artifact objects for non-representative
  snapshots (status `archived`: metadata retained, artifacts gone).
- `on_thin.summary: keep` — retain the compact severity rollup so **trend charts remain
  continuous** even where full artifacts were dropped. Set to `purge` to fully remove the
  snapshot (status `purged`).

This is the core "intelligence": Hibou keeps cheap trend continuity forever while keeping
heavy artifacts only for representatives inside their retention horizon.

### Protection rules (`pin`)

Snapshots matching any protection rule are never thinned or evicted, by either mechanism:

- `tags: true` — release/tag snapshots are permanent history.
- `latest_per_ref: true` — the current gate state of each ref is always retained at full
  fidelity.
- `labels: [...]` — snapshots carrying a configured label (for example `baseline`, `audit`)
  are pinned, supporting compliance baselines.
- `referenced_by_open_findings: true` — a snapshot still backing an open/unresolved finding is
  retained so the evidence chain is intact.
- A per-snapshot `pinned` flag and a `retention_hold` flag (legal/audit hold) always win over
  any age- or tier-based rule.

### `failed` snapshots

`failed` snapshots (stale `pending` builds swept by ADR-related cleanup, and timeout-splits)
are reclaimed on a short, separate `failed_retention` window (default 7 days): artifacts purged,
then the row purged. They are never eligible to become tier representatives.

## Configuration

Retention is configured declaratively through the existing config layering (ADR-003: env +
YAML via viper, the same mechanism as `upload.window`). The design favors **presets for the
common case** with **granular overrides for flexibility**. Most teams set only a preset and a
budget.

```yaml
retention:
  # Pick a starting point; everything below overrides the preset.
  preset: envelope            # envelope | standard | compliance | minimal | legacy

  # Mechanism A — storage envelope (per-repo hard ceiling)
  storage:
    budget: 5GB               # max artifact storage per repo (0 = unlimited / disabled)
    warn_at: 80%              # notify before any eviction
    target: 85%               # evict down to this once budget is hit (hysteresis)
    evict_order: spread       # spread (decimate — keeps a decent history) | oldest | worst-first

  keep_all: 14d               # recent window kept at full fidelity (both mechanisms honor it)

  # Mechanism B — tiered downsampling (optional; off by default)
  tiers:
    enabled: false
    week_anchor: friday       # ISO weekday the weekly representative aligns to
    representative: last       # last | first | worst
    daily:   { keep: 30 }     # one per day for 30 days
    weekly:  { keep: 26 }     # one per week for 26 weeks (~6 months)
    monthly: { keep: 24 }     # one per month for 24 months
    yearly:  { keep: 7 }      # one per year for 7 years

  on_thin:                    # how eviction AND downsampling reclaim space
    artifacts: purge          # purge | keep   (heavy SBOM/SARIF/VEX blobs)
    summary:   keep           # keep  | purge  (compact severity rollup for trends)

  pin:                        # protection rules — honored by both mechanisms
    tags: true
    latest_per_ref: true
    labels: [baseline, audit]
    referenced_by_open_findings: true

  pr:                         # ephemeral; matters most on large, PR-heavy repos
    keep_all: 7d
    after_close: purge        # purge once the PR is merged/closed

  failed_retention: 7d
  auto_purge: false           # master switch for destructive reclaim; ships OFF so upgrades
                              # only warn — set true to enable eviction/purge
  dry_run: false              # log keep/thin/evict decisions without mutating
```

Equivalent flat env keys are provided for every field (`RETENTION_PRESET`,
`RETENTION_STORAGE_BUDGET`, `RETENTION_STORAGE_WARN_AT`, `RETENTION_KEEP_ALL`,
`RETENTION_TIERS_ENABLED`, `RETENTION_TIERS_WEEK_ANCHOR`, `RETENTION_AUTO_PURGE`, ...),
consistent with ADR-003. Sizes accept `KB`/`MB`/`GB`/`TB`; percentages accept `N%` of budget.
For compatibility, Hibou also accepts the older `pin.labeled` and `pr_snapshots.*` aliases,
but shipped examples and new configs should use `pin.labels` and `pr.*`.

### Presets

- `envelope` (**default**): Mechanism A only — a per-repo budget plus a short recent window,
  with downsampling off. The simplest posture and the recommended choice for large or PR-heavy
  repositories: set a budget, get warnings, evict oldest-first when full. No tiers or cadences
  to reason about.
- `standard`: envelope **plus** light downsampling (`daily` + `weekly` only) for teams that want
  some structured history without the full ladder.
- `compliance`: large or unlimited budget, full GFS ladder, `on_thin.summary: keep` everywhere,
  `worst` representative, and a generous `pin` set; tuned for audit retention.
- `minimal`: small budget, aggressive eviction, `on_thin.summary: purge`; tuned for the most
  cost-sensitive setups.
- `legacy`: reproduces the pre-ADR-014 behavior exactly (no envelope, 90-day hot, 7-year
  archive, `auto_purge: false`) so upgrades are a no-op until an operator opts in.

### Layering (future-ready)

The global config above is the baseline. The policy resolver is written so that a
**per-organization** and **per-repository** override can supersede the global default — the
storage envelope in particular is most useful as a per-repo budget, so the schema reserves room
for a per-repo `budget` from the start. Per-scope override *storage* is out of scope for the
first implementation, but the resolver and schema are designed to admit it without rework.

## Worked example

Consider a large, active repository: dozens of open PRs, hundreds of CI builds per day,
frequent retries. Under the default `envelope` preset with a 5 GB budget and downsampling off:

- The most recent 14 days stay at full fidelity; PR snapshots are kept for 7 days then purged on
  close, which absorbs most of the churn.
- As artifact storage approaches 4 GB (80%), the repo owner is notified. At 5 GB, Hibou begins
  evicting the most redundant unprotected snapshots — thinning the densest, closest-spaced
  points first (artifacts dropped, summary kept) so the long-term trend survives — until usage
  falls to ~4.25 GB (85%), then stops.
- Tags, the latest snapshot per branch, audit-labeled baselines, and snapshots backing open
  findings are never evicted; if those *alone* ever exceed 5 GB, eviction stops and a
  high-priority alert tells the owner to raise the budget or unpin.

The bill is bounded and predictable with essentially no policy tuning. A team that also wants a
multi-year, Friday-aligned trend simply switches to `standard` or `compliance` and enables
`tiers`, at which point downsampling keeps the long history small enough that the envelope
rarely has to evict at all.

## Implementation

- `internal/retention/policy.go`: replace the three-field `Policy` with a resolved policy
  covering both mechanisms (`Storage` {Budget, WarnAt, Target, EvictOrder}, `KeepAll`, `Tiers`
  {Enabled, WeekAnchor, Representative, Daily/Weekly/Monthly/Yearly}, `OnThin`, `Pin`,
  `PRSnapshots`, `FailedRetention`, `AutoPurge`, `DryRun`) plus `PresetPolicy(name)` and a
  `Resolve` step that layers config over a preset.
- `internal/retention/selection.go` (new): pure, deterministic GFS keep-set computation over a
  slice of snapshots given a policy and a reference "now"; fully unit-testable, with explicit
  coverage for week-anchor alignment, DST/timezone boundaries, sparse timelines, and tie-breaks.
- `internal/retention/envelope.go` (new): per-repo accounting and watermark-driven eviction —
  given a repo's current artifact bytes, the budget, watermarks, the protected set, and the
  eviction order, it produces a deterministic ordered eviction plan and stops at the target
  watermark (or when only protected snapshots remain). The default `spread` order ranks
  candidates by temporal redundancy (recency-weighted gap to nearest retained neighbors) so the
  retained set stays spread across the timeline; `oldest` and `worst-first` are simpler ranks.
- `internal/retention/worker.go`: run time-based shaping (failed/PR windows, GFS when enabled)
  first, then envelope enforcement; apply `archived` (artifacts reclaimed, summary kept) or
  `purged` (removed) transitions; honor `dry_run` by logging decisions only; emit notifications
  via `internal/notify` at `warn_at`, at the budget, and on protected-exceeds-budget.
- `internal/store`: track artifact bytes per snapshot and a running per-repository total
  (migration) so envelope enforcement does not scan object storage each pass; add `pinned` and
  `retention_hold` columns to `snapshots`; add timeline-scoped listing for GFS selection and a
  summary-only "tombstone" update.
- `internal/config/config.go`: parse `retention.*` (and env equivalents) into the resolved
  policy, defaulting to the `envelope` preset with `auto_purge: false`; wire it into
  `retention.NewWorker` in `internal/server/server.go` (replacing the hardcoded
  `DefaultPolicy()`).
- Audit: every destructive reclaim (eviction or downsample purge) is recorded via the existing
  audit log, and `dry_run` produces the same decisions without mutation for safe rollout.

The selection and eviction logic must be deterministic and idempotent: re-running a pass over an
unchanged repository must produce no further mutations.

## Backward Compatibility

- `auto_purge` ships **off**: out of the box the new model is observe-and-warn only — it
  computes keep/evict decisions and notifies on over-budget repos but deletes nothing until an
  operator opts into reclaim. Upgrades never silently remove data.
- The `legacy` preset reproduces today's behavior precisely (no envelope, 90-day hot, 7-year
  archive) for operators who want zero change in posture.
- Existing `status` values are reused: `archived` now means "artifacts reclaimed, summary
  retained"; `purged` remains "removed". No new terminal states are introduced.
- `dry_run` allows validating a budget or tier policy against real data before enabling reclaim.

## Consequences

Benefits:

- A hard, predictable **per-repository cost ceiling** via the storage envelope, configurable in
  one line ("give each repo N GB"). With the default `spread` eviction it still keeps a *decent
  decimated history* — dense recent, sparser as it ages — at whatever depth the budget allows,
  not just a recent sliding window. This is enough on its own for large, PR-heavy repositories.
- Optional time-based shaping keeps long history dense-recent and sparse-old, aligned to a
  team's review cadence via `week_anchor`, for teams that want it — without forcing that
  complexity on everyone.
- Severity trends stay continuous through summary-only retention, decoupled from expensive
  artifact storage, under both eviction and downsampling.
- Safe by default: warnings before deletion, `auto_purge` master switch off on upgrade,
  `dry_run`, audit logging, and protection rules that never let a number delete something a
  human marked important.

Tradeoffs:

- Hibou owns two reclaim paths (deterministic GFS selection and watermark-driven eviction),
  including timezone/DST and week-anchor edge cases and per-repo byte accounting that must stay
  accurate as uploads and reclaims occur.
- Reclaim is destructive for artifacts; this is mitigated by `auto_purge`, `dry_run`, audit
  logging, watermark hysteresis, and protection rules (`pin`, `retention_hold`).
- A snapshot whose artifacts were reclaimed can no longer be re-scanned from its raw inputs;
  only its summary remains. Teams needing full reproducibility must raise the budget, widen
  `keep_all`, add tiers, or pin the relevant snapshots.
- Introduces schema changes (per-snapshot artifact bytes, per-repo storage total, `pinned`,
  `retention_hold`) and a summary-only tombstone path alongside the existing lifecycle.
