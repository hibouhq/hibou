# ADR-014 Implementation TODO — Snapshot retention (storage envelopes + tiered downsampling)

Tracking checklist derived from [ADR-014](014-tiered-snapshot-retention.md). Tick items as
they land. Phases are ordered to keep the build green: the pure algorithm files and the new
policy model come first (independently unit-testable, no DB or wiring changes), then schema +
store, then worker/config wiring, then docs and full validation.

> Conventions: all destructive reclaim defaults OFF (`auto_purge: false`); selection and
> eviction must be **deterministic and idempotent**; `dry_run` produces decisions without
> mutation.

## Phase 1 — Pure policy model & presets (`internal/retention/policy_tiered.go`)

- [x] `RetentionPolicy` struct covering both mechanisms (`Storage{Budget,WarnAt,Target,EvictOrder}`,
      `KeepAll`, `Tiers{Enabled,WeekAnchor,Representative,Daily/Weekly/Monthly/Yearly}`, `OnThin`,
      `Pin`, `PRSnapshots`, `FailedRetention`, `AutoPurge`, `DryRun`)
- [x] Enum types: `EvictOrder` (spread/oldest/worst-first), `RepresentativeChoice`
      (last/first/worst), `ThinAction` (purge/keep)
- [x] `Preset(name)` for `envelope` (default), `standard`, `compliance`, `minimal`, `legacy`
- [x] Unit tests for preset defaults and the legacy = pre-ADR posture

## Phase 2 — GFS keep-set selection (`internal/retention/selection.go`)

- [x] Pure `selectTimelineKeep(snaps, now, policy)` over one `(repository, ref)` timeline
- [x] Recent window (`keep_all`) always kept
- [x] Tiered representatives: bucket by daily/weekly/monthly/yearly, one rep per period for the
      most-recent `keep` periods; finer tier not double-counted by coarser
- [x] `week_anchor` alignment (default monday; teams set friday)
- [x] Representative choice: `last` / `first` / `worst`
- [x] Pinned / `retention_hold` / protected always kept
- [x] Unit tests: week-anchor, sparse timelines, tie-breaks, representative variants

## Phase 3 — Envelope eviction planner (`internal/retention/envelope.go`)

- [x] Pure `planEviction(snaps, currentBytes, targetBytes, order, now)` returning an ordered plan
- [x] `spread` (default): recency-weighted temporal-redundancy rank (gap to nearest retained
      neighbors / recency), evict most-redundant first, recompute neighbors each step
- [x] `oldest` (recent sliding window) and `worst-first` (least-severe first) ranks
- [x] Protected snapshots never evicted; stop at target watermark or when only protected remain
- [x] Unit tests: spread keeps endpoints & thins dense middle, oldest, worst-first, protected,
      stop-at-target, protected-exceeds-budget

## Phase 4 — Schema & store

- [x] Migration `00011`: `snapshots.pinned bool`, `snapshots.retention_hold bool`,
      `snapshots.artifact_bytes bigint`; per-repo running artifact-bytes total
- [x] sqlc queries: timeline-scoped listing (per repo+ref) for GFS
- [x] sqlc queries: set `pinned` / `retention_hold`, update artifact bytes, repo total
- [x] sqlc queries: summary-only tombstone update (archived: artifacts gone, summary kept)
- [x] sqlc queries: repository usage/listing for envelope pass
- [x] `rtk make generate`

## Phase 5 — Worker integration (`internal/retention/worker.go`)

- [x] Run time-based shaping first (failed/PR windows, GFS when enabled), then envelope
- [x] Apply `archived` (artifacts reclaimed, summary kept) vs `purged` transitions
- [x] Honor `dry_run` (log decisions, no mutation)
- [x] Post-upload nudge in addition to periodic pass
- [x] Update `WorkerStore`/adapter for new operations
- [x] Worker tests (idempotent re-run = no further mutation)

## Phase 6 — Config parsing & wiring

- [x] Parse `retention.*` YAML + flat `RETENTION_*` env into resolved policy (default `envelope`,
      `auto_purge: false`); sizes `KB/MB/GB/TB`, percentages `N%`
- [x] Wire resolved policy into `retention.NewWorker` in `internal/server/server.go`
      (replace hardcoded `DefaultPolicy()`)

## Phase 7 — Notifications & audit

- [x] `internal/notify`: warn at `warn_at`, alert at budget, high-priority on
      protected-exceeds-budget; throttled
- [x] Audit-log every destructive reclaim (eviction / downsample purge)

## Phase 8 — Docs & validation

- [x] Update `hibou-server.example.yaml` with the `retention:` block
- [x] Update `SPEC.md` retention section
- [x] `rtk make generate && rtk go build ./... && rtk go vet ./... && rtk go test ./...`
