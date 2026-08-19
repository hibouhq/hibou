# ADR-025: Instance jobs & workers observability

## Status

Proposed

## Context

Since [ADR-015](015-stateless-processing-and-worker-scaling.md), all durable background
work is coordinated through PostgreSQL with lease-based claims. Three job sources already
persist full timing data:

| Source | Enqueue | Start | Finish | Extras |
|---|---|---|---|---|
| `secret_scan_jobs` | `created_at` | `started_at` | `finished_at` | `mode`, `status`, `claimed_by`, `attempts`, `last_error` |
| `snapshots.artifact_processing_*` | `created_at` (snapshot) | `artifact_processing_started_at` | `artifact_processing_finished_at` | `status`, `claimed_by`, `attempts`, `last_error` |
| `scans` (+ `scan_providers`) | `created_at` | `started_at` | `completed_at` | `triggered_by`, per-provider `response_time_ms` |

But operators have no way to see any of it. The entire JSON metrics surface is
`GET /api/v1/metrics` (uptime, Go version, secret-scan queue depth), and the only job
listing is per-repo (`GET .../secrets/jobs`, last 20 rows). There is no view of:

- what is queued and running right now, instance-wide
- how long jobs wait in queue and how long they run
- whether wait or run time is degrading versus the historical norm
- how many worker replicas exist, whether they are alive, and what resources they use

Worker replicas are anonymous today: each process generates a `hostname:pid:uuid` worker
ID ([server.go](../../internal/server/server.go) `newArtifactWorkerID`) that appears in
`claimed_by` columns, but nothing records which workers exist, since when, or their
health. A dead worker is only visible indirectly, as an expired lease.

## Decision

Add an **instance-admin observability page** (`/settings/jobs`) backed by three new
instance-admin endpoints and one new table (a worker registry). Job statistics are
computed on demand from the timestamps the three job sources already persist — **no new
job storage, no metrics pipeline, no external dependency (no Grafana/Prometheus stack
required for the in-app view)**.

### 1. Worker registry: `worker_instances` (migration `00029`)

Each replica upserts one row keyed by its existing worker ID and heartbeats it:

```sql
CREATE TABLE worker_instances (
    id                 text PRIMARY KEY,          -- hostname:pid:uuid (= claimed_by)
    hostname           text NOT NULL,
    pid                integer NOT NULL,
    version            text NOT NULL DEFAULT '',
    loops              text[] NOT NULL DEFAULT '{}',  -- enabled background loops
    started_at         timestamptz NOT NULL,
    last_heartbeat_at  timestamptz NOT NULL,
    stopped_at         timestamptz,               -- graceful shutdown marker
    cpu_percent        real,                      -- since previous heartbeat
    memory_rss_bytes   bigint,
    heap_alloc_bytes   bigint,
    goroutines         integer,
    gomaxprocs         integer,
    active_jobs        integer NOT NULL DEFAULT 0 -- in-flight claims on this replica
);
```

- The heartbeat loop runs on **every** replica (API-only replicas too — they also hold
  the instance-admin watcher, gate reconcile, etc.), every `worker.heartbeat_interval`
  (the existing config knob), and is not gated by any `background.*` flag.
- **Resource sampling is self-reported and dependency-free**: CPU% from the delta of
  `getrusage(RUSAGE_SELF)` utime+stime between heartbeats (unix; nil on other
  platforms), RSS from `/proc/self/statm` when available, heap/goroutines/GOMAXPROCS
  from the Go runtime. These are per-process numbers, not cgroup limits; the page labels
  them as such. Container-level metrics remain Prometheus/`/metrics` territory.
- Liveness is derived, not stored: a row is `online` if `last_heartbeat_at` is within
  3× the heartbeat interval, `stale` beyond that, `stopped` when `stopped_at` is set.
  Graceful shutdown sets `stopped_at` next to the existing claim release. Rows with no
  heartbeat for 7 days are deleted opportunistically during heartbeat.
- Because the registry key equals `claimed_by`, running jobs join to the worker that
  holds them, and `active_jobs` cross-checks lease reality.

### 2. Endpoints (instance admin, `sessionOnlyRoute`)

All three follow the existing instance-admin pattern: explicit
`hasPrincipal` + `isInstanceAdmin` checks, `api.JSON` envelopes, swagger annotations,
declarations in `route_scope.go`.

- **`GET /instance/jobs/overview`** — current state, cheap enough to poll:
  per-kind counts by status (queued / running / completed-24h / failed-24h), oldest
  queued age, plus the worker list (registry rows + derived liveness + per-worker
  running-job count from the claim columns).
- **`GET /instance/jobs/timeline?window=1h|6h|24h|7d`** — the Gantt feed: a unified,
  normalized list of job runs overlapping the window
  (`kind, id, label (repo/org or scan trigger), status, queued_at, started_at,
  finished_at, worker_id, attempts, error`), newest first, capped at 500 rows
  (cap reported in the response so truncation is visible).
- **`GET /instance/jobs/stats?window=1h|6h|24h|7d`** — aggregates for charts and
  anomaly detection. Per kind: time-bucketed series (bucket size scales with the
  window: 5m/15m/1h/6h) of completed/failed counts and p50/p95 run duration and queue
  wait (`percentile_cont` in SQL), plus a **baseline** = p50/p95 over the trailing
  7 days preceding the window.

The three sources are normalized in one new query file
(`internal/store/queries/instance_jobs.sql`) via `UNION ALL` into a common job-run
shape; sqlc generates the rest. `kind` values: `secret_scan`, `artifact_processing`,
`advisory_scan`.

### 3. Anomaly rule ("increase from the standard base")

Deliberately simple and explainable, computed client-side from the stats payload:

> A kind is **degraded** in the current window when it has ≥ 5 samples and its p50
> (duration or queue wait) exceeds 1.5× the trailing-7-day baseline p50, or its p95
> exceeds 2× the baseline p95.

The page shows a per-kind badge (normal / degraded / no-baseline) and the reason
("queue wait p50 4.2s vs baseline 1.1s"). No alerting, no persistence of verdicts —
this is a visibility feature, thresholds can move without a migration.

### 4. Frontend: `/settings/jobs`

A new child of the existing Settings view, listed in the **Instance** nav group
(cosmetically gated by `auth.isInstanceAdmin` like its siblings; the API enforces).
Polls `overview` every 10 s and `timeline`+`stats` every 30 s (pausable), with a
window selector.

Layout, top to bottom:

1. **Stat tiles** — running, queued (with oldest-age), failed 24h, workers online.
2. **Degradation banners** — one per degraded kind, from the anomaly rule.
3. **Timeline (Grafana-style Gantt)** — hand-rolled inline SVG, matching the house
   style (`InsightsTab.vue`, `CoverageTreemap.vue`; chart.js stays unused): one lane
   per kind, one bar per job run — muted segment for queue wait, status-colored segment
   for run time (`ok`/`danger`/`accent` for running), a "now" line, hover tooltip with
   the normalized job fields.
4. **Per-kind stats** — small multiples: throughput bars (completed/failed per bucket)
   with a p95-duration line, current vs baseline table.
5. **Workers table** — hostname/pid, version, status (online/stale/stopped), uptime,
   last heartbeat, CPU%, RSS, heap, goroutines, active jobs, enabled loops.

## Out of scope (follow-ups)

- **Run records for ticker-driven loops** (retention pass, advisory sweep, stale
  notifiers, gate reconcile): they persist no start/finish rows today, so they cannot
  appear in the timeline. If needed, a later `background_loop_runs` table can adopt the
  same normalized shape; the UI already renders kinds generically.
- **WebSocket push** for live updates (a `jobs.updated` topic); polling ships first.
- **Alerting/retention of anomaly verdicts** — Prometheus `/metrics` remains the
  integration point for real alerting.
- **Job control actions** (retry/cancel from the UI).

## Consequences

- Operators see queue depth, wait/run latency, degradation, and worker fleet health in
  one place without deploying a metrics stack; small installs get Grafana-like insight
  for free.
- One new table and one heartbeat write per replica per interval — negligible load.
  Stats queries scan bounded windows on already-indexed timestamp columns; the
  timeline is row-capped.
- The worker registry finally gives `claimed_by` strings an owner, which also helps
  debugging expired leases.
- Self-reported resource numbers are approximations (process-level, not cgroup); the
  UI must label them to avoid being mistaken for container limits.
