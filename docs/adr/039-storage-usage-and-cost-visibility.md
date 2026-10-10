# ADR-039: Storage usage and cost visibility

## Status

Proposed. Implemented: the sampler and exporters (§2–§5) and the admin page
(§6). The cost join and dashboards are follow-ups (§7). Builds on the worker
registry and the jobs page ([ADR-025](025-instance-jobs-observability.md)) and
on stateless replicas with leader-locked loops ([ADR-015](015-stateless-processing-and-worker-scaling.md)).

## Context

An instance admin has to answer three questions:

1. **What is growing, and how fast?** Postgres (findings, advisory events, audit
   logs, per-line coverage, the ~400k-row CVE feed mirror) and the artifact
   store (raw SBOM/SARIF/coverage uploads) both grow with every upload.
2. **Is storage healthy?** Dead-tuple bloat, transaction-ID wraparound,
   connection exhaustion, long transactions that block vacuum, objects that
   leak in the bucket after a failed delete.
3. **What does it cost?** For the database, the bucket, and the volumes.

Hibou answers none of these today. `/metrics` exposes scan, upload and
notification counters only. Operators learn about storage when the volume is
full or the invoice arrives.

### Constraints

- **Hosting varies.** Postgres can be CloudNativePG in-cluster, or managed
  (RDS, Cloud SQL, Azure Flexible Server, other providers). The artifact store
  can be AWS S3, any S3-compatible service (MinIO, SeaweedFS, Ceph RGW, other
  clouds' object storage) or a local filesystem volume. No billing API is
  common to all of them, and a self-hosted instance has no bill at all.
- **No maintenance treadmill.** Nothing in hibou may need a manual update
  when a provider changes prices or adds a region.
- **No new required infrastructure.** VictoriaMetrics/Grafana are out of scope
  for now. The output must be consumable by any Prometheus-compatible scraper
  later, without changes to hibou.

### Security gap found while scoping this

`/metrics` is served on the application port with no authentication. The Helm
chart's ingress routes `/` to that port, so on a default chart install the
endpoint is reachable from the internet. Adding table names and storage sizes
would widen that exposure. The fix is part of this ADR (§5).

## State of the art (October 2026)

| Concern | Reference tool or standard | Why it is not enough on its own |
|---|---|---|
| Kubernetes cost allocation | **OpenCost** (CNCF): allocates node, PVC and load-balancer cost per namespace or workload. Prices come from cloud pricing APIs, and on-prem uses a custom price sheet. | Sees the cluster only. Managed Postgres and object storage bills are outside it. |
| Cloud billing data | **FOCUS** (FinOps Open Cost & Usage Specification): vendor-neutral billing export schema, supported natively by the major clouds. | It is the bill. Granularity is per account, resource or bucket, never "audit logs vs. findings". Needs billing-scope credentials. |
| Postgres health | **postgres_exporter**; CNPG's built-in exporter. | Infrastructure view: it cannot say which hibou feature owns a table, and it cannot run as a sidecar on most managed services. |
| Object storage | **S3 Storage Lens / Inventory** (AWS only); MinIO and SeaweedFS native metrics. | Each is tied to one backend. `ListObjectsV2` is the only universal primitive, and its requests are billed. |
| Volumes | kubelet `kubelet_volume_stats_*`. | Already exported by Kubernetes; nothing for hibou to add in-cluster. |

The industry split is consistent: **applications export usage quantities,
and a FinOps layer multiplies them by prices it obtains from the provider.**
Hibou should be a good usage source and stay out of pricing.

## Decision

### 1. Hibou measures usage, never price

Hibou exports **bytes, rows and objects** with low-cardinality labels. It does
not store unit prices or call billing APIs. Cost is computed outside hibou:

- **In-cluster resources** (CNPG volumes, the filesystem artifact PVC, bundled
  SeaweedFS): OpenCost prices them automatically from the provider's pricing
  API, or from a custom price sheet when self-hosted.
- **Managed services** (managed Postgres, a provider bucket): the provider's
  FOCUS export gives the bill. Hibou's metrics split that bill by usage share.
  For example, `hibou_db_table_size_bytes / hibou_db_size_bytes` gives each
  table's share of the database bill.
- **Self-hosted or dogfood with no bill**: the storage stats on their own are
  the deliverable. They show growth, bloat and orphans.

No price table exists, so none needs updating.

### 2. One storage sampler, leader-locked, persisted

A new background loop, `storage_usage`, runs on every replica:

- Every `storage_usage.interval` (default **15m**), each replica tries the
  advisory lock `hibou:storage-usage` (`store.WithLeaderLock`). The winner
  collects a **sample** and stores it as one JSON document in
  `instance_settings` (key `storage_usage_sample`).
- Every replica then loads the stored sample and serves it on `/metrics`. All
  replicas export identical values, so `max without (instance, pod)` collapses
  them in PromQL. `hibou_storage_sample_timestamp_seconds` gives the sample's
  age for staleness checks.
- Scrapes never run SQL. Measurement cost is fixed by the interval, not by
  scrape rate × replica count.
- The persisted document is also what the admin page reads (§6), so the page
  does not need Prometheus.

A sample has three independent sections. A failure in one section does not
drop the others; each section reports `hibou_storage_sample_success{source}`.

#### 2a. Postgres (`source="postgres"`)

All of these come from catalog and statistics views. Each read runs in a
`READ ONLY` transaction with a 10-second `statement_timeout`.

| Metric | Source | Spots |
|---|---|---|
| `hibou_db_size_bytes` | `pg_database_size(current_database())` | growth; feeds cost share |
| `hibou_db_table_size_bytes{table,part="table\|index"}` | `pg_table_size` (heap + TOAST), `pg_indexes_size` | which feature grows |
| `hibou_db_table_rows{table,state="live\|dead"}` | `pg_stat_user_tables` estimates | bloat, autovacuum lag |
| `hibou_db_connections_used`, `hibou_db_connections_max` | `pg_stat_activity`, `max_connections` | pool exhaustion |
| `hibou_db_xid_age` | `age(datfrozenxid)` | wraparound risk (forced shutdown at ~2.1 billion) |
| `hibou_db_oldest_transaction_seconds` | `pg_stat_activity.xact_start` (own backends) | long transactions that block vacuum |
| `hibou_db_cache_hit_ratio` | `pg_stat_database` | undersized `shared_buffers` |

The tables reported are those in the `public` schema, the 100 largest only, so
cardinality stays bounded. Partitioned tables (`audit_logs`) are reported as
their parents' totals, not per monthly partition.

#### 2b. Artifact ledger (`source="ledger"`)

`snapshot_artifacts` already records `size_bytes` for every stored object.
Summing it per `kind` gives **what hibou believes it stored** for the cost of
one aggregate query, on every backend, with no provider call:

- `hibou_artifact_ledger_objects{kind}`, `hibou_artifact_ledger_bytes{kind}`

#### 2c. Artifact backend inventory (`source="backend"`, opt-in)

This measures **what is actually in the backend**:

- S3 and S3-compatible: paged `ListObjectsV2` over the bucket. It counts keys
  and sums sizes, and never reads object bodies. It stops at
  `storage_usage.inventory.max_objects` (default 1,000,000) and reports
  `hibou_artifact_backend_scan_truncated`.
- Filesystem: walks the artifact directory, then `statfs` on the volume for
  `hibou_artifact_volume_capacity_bytes` and
  `hibou_artifact_volume_free_bytes`.

Exports `hibou_artifact_backend_objects` and `hibou_artifact_backend_bytes`.
**`backend_bytes − sum(ledger_bytes)` is the drift signal.** A positive
value means orphans, objects left behind by a failed delete or a crashed
upload. A negative value means missing objects: ledger rows whose bytes are
gone, for example after a backend restore or a misconfigured path.

The inventory is off by default (`storage_usage.inventory.enabled`). It costs
one LIST request per 1,000 keys. When enabled, it runs at most every
`storage_usage.inventory.interval` (default **24h**) and rides on the same
leader-locked tick.

### 3. Metric conventions

- Namespace `hibou_`, base units (`_bytes`, `_seconds`), gauges only.
- **Labels never carry tenant data.** There are no org, repo or user labels,
  and no bucket name, endpoint, hostname or object key. The permitted labels
  are `table` (schema object names, capped), `part`, `state`, `kind` (artifact
  kind, from a fixed set) and `source`.
- The exporter is a custom `prometheus.Collector` that renders the current
  sample on each scrape. A dropped table therefore disappears from the output
  instead of lingering as a stale series.

### 4. Least privilege

- **Postgres:** catalog functions and `pg_stat_*` views only, as the
  application role. No superuser, `pg_monitor` or `pg_read_all_stats` is
  needed. When a value is not visible to the role, that metric is omitted, not
  faked.
- **S3:** the inventory needs `s3:ListBucket` only, the permission `Exists`
  already relies on: without it, AWS S3 answers `HeadObject` on a missing key
  with 403 instead of 404. No new credential and no billing scope are needed.
- **Filesystem:** read-only walk of the existing artifact path.

### 5. Securing `/metrics`

`metrics.enabled` (default `true`) is the master switch: `false` serves
`/metrics` on no listener. When it is on, two independent controls apply,
both configuration-only:

- **Dedicated listener** (`metrics.port`, default `0`). When set, `/metrics`
  is served **only** on that port and removed from the application router. The
  ingress forwards only the application port, so the endpoint drops out of the
  public surface. The Helm chart sets `9090` by default and exposes it as a
  `metrics` port on the Service and on every hibou pod, workers included.
- **Bearer token** (`metrics.bearer_token` or `metrics.bearer_token_file`,
  the file wins). When set, `/metrics` requires
  `Authorization: Bearer <token>`. The check is constant-time, and any other
  input gets 401. Prometheus (`authorization.credentials_file`), VMAgent and
  the OpenTelemetry Collector's Prometheus receiver all support this.

If neither control is configured, `/metrics` keeps working as before so
existing scrapes don't break, and startup logs a warning naming the exposure.

The Helm chart follows the common `metrics.*` layout:

```yaml
hibou:
  metrics:
    enabled: true
    port: 9090
    auth:                 # optional bearer token
      existingSecret: ""
      existingSecretKey: token
    podMonitor:           # Prometheus Operator; the VictoriaMetrics operator converts it
      enabled: false
      interval: 60s
      labels: {}
    networkPolicy:        # metrics port only from `from`; application port unchanged
      enabled: false
      from: []
```

- **PodMonitor, not ServiceMonitor:** worker pods have no Service but export
  their own job counters, so a ServiceMonitor would miss them. The PodMonitor
  selects server and worker pods and sends the bearer token when `auth` is
  set. Both are off by default because they need the operator CRDs.
- **NetworkPolicy** is the Kubernetes-native control and complements the
  token. It leaves the application port open as before and admits the
  metrics port only from the configured `from` peers. The chart refuses to
  render it with an empty `from`, which would lock every scraper out.
The JSON `/api/v1/metrics` (uptime, Go version, secret-scan queue depth) is
unchanged here. Tightening it is listed as a follow-up.

### 6. Admin page: Settings → Instance → Storage

The primary surface for an admin, with no metrics stack required. It sits
next to Jobs & workers (ADR-025) at `/settings/storage`.

- **API:** `GET /api/v1/instance/storage`, for instance admins only
  (`requireInstanceAdmin`, `sessionOnlyRoute`). It returns the persisted
  sample as stored, the sampler settings, the artifact backend type and how
  `/metrics` is exposed (`disabled`, `dedicated_port`, `token` or `public`). The handler
  reads one `instance_settings` row and never measures, so loading the page
  costs nothing.
- **Tiles:** database size, artifacts recorded (bytes, objects, backend),
  connections used/max, and volume free (filesystem with the inventory on) or
  else the sample's age.
- **Database health:** transaction-ID age against the ~2.1 billion limit,
  oldest open transaction, cache hit ratio, and when and how fast the sample
  was taken.
- **Largest tables:** sorted by data + index size, with each table's share of
  the database (the cost split for a managed-database bill), live and dead
  rows. Dead rows are highlighted when there are at least 10k and they exceed
  20% of live rows.
- **Artifacts:** ledger per kind, and the backend inventory with its
  difference from the ledger, or a hint to enable the inventory.
- **Warning banners**, computed client-side so thresholds can change without a
  migration (`site/src/lib/storageUsage.ts`, unit-tested):

  | Check | Warn | Danger |
  |---|---|---|
  | Sample age | > 3 × interval | |
  | A source failed | | always |
  | Transaction-ID age | ≥ 200M (`autovacuum_freeze_max_age` default) | ≥ 1B |
  | Connections | ≥ 80% of `max_connections` | |
  | Oldest open transaction | ≥ 1h | |
  | Artifact volume free | < 15% | < 5% |
  | Backend vs ledger drift | ≥ max(1 MB, 5% of ledger), shown as orphaned or missing | |
  | `/metrics` exposure | `public` | |

- There is no polling and no "measure now" button. The sample changes once
  per interval, and an on-demand bucket listing is exactly the cost the
  inventory interval exists to bound. A Reload button re-reads the sample.

### 7. Out of scope (follow-ups)

- **Dashboards and alert rules** (VictoriaMetrics/Grafana). The metrics are
  designed for them; example queries are below.
- **Growth history in-app.** Prometheus `predict_linear` covers forecasting
  once a TSDB exists; hibou keeps only the latest sample.
- **Cost join.** OpenCost plus FOCUS ingestion is an operator-side deployment
  choice, not hibou code.
- **`/api/v1/metrics` exposure.** Move it behind auth or drop the Go version.

### Consuming the metrics (reference, not shipped)

```promql
# Days until the artifact volume is full, from 7 days of trend
max(hibou_artifact_volume_free_bytes)
  / -deriv(max(hibou_artifact_volume_free_bytes)[7d:1h]) / 86400

# Orphaned bytes in the bucket (needs the inventory)
max(hibou_artifact_backend_bytes) - sum(max by (kind) (hibou_artifact_ledger_bytes))

# Bloat: tables with more dead than live tuples
max by (table) (hibou_db_table_rows{state="dead"})
  > max by (table) (hibou_db_table_rows{state="live"})

# Share of the managed-database bill per table
max by (table) (sum without (part) (hibou_db_table_size_bytes)) / scalar(max(hibou_db_size_bytes))

# Sampler stopped
time() - max(hibou_storage_sample_timestamp_seconds) > 3 * 15 * 60
```

## Considered options

| Option | Verdict |
|---|---|
| **A. Price table in hibou × usage** | Rejected. Prices vary by provider, region and tier, and change. Someone would have to keep the table current, which is exactly the treadmill to avoid. |
| **B. Hibou calls billing APIs** (Cost Explorer, Cost Management, BigQuery billing export) | Rejected. Needs per-provider code and billing-scope credentials, which are among the most sensitive in an account. Nothing exists for S3-compatible or on-prem backends, and bills cannot attribute cost to hibou features. |
| **C. External exporters only** (postgres_exporter, kubelet, backend-native metrics) | Kept as a complement, rejected as the answer. They cannot attribute bytes to hibou features or detect orphans, and they are not uniformly deployable on managed services. |
| **D. Compute on every scrape** | Rejected. `pg_*_size` over ~100 tables plus a bucket LIST, multiplied by replicas and scrape rate, puts measurement load on the database it measures. |
| **E. Leader-locked sampler, persisted sample, usage-only export** | **Chosen.** Platform-agnostic, needs no maintenance, bounded cost, and one sample feeds both `/metrics` and the admin page. |

## Consequences

- Every deployment gets DB and ledger storage stats with no configuration.
  The bucket inventory is one switch away.
- Cost stays a join that the operator performs. Hibou documents the queries,
  not the prices.
- The chart's default changes `/metrics` from public to cluster-internal. Any
  external scraper that relied on the ingress path must move to the `metrics`
  port (or enable the PodMonitor) or set a bearer token.
- Admins see storage in Settings → Storage on every deployment, with or
  without a metrics stack.
- One more leader-locked loop and one more `instance_settings` key (a few KB).
