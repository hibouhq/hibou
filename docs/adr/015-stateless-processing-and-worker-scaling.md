# ADR-015: Stateless processing and worker scaling

## Status

Accepted

## Target architecture: stateless modular monolith

Hibou remains a single modular-monolith Go binary, not a microservices split. The deployable unit stays one binary with strict `internal/` package boundaries, consistent with [ADR-001](001-single-binary-embedded-spa.md) and [ADR-005](005-internal-package-architecture.md).

That binary runs as `N` stateless replicas behind a load balancer. Any replica may serve any request. Replicas are disposable and interchangeable.

For Hibou, "stateless" means no process holds authoritative state between requests. All authoritative state lives in PostgreSQL for control, coordination, and metadata, and in a shared object store for raw artifact bytes. A running process is therefore a function of those backing stores plus configuration, not a source of truth in itself.

The same binary may run in API-only, worker-only, or combined roles. See [Replica model](#replica-model).

Stateless does not mean no background work. Durable background work remains part of the architecture, but it runs in workers using the same binary in a worker role, pulling work durably from PostgreSQL through atomic lease-based claims.

### Statelessness contract

- No server-side session storage. Sessions are signed tokens or cookies. This is already true for the HMAC-signed `hibou_session` cookie.
- No server-side OAuth flow state map. OAuth state is carried in a signed cookie. This is already true.
- No in-process data is a source of truth. In-memory caches must be Postgres-backed or strictly best-effort with short TTLs.
- The in-memory event bus in [`internal/events`](../../internal/events/) is for local side effects only. It must not be used for cross-replica orchestration. Cross-replica fan-out, including WebSocket notifications, must use PostgreSQL transport such as `LISTEN/NOTIFY` or polling.
- Raw artifacts live in shared storage for any multi-replica deployment. The default is an object store; the local filesystem backend is single-replica only unless operators explicitly back it with a shared ReadWriteMany volume.
- All durable work is claimed atomically from PostgreSQL using leases, and all processors are idempotent and safe to retry.
- A shared signing secret, `session.secret`, must be configured and identical across all replicas. The insecure default must not be used in production.

### Current statelessness status

Already stateless / replica-safe:

- Auth sessions use an HMAC-signed `hibou_session` cookie with no server-side store: [`internal/auth/auth.go`](../../internal/auth/auth.go).
- OAuth flow state uses an HMAC-signed `hibou_oauth_state` cookie with no server-side state map: [`internal/auth/auth.go`](../../internal/auth/auth.go).
- Advisory cache is backed by PostgreSQL in `advisory_cache`: [`internal/cache/cache.go`](../../internal/cache/cache.go).
- Background loops are config-gated for API-only and worker-only role splits: this ADR, [Replica model](#replica-model).
- Snapshot work claiming is database lease-based, including `FOR UPDATE SKIP LOCKED` as an allowed claim pattern: this ADR, [Work-claim model](#work-claim-model).

Residual gaps to close:

- Artifact storage is filesystem-only today and the Helm chart has no artifact PVC or volume mount. [`internal/objstore/filesystem.go`](../../internal/objstore/filesystem.go) stores artifacts on replica-local disk, [`internal/objstore/s3.go`](../../internal/objstore/s3.go) is only an unimplemented placeholder, [`internal/server/server.go`](../../internal/server/server.go) wires only `objstore.NewFilesystemStore`, and the chart deployments write `cfg.ArtifactPath` onto ephemeral pod storage: [`chart/hibou/templates/hibou-deployment.yaml`](../../chart/hibou/templates/hibou-deployment.yaml), [`chart/hibou/templates/hibou-worker-deployment.yaml`](../../chart/hibou/templates/hibou-worker-deployment.yaml). The chosen direction is a vendor-neutral S3-compatible object-store backend in [`internal/objstore/s3.go`](../../internal/objstore/s3.go) with a bundled self-hosted SeaweedFS server as the default DMZ and air-gap object store; the backend must be configurable to point at any S3-compatible endpoint, and artifact bytes are not stored in PostgreSQL.
- `session.secret` still defaults to `change-me-in-production` and must be rejected or loudly warned outside development in the app, but the chart already provisions one shared session secret for replicas through [`chart/hibou/templates/hibou-session-secret.yaml`](../../chart/hibou/templates/hibou-session-secret.yaml).
- WebSocket real-time fan-out is replica-local because the hub and live notification path are in-process: [`internal/ws/hub.go`](../../internal/ws/hub.go), [`internal/events/bus.go`](../../internal/events/bus.go), [`internal/notify/service.go`](../../internal/notify/service.go).
- The in-memory event bus is process-local and needs an explicit local-only contract for future work: [`internal/events/bus.go`](../../internal/events/bus.go).
- Graceful shutdown and draining on `SIGTERM` still need to drain in-flight uploads and WebSocket connections and release worker claims promptly.
- Worker claims renew through an owner-guarded heartbeat loop while work is in flight; if renewal fails because ownership is lost, the worker abandons processing and leaves the snapshot reclaimable by the current or next lease owner.
- Helm and Kubernetes guardrails still need to block unsafe replica and storage combinations and add rollout safety defaults.
- Processor idempotency coverage still needs to extend across coverage, VEX or call-graph, and secret or commit paths as they move onto the worker framework.

Tracked in [TODO-ARCH-stateless.md](../../TODO-ARCH-stateless.md).

## Context

Hibou is growing beyond a single synchronous upload path. The project already includes or is expected to include several background or semi-background concerns:

- SBOM dependency ingestion
- SARIF vulnerability ingestion
- VEX and call-graph processing, initially for Go-based analysis
- coverage parsing and aggregation
- delayed secret/commit scan follow-up or aggregation
- retention and lifecycle work
- future artifact-backed analyzers

Not all work belongs on the delayed path.

- Immediate-path work stays request- or webhook-triggered when latency is low and the caller expects an immediate answer. Example: push-time secret scanning.
- Delayed-path work is durable background processing that can outlive the request. Examples: artifact ingest, coverage aggregation, VEX/call-graph work, retention sweeps.
- Delayed-path notification generation that produces durable user-visible side effects, such as stale-scan events, belongs under the same role-gated loop model.

Today the system is inconsistent. Some upload types are only stored as snapshot artifacts, some are processed in local goroutines, and coordination relies on in-process behavior. That model has three problems:

1. it does not scale cleanly across multiple API replicas
2. it is vulnerable to duplicate processing or lost work when processes crash
3. it encourages one-off background paths instead of one maintainable processing model

The immediate symptom is visible in the dependency/security views: SBOM and SARIF uploads are accepted and stored, but no replica-safe ingest path turns them into components or vulnerabilities.

## Decision

Hibou will use a stateless-server plus DB-claimed worker model.

### Core rules

- API servers stay stateless. Their job is to authenticate, validate, persist metadata/artifacts, and mark work as ready.
- PostgreSQL is the source of truth for work ownership and progress.
- Workers claim work atomically from PostgreSQL using lease-based ownership.
- Artifact processing must be idempotent and safe to retry.
- The in-memory event bus is for local side effects only. It must not be used as the source of truth for cross-replica orchestration.

### Replica model

The same binary may run in different roles:

- API-only replicas
- worker-only replicas
- combined replicas for small deployments

Multiple replicas of each role are allowed. A worker must never assume it is the only processor.

Runtime config must allow delayed loops to be enabled or disabled independently so operators can choose between:

- one combined deployment that serves requests and runs delayed loops
- API replicas with delayed loops disabled
- optional worker replicas with delayed loops enabled

For Kubernetes and Helm, the first implementation keeps one binary and exposes a simple optional worker deployment rather than introducing a separate worker image.

### Work-claim model

For the first pass, work is claimed at the snapshot level.

Each claimable snapshot has worker-owned processing state such as:

- lifecycle state (`pending`, `ready`, `processing`, `complete`, `failed`)
- `claimed_by`
- `claim_expires_at`
- attempt counters and timestamps

The initial implementation keeps this state directly on the `snapshots` row and only claims snapshots that have completed uploads plus claimable stored artifacts. In this batch, claimable artifacts are:

- SARIF documents for vulnerability/finding ingest
- CycloneDX JSON SBOM documents for component ingest

The first pass uses lease expiration plus bounded retry counts, plus an owner-guarded heartbeat loop that renews active claims while processing remains in flight. It still does not add a separate queue table.

Only snapshots that are already `complete` are eligible for first-time artifact processing. Snapshots that become `failed` because the upload lifecycle timed out or otherwise never completed are not claimable. Retries stay limited to snapshots that previously failed during artifact processing itself.

A worker claims a snapshot with an atomic database operation such as:

- `UPDATE ... SET claimed_by = $worker, claim_expires_at = $lease ... WHERE id = (...) AND claimed_by IS NULL ... RETURNING *`
- or `SELECT ... FOR UPDATE SKIP LOCKED` followed by guarded update

Only the worker that owns the active claim may finalize or fail the processing run.

### Idempotency model

Processors must tolerate retries, duplicate deliveries, and crash recovery.

Examples:

- component upserts must be conflict-safe
- snapshot-to-component associations must be deduplicated
- vulnerability creation must use stable fingerprints or equivalent uniqueness constraints
- coverage ingestion must support multiple reports without corrupting prior data

This is required both for worker crashes and for multi-replica race protection.

### Artifact storage strategy (DMZ / self-hosted)

The shared artifact backend must work in DMZ, self-hosted, and air-gapped deployments, must be deployable through the project Helm chart, and must work in dogfood. Today the chart does not provision an artifact volume, so [`chart/hibou/templates/hibou-deployment.yaml`](../../chart/hibou/templates/hibou-deployment.yaml) and [`chart/hibou/templates/hibou-worker-deployment.yaml`](../../chart/hibou/templates/hibou-worker-deployment.yaml) write `cfg.ArtifactPath` to ephemeral pod disk. That means artifacts are lost on pod restart even with one replica and are not shareable across replicas.

The ranked artifact-storage strategy is:

1. Default for any multi-replica or Helm-chart deployment: a self-hosted, S3-compatible object store, with SeaweedFS (Apache-2.0, GA) bundled and deployable through the project Helm chart as the default. SeaweedFS stores artifact bytes on its own ReadWriteOnce volume, so it needs only the block storage the cluster already provides and does not require a ReadWriteMany provisioner. Hibou replicas remain stateless; SeaweedFS is the only new stateful workload. This fixes today's ephemeral-artifact loss and makes artifacts shareable across replicas.
2. The object-store backend in [`internal/objstore/s3.go`](../../internal/objstore/s3.go) must be vendor-neutral: configurable endpoint, region, bucket, access key, secret key, path-style addressing, and TLS. Operators can therefore repoint Hibou at any S3-compatible server, including the bundled SeaweedFS, an external Ceph RGW, AWS S3, RustFS, or any other S3 API implementation, through configuration alone with no code change.
3. The local filesystem backend in [`internal/objstore/filesystem.go`](../../internal/objstore/filesystem.go) remains supported for single-replica and development deployments only.
4. Optional: an RWX shared volume behind the filesystem store for operators who already run a ReadWriteMany provisioner and prefer a shared volume to an object-store service.
5. Artifact bytes are never stored in PostgreSQL. PostgreSQL stays the source of truth for control, coordination, and metadata only. Artifact lifecycle and eviction is handled by [ADR-014](014-tiered-snapshot-retention.md) retention through the object store's delete path.

Rejected: AWS S3 and MinIO are not bundled and are not the default. AWS S3 is unfit as a DMZ or air-gap default because it adds a cloud dependency, though it remains reachable through the vendor-neutral client at operator discretion. MinIO is not bundled because it is unmaintained. RustFS (Apache-2.0) remains a watch-list target through the same vendor-neutral backend once it reaches stable GA.

## Implementation

### Short term

- add snapshot processing state and DB claim queries
- add a worker loop for claimable snapshots
- keep uploads lightweight: persist artifacts, mark snapshot ready, return
- ingest SARIF and CycloneDX JSON artifacts from object storage through the worker loop
- keep push-time secret scanning on the immediate webhook path
- add config/env toggles for delayed loops so deployments can split API and worker roles
- include stale-scan notification generation in those delayed-loop toggles so API-only replicas do not emit duplicate durable notifications
- expose a simple optional worker deployment in Helm for Kubernetes role splits
- fix user-facing fallback logic so views prefer the latest data-bearing snapshot instead of a failed empty one when no complete snapshot exists
- keep route compatibility for existing analysis consumers such as `/findings` and `/vulnerabilities` while the backend serves the same vulnerability dataset

### Medium term

- move all artifact-backed work onto the same processing framework
- extend the same multi-worker safety model, including the implemented owner-guarded lease renewal/heartbeat behavior, as more artifact-backed processors move onto the framework
- make processor registration generic by artifact/work type:
  - dependency ingest
  - SARIF ingest
  - VEX and call-graph processing
  - coverage ingest
  - secret/commit scans
  - future analyzers

Dependency advisory matching is intentionally deferred from this first worker batch. Once SBOM component ingest is stable, the next slice can trigger the existing dependency scanner from the same snapshot worker path.

### Out of scope for this ADR

- external queue infrastructure such as Kafka, SQS, or NATS
- artifact-level parallelism inside a single snapshot
- splitting PostgreSQL ownership from long-term metrics/event streaming

Those may be added later if scale requires them, but the first scalable step is to make PostgreSQL coordination explicit and reliable.

## Consequences

Benefits:

- API replicas remain simple and horizontally scalable
- multiple worker replicas can be added safely
- failures become recoverable through leases and retries instead of manual cleanup
- future scanners and processors fit one shared model instead of new custom goroutine paths
- the design remains maintainable because orchestration state lives in one place

Tradeoffs:

- schema and worker state become more explicit
- processors must be written carefully for idempotency
- PostgreSQL becomes more central to operational correctness, so claim queries and indexes matter

## Rationale

This keeps the architecture simple enough for the current project size while leaving room to scale.

It is closer to Argo CD's operational shape than to a single-node background-thread model:

- stateless API layer
- DB-backed control state
- horizontally scalable workers/reconcilers

That is a better fit for Hibou than relying on request-scoped goroutines or local in-memory dispatch for durable background processing.
