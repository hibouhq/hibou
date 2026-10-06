# Hibou architecture

A current-state map of the codebase for engineers working on it. Decisions and
their rationale live in [docs/adr/](adr/); this document describes what exists
today and where. Deployment topology is in [DEPLOYMENT.md](DEPLOYMENT.md), the
threat model in [THREAT-MODEL.md](THREAT-MODEL.md).

## The shape: one binary, three roles

Hibou ships as a single Go binary embedding the Vue SPA
([ADR-001](adr/001-single-binary-embedded-spa.md)). The same binary is:

- **`hibou serve`** — the API server, SPA host, webhook receiver, and every
  background worker. Replicas are stateless
  ([ADR-015](adr/015-stateless-processing-and-worker-scaling.md)): all
  coordination lives in PostgreSQL, artifact bytes in an object store.
- **the CLI** — `upload`, `gate`, `analyze`, `release`, `secretscan`, … under
  [cmd/](../cmd/), used from CI pipelines. CLI and API share the same domain
  packages, never duplicated logic
  ([ADR-005](adr/005-internal-package-architecture.md)).
- **an MCP server** — the same domain services exposed as tools
  ([internal/mcp](../internal/mcp/)).

Stack: Go + Chi v5 + zerolog + sqlc + golang-migrate; PostgreSQL;
Vue 3 + TypeScript + Pinia + Tailwind in [site/](../site/), embedded via
[internal/ui](../internal/ui/).

## The ingest pipeline (the main data flow)

Everything hangs off **immutable, per-commit snapshots**:

```
CI pipeline ──upload──▶ objstore ──▶ artifact_processing worker
   (SBOM, SARIF, coverage,              │ parses + persists
    JUnit, secrets reports)             ▼
forge webhooks ─────────▶ refs ◀── snapshots ──▶ components / vulnerabilities /
   (push, PR, installation)             │         coverage / test results
                                        ▼
                     advisory scan (providers) + delta vs target branch
                                        │
                                        ▼
                        quality gates ──▶ forge check runs (PR status)
```

1. **Upload** (`POST /uploads`, CLI `hibou upload`): raw bytes land in the
   object store ([internal/objstore](../internal/objstore/) — S3/MinIO/local),
   never in PostgreSQL. A durable job row is claimed by a worker
   ([internal/worker](../internal/worker/): lease + heartbeat,
   `FOR UPDATE SKIP LOCKED`) and parsed by format packages:
   [sbom](../internal/sbom/) (CycloneDX/SPDX), [sarif](../internal/sarif/),
   [coverage](../internal/coverage/) ([ADR-008](adr/008-coverage-integration.md),
   line-level patch coverage per ADR-018bis),
   [testresults](../internal/testresults/) (JUnit),
   [distro](../internal/distro/) (release-scoped OS package identity).
2. **Findings** are unified across types — dependency, container, malware,
   sast/weakness, secret — in one model
   ([ADR-012](adr/012-unified-vulnerability-model.md)), deduplicated by
   fingerprint ([internal/findings](../internal/findings/)).
3. **Advisory matching**: the scan loop matches components against the
   canonical advisory model ([ADR-007](adr/007-canonical-advisory-model.md):
   one advisory, many aliases, many sources) via
   [internal/scanner](../internal/scanner/), fed by providers
   ([internal/provider/osv](../internal/provider/osv/),
   [internal/provider/trivy](../internal/provider/trivy/)) with response
   caching, plus locally authored ranges (see cvetriage below).
4. **Delta + gates**: [internal/delta](../internal/delta/) diffs a PR snapshot
   against its target branch (suppressions per ADR-023/026, VEX filtering per
   [ADR-009](adr/009-vex-integration.md)) and evaluates gates
   ([ADR-018](adr/018-forge-native-quality-gate-checks.md)):
   stored per-org/repo thresholds, `.hibou.yaml` sections
   ([internal/repoconfig](../internal/repoconfig/)), the license policy
   ([ADR-029](adr/029-license-policy-model.md)/[030](adr/030-org-license-policy-and-repo-override.md),
   [internal/license](../internal/license/)), and two **unconditional blocks**:
   malware, and known-exploited vulnerabilities
   ([ADR-032](adr/032-kev-catalog-and-exploited-gate.md)). Verdicts publish as
   forge check runs via [internal/forge](../internal/forge/).

   ⚠️ The delta service reaches optional store capabilities through interface
   assertions on `delta.StoreAdapter`; every such interface is pinned with a
   compile-time assertion in
   [internal/delta/adapter.go](../internal/delta/adapter.go). Add the pin when
   you add an interface — a missed forwarding method once shipped a gate that
   silently never ran (ADR-029's implementation notes).

## Domain model anchors

`organizations → repositories → refs (branches/PRs,
[ADR-017](adr/017-canonical-pull-request-ref.md)) → snapshots → components /
vulnerabilities / coverage / test results`. Advisories are global
(instance-wide) with aliases and per-provider sources. Human decisions attach
to findings by fingerprint: acceptances/waivers
([ADR-023](adr/023-triage-acceptance-ux.md)), in-source suppressions +
disputes (ADR-023/026), VEX statements. Releases and deployments
([ADR-024](adr/024-release-tracking.md)) anchor "what is running where".
Retention is tiered ([ADR-014](adr/014-tiered-snapshot-retention.md),
[internal/retention](../internal/retention/)).

## Forge integration

[internal/forge](../internal/forge/) abstracts GitHub, GitLab, and Forgejo:
webhook parsing, check-run publishing (`gate_publisher`), clone-token minting,
repo inventory. Org/membership mirroring is forge-authoritative — no manual
membership: [internal/orgprovision](../internal/orgprovision/),
[internal/permissionsync](../internal/permissionsync/),
[internal/repoinventory](../internal/repoinventory/), with
[internal/rbac](../internal/rbac/) enforcing roles and
[internal/auth](../internal/auth/) / [internal/apitoken](../internal/apitoken/)
handling sessions and CI tokens.

## Advisory intelligence (beyond providers)

- **CVE feed** ([ADR-028](adr/028-cve-subscriptions-with-manual-purl-triage.md)):
  [internal/cvefeed](../internal/cvefeed/) sweeps the cvelistV5 git repo
  (blobless clone, 15 min cadence); [internal/cvetriage](../internal/cvetriage/)
  matches records against watched products and turns human purl mappings into
  locally authored advisories, with review/divergence passes.
- **Known-exploited catalogs**
  ([ADR-032](adr/032-kev-catalog-and-exploited-gate.md)):
  [internal/kev](../internal/kev/) mirrors CISA KEV and the ENISA EUVD
  exploited set side by side; membership is a union and gates
  unconditionally. New sources implement the two-method `kev.Source`
  interface.
- **VEX** ([ADR-009](adr/009-vex-integration.md)):
  [internal/vex](../internal/vex/) imports/exports CSAF and CycloneDX VEX;
  effective status filters deltas and auto-VEXes on upgrade.

## Background work: two concurrency primitives, on purpose

All loops start in `startBackgroundLoops`
([internal/server/server.go](../internal/server/server.go)) and report through
the worker heartbeat. Two distinct mechanisms — pick the right one:

| Primitive | For | Where |
|---|---|---|
| **Leader lock** (`store.WithLeaderLock`, Postgres advisory lock) | loops that are idempotent but wasteful to run on N replicas: advisory scan, retention, CVE feed sweep, KEV sync | [internal/store/advisory_lock.go](../internal/store/advisory_lock.go) |
| **Durable job claiming** (lease + heartbeat + `SKIP LOCKED`, attempts + backoff) | exactly-once work units: artifact processing, secret scans | [internal/worker](../internal/worker/), `*_jobs.sql` queries |

Loop health goes to `instance_settings` as JSON (e.g. `cve_feed_last_sweep`,
`kev_last_sync`) so "quiet" and "broken" never look alike; the advisory
activity endpoint serves it to the UI. Process-local fan-out uses
[internal/events](../internal/events/) (bus) → [internal/ws](../internal/ws/)
(websocket hub) and [internal/notify](../internal/notify/) (email/Discord/…
via rules and integrations).

Secret scanning ([ADR-010](adr/010-secret-scanning.md),
[internal/secretscan](../internal/secretscan/)) clones repos with
gitleaks/trufflehog providers — opt-in per deployment because of clone load;
retries back off `5·attempts²` minutes so transient host pressure cannot burn
every attempt.

## Server & API surface

[internal/server](../internal/server/) is deliberately thin per handler: Chi
routes, middleware (rate limiting, forge IP allowlist, HMAC webhook
validation), JSON envelopes from [internal/api](../internal/api/), filter
expressions via [internal/filterquery](../internal/filterquery/)
([ADR-013](adr/013-boolean-filter-expressions.md)). OpenAPI is generated by
swag from handler annotations into [internal/apidoc](../internal/apidoc/).
Comparisons between snapshots/SBOMs are pure functions in
[internal/comparison](../internal/comparison/)
([ADR-016](adr/016-snapshot-comparison.md)). Compliance exports live in
[internal/compliance](../internal/compliance/); audit logging in
[internal/audit](../internal/audit/); Prometheus metrics in
[internal/metrics](../internal/metrics/).

## Persistence & codegen

[internal/store](../internal/store/): embedded golang-migrate migrations
(`migrations/NNNNN_*.sql`, auto-applied on `serve`), hand-written SQL in
`queries/*.sql` compiled by **sqlc** into `dbgen/` (never edit generated
files), thin `*Queries` wrappers for multi-statement transactions. CI enforces
`make check-generate` (sqlc + swag output committed and current) and
`sqlc diff`.

```bash
make generate   # sqlc + swag
make lint       # sqlc diff, golangci-lint, eslint
make test       # recreate hibou_test, go test -race ./..., vitest
make all        # generate + lint + test + build
```

Store/server tests run against a real PostgreSQL (`HIBOU_DATABASE_URL`,
skip when unreachable); external HTTP is faked with `httptest`; network smoke
tests hide behind the `live` build tag.

## Frontend

[site/](../site/) is a Vue 3 SPA (Pinia stores, typed API client in
`src/api/client.ts`, Tailwind tokens in `tailwind.config.ts`, lucide icons).
Display logic that deserves tests lives in `src/lib/*.ts` with vitest.
Backend-ahead-of-UI gaps are tracked in [TODO-UX.md](../TODO-UX.md).

## Extension points, quickly

- **New forge**: implement the provider interfaces in `internal/forge`.
- **New advisory provider**: `internal/provider/<name>` following osv's shape.
- **New exploited-vulnerabilities source**: implement `kev.Source` (Name,
  Fetch, WithdrawalGrace) and wire it in `startBackgroundLoops`.
- **New background loop**: pick leader lock vs job claiming (table above), add
  a health key, register in `startBackgroundLoops`.
- **New gate section**: extend `delta.GateConfig`/`EvaluateGatesWithConfig`;
  pin any new store capability on the adapter.
- **New scheme/config knob**: `internal/config` (viper keys + validation) and
  document it in [hibou-server.example.yaml](../hibou-server.example.yaml).
