# ADR 010: Scalable Secret Scanning

## Status

Accepted

## Context

Hibou already stores normalized secret findings in `secret_findings`, but Phase 5 still lacks the runtime integration that turns that schema into a scalable feature. We need secret scanning that works on day zero for onboarding, scales to push-time checks, and remains extensible as teams adopt different scanners such as gitleaks, truffleHog, or GitHub Secret Scanning.

The design has to satisfy four constraints:

1. Multiple providers must plug into one normalization flow.
2. Full repository scans and incremental push checks must share the same model.
3. Push blocking must be possible without persisting every synchronous check.
4. Raw secrets must never be stored by Hibou.

## Decision

We will implement a tool-agnostic secret scanning framework built around a `SecretScanProvider` interface. Providers are responsible for talking to a scanner or API and returning normalized `SecretFinding` values. A scanner orchestrator runs one or more providers, deduplicates findings by fingerprint, persists normalized results for snapshot-based workflows, and exposes a synchronous push-check path for pre-receive blocking.

### Provider model

Each provider implements:

- `Name()`
- `ScanRepo(ctx, opts)` for full-repository scans
- `ScanDiff(ctx, opts)` for incremental scans when supported
- `Capabilities()` to advertise full scan, incremental scan, and verification support

This keeps provider onboarding small: adding a new scanner requires implementing the interface and registering it in server wiring.

### Scan modes

We support two modes:

1. Full repository scan
   Used for onboarding, backfills, and manual rescans.
2. Incremental diff scan
   Used for push-time checks and webhook-driven updates.

Providers that cannot do incremental scans explicitly report that limitation. The orchestrator can skip them for push checks or fall back to full scans when that tradeoff is acceptable.

### Push blocking

We expose a synchronous API endpoint for pre-receive style integrations. Callers send repo coordinates or clone parameters and receive normalized findings immediately. This path does not need to persist findings. It exists to support GitGuardian-style blocking flows where the gate decision must happen inline with the push.

### Scalability

The orchestration model is built for scale:

- full scans and asynchronous ingestion run outside the request path
- providers can be selected independently and run as a set
- findings are deduplicated with a deterministic fingerprint
- snapshot storage supports pagination and repo-level aggregation
- event publication allows downstream consumers to react without tight coupling

The fingerprint format is:

`sha256(file_path + start_line)` when a provider reports a line number.

When a provider cannot report a line and returns `start_line = 0`, the fallback format is `sha256(file_path + secret_hash)`. This preserves location-based dedup when line data exists and falls back to hash-based identity only when location data is unavailable.

This defines one canonical finding per file location when that location is known, regardless of which tool detected it. Providers that cannot supply a stable line number still deduplicate by hashed secret value within the file without storing the raw secret.

Per-tool details including rule ID, severity, description, secret hash, and verification status are preserved in the `secret_finding_sources` table as metadata, so the UI can display each tool's specific assessment of the same finding.

### Cross-provider deduplication

Tool identity is intentionally excluded from the fingerprint. When multiple providers report the same file location, Hibou stores one canonical row in `secret_findings` and records per-tool attribution in `secret_finding_sources`. If line data is missing, providers only deduplicate together when they report the same `file_path` and `secret_hash` fallback fingerprint.

This split keeps remediation and lifecycle state attached to a single normalized finding while preserving which scanners detected it, when they first and last saw it, and how many scans reported it. It also enables tool effectiveness reporting, overlap analysis between scanners, and unique-find-per-tool metrics without duplicating remediation state.

### Security

Hibou never stores the raw secret value. Providers hash the matched secret with SHA-256 and only the hash is persisted. The normalized record can still drive remediation, deduplication, and lifecycle management without retaining the secret itself.

## Consequences

### Positive

- Adding providers is low-friction and does not change server or store contracts.
- Push protection and asynchronous onboarding scans reuse the same normalization model.
- Secret findings integrate with snapshots, delta workflows, and remediation state.
- The design works for exec-based and API-based providers.

### Tradeoffs

- Some providers cannot support true incremental scan semantics.
- API-based providers may expose less file-level detail than local scanners.
- Repo-level summary queries may need further optimization if result volume grows materially.

## Alternatives Considered

### Single hard-coded provider

Rejected. It solves initial delivery but makes later adoption of GitHub or truffleHog expensive and pushes provider-specific assumptions into server and store code.

### Persist raw secrets for richer workflows

Rejected. It materially increases risk and is unnecessary for deduplication, routing, or remediation.

### Separate models for onboarding scans and push checks

Rejected. It duplicates normalization, increases drift, and makes provider support inconsistent.
