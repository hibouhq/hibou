# ADR-054: GitHub integration without inbound webhooks

## Status

Implemented for GitHub/GHES (2026-11-09), with bounded reconciliation scopes.
GitLab/Forgejo polling and fully disconnected metadata parity remain out of
scope. Webhook remains the default; no deployment changes mode implicitly.

Implementation notes:

- `event_mode`, `poll_interval` and `inventory_interval` load from server YAML
  and indexed environment variables; Helm exposes `eventMode`, `pollInterval`
  and `inventoryInterval`. Poll/hybrid require GitHub App credentials.
  Poll mode refuses webhook delivery even in development or when a secret
  remains configured. OAuth login remains independent.
- Migration `00074` persists per-provider inventory and per-enrolled-repository
  ref/PR/release/build schedules, checkpoints, page validators, attempts,
  errors and leases. Claims are fenced and reclaimable across replicas.
  A replica processes one scope at a time; each scope has a two-minute
  deadline and a three-minute lease. Provider-level PostgreSQL advisory locks
  serialize poll fetch/application with hybrid webhook application.
- Scale/security hardening uses migrations `00075`/`00076`: immutable
  enrollment bindings and live inventory account IDs, indexed run sampling,
  and provider-wide API backoff shared by replicas.
- Full paginated observations are collected before applying a diff.
  Inventory/ref/PR/release/build changes, analysis enqueue and checkpoints
  commit transactionally. Existing lifecycle handlers are reused through a
  transaction-bound facade; no HTTP webhook replay or fabricated sender.
  Analysis observations deduplicate by repo/ref/commit and producer revision.
  Removed/inaccessible inventory is not deleted history; ref disappearance
  retires the head without deleting snapshots. Release removal retains
  rollout history under ADR-024.
- GitHub resource readers use repository-scoped read tokens, per-page ETags
  and durable cached bodies. A first-page 304 still visits later pages.
  Rate-limit/reset and Retry-After errors defer the shared GitHub client and
  durable scope retry; scheduling/backoff includes jitter. Denied capabilities
  remain visible errors, not empty successful inventories.
- Names are routing metadata, not authority. Polling verifies the enrolled
  account/repository IDs against current inventory; token minting checks the
  immutable installation account and uses `repository_ids`, including in
  GHES. Namespace reuse or repository recreation does not rebind existing
  security history. Hybrid repository webhooks also verify the payload's
  immutable identities. Unknown legacy identity is blocked rather than
  guessed; the migration anchors known pre-existing inventory IDs.
- Verified onboarding checks the signed-in user's current installed-account
  administration by immutable IDs. Historical installer bindings alone do
  not authorize the polling onboarding path. Discovery does not enroll repos.
- PR lifecycle timestamps come from GitHub. Ref upserts distinguish
  authoritative PR observations from CI metadata, so an older head/merge
  upload cannot overwrite a known PR head or target. Base changes also
  request gate recomputation. Publication intent stays durable until current
  open-PR checks have persisted forge acknowledgements.
- Build reconciliation only fails pending snapshots matching run ID, attempt
  and commit. Unidentified/mismatched runs retain timeout behavior with a
  visible explanation. Successful CI execution is not analysis completion.
- **Settings → Instance → Forge delivery** and
  `GET /api/v1/instance/forges/events` expose mode, per-capability scopes,
  attempt/success/next-due times, errors, degradation notes and pending check
  publication. Onboarding identifies outbound-only accounts. Jobs & workers
  includes reconciliation runs and sampled counts/latency stats. Successful
  unchanged cycles are sampled hourly per scope; material changes, reported
  errors and recovery runs are retained. The horizon is 14 days with bounded
  cleanup batches. Authorized "Sync now" requests coalesce into the scheduler
  and do not bypass the shared API backoff.

**Hundreds-of-repositories amendment:** defaults are 5-minute active PR/build
polling and 30-minute inventory/ref/release/inactive discovery. Existing
explicit shorter intervals remain supported. Uploads wake their own repo's
PR/build scopes. The scheduler no longer sleeps one second after every
completed scope; unchanged checkpoints are not rewritten, enrollment scopes
are ensured in a set-based query, stable inventory does not flush all
repository tokens, and installation pages use conditional requests too.
Provider serialization remains intentional for webhook/poll ordering.

Bandwidth is not zero on a 304. A controlled two-installation fixture with
500 repos per organization measured 13 cold requests / 2,455,612 body bytes,
then 11 immediate unchanged requests / zero body bytes / zero token mints.
Actual HTTP/1.1 fixture socket traffic for that warm run was 1,690 bytes in
and 3,105 bytes out, excluding TLS; production headers and compression differ.
Projected conditional metadata retained 200,572 bytes; unused response fields
are not stored. Versioned cache projections force a fresh fetch when reader
schemas change. Decoded responses are bounded to 16 MiB/page and 64 MiB/scope,
and retained conditional metadata to 16 MiB, before checkpoint application.
The PostgreSQL/controlled-reader test processes 250 quiet repos / 1,000
scopes in roughly 8 seconds per cycle in development, stores 1,000 samples
after two quiet cycles, and avoids every unchanged checkpoint rewrite. These
are fixture measurements, not live GitHub/GHES throughput guarantees. See
[deployment bandwidth guidance](../DEPLOYMENT.md#hundreds-of-repositories-bandwidth-storage-and-freshness)
for request budgets and assumptions.

Operational bounds: each paginated GitHub list is capped at 100 pages,
tracked-ref/release application at 10,000 rows, and a checkpoint at 16 MiB.
Exceeding a bound fails visibly without applying removals or advancing the
checkpoint. Pending builds are processed in pages of 100 identities with a
durable cycling offset. These are scheduling targets, not a freshness SLA;
large scopes, outages and rate limits increase lag.

Validation uses controlled GitHub HTTP fixtures (including GHES API prefixes),
PostgreSQL-backed lifecycle/lease/rollback tests, verified-onboarding tests,
and a no-webhook PR → CI upload → artifact processing → published gate test.
This is not a claim of a live customer GitHub/GHES or firewall deployment test.

Related: [ADR-015](015-stateless-processing-and-worker-scaling.md) (durable
workers), [ADR-017](017-canonical-pull-request-ref.md) (canonical PR refs),
[ADR-018](018-forge-native-quality-gate-checks.md) (forge checks),
[ADR-024](024-release-tracking.md) (release lifecycle),
[ADR-025](025-instance-jobs-observability.md) (job visibility),
[ADR-034](034-absence-is-not-resolution.md) (evidence and resolution),
[ADR-036](036-automatic-scan-planning-and-verification.md) (scan planning),
and [ADR-052](052-forge-write-access-least-privilege.md) (forge permissions).

## Context

A self-hosted Hibou instance may reach GitHub over HTTPS while GitHub cannot
reach Hibou: private networks, VPN-only deployments, firewall rules, or policies
that prohibit inbound webhook delivery. Some organizations also prohibit
configuring webhooks even when network connectivity would allow them.

Hibou should not require a public ingress, tunnel, relay, or development-mode
security exception to work in that environment. "No webhooks" is not "no GitHub
API": outbound API and Git access remain available, and CI runners must be able
to reach Hibou to upload analysis.

### Context before implementation

- [Startup validation](../../internal/config/config.go) rejects a configured
  forge without a webhook secret outside development.
- [Webhook handlers](../../internal/server/webhooks.go) maintain refs and PR
  lifecycle, request gate recomputation, enqueue server-side secret scans and
  dependency extraction, ingest releases, and fail pending snapshots after
  failed builds. Installation events also feed inventory and org provisioning.
- [Repository inventory](../../internal/repoinventory/service.go) already
  reconciles installations and accessible repositories through the API. The
  [manual sync endpoint](../../internal/server/sync.go) exposes that operation,
  but inventory sync is not a replacement for the other webhook effects.
- [Uploads](../../internal/server/uploads.go) already carry repository/ref,
  commit and build identity, PR metadata, and head/base/merge provenance. They
  can populate analysis without a preceding webhook, but cannot report a PR
  closing, an installation being removed, or a pipeline that never uploads.
- The [forge abstraction](../../internal/forge/forge.go) has repository and
  branch reads, but no general read interface for PR lifecycle, workflow runs,
  tags, or releases. Polling those requires additional provider capabilities.

Simply making the webhook secret optional would therefore leave Hibou looking
connected while important state silently becomes stale.

## Decision

Support **outbound-only GitHub reconciliation**, complemented by existing CI
uploads. Webhooks become an optional low-latency input, not a prerequisite for
correctness in the new mode.

The first implementation targets GitHub, including configured GitHub Enterprise
API URLs. Keep the reconciliation contract provider-neutral, but do not claim
GitLab/Forgejo support until their adapters and tests exist. No external message
broker or relay service is required.

### 1. Explicit delivery mode

Add a per-forge `event_mode`, exposed as `HIBOU_FORGE_N_EVENT_MODE` and through
the server YAML and Helm configuration:

| Mode | Behavior | Webhook secret |
|---|---|---|
| `webhook` | Existing webhook-driven behavior; default for existing deployments | Required |
| `poll` | API reconciliation and CI uploads; webhook receiver disabled | Not required |
| `hybrid` | Webhooks for latency, reconciliation for recovery | Required |

Reject unknown modes, unsupported provider/mode combinations, non-positive poll
intervals, and missing credentials required for reconciliation. Never infer
`poll` from a missing secret or a quiet webhook stream.

In `poll` mode, do not mount/accept that provider's webhook receiver, even if a
secret remains configured. In `webhook` and `hybrid`, retain signature validation,
replay protection, IP policy and rate limits unchanged. Never accept unsigned
webhooks as a fallback. OAuth/login validation remains independent.

GitHub App authentication remains the supported machine identity; disabling the
App's webhook delivery does not require replacing it with a personal token.
Keep OAuth for interactive login and existing API tokens for CI uploads.
Browser login still needs a callback reachable by the user's browser; it does
not require GitHub's servers to initiate a webhook connection.

### 2. Reconcile resource state, not a fabricated event stream

Add capability interfaces alongside `forge.Provider` for paginated PRs, tags,
releases and relevant workflow runs. Include immutable IDs, revision/timestamp
information and lifecycle fields needed to compare observations. Do not expand
every provider with placeholder methods that return empty successful results.

Extract transport-independent application logic from webhook handlers.
Authenticated webhooks and API observations use the same ref normalization,
inventory, lifecycle, gate and work-enqueue rules. A poll observation is not a
synthetic push: API reads cannot reconstruct every intermediate push, sender,
or exact `before..after` range.

| State/effect | Outbound-only reconciliation |
|---|---|
| Installations and inventory | Enumerate App installations and their selected repositories; reconcile account identity, additions, removals, renames, archive state and default branch |
| Branches and tags | Observe current heads and disappearance; update tracked refs and trigger applicable work when commit identity changes |
| PRs | Reconcile open PRs and revisit locally open PRs until closed/merged; capture title, source, target, head and authoritative lifecycle timestamps |
| Quality gates | Recompute on relevant head/base or policy changes and after uploads; publish through existing forge check/status support when authorized |
| Server-side analysis | Enqueue existing secret-scan and dependency-extraction jobs for eligible enrolled refs; no new CI execution service |
| Builds | Query runs associated with pending snapshots; reconcile terminal failure/cancellation/timeout using build identity and attempt |
| Releases | Reconcile published metadata, tag movement and removal through ADR-024 rules; preserve rollout history and shipped-snapshot identity |

Use the canonical PR ref from ADR-017. Preserve PR head, checked-out merge and
base commit provenance separately: a merge-build upload must not overwrite the
PR's authoritative head. Reconcile base changes as well as head changes so PR
deltas do not remain stale after the target branch advances.

Limit expensive ref/workflow scans to enrolled repositories and relevant refs,
including release-policy tags. Discovering an accessible repository does not
enroll it or start scanning it.

For initial observation or a force-push/non-ancestor change, use a supported full
scan at the observed commit rather than inventing an incremental range. Periodic
polls cannot guarantee inspection of commits pushed and removed between polls;
organizations requiring every-push secret scanning must retain webhooks or
enforce scans in CI/pre-receive. Missing observations never resolve findings or
establish clean coverage (ADR-034).

### 3. Bootstrap without installation events

On enabling polling, enumerate installations and seed inventory without waiting
for an installation webhook. Bind accounts and repositories by provider instance
and immutable forge IDs so renames do not create a second tenant.

Installation presence is not proof that the current user is an organization
administrator. The existing org provisioning flow uses installer evidence that
may be absent without webhooks. Add a verified onboarding path: check the
signed-in user's current forge authority for the installed account before
allowing org creation/admin assignment, or require explicit instance-admin
binding. Do not fabricate an installation sender, grant admin to the first
person to log in, or treat a supplied account name as authorization.

Reuse existing permission synchronization/revalidation. An inventory observation
does not grant a user repository access. Installation suspension or confirmed
access removal stops new forge work and invalidates affected cached credentials;
keep historical analysis under Hibou's existing authorization/retention policy.

### 4. Durable, bounded reconciliation

Reuse PostgreSQL-backed lease/claim patterns from ADR-015. Persist scheduling
and progress per provider/installation/repository and resource kind: next due
time, last attempt/success, cursor or watermark, conditional-request validator,
retry state and last error. Multiple replicas must not independently poll the
same scope. Resume after crashes; do not rely on an in-memory ticker alone.

The implemented scale-aware defaults are a 5-minute active PR/pending-build
cadence and a 30-minute inventory/ref/release/inactive-discovery cadence,
with jitter and bounded execution. The original 60-second/5-minute targets
remain available through explicit configuration but are not the defaults.
Operators may tune these per forge. They are scheduling targets, not a freshness
SLA: pagination, API budgets, retries and outages add delay.

- Page through every required result set. Use conditional requests where the
  endpoint supports them, without assuming unchanged first-page data proves
  that every page is unchanged.
- For update-time cursors, overlap windows and deduplicate by immutable identity
  and revision; advance a checkpoint only after its observations are committed.
  Periodic complete reconciliation catches removals and missed updates.
- Stage complete list results before applying absence-based removals. A failed
  page, truncated response, timeout, rate limit or permission error is not an
  empty authoritative inventory. Apply the inventory diff atomically; do not
  reuse a mark-all-removed/reinsert sequence without transactional protection.
- A `404` may mean lost visibility, not deletion. Verify scope/access and
  distinguish inaccessible/unknown from confirmed removal. Fail closed for new
  operations whose authorization cannot be established, without destroying
  historical state.
- Honor GitHub rate-limit/reset and `Retry-After` headers, including secondary
  limits; back off with jitter. Share budgets across reconciliation and other
  forge operations, prioritize active PRs, and surface deferred/stale scopes.
- Coalesce manual "Sync now" requests into the same durable scheduler and
  budget. Preserve authorization on the existing inventory sync surface.

State application and durable work enqueue must be crash-safe and idempotent.
Deduplicate analysis by repository/ref/commit and effective analysis revision;
deduplicate gate publication by its semantic inputs and result. Re-reading
unchanged resources or receiving both a webhook and poll observation must not
create duplicate snapshots, jobs, release records or notifications.

An API observation fetched before a newer webhook must not overwrite it. Use
resource revisions where available and serialize/refetch conflicting mutable
state before applying it; local receipt time alone cannot establish ordering.
Webhook replay IDs remain transport protection, not the domain deduplication
key. Never replay polling observations through the public HTTP webhook endpoint.

### 5. CI uploads remain a first-class input

Existing CLI/action upload contracts continue to work in every mode. Do not
require an extra GitHub-to-Hibou callback or a new CI lifecycle protocol to make
polling usable. Upload-driven analysis, snapshot completion, comparisons,
finding ingestion and gate computation remain available before the next poll.

Uploads authenticate through normal Hibou token scopes and cannot grant
installation access, organization ownership or repository enrollment rights.
CI metadata supplements analysis provenance; it is not authority for current
PR lifecycle or installation permissions.

Build reconciliation must distinguish run attempts and concurrent workflows:
failure of an unrelated or older run must not fail the current snapshot.
Runs without sufficient identity stay pending until the existing timeout policy
applies; expose the reason rather than attributing an arbitrary failed run.
Successful CI execution alone is not proof of uploaded analysis or scan coverage.

If GitHub API access is also prohibited, this ADR does not promise metadata
parity. CLI/CI ingestion is a separate, explicitly degraded deployment profile;
fully disconnected operation and alternative authentication are outside scope.

### 6. Least privilege and visible degradation

Apply ADR-052 per-operation, repository-scoped tokens and tier caps. Polling
needs read capabilities, not broader contents write: metadata/contents for
inventory and refs, pull requests read for PR lifecycle, and Actions read when
workflow-run reconciliation is enabled. Release/tag reads use the relevant
repository read permissions. Existing check/status writes remain optional
reporting capabilities; do not elevate a `read` tier automatically.

Declare any additional read permission in the operation permission map and
surface missing permissions per capability. Missing PR/ref/inventory access
prevents claiming the core polling integration is healthy; optional missing
Actions read leaves failed-build detection dependent on timeouts. Do not report
an unsupported API, denied request or empty fallback as successful sync.

Expose mode and capability status in forge settings/onboarding, including last
successful reconciliation, lag, next retry, rate-limit deferral and actionable
errors. Distinguish "analysis uploaded", "forge metadata fresh", and "check
published". Record jobs using ADR-025 conventions and audit material inventory,
permission and lifecycle changes once, with `webhook` or `poll` provenance.

No public webhook ingress is necessary in `poll` mode. Operators must still
provide outbound access to the configured API/Git endpoints and a private path
from authorized browsers/runners to Hibou. Do not introduce a mandatory
third-party relay or send credentials to an external polling service.

## Alternatives considered

| Option | Reason not selected as the primary design |
|---|---|
| Require public ingress, a tunnel or webhook relay | Violates the deployment constraint and adds an external delivery dependency |
| Only remove webhook-secret validation | Starts the server but silently loses lifecycle and scheduling behavior |
| CI uploads only | Useful for ingestion, but cannot observe installation changes, closed PRs, deleted releases or builds that never upload |
| Poll the GitHub Events API as an event log | Its retained/visible activity is not a complete authoritative resource inventory; it cannot provide correctness or every-push coverage |
| Have CI post synthetic GitHub webhooks | Conflates CI upload authority with forge lifecycle/installation authority and still misses events when CI does not run |
| Automatically switch when webhooks are quiet | Quiet repositories and broken delivery are indistinguishable; hides security and freshness changes |

## Consequences

- Private-network deployments become supported without exposing a webhook
  receiver or weakening production startup security.
- Webhook, polling and upload inputs share domain behavior rather than creating
  separate implementations of ref and finding lifecycle.
- Metadata becomes eventually consistent, API consumption increases, and some
  transient activity cannot be recovered. Freshness and every-push limitations
  are part of the product contract, not hidden implementation details.
- GitHub App onboarding, resource-read adapters, durable reconciliation,
  configuration, settings UI and operational documentation all need changes.
  This is more than adding a cron job around repository sync.
- Existing installations retain webhook behavior until explicitly migrated.

## Rollout and acceptance criteria

1. Extract shared domain operations and add GitHub read capabilities, pagination,
   revision handling and declared permissions without changing webhook behavior.
2. Implement durable scheduling, inventory bootstrap and verified no-webhook
   onboarding. Add mode validation and environment/YAML/Helm wiring together.
3. Implement ref/PR, build and release reconciliation, including safe removals,
   scan enqueue and gate recomputation. Add capability/freshness visibility.
4. Document App webhook deactivation, permissions, private runner connectivity,
   expected latency and switching modes in deployment and user guides.

Before calling the mode supported, verify:

- Production starts with `poll` and no webhook secret, and refuses webhook
  delivery for that provider; default/hybrid still reject a missing secret and
  invalid signatures. Unsupported modes and missing required credentials fail
  explicitly, without enabling development mode.
- A private instance bootstraps an already-installed App without a webhook,
  verifies org-admin authority, discovers selected repos and preserves explicit
  enrollment. Renames, suspension, removal and permission loss are handled.
- PR open, head/base update, close, merge and reopen converge through polling;
  CI head/merge uploads produce one canonical PR ref and preserve provenance.
  Gates follow the correct current commit, not a stale webhook/poll result.
- Branch/tag movement, force-push, release edits/removal and pinned rollout
  history obey existing lifecycle rules. A clean poll never resolves findings.
- Failed/cancelled/timed-out builds affect only matching pending snapshots and
  attempts; missing Actions permission is visibly degraded, not false success.
- Multi-page/partial failures, conditional responses, API outages and rate limits
  neither remove unobserved resources nor advance incomplete checkpoints.
- Two replicas, lease expiry, restart, duplicate input and hybrid races converge
  without duplicate durable jobs or lost work. A delayed poll cannot overwrite
  a newer authoritative state.
- With a fake clock and adequate API budget, a change is applied by the first
  completed eligible reconciliation; retries and backoff update visible lag and
  error state. Unchanged cycles do not enqueue repeated scans or notifications.
- Existing CI-only upload paths and webhook integration tests still pass. An
  end-to-end poll-mode test blocks GitHub-originated ingress while allowing
  outbound API/Git and runner uploads, and exercises analysis through gate output.
