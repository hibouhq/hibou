# ADR-024: Release tracking — derived releases, client rollout, advisory freshness

## Status

Accepted — implemented (2026-08-18), except the Deployments phase (§8), which
is design-only.

Implementation notes:

- Migration `00023_release_tracking`: `html_url`, `source` (`tag|forge`),
  `pending_snapshot_id`, `diverged_at`, `dismissed_commit_sha` on `releases`;
  `idx_deployments_release_id`.
- Derivation: `reconcileReleasesForSnapshot` runs on every snapshot
  completion (`internal/server/snapshot_processing.go`) — snapshot adoption,
  tag-pattern derivation, and the re-tag divergence rules live there. The
  pattern resolves per repo (`releaseTagPatternForRepo`) from
  `releases.tag_pattern` in `.hibou.yaml` (`internal/repoconfig`, JSON schema
  included), default in `defaultReleaseTagPattern`. Forge ingestion parses
  `release` events for GitHub/Gitea/Forgejo/GitLab into a normalized
  `forge.ReleaseEvent`.
- The old `POST .../releases` create endpoint and the planned
  `hibou release create` are gone, and there is no DELETE endpoint —
  removal is webhook-derived (§5b, `removeDerivedRelease`). The remaining
  lifecycle endpoints (divergence, clients) gate on admin|release_manager
  via `requireReleaseManager`. Migration `00023` also moves the
  `deployments.release_id` FK from CASCADE to RESTRICT.
- Freshness rides the existing advisory scan pass: release-pinned snapshots
  are appended (deduped) to `listLatestSnapshotsForAdvisoryScan`, so the
  leader lock, overlap guard, shared advisory cache, and provider batching
  all apply unchanged. Per-release "Re-scan" reuses
  `POST .../components/scan?snapshot=`.
- UI: `repo/ReleasesTab.vue` behind a fenced pill tab in `RepoDetailView`;
  `org/ClientsTab.vue` replaces the legacy standalone `ClientsView` (same
  URL, now an org tab; `ClientDetailView` unchanged).

## Context

SPEC.md already promises release tracking as a first-class concern: `releases`
layer lifecycle metadata on top of tagged refs, `deployments` connect a client
to a release, and impact analysis must answer "which releases are affected by
CVE-X" and "which client environments are currently exposed".

Most of the backend exists:

- Tables `releases` (`UNIQUE (repo_id, version)`, `snapshot_id` nullable),
  `clients`, `deployments` with store wrappers and sqlc queries.
- `POST/GET /orgs/{provider}/{slug}/repos/{repoSlug}/releases`,
  client CRUD, `POST .../clients/{clientSlug}/deployments`, and a
  client-impact query joining active deployments → releases → snapshot
  vulnerabilities.
- A `release_manager` org role wired into Casbin
  (`internal/rbac/policies.go`).

What is missing:

1. **No UI.** There is no Releases surface at all; the standalone Clients page
   predates the current design language (legacy `rounded-3xl` style) and is
   parked outside the org tab structure.
2. **Released snapshots go dark.** A release points at the snapshot that was
   scanned when it shipped. The org-wide rescan only touches each repo's
   *latest* snapshot, so a CVE published after the release never lights up the
   shipped version. Worse, the retention worker may prune the release's
   snapshot entirely — it honors the `pinned` flag, but nothing sets it.
3. **No forge ingestion.** Teams that publish GitHub Releases (or
   Gitea/Forgejo releases) have to call the API a second time from their
   pipeline; the platform should ingest the forge event directly.
4. **No release-side client assignment.** Deployments can only be recorded
   from the client side (`POST /clients/{slug}/deployments`); a release
   manager looking at a release cannot say "client X got this" without leaving
   the page.
5. **Manual creation is error-prone.** The existing `POST .../releases`
   endpoint invites hand-made releases whose version, ref, and snapshot can
   all disagree with what was actually shipped.

## Decision

### 1. Releases is a repo-scoped tab, visually fenced from the ref-scoped tabs

Releases live on the repository (a release *of* a repo). No org-level releases
view: aggregating versions across heterogeneous repos answers no real
question; cross-repo exposure is already the Clients / client-impact lens.

Every existing repo tab (Overview, Vulnerabilities, Coverage, Tests,
Dependencies) is scoped to the ref/snapshot selector. Releases is not — it
spans tags and pinned snapshots. Rendering it as "just another underline tab"
would leave a dead ref selector and snapshot strip on screen. Instead:

- The tab sits immediately after **Dependencies**, separated by a vertical
  divider on each side, and renders as a **filled pill** rather than the
  underline treatment — same row, different species.
- When the Releases tab is active, the ref/PR selector and the snapshot chip
  strip are **not rendered**; the tab brings its own filter bar (version
  search, client filter, vulnerable-only toggle).
- Route: `orgs/:provider/:slug/repos/:repoSlug/releases` (`repo-releases`),
  no `ref`/`snapshot` query coupling.

### 2. Data model

Migration `00023_release_tracking`:

```sql
ALTER TABLE releases
    ADD COLUMN html_url text,                        -- forge release page
    ADD COLUMN source   text NOT NULL DEFAULT 'tag', -- tag | forge
    ADD COLUMN pending_snapshot_id uuid REFERENCES snapshots(id) ON DELETE SET NULL,
    ADD COLUMN diverged_at timestamptz,
    ADD COLUMN dismissed_commit_sha text;
```

- `html_url` links the row back to the GitHub/Gitea/Forgejo release page when
  the release came from (or was matched to) a forge release.
- `source` records what derived the row (version tag vs forge webhook) for
  display and debugging; it is not an authorization axis.
- `pending_snapshot_id` / `diverged_at` / `dismissed_commit_sha` carry the
  re-tag divergence state (§5a).

**Snapshot pinning.** Deriving a release with a snapshot sets
`snapshots.pinned = true` so the retention worker never prunes shipped state.
Removing a release (§5b) or repointing it (§5a) unpins a snapshot only when
no other release references it.

### 3. Enriched release listing and risk semantics

`GET .../releases` returns, per release: open-risk severity counts computed
from the pinned snapshot's vulnerabilities, the clients currently on the
release (via `active` deployments), and the last scan time of the snapshot.

Risk counts follow the platform-wide open-risk semantics (ADR-023): status
`detected` only (not `resolved`/`suppressed`), `false_positive` acceptances
excluded via the `(repo_id, fingerprint)` acceptance index, accepted risk
still counts. A release whose `snapshot_id` is null renders as "not analyzed",
never as "clean".

Filters: `q` (version substring), `client` (client slug — releases that client
has an active deployment of), `vulnerable=true` (at least one open finding).

### 4. Client assignment from the release side

`POST .../releases/{releaseID}/clients` — body `{client_slug, environment?,
notes?}` — creates a `deployments` row (`status = active`, `deployed_at =
now()`, `deployed_by` = actor display). Assigning a client to a release when
that client already has an *active* deployment of another release of the same
repo in the same environment marks the previous deployment `superseded`
(rollouts move forward; explicit rollbacks stay on the client page).

`DELETE .../releases/{releaseID}/clients/{deploymentID}` marks the deployment
`rolled_back`.

Authorization: `admin` and `release_manager` org roles (server-side; the UI
hides the affordances on top of that, never instead of it). Both actions are
audited (`release.client_added`, `release.client_removed`).

The client-side endpoint (`POST /clients/{slug}/deployments`) stays — it is
the automation surface for pipelines that think in client terms.

### 5. Releases are derived, never hand-created

Manual creation is error-prone: a hand-typed version can disagree with the
tag, the ref, and the analyzed snapshot all at once. There is **no create
endpoint, no create form, no `release create` CLI**. A release row
materializes from exactly two signals, converging on the `(repo_id, version)`
identity:

1. **Version tags.** When a snapshot completes on a tag ref whose name
   matches the release tag pattern, a release is derived with
   `source = 'tag'`, the snapshot attached and pinned. The pipeline does
   nothing new: tagging and uploading the tag's analysis *is* the release —
   no webhook, no release event, no API call required. The pattern defaults
   to `^v?\d+\.\d+(\.\d+)?([-+]…)?$` (v1.2.3, 1.2, v2.0.0-rc.1) and is
   **configurable as code** by the repo's developers via `.hibou.yaml`:

   ```yaml
   releases:
     tag_pattern: "^payments-v\\d+\\.\\d+\\.\\d+$"
   ```

   An invalid pattern fails config validation (the file is then ignored,
   like any other invalid `.hibou.yaml`), and the platform default applies.

   **Outage semantics**: "file absent" and "file unreadable" are different
   facts. Absent (or invalid) means the default is the repo's configuration.
   A transport error — forge partially down — means the repo's intent is
   unknown, and derivation must not guess: guessing with the default could
   silently derive a release a custom pattern excludes, or miss one it
   requires. Derivation is deferred instead, and the periodic reconcile
   sweep (which re-runs derivation idempotently as part of the advisory scan
   pass) heals it once the forge answers again.
2. **Forge releases.** GitHub `release` webhooks (and Gitea/Forgejo
   `release`, GitLab `Release Hook`): resolve the tag to a `refs` row
   (creating the tag ref if the push webhook hasn't landed yet), attach the
   latest complete snapshot of that ref when one exists, upsert with
   `html_url`, `published_at`, `source = 'forge'`. Draft releases are
   skipped; `deleted`/`unpublished` events are ignored — shipped state stays
   on record, removing a release row is a human decision made in Hibou.

**Webhook-before-upload race.** A forge release usually fires before the
pipeline's analysis upload finishes. When a snapshot later completes on that
tag ref, any snapshot-less release of the ref adopts it (and it gets pinned).

The only remaining write surfaces are lifecycle operations for release
managers: assign/remove clients (§4) and resolve divergence (§5a). `hibou
release list` and `hibou release deploy` cover the read and rollout sides
from CI.

### 5a. Re-tag divergence — the deleted-and-recreated tag

The hard edge case: a released tag is deleted and recreated on another
commit. Two legitimate stories share that signal:

- *The release was a mistake* — re-tag is a correction and the release should
  follow the new commit.
- *Clients already run the old build* — silently repointing would make the
  platform lie about what is deployed: exposure reports would describe a
  build nobody runs.

The tiebreaker is whether anyone runs it:

- **No active deployments** → the re-tag is treated as a correction: the
  release repoints to the new snapshot automatically (old snapshot unpinned
  when unreferenced, new one pinned), logged as a repoint.
- **Active deployments exist** → the release keeps the shipped snapshot and
  records the candidate in `pending_snapshot_id` + `diverged_at`. The UI
  shows a "Tag moved" warning on the row and, in the detail panel, the
  shipped commit vs the tag's new commit with two actions (release managers):
  - **Adopt new build** — `POST .../releases/{id}/divergence {action:
    "adopt"}`: repoint to the pending snapshot, recompute posture from it,
    pin/unpin accordingly. Deployment records stay (they record that the
    client was given this release), audited as `release.retag_adopted`.
  - **Keep shipped build** — `{action: "keep"}`: divergence cleared,
    `dismissed_commit_sha` remembers the ignored commit so the same re-tag
    does not re-flag on the next scan; audited as `release.retag_dismissed`.
    A *further* re-tag onto yet another commit flags again.

A re-published forge release for an existing version never overwrites the
shipped snapshot either — only the derivation pass (which owns the divergence
rules) repoints.

### 5b. Removal is derived too — and audited

There is no manual delete either: a hand-deleted release is the same
error surface as a hand-created one, and the row would re-derive on the next
upload anyway. A release disappears only when its **source** does:

- **Tag deleted** (push webhook with the all-zero SHA on a tag ref) or
  **forge release deleted/unpublished** → the release is removed **iff no
  deployment ever referenced it** (any status — rolled back counts as
  history). Its snapshot is unpinned when no other release needs it.
- **Rollout history wins.** If any deployment exists, the release stays on
  record whatever happens to the tag; exposure reporting must keep describing
  what clients ran. A later tag re-creation flows into the §5a divergence
  rules.
- **Every derived removal is audited** (`release.removed`, actor type
  `webhook`, context carries repo, version, source, and the trigger:
  `tag_deleted` / `forge_release_deleted`). The keep-because-shipped decision
  is logged.
- The `deployments.release_id` FK moves from `ON DELETE CASCADE` to
  `RESTRICT` — the original cascade meant deleting a release silently erased
  who ran it; now no code path can.

### 6. Advisory freshness — global, cache-shaped, rate-limit-aware

The problem is global, so the solution is global — not per repo:

- **The advisory cache is the dedup point.** Cache keys are
  `(provider, ecosystem, package)` across the whole instance. When the
  refresh pass scans release snapshots in sequence, the first snapshot that
  queries `npm/lodash` warms the cache for every other snapshot — in *any*
  repo — that holds the same package. Shipped software clusters heavily on
  common dependencies, so the marginal provider cost of each additional
  release approaches zero.
- **Periodic refresh worker.** A background loop (configurable interval,
  default daily; jittered start) lists distinct release-pinned snapshots and
  runs the *cache-honoring* scan path (`RunScan`) over each. Provider traffic
  is bounded by cache TTL (a package queried within TTL costs nothing) and by
  the provider's `BatchSize()` chunking. The worker processes snapshots
  sequentially — freshness needs days-level latency, not seconds — so it
  never bursts against provider rate limits.
- **On-demand rescan.** The release detail panel exposes "Re-scan", wired to
  the existing `TriggerRescan` path (cache-*invalidating*) against the
  release's snapshot, for when someone needs a genuinely fresh answer now.
  This is the existing `POST .../components/scan?snapshot=<id>` endpoint.
- The UI always shows *scanned N ago* on each release so staleness is
  visible, whichever path last ran.

Existing event plumbing (notifications on new findings, gate recompute) fires
from the scan itself; a release lighting up notifies exactly like a branch
lighting up.

### 7. Clients become an org tab

The standalone `/clients` page moves into the org tab bar (`org-clients`),
restyled to the current design language. Clients are org-scoped and usable
from any repo's Releases tab — one client list, many repos deploying to it.
The old route redirects.

### 8. Future phase — Deployments (design only, not built now)

A Deployments surface will track *where releases actually run*, reconciling
several sources of truth:

- **Pipeline-reported (push).** The deploy job calls
  `POST /clients/{slug}/deployments` (exists today) or the release-side
  endpoint. Works for SaaS and any CD pipeline we own. `deployed_by` records
  the automation principal.
- **GitOps-derived (pull).** A watcher resolves the desired state from a
  GitOps repo (image tags / chart versions in the environment overlays) and
  matches them to releases via `version` or `image_digests`. A deployment row
  is upserted per (client/environment) with provenance `gitops`; drift =
  desired release ≠ last pipeline-reported release.
- **Cluster-observed (agent).** An in-cluster agent reports running image
  digests; matching against `releases.image_digests` yields *observed*
  deployments — the strongest signal, catching hotfixes and manual rollbacks
  that never went through a pipeline.
- **Client self-reported.** For software operated by the clients themselves:
  a client-scoped token (building on ADR-020 scopes, e.g.
  `deployments:self-report` bound to one client) lets their installer or
  telemetry ping `POST /clients/{slug}/deployments`. Untrusted-by-design:
  self-reported rows are labeled and never *reduce* exposure (a client that
  stops reporting keeps its last known deployment, flagged stale).

Reconciliation model: `deployments` gains a `provenance` axis
(`pipeline | gitops | agent | self_reported`) and the page renders desired vs
observed per client/environment. Vulnerability exposure keeps using *active*
deployments regardless of provenance — over-counting exposure is the safe
failure mode. This phase gets its own ADR when built; nothing in this ADR
blocks it (the `deployments` table already carries environment, status,
rollback target, and actor).

## Consequences

- "Which releases are vulnerable" becomes a first-page answer per repo, and
  stays true over time: pinned snapshots survive retention, and the global
  refresh worker re-lights shipped versions when new advisories land — at a
  provider cost that amortizes across repos through the shared cache.
- Release managers assign clients where they think: on the release. Pipelines
  automate the same thing (`hibou release deploy`, or the deployments API),
  and releases themselves require zero pipeline changes — tag + upload, or a
  GitHub release, is all it takes.
- A recreated tag can never silently change what the platform claims clients
  run; it either corrects an unshipped mistake automatically or demands an
  explicit, audited decision.
- Pinning shipped snapshots grows retention storage by design; the tiered
  retention policy (ADR-014) still governs everything unpinned.
- The refresh worker adds steady background provider traffic, bounded by
  cache TTL; instances with many releases but few distinct packages pay
  almost nothing extra.
- One more tab species (fenced pill) in the repo tab bar — a deliberate
  signal that Releases (and later Deployments) are shipped-artifact surfaces,
  not ref-scoped analysis surfaces.

## Alternatives considered

- **Manual release creation (API/CLI/UI).** Rejected: error-prone (version,
  ref, and snapshot can disagree), and derivation makes it unnecessary — the
  tag or the forge release already carries the identity.
- **Manual release deletion.** Rejected for the same reason as manual
  creation, plus a sharper one: the FK cascade meant it silently destroyed
  rollout history. Removal now derives from source deletion with the
  history guard.
- **Always repoint on re-tag.** Rejected: with clients on the release it
  falsifies exposure reporting. **Never repoint** was also rejected: the
  no-deployments case is overwhelmingly a correction, and demanding a human
  decision there is noise.
- **Org-level Releases view.** Rejected: a release is meaningful only against
  its repo; a cross-repo version list answers no operator question that the
  Clients/impact lens doesn't answer better.
- **Releases as tagged refs only (no separate table).** Rejected in SPEC
  already: refs carry no lifecycle metadata (publication, artifacts,
  provenance, forge URL), and a tag can exist without a shipped release.
- **Re-scan releases on every advisory feed change (event-driven).** Cleaner
  in theory (scan only affected packages), but requires inverting the
  feed→package→snapshot index and a feed-diff pipeline we don't have. The
  periodic cache-shaped sweep gets 95% of the value with none of that
  machinery; the event-driven path remains open later.
- **Separate mode switch (Analyze/Ship) instead of a fenced tab.** Stronger
  separation, but hides Releases behind a click and breaks the requested
  adjacency to Dependencies.
