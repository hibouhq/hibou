# ADR-018: Forge-native, non-blocking quality gate checks

## Status
Accepted

## Context

Classic Sonar-style quality gates break the CI build by having a scanner/CLI exit
non-zero. That is painful — and worse on a false positive, where a red build blocks
a merge until CI is re-run, even after the finding has been triaged away.

Hibou already evaluates the quality gate **server-side** (`internal/delta/gate.go`,
`GateResult{Passed, Reasons}`) and, on scan completion for a PR snapshot, posts a
commit status (`hibou/security`) to the forge via `forge.Annotator`
(`internal/forge/annotator.go`). The CLI (`hibou upload`) is already fire-and-forget
— it never exits non-zero on a gate result. Commit statuses are implemented for all
three forges (GitHub `github.go`, GitLab `gitlab.go`, Forgejo/Gitea `forgejo.go`).

What was missing:

1. The gate outcome was **never persisted**, so the forge post could not be updated
   idempotently or retried, and the UI/CLI had nothing durable to read.
2. The check only refreshed on **scan completion** — a false-positive dismissal
   (VEX), a manual override, or an advisory re-evaluation did not re-post it, so a
   red check stayed red until CI ran again.
3. GitHub's richer **Check Run** (markdown summary, annotations, re-run) was unused,
   even though the GitHub client already supports App mode (which can mint
   `checks:write` installation tokens).
4. There was no explicit **advisory vs. blocking** policy — and no first-class,
   opt-in way for a team that *wants* a hard CI failure to get one.

### Forge capability reality (verified)

All three forges surface a PR "Checks" panel that branch protection can mark
**Required** — but it is rendered from the **Commit Status API**, not a separate
check-runs API:

| Forge | Commit Status API | Requirable PR check | Rich check-run (md summary + annotations + re-run) |
|-------|-------------------|---------------------|-----------------------------------------------------|
| GitHub | ✅ | ✅ | ✅ Checks API (needs App `checks:write`) |
| GitLab | ✅ | ✅ | ⚠️ only via Ultimate "External Status Checks" |
| Forgejo/Gitea | ✅ | ✅ | ❌ (commit status only) |

So the **commit status is the portable, requirable check on every forge**; the
GitHub Check Run is a presentation upgrade, not a requirement.

## Decision

### 1. Hibou never breaks the build; enforcement is the forge's + admin's choice
The CLI never influences the CI exit code by default. The forge check is the signal;
whether it blocks a merge is decided by the repo admin via branch protection /
required checks — not by Hibou.

### 2. Advisory by default, blocking opt-in — per branch pattern
A new `.hibou.yaml` gate field `enforcement: advisory|blocking` (default `advisory`,
`internal/repoconfig`). Mapping (`forge.gateForgeStatus`):

- **advisory** — informational, must never block. GitHub Check Run → `neutral`
  conclusion; commit-status-only forges → post `success` with the verdict in the
  description (no `neutral` state exists there).
- **blocking** — post a real `failure` so a *required* check blocks the merge.

The bus event (`gate.passed` / `gate.failed`) always reflects the **real** pass/fail
(so notifications fire regardless of advisory display).

### 3. Persist the outcome (`pr_checks`) for idempotent, live updates
Migration `00022_pr_checks`, keyed `(repo_id, head_sha, context)`: `state`,
`conclusion`, `enforcement`, `passed`, `reasons`, `external_id` (GitHub check-run
id), `target_url`, `forge_synced_at`, `last_error`. Idempotent upsert → re-posts
update in place; unsynced rows drive a retry loop (`Annotator.ReconcileUnsynced`).

### 4. Re-publish on any gate-affecting change (live update, no CI re-run)
`Annotator.PublishGateForRef(refID)` re-evaluates + re-posts a PR's head. It is
driven by:
- `events.ScanCompleted` (existing), and
- a new `events.GateRecomputeRequested` (payload `ref_id` | `repo_id` | `org_id`),
  published by **VEX create/update/delete** (`suppressions.go`) — the false-positive
  path. A dismissed finding flips the check live.

Cross-replica note (ADR-015): the event bus is process-local, but every replica
runs a `GatePublisher` subscribed to its own bus and any replica can post to the
forge, so a recompute request is handled exactly once — on the replica that
published it. It is deliberately **not** fanned out to all replicas (that would
post N× to the forge). The one thing that must reach other replicas is the
resulting **UI refresh**: a `gate.updated` WebSocket broadcast, which the WS fanout
bridges cross-replica over Postgres LISTEN/NOTIFY, so a browser connected to any
replica updates live. The PR webhook (`synchronize`/`reopened`) also publishes a
recompute so a new head refreshes the check.

### 5. GitHub Check Run when in App mode
`forge.CheckRunProvider` (`SupportsCheckRuns`, `CreateOrUpdateCheckRun`). The GitHub
implementation (`github_checks.go`) mints an installation token, finds an existing
run by `(head_sha, name)` and PATCHes it, else POSTs — idempotent, with a markdown
summary built from the gate reasons and **inline code annotations** (`output.annotations`)
for new findings that carry a file/line, capped at the API's 50-per-request limit.
OAuth-only GitHub and the other forges fall back to the commit status automatically;
GitLab and Forgejo/Gitea have no server-push inline-annotation API, so they get the
status/summary without annotations. The `forge.Annotator` type is named
`GatePublisher` (it publishes the check; the inline annotations are one part of it).

### 6. Deep link to triage
The commit status `target_url` / check-run `details_url` point at the SPA PR gate
page (`/orgs/:provider/:slug/repos/:repoSlug/pulls/:pr`), where a user can see the
reasons and dismiss / add a VEX statement — which triggers §4 and flips the check.

### 7. Read endpoint
`GET /{provider}/{slug}/repos/{repoSlug}/pulls/{pr}/gate` (`handleGetPRGate`) returns
the persisted `pr_checks` row, falling back to an on-demand computation when nothing
has been posted yet. Read-only; never affects a build.

### 8. CLI build-break is an opt-in escape hatch (default OFF)
`hibou gate` (opt-in `--fail-on-gate`, default false) polls the read endpoint and
exits non-zero only when explicitly asked to. It exists for environments without the
server↔forge loop (no App/OAuth configured, air-gapped CI), **not** because any forge
lacks a requirable check. Default and unset → always exit 0.

## Consequences

- Dismissing a false positive (VEX) flips the PR check green in seconds, no CI
  re-run. This is the core ergonomic win over Sonar-style hard fails.
- The commit status remains the portable mechanism; GitHub gets a richer check when
  App mode is configured; nothing regresses for GitLab/Forgejo.
- Gate results are now durable (`pr_checks`), enabling idempotent updates, a retry
  loop, and a UI/CLI read model.
- Manual gate **override** (admin/`release_manager`) is implemented:
  `POST .../pulls/{pr}/gate/override` persists to `pr_checks` override columns, and
  `GatePublisher.applyGateOverride` forces the published outcome so the check flips
  live (audit-logged `gate.override`).
- The concurrent DB refactor squashed all migrations into `00001_initial_schema`;
  `pr_checks` and its override columns live there — there is no separate migration
  file for this feature.
- Live UI: a `gate.updated` WebSocket broadcast pushes gate changes to the PR page
  (cross-replica via the WS fanout's Postgres LISTEN/NOTIFY bridge); the UI poll is
  now a fallback. The PR webhook triggers recompute on a new head.
- **Still deferred:** a check-run `requested_action` re-run button; server-handler
  tests that need a test Postgres.
