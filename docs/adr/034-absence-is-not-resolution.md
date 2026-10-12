# ADR-034: Absence is not resolution — scan coverage and finding persistence

## Status

Accepted (2026-10-10). Rollout steps 1–4 are implemented; see
[the implementation plan](034-036-implementation-plan.md) for what landed and
the remaining gaps (Forgejo compare, MCP write tool).

## Context

### How hibou resolves findings today

Findings are rows attached to a **snapshot** (one scan of one commit). A
finding counts as *resolved* when it is in the older snapshot and missing from
the newer one: the PR delta, the "this PR fixes X" claims, open counts, KEV
counts and gates all rest on that set difference
([ADR-012](012-unified-vulnerability-model.md) §9).

Manual and agent-filed findings ([ADR-020](020-fine-grained-api-tokens.md),
"Finding provenance") are attached to the latest snapshot of a branch when
they are filed. Nothing copies them to the next snapshot, so the next scan of
the branch makes them disappear, which reads as resolved.

### Why a finding disappears without being fixed

| Cause | Example |
|---|---|
| The tool did not run | the CI job skipped the upload, or a tool was removed from the pipeline |
| Partial scan | diff-aware runs (`--baseline-commit`), changed-files-only PR jobs, monorepo path filters |
| Analysis budget | Opengrep/Semgrep give up on a file after 5 s per rule (`--timeout`), or skip large files (`--max-target-bytes`); deeper analyzers also cap their work per file or per path, so what they cover can vary from run to run |
| File not analysed | parse error, unsupported syntax, excluded path |
| Tool or rule change | rule disabled, ruleset changed, scanner upgraded (rules renamed, fingerprint algorithm changed, e.g. Sobelow 0.14) |
| Identity drift | line-based fingerprints change when code above moves; the delta's pairing key included the line, so it did not catch this (see §7) |
| Suppression dropped | most scanners delete suppressed results instead of marking them ([SAST-SCANNERS.md](../SAST-SCANNERS.md)) |
| Non-deterministic producer | AI review agents: two runs over the same code return different findings |
| Nobody re-runs it | manual and agent-filed findings have no producer that would report them again |

Scanners report part of this in SARIF (`tool.driver.version`,
`invocations[].executionSuccessful`, `toolExecutionNotifications` for skipped
files and timeouts), but hibou ignores it today.

### Consequences

- PR checks claim fixes that never happened, and gates pass because a scan was
  incomplete.
- Open counts and dashboards drop after a broken CI run.
- When the finding comes back, the PR check reports it as *new*, and nothing
  shows the gap. Triage decisions survive because they are keyed by
  fingerprint.
- Findings filed by a person or an AI agent vanish at the next commit.

## Decision

**A finding is resolved only on evidence: the producer that reported it ran
again, covered it, and the code changed. Otherwise it stays open and says it
was not re-checked.**

### 1. Two kinds of findings

- **Produced findings** come from a *producer run* that can be repeated: a
  SARIF upload, SBOM advisory matching, secret scanning, an AI scanner run
  over a declared scope.
- **Assertions** are one-off statements by a person or an agent through the
  findings API. Nothing re-runs them, so only an explicit decision ends them.

### 2. Producer runs are recorded

Every upload records, per producer: name, version, configuration digest
(ruleset), scope (`full` or `partial` with the paths covered), outcome
(`completed`, `partial`, `failed`) and the files it did not analyse with the
reason (timeout, too large, parse error). Values come from SARIF when present,
from upload parameters otherwise.

This is the **coverage** of a snapshot: for any file and producer, hibou can
say whether that producer actually looked at it.

### 3. Presence states

Each produced finding is tracked across the snapshots of a branch by
`(producer, fingerprint)`. When a new snapshot is processed and the finding is
not in it:

| State | When | Counts as open | Shown as |
|---|---|---|---|
| **Not re-checked** | the producer did not run, ran partially without this file, skipped the file, or failed | yes | "Not re-checked since `a1b2c3d`" |
| **Unconfirmed** | the producer covered the file, but the file did not change since the finding was last seen | yes | "Disappeared without a code change" |
| **Resolved — fixed** | the producer covered the file and the file changed | no | "Resolved in `e4f5a6b`" |
| **Resolved — file removed** | the file was deleted or renamed away | no | "Resolved — file removed" |
| **Resolved — no longer reported** | unconfirmed for N consecutive covered scans (default 3), or the producer's version or ruleset changed | no | "No longer reported by gosec 2.29" |

"File changed" comes from the forge's commit comparison between the commit
where the finding was last seen and the new snapshot's commit. Two snapshots of
the same commit (two CI workflows) count as unchanged. When the forge has no
compare support at all, the change check is skipped and coverage alone decides.
When a comparison is not obtained (compare budget spent, forge error or rate
limit, file beyond a truncated list), the finding stays **unconfirmed** and is
checked again on the next snapshot: an unanswered question is never a fix.

The check is cheap on the forge: it is asked only for findings their producer
covered and no longer reports; one comparison answers every file between two
commits; both SHAs are immutable, so each pair is fetched once and cached;
at most three base commits are compared per snapshot; concurrent requests for
one pair are merged; and a failed pair is not retried for ten minutes. Branch
comparisons are cached as paths and status only, without hunks, and fetched
before the reconcile transaction takes its lock.

For a taint finding (SARIF `codeFlows`), [ADR-036](036-automatic-scan-planning-and-verification.md)
§6 applies: only a full-scope run re-checks it, and *Resolved — fixed* needs a
change in any file of its stored trace, not only the sink file; otherwise it
stays unconfirmed.

A finding that comes back keeps its identity, history and triage, and the
timeline shows the gap.

### 4. Assertions persist until decided

Manual and agent-filed findings are carried to every new snapshot of their
branch. They end only by:

- an explicit **resolve** (the problem is gone; `triage:write`, like an
  acceptance) or **retract** (the assertion was wrong; the person or token
  that filed it, the token's owner, or an org admin), recorded with the reason
  and the principal;
- **file removed**, which does not resolve them but marks them "Location
  gone — needs review".

An agent that re-examines code can **re-assert** a finding (confirm it is
still there), which updates "last confirmed" without creating a duplicate.
Re-asserting, or filing the same finding again, reopens a resolved or retracted
assertion.

### 5. Resolution policy per producer

| Policy | Meaning | Default for |
|---|---|---|
| `coverage` | rules of §3 | SARIF tools, SBOM matching, secret scanning |
| `consecutive-absence:N` | resolved after N covered scans without it, code change not required | opt-in for noisy tools |
| `explicit` | only an explicit decision resolves | assertions; AI scanner runs |
| `retired` | the producer was removed on purpose; while it does not run, its findings resolve as *producer retired* | set by an org admin |

AI scanners default to `explicit` because sampling makes one missing result
weak evidence; an org can switch a given agent to `consecutive-absence:N`.
The policy is shown in the tool catalog.

### 6. PR deltas and gates

- "Fixed by this PR" lists only *Resolved — fixed* and *file removed*.
- Not re-checked and unconfirmed findings stay on the base side of the gate:
  they keep counting.
- A PR whose scan was partial says so, grouped by producer and reason:
  "`gosec` — scanned only part of the code, not these files (12)". Hibou does
  not know a producer's total file count, so it does not print "12 of 340".
- Only *fixed* and *file removed* resolutions are claimed as fixes ("fix in
  #N"); *no longer reported* and *producer changed* are listed, not claimed.

### 7. Finding identity survives line moves

Most scanners emit no fingerprint, and hibou's fallback identity hashed the
start line. Moving code above a finding then read as a new finding plus a fix,
and dropped its triage. Three measures:

- `hibou upload` adds a content fingerprint (`partialFingerprints["hibou/contextHash/v1"]`:
  tool, rule, path and the whitespace-normalized flagged line with two lines of
  context, numbered for identical contexts) when the SARIF carries none. It is
  computed from the CI checkout; the server never needs the source.
- The delta pairs a new and a resolved finding with the same tool, rule, file
  and message, without the line, when the match is one-to-one in both
  snapshots.
- When a finding is re-keyed between two snapshots of a ref, its acceptance and
  dispute are copied to the new fingerprint (audit action `finding.rekeyed`).

## UX

**Finding list.** Open findings that were not re-checked or are unconfirmed
carry a small badge next to the status (clock icon, grey for not re-checked,
amber for unconfirmed) with a tooltip naming the commit where the finding was
last seen and the reason. A filter qualifier `presence:` (`reported`,
`not-rechecked`, `unconfirmed`) sits with the other filters and works in saved
presets.

**Finding detail.** The timeline shows *not re-checked* (with the reason, e.g.
"the scanner skipped the file (timeout)"), *re-checked* when the finding is
reported again after a gap, and *resolved* / *no longer reported* with the
evidence. Assertions show "Filed by … · last confirmed …" and the actions
**Still there** (re-assert), **Resolve…** (with reason), **Retract…** and, once
closed, **Re-assert**. The presence badge is not shown on open assertions: they
are always carried, which the "Filed by hand" section already says.

**Repository overview.** There is no snapshot page; the overview's **Scan
coverage** panel follows the selected snapshot. It lists each producer: ran /
new / missing compared with the previous snapshot, version (with the change),
full, partial or "full (assumed)", and the files not analysed, expandable to
the list with reasons. A missing producer is highlighted.

**PR check summary.** Counts *New*, *Fixed*, *Not re-checked*, *Unchanged*;
the not re-checked findings are grouped by producer and reason in a collapsed
section that says they still count. The compare view has the same three groups.

**Tool catalog.** Org Settings → Tools lists each producer with its health
(latest run completed, partial or failed, with a warning for the last two) and
its resolution policy, editable by org admins.

## Database

Existing snapshot-scoped `vulnerabilities` rows stay the unit every reader
counts. A finding that was not re-checked is **copied into the new snapshot**
("carried forward") with its presence, so counts, gates, trends and org views
keep working unchanged; only the delta, the timeline and the UI read the
presence. This replaces the branch-level `finding_presence` table first
proposed here, which would have required rewriting every reader.

`producer_runs` — one row per producer run per snapshot.

| Column | Notes |
|---|---|
| `id`, `snapshot_id` | |
| `artifact_id`, `run_index` | the SARIF artifact and run position; NULL artifact for server-side producers |
| `producer` | `lower(tool.driver.name)`, `secret-scanning`; SBOM matching is read from the existing `scans` rows as `sbom-matching` |
| `version`, `config_digest` | from SARIF or upload parameters; nullable |
| `scope`, `scope_declared` | `full` or `partial`; `scope_declared = false` when nobody said (an assumed full run) |
| `scope_paths` | text[]; set for `partial` |
| `outcome` | `completed`, `partial`, `failed` |
| `skipped_files` | jsonb `[{path, reason}]`, reason `timeout`, `too_large`, `parse_error`, `resource_limit`, `other` |
| `finding_count`, `detail`, `created_at` | `detail`: diagnostics that name no file, or the failure |

Columns added to `vulnerabilities` for carried rows:

| Column | Notes |
|---|---|
| `presence` | `reported`, `not_rechecked`, `unconfirmed` |
| `presence_reason` | why it was carried: `producer_missing`, `producer_failed`, `producer_pending`, `outside_scope`, `partial_scope`, `partial_run`, `file_skipped:<reason>`, `unchanged`, `unchanged_trace`, `absent`, `explicit_policy`, `assertion`, `location_gone` |
| `last_seen_snapshot_id`, `last_seen_commit` | where the producer last reported it |
| `consecutive_absences` | covered scans in a row without it |

`finding_resolutions (repo_id, ref_id, snapshot_id, type, fingerprint,
producer, reason, commit_sha)` — the evidence of a resolution, since a resolved
finding has no row in the snapshot that resolved it.

`finding_assertions (repo_id, fingerprint)` — the assertion lifecycle, keyed
by fingerprint like `finding_acceptances`: `last_confirmed_at/by/api_key_id`
and one decision group `closed_kind` (`resolved` | `retracted`),
`closed_at/by/api_key_id`, `closed_reason`. Columns on the per-snapshot rows
would be copied every commit.

`producer_policies (org_id, producer, policy, threshold)`, with the defaults
of §5 when no row exists.

## API

- **`.hibou.yaml`** declares how CI runs each tool, keyed by SARIF tool name:
  `scanners: {<tool>: {scope: full | partial | changed-files, paths: [...]}}`.
  `changed-files` means a PR build scans only the PR's files; hibou derives
  them from the PR comparison it already fetches for the diff and patch
  coverage, so CI lists nothing. Branch builds of such a tool are full. The
  section describes coverage only; enabling and requiring scanners stays
  hibou state (ADR-035 D10/D11).
- **Uploads** accept optional `scope` (`full` / `partial`) and `paths`, which
  override `.hibou.yaml` for one upload (CLI `--scope`, `--path`), plus
  `tool_version` and `config_digest`, which `hibou scan` sends; SARIF values
  win for the version.
- **Findings** gain `presence`, `presence_reason`, `last_seen_commit`,
  `consecutive_absences`; the finding detail gains `assertion`.
- `POST /orgs/{provider}/{slug}/repos/{repo}/findings/{fingerprint}/reassert`
  and `…/retract` (`vulnerabilities:write`), `…/resolve` (`triage:write`).
  Finding routes are keyed by fingerprint, like `…/history`.
- `GET …/snapshots/{id}/producer-runs` returns the producer runs compared with
  the previous snapshot of the ref. "Coverage" already names test coverage in
  the API and UI, hence the name; the UI calls it *Scan coverage*.
- `GET/PUT/DELETE /orgs/{provider}/{slug}/producer-policies` (writes are
  admin-only).
- The delta response gains `not_rechecked_vulnerabilities` beside `new` and
  `resolved`; resolved entries carry `resolution_reason`.

## Rollout

1. Record producer runs and show the Coverage panel. No behaviour change.
2. *Not re-checked*: a missing or partial producer no longer resolves findings.
3. *Unconfirmed* and the code-change rule, with `consecutive-absence` as the
   escape for unstable tools.
4. Carry assertions forward; reassert and retract endpoints.

Each step is useful alone and can ship separately.

## Alternatives considered

- **Keep "absent = resolved".** Simple, but every cause in the table above
  becomes a false fix.
- **Grace period in time** ("resolved after 7 days absent"). Ignores whether
  anything was scanned; a branch with no commits for a week would resolve
  everything that flickered once.
- **Always require a human to confirm resolutions.** Correct but does not
  scale; the coverage rule removes the need in the common case.
- **Hash file contents ourselves.** Hibou does not hold the source; the forge
  comparison gives the same answer without cloning.

## Decided questions

- Default N for `consecutive-absence`, and for unconfirmed findings becoming
  *no longer reported*: 3.
- *Unconfirmed* counts toward gates: it is an open finding.
- Scope is declared once per repository in `.hibou.yaml` (`scanners:`), not
  per workflow step: one step often uploads several tools' reports, and how
  a tool is run is a stable fact of the CI. Precedence: a scan plan binding,
  then the upload's `--scope`/`--path`, then `.hibou.yaml`. A tool nobody
  declared is recorded as an assumed full run (`scope_declared = false`),
  which ADR-035/036 strict coverage policies do not accept as evidence. When
  `.hibou.yaml` cannot be read (forge error), undeclared runs are recorded
  as partial: coverage unknown is never full. The file is read from the
  default branch, so a PR cannot widen what its own scan claims to cover.

- A producer removed from CI on purpose is **retired** by an org admin
  (policy `retired`): while it does not run, its findings resolve as
  *producer retired*, a decision recorded as such and never counted as a fix.
