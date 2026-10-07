# Plan — gate race, commit provenance, KEV visibility, PID-1 reaper

Status: **implemented** (validated 2026-10-07; shipped as alpha.82) except the
items explicitly marked remaining. Adaptations from review are noted inline.
Context: dogfood findings from the KEV rollout (PR hibou-sample-project#11,
2026-10-07).

---

## 1. The quality gate passed on a PR that introduced a known-exploited vuln ✅

### What happened (evidence from dogfood)

Timeline for PR #11 (head `4b1ed2e`):

| time (UTC) | event |
|---|---|
| 12:45:10 | PR snapshot marked `complete` (15 uploads received) |
| 12:45:0x | a gate publish attempt fails: GitHub API error on `list check-runs` (GitHub was returning 502s) |
| 12:47:38–39 | SARIF ingest writes the 10 **sast** findings |
| **12:47:41** | **gate verdict stored: `passed=t`**, `delta_summary={}` — evaluated while the snapshot held only sast findings |
| 12:47:53–12:48:06 | advisory scan writes the 474 **dependency** findings (including jquery/KEV) |
| after | no later verdict is persisted (`pr_checks.updated_at` stays 12:47:41); the sticky comment shows the mid-scan delta: "2 new (high) / 631 resolved / 0 unchanged" |

Two independent defects:

- **D1 — ordering**: `ScanCompleted` fires per completed stage (artifact
  processing, each advisory scan, secret scan). The gate evaluates on the
  *first* one, i.e. before dependency findings exist. A PR that removes
  nothing then shows "631 resolved", and KEV/malware blocks cannot fire
  because the findings they block on are not written yet.
- **D2 — no recovery**: the re-publish triggered by the advisory scan's own
  completion died on a transient GitHub error, and nothing retried *with
  re-evaluation*: the reconcile loop only picks refs whose last post failed
  (`forge_synced_at IS NULL`); the 12:47:41 post had *succeeded*, so the stale
  "passed" was considered synced and final.

### Proposed fix

1. **Gate precondition — advisory scan completeness.** In
   `publishForSnapshotID`/`PublishGateForRef`, before evaluating a PR
   snapshot: require that the snapshot has at least one **completed advisory
   scan** and no running one (`scans` table). Until then, publish the existing
   pending state with "advisory scan in progress" wording. Same precondition
   on the *base* snapshot is not needed (it is historical by construction).
2. **Persist-then-publish.** `evaluateAndPublish` currently evaluates and
   pushes to the forge in one motion. Change to: evaluate → persist verdict
   (`pr_checks` row, `forge_synced_at = NULL`) → push → mark synced on
   success. A forge failure then leaves an unsynced row that the reconcile
   loop retries — and the retry goes through `PublishGateForRef`, which
   re-evaluates, so it also heals verdicts that went stale between failure
   and retry.
3. **Regression tests**: (a) gate not evaluated while a scan is running →
   pending status; (b) forge publish failure leaves row unsynced; reconcile
   re-publishes the *current* verdict.

Acceptance: re-running PR #11's flow on dogfood produces a **failed** gate
whose reason names `jquery@3.4.1` as known-exploited, with a sane delta
(≈1 new / ~480 unchanged / few resolved), even if GitHub throws a 502 at any
single step.

Open question for review: should the pending state at "advisory scan in
progress" also apply to *branch* snapshots recomputing open PRs? Proposal: yes
(same staleness logic).

---

## 2. Commit provenance: head vs merge-build vs base SHA ✅
(implemented GitHub + GitLab capture; PR-comment SHAs are written in full so
every forge auto-links them — no web-URL plumbing)

### Concern

CI on GitHub `pull_request` events builds a **temporary merge commit**
(`refs/pull/N/merge`, exposed as `GITHUB_SHA`), not the PR head. What was
*really* tested is "head merged into base-at-that-moment". Today hibou stores
one `commit_sha` and the comment says only "evaluated commit 4b1ed2e".

### Proposed design

- **Schema**: `snapshots` gains two nullable columns:
  - `merge_commit_sha` — the temporary merge commit CI actually checked out;
  - `base_commit_sha` — the base-branch commit that merge used.
  `commit_sha` keeps meaning **the developer's commit** (PR head) everywhere.
- **Capture** (no user action needed): the upload CLI, when running in GitHub
  Actions on a `pull_request` event, reads `GITHUB_EVENT_PATH`:
  `pull_request.head.sha` → `commit_sha` (already the behavior),
  `GITHUB_SHA` → `merge_commit_sha`, `pull_request.base.sha` →
  `base_commit_sha`. Explicit flags `--merge-commit` / `--base-commit`
  override. `hibou-upload-action` needs no interface change.
  Branch/tag events leave both empty.
- **API**: the fields ride on snapshot responses.
- **UI**: snapshot/compare headers keep showing the dev commit; hovering it
  shows a tooltip "head `4b1ed2e` · tested as merge `f3a9c01` · onto base
  `789af0d`". No layout change.
- **PR comment**: one additional concise line under "evaluated commit":
  `evaluated commit 4b1ed2e (head) — tested as merge f3a9c01 onto main@789af0d`
  with each SHA linking to the forge. Omitted when the merge SHA is unknown.

Open questions for review:
- Also record `base_ref`? (we already have `pr_target_branch` on snapshots —
  proposal: reuse it, don't duplicate.)
- GitLab merged-results pipelines and Forgejo have equivalents; capture is
  env-based per forge and can land later. OK to ship GitHub-only first?

---

## 3. KEV visibility on dependency/vulnerability lists 🟡
(shipped: per-row exploited badge + "Exploited only" filter on repo and org
vulnerability lists — repo filter client-side over the full list, org filter
SQL-side. Remaining: Dependencies tab/component modal badge, org-overview
exploited count.)

### Concern

KEV currently shows only in the finding drawer and the admin advisory page.
Expected: visible on the dependency/vulnerability views directly.

### Proposed change (the remaining TODO-UX items)

- **Backend**: batched exploited lookup on list responses (same enrichment
  pattern as `FixedInPRs`): `kev: true` per row on repo/org vulnerability
  lists and on component/dependency advisory rows; an org-level
  `exploited_count` on the aggregation endpoint.
- **Frontend**:
  - repo + org **Vulnerabilities** tabs: red "exploited" flame badge on rows,
    plus an **Exploited** filter chip;
  - **Dependencies** tabs + component/library modal: the same badge next to
    the advisory severity;
  - org overview: "N exploited" stat next to the severity counts.

---

## 4. PID-1 zombie reaper (feed outage root cause) ✅
(adaptation: the "manual retry" follow-up already existed as the repo view's
"Scan secrets" button — it now reads "Retry secret scan" after a failed job)

`hibou-server` runs as PID 1 in the pod and never reaped orphaned `git`
processes: 3,135 zombies in 43 min on dogfood, pids cgroup limit 4,646 — then
every `fork()` fails (`Resource temporarily unavailable`). That is the 37-day
CVE-feed outage AND the 24/09 secret-scan failures.

**In the working tree now** (needs your validation):
- `internal/initproc`: when PID 1, the binary re-executes itself as a child,
  reaps all orphans, forwards signals, propagates the exit code. Covered by a
  subreaper-based test (verified to fail if reaping is removed) and a manual
  PID-1 run in a container.
- Alternative if preferred: ship `tini` in the base image
  (`apko.yaml` + `ENTRYPOINT ["tini","--","hibou-server"]`) and delete
  `initproc`. Decision point: in-binary (zero image change, more code) vs tini
  (industry standard, image/entrypoint change, needs apko lock regen).
- Also fixed alongside: `published` advisory events were dropped for 37 days'
  worth of records (`detail` NULL violates NOT NULL) — now defaults to `{}`,
  with a regression test.
- Known flake, pre-existing: `TestReleaseSecretScanJobClaimsReturnsWorkToPending`
  fails under full-suite parallelism (cross-package job quarantine); passes
  isolated ×3. Tracked here, not fixed in this batch.

Until this ships, dogfood's feed dies again every ~1 h of sweeping; a pod
restart only resets the zombie count.

---

## 5. "Fix already in flight" claims PRs that fix nothing ✅
(implemented: claims recorded only when verified against the current base via
CI-recorded base_commit_sha; unverified evaluations CLEAR claims; corrupt rows
purged by migration 00038; delta compares against the recorded-base snapshot
when it still exists; chip/tooltip/drawer reworded with the verified base)

### What happened (evidence from dogfood)

`pr_check_resolved_fingerprints` per open PR on the sample repo:

| PR | snapshot age | claimed resolved |
|---|---|---|
| #11 | fresh (12:45) | **631** — the §1 mid-scan race: verdict stored before the advisory scan wrote the PR's dependency findings, so nearly everything on main looked "resolved" |
| #3 | July | **602** |
| #2, #4–#9 | July | **~94 each** |

The July numbers are a second, independent defect: the delta compares the
PR's (old) snapshot against the **latest** base snapshot. Any finding that
landed on main *after* the PR snapshot was taken is absent from the PR side —
and gets counted as "resolved by this PR". The PR never touched it; it is
simply stale. Every finding view then shows "fix already in flight" pointing
at PRs that fix nothing, which buries the real in-flight fixes.

### Proposed fix — make "resolved" ancestry-aware (your "git checks")

A finding may only be claimed resolved by a PR if the PR's snapshot could
have *seen* it:

1. **Right base, not latest base** (builds on §2): the delta's base side
   becomes the target-branch snapshot at the PR's recorded
   `base_commit_sha` — the commit CI actually merged against — falling back
   to the newest base snapshot that is an **ancestor of the PR head**
   (forge compare / merge-base API), and only then to "latest" as today.
   With the right base, a stale PR shows new-on-main findings as *neither*
   new nor resolved, which is the truth.
2. **Staleness guard on the claim**: when the base used for the delta is not
   the current base head, resolved fingerprints are still computed for the
   gate verdict but are **not recorded** into `pr_check_resolved_fingerprints`
   (or recorded with a `stale` flag the UI ignores). "This PR fixes X" is an
   assertion about merging it *now*, so it must be computed against now.
3. **Backfill/cleanup**: on deploy, purge resolved-fingerprint rows whose
   check predates this fix (they are the corrupt 94s/631); the next recompute
   repopulates the honest ones.
4. **UI honesty**: the "Fix already in flight" chip shows, on hover, which
   base the claim was computed against ("verified against main@789af0d").
   The tooltip's current wording also overclaims — "**Already fixed by** #1
   feat(go): add summary statistics helpers" on a glibc CVE (observed on
   dogfood; the list even included #11, the PR that *adds* a vulnerability).
   Reword to "Resolved when merged: …", which is what the delta actually
   asserts — and cap the tooltip at 2–3 PRs plus a count.
5. **All surfaces heal from the same data fix** — acceptance must check each:
   the list chip, its tooltip, AND the finding drawer's "Fix already in
   flight" section, which currently lists all 7 bogus PRs for a glibc CVE and
   then *advises* "Merging it resolves this finding — usually better than
   accepting the risk" (observed on dogfood). That advice line must only
   render for verified claims; with several claiming PRs it should also not
   imply merging any one of them suffices.

Open question for review: for forges without a cheap merge-base API call we
can derive ancestry from `base_commit_sha` captured at CI time alone (§2) —
acceptable to make the feature GitHub-first like §2?

---

## 6. Vulnerabilities list shows raw/truncated HTML entities ✅
(implemented in internal/sanitize at both ingest choke points + repair
migration 00037; adaptation: Go's HTML5 decoder RECOVERS the truncated
"-&gt" to "->" instead of amputating — upstream had lost only the ';')

### What happened (evidence from dogfood)

Row for CVE-2026-77117 renders `…SHIFT_JISX0213 -&gt`. The stored finding
*title* is exactly that: the upstream advisory text encoded `->` as `-&gt;`,
ingest never decoded entities, and a length cap then truncated **mid-entity**
(`&gt;` → `&gt`). 3 findings on dogfood have entities in titles; the
`advisories` table has none — so the leak is the scanner-report ingest path
(Trivy OS-package findings), not the advisory model and not the Vue layer
(which correctly escapes what it is given).

### Proposed fix

1. Decode HTML entities (`html.UnescapeString`) on finding title/description
   at ingest, **before** any truncation.
2. Make the truncation rune-safe and entity-safe (truncate the decoded text).
3. One-time cleanup: `UPDATE` the handful of stored rows (decode + re-trim);
   fingerprints don't change (they key on advisory/component, not title).
4. Regression test with an entity-encoded, over-long title.

### Also visible in the same screenshot (already covered)

- "fix in #1 +6" on every glibc row — §5's bogus resolved claims.
- The red secret-scan failure banner (attempt 3, terminal) — §4's zombie
  exhaustion; the backoff shipped in alpha.81 worked as designed but the host
  stayed choked past all three attempts. **Follow-up added to §4's scope:** a
  manual "retry scan" affordance for terminally failed secret scans — today
  only a new push re-enqueues one, so the kev-tests branch stays red until
  then even after the host is healed.

---

## Sequencing (after validation)

1. Ship §1 + §4 as `v0.1.0-alpha.82` quickly (correctness: gate + feed).
2. §2 next — §5 depends on its `base_commit_sha`.
3. §5 (ancestry-aware resolved claims + cleanup of corrupt rows), then §3
   (KEV on lists), as `alpha.83`.
4. Re-run the PR #11 scenario end-to-end as acceptance for §1 and §5; the
   existing KEV fixtures serve as acceptance for §3.

Please mark each section keep / change / drop.


----

human comment: pls also fix in sample project, there's a bunch of weird license ids...
-
	Weak copyleft	4	1
Apache-2.0 AND LGPL-3.0-or-laterand	Weak copyleft	3	1
BlueOak-1.0.0	Permissive	3	1
GFDL-1.3-only	Copyleft	3	1
LGPL-2.0-or-later AND GPL-3.0-or-laterand	Copyleft	3	1
LGPL-2.0-or-later AND LGPL-2.0-or-later WITH exceptions AND GPL-2.0-or-later AND GPL-2.0-or-later WITH exceptions AND BSD-3-Clause AND Inner-Net AND ISC AND Public-Domain AND GFDL-1.3-or-laterand	Unknown	3	1
OpenSSL	Permissive	3	1
Python-2.0	Permissive	3	2
Zlib	Permissive	3	1
BSD-3-Clause AND GPL-2.0-or-laterand	Copyleft	2	1
BSD-3-Clause AND LGPL-2.0-only AND Sleepycatand	Copyleft	2	1
BSD-3-Clause OR GPL-2.0-or-lateror	Permissive	2	1
GFDL-1.2-only

you see some AND OR conditions, it only occur on the sample so are theses us who fucked up something? or is it really the output of trivy  or equivalent? (fix it directly if you find an issue)

