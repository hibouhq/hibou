# Finding presence and bundled scanners

A developer guide to two connected subsystems:

- **Finding presence** ([ADR-034](adr/034-absence-is-not-resolution.md)):
  deciding what it means when a finding is missing from a new scan. This
  decides whether a finding is fixed, so it feeds counts, gates, PR claims
  and the finding timeline.
- **Bundled scanners** ([ADR-035](adr/035-bundled-scanners-and-coverage-policy.md),
  [ADR-036](adr/036-automatic-scan-planning-and-verification.md)): deciding
  what should scan a repository, running it in CI, and proving that it ran.

Read this before changing anything under `internal/presence`,
`internal/delta`, `internal/scan*`, or the reconcile code in
`internal/server`. Decisions and their rationale are in the ADRs; the
implementation history and open items are in the
[implementation plan](adr/034-036-implementation-plan.md). This document
describes the code as it is.

---

## 1. Invariants

Each of these is covered by tests. If a change breaks one, the change is
wrong, not the invariant.

1. **A missing finding is resolved only on evidence.** Hibou resolves it
   only when the scanner that reported it ran again, covered its file and,
   under the default policy, the code changed. Anything else keeps it open.
2. **An unanswered question is never a fix.** A forge compare that was not
   obtained (budget spent, error, truncated list), a pending scan, or an
   incomplete repository listing leads to *unconfirmed*, *not re-checked*
   or *unknown*, never to *fixed*. The single exception is written into the
   ADR: a forge with **no compare support at all** lets coverage alone
   decide.
3. **Every reader sees open findings as rows of the latest snapshot.** A
   finding that was not re-checked is *copied* into the new snapshot. Code
   that counts rows of a snapshot needs no presence awareness.
4. **Reconcile only ever touches carried rows.** It never deletes or edits
   a row a producer reported (`presence = 'reported'`).
5. **A tool name is not proof.** Only a report uploaded with its scan plan
   job (`plan_id` + `plan_job_id`) satisfies a blocking requirement.
6. **The server never runs repository code.** Detection reads the file
   list; execution happens in CI.
7. **Artifacts are identified by sha256, never by version.** The OpenGrep
   interfile pre-release reports its version as `1.30.0`.
8. **Scanner policy is org state.** Settings, requirements and exceptions
   live in the database and are never read from a branch, so a PR cannot
   change them.
9. **The forge is asked as little as possible.** Each commit pair is
   compared at most once and cached forever, at most 3 bases per snapshot,
   and never while the reconcile transaction holds its lock.

---

## 2. Overall flow

```
                         ┌──────────────────────── hibou server ─────────────────────────┐
  CI job                 │                                                               │
  ──────                 │  scancatalog (embedded)   applicability ──► repo_applicability │
  hibou scan ──POST plan─┼─► scanpolicy.Resolve ──► scanplan.Build ──► scan_plans         │
     │   ◄── plan ───────┤                                                               │
     │ scanrun: fetch +  │                                                               │
     │ verify + run      │                                                               │
     ▼                   │                                                               │
  hibou upload ──SARIF───┼─► uploads ─► snapshot_artifacts ─► worker: ingest             │
  (+fingerprints,        │                                    ├─► vulnerabilities        │
   paths, plan binding)  │                                    ├─► producer_runs  ◄── evidence
                         │                                    ▼                          │
                         │                      presence reconcile (carry / resolve)     │
                         │                        ├─► vulnerabilities (carried rows)     │
                         │                        └─► finding_resolutions                │
                         │                                    ▼                          │
                         │   delta / PR gate / timeline / UI     scancoverage ─► scan_coverage
                         └───────────────────────────────────────────────────────────────┘
```

The two halves meet at **`producer_runs`**:

- The left half (ADR-035/036) produces runs, ideally bound to a plan job.
- The right half (ADR-034) consumes them as evidence.

Runs uploaded outside `hibou scan`, for example a plain SARIF upload,
still count as evidence for presence. They just cannot satisfy a blocking
coverage requirement.

---

## 3. Package map

All decisions live in **pure packages** that take inputs and return
results, with no database or network access. The server loads inputs,
calls them and writes the results. Keep it that way: it is what makes the
rules testable in isolation.

| Package | Responsibility | Pure |
|---|---|---|
| [internal/sarif](../internal/sarif/) | Parse SARIF. Run evidence (`ExtractRunEvidence`), code-flow files (`TraceFiles`), content fingerprints (`AddContextFingerprints`), URI rewriting (`RewriteArtifactURIs`) | yes |
| [internal/presence](../internal/presence/presence.go) | **ADR-034 rules**: `Plan(previous, current, opts)` returns carries and resolutions | yes |
| [internal/delta](../internal/delta/delta.go) | PR delta: new / fixed / not re-checked. Line-drift pairing, `RekeyedPairs` | mostly |
| [internal/scancatalog](../internal/scancatalog/) | Embedded scanner catalog (`catalog.json`), validation, distribution policy (`Resolve`) | yes |
| [internal/applicability](../internal/applicability/applicability.go) | Which scanners apply to a repo, from its tracked paths | yes |
| [internal/scanpolicy](../internal/scanpolicy/scanpolicy.go) | Org requirement → repo choice → org default; one decision per scanner | yes |
| [internal/scanplan](../internal/scanplan/scanplan.go) | Decisions + catalog → reproducible plan with jobs or blockers | yes |
| [internal/scancoverage](../internal/scancoverage/scancoverage.go) | Configured vs observed → state per scanner | yes |
| [internal/scanrun](../internal/scanrun/) | **CI side**: verified fetch and cache (`Fetcher`), scanner adapters | — |
| [internal/scanbundle](../internal/scanbundle/scanbundle.go) | Offline bundle export and import | — |
| [internal/server](../internal/server/) | Glue: load, call, persist, HTTP API, hooks | — |
| [cmd/](../cmd/) | `hibou upload`, `hibou scan`, `hibou scanners bundle` | — |

---

## 4. Finding presence (ADR-034)

### 4.1 Evidence: producer runs

A **producer** is whatever re-checks a finding.

| Finding | Producer key (`presence.ProducerOf`) | Where its runs come from |
|---|---|---|
| `sast` (and other code types) | `lower(scanner_name)` = `lower(tool.driver.name)` | `producer_runs`, one row per SARIF run ([`sarifProducerRuns`](../internal/server/snapshot_processing.go)) |
| `secret` | `secret-scanning` | `producer_runs`, written by [`recordSecretScanRun`](../internal/server/secret_scan_processing.go) (incremental scan = partial) |
| `dependency`, `malware` | `sbom-matching` | **derived** from the snapshot's latest `scans` row (`store.SnapshotProducerRuns`); no producer_runs row |
| manual / agent (`origin` human or agent) | none: an *assertion* | — |

A run records:

- **scope**: `full` or `partial`, plus `scope_paths`. It comes from, in
  order: the scan plan binding, the upload's `--scope`/`--path`, then the
  repo's `.hibou.yaml` `scanners:` section
  ([scanner_scope.go](../internal/server/scanner_scope.go)).
  `scope_declared = false` means nobody said; it is hibou's assumption, not
  evidence.
- **outcome**: `completed`, `partial` or `failed`.
- **skipped files**, each with a reason. OpenGrep writes the path only in
  the notification message; [evidence.go](../internal/sarif/evidence.go)
  parses it out.
- **version** and **config digest**.

How CI runs each tool is declared once, in `.hibou.yaml`:

```yaml
scanners:            # key: SARIF tool.driver.name, case-insensitive
  semgrep:
    scope: changed-files   # PR builds scan only the PR's files
  eslint:
    scope: partial
    paths: [web/]
```

`changed-files` needs no file list from CI: on a PR snapshot the server
takes the paths of the PR comparison (`snapshot.base_commit_sha`, else the
target's tip, against the head), the pair the PR diff and patch coverage
already fetch and cache. The file is read only when a SARIF upload of the
snapshot declared no scope, before the ingest transactions. A truncated or
failed comparison, or an unreadable config, yields a partial run without
paths: every absence reads as not re-checked.

A SARIF artifact that cannot be ingested is recorded as a `failed` run of
its tool ([`recordFailedArtifactRun`](../internal/server/snapshot_processing.go)).
Its findings then read as not re-checked instead of fixed.

`SnapshotCoverageKnown` is false for snapshots processed before runs
existed (SARIF artifacts but no runs). The PR delta keeps the old "absent =
resolved" reading for those.

### 4.2 Identity: the fingerprint must survive code moves

Presence keys everything on `(type, fingerprint)` (`presence.FindingKey`).
Three layers keep that key stable:

1. **Content fingerprint (CLI).** `hibou upload` adds
   `partialFingerprints["hibou/contextHash/v1"]` to results that have no
   fingerprint. It hashes the tool, rule, path, the flagged line and two
   lines of context (whitespace-normalized), plus an occurrence index.
   Before that it rewrites source-root-relative paths (SpotBugs) to
   repo-relative ones (`withRepoRelativePaths`), so the hash reads the
   right file.
2. **Delta pairing.** `cancelIdentityPairs` (same identity and line) and
   `cancelLineDriftPairs` (same tool, rule, file and message, one-to-one in
   both snapshots) stop a moved finding from reading as new plus fixed.
3. **Triage follows re-keys.** [`carryTriageAcrossRekeys`](../internal/server/finding_rekey.go)
   uses `delta.RekeyedPairs`. It **copies**, never moves, acceptances and
   disputes to the new fingerprint, and writes an audit entry
   (`finding.rekeyed`).

The server's fallback fingerprint (no scanner or content fingerprint) is
line-based and scoped to the **repository**, not the ref, so a PR and its
target agree.

### 4.3 The decision: `presence.Plan`

For every open, produced finding of the previous snapshot of the ref that
the current snapshot does **not** report:

```
not covered, producer retired and not running ─────────► resolve producer_retired
not covered by its producer ───────────────────────────► carry  not_rechecked  (reason)
covered:
  policy explicit ──────────────────────────────────────► carry  unconfirmed  explicit_policy
  producer version / config digest changed ─────────────► resolve producer_changed
  file removed or renamed away (since last seen) ───────► resolve file_removed
  policy consecutive-absence:
     absences+1 ≥ N ─────────────────────────────────────► resolve no_longer_reported
     else ───────────────────────────────────────────────► carry  unconfirmed  absent
  policy coverage (default):
     a relevant file changed ────────────────────────────► resolve fixed
     change question deferred ───────────────────────────► carry  unconfirmed  change_unchecked
     forge cannot compare at all ────────────────────────► resolve fixed (coverage alone)
     absences+1 ≥ N ─────────────────────────────────────► resolve no_longer_reported
     else ───────────────────────────────────────────────► carry  unconfirmed  unchanged | unchanged_trace
assertion (manual/agent):
  closed (resolved/retracted) ───────────────────────────► dropped
  file removed ──────────────────────────────────────────► carry  not_rechecked  location_gone
  else ──────────────────────────────────────────────────► carry  not_rechecked  assertion
```

Notes on the rules:

- **Covered**: see `coveringRun`. A run covers a file if it finished, did
  not skip the file, had it in scope, and left no diagnostic without a
  path (a rule that failed to load puts the whole run in doubt). Not
  covered gives one of `producer_missing`, `producer_failed`,
  `producer_pending`, `outside_scope`, `partial_scope`, `partial_run`, or
  `file_skipped:<reason>`.
- **Relevant file**: the finding's own file, plus, for a taint finding,
  every file of its code flow (`metadata.trace_files`). A taint finding is
  covered only by a **full-scope** run (ADR-036 §6, D7).
- **"Since last seen"**: the change check compares from the commit where
  the producer last *reported* the finding, not from the previous
  snapshot. That way a file edited while the finding was not re-checked
  still counts.
- **Policies**: `producer_policies`, editable in Settings → Tools:
  `coverage` (default), `consecutive-absence`, `explicit` (default for
  `agent:*`), and `retired` (a producer removed on purpose; its findings
  resolve as `producer_retired` while it does not run). `N = 3`
  (`presence.DefaultAbsenceThreshold`).
- **`consecutive_absences`** counts covered scans without the finding. It
  is kept unchanged while the finding is not re-checked.

`presence.ReasonText` is the single source of wording for reasons. The PR
comment uses it, and `site/src/lib/presence.ts` mirrors it for the UI.
Change both together.

### 4.4 Applying the decision: reconcile

[`reconcileFindingPresence`](../internal/server/finding_presence.go) runs:

- after artifact ingest, from `afterArtifactIngest`, after the triage
  re-key and before the snapshot completes and the gate reads it;
- after every secret scan and every advisory scan, through
  `reconcileFindingPresenceLate`, which also requests a gate recompute
  when rows changed.

It runs in two passes:

```
pass 1 — unlocked (prefetchPresenceComparisons)
   load lean rows + runs + policies ─► Plan with a recording checker
   ─► base commits actually asked about (none ⇒ no forge call)
   ─► fetch ≤ 3 comparisons (previous commit first), cache-first

pass 2 — one transaction (reconcileFindingPresenceTx)
   pg_advisory_xact_lock(ref) ─► reload lean rows + runs
   ─► Plan with prefetchedChangeChecker (memory only; missing ⇒ Deferred)
   ─► diff against existing carried rows:
        insert (CarryVulnerabilitiesForward) · update (UpdateCarriedPresence)
        · delete (DeleteCarriedVulnerabilities)
   ─► ReplaceFindingResolutions(snapshot)
```

Details that matter:

- **Diff, not rewrite.** `vulnerability_external_issues` and
  `vulnerability_state_transitions` cascade from row ids. Deleting and
  re-inserting every carried row would lose them.
- **Re-reported wins.** The `CreateVulnerability` upsert resets `presence`
  to `reported`. A producer that lands later turns a carried row into a
  real observation.
- **Lean reads.** `ListPresenceRowsBySnapshot` selects only the columns
  `Plan` reads, with metadata reduced to `trace_files`. Reconcile runs
  often, on snapshots that can hold tens of thousands of rows.
- **Predecessor.** `GetPreviousCompleteSnapshotByRef` returns the latest
  `complete|active` snapshot of the ref created earlier. A predecessor that
  completes after its successor was reconciled is not re-chained (a known
  gap).

### 4.5 The forge budget

[presence_changes.go](../internal/server/presence_changes.go) holds the
forge-facing code:

| Mechanism | Where |
|---|---|
| Ask only for covered-and-absent findings | `Plan` calls the checker only on that path |
| One compare answers every file between two commits | `comparisonIndex` |
| Cache forever (immutable SHAs) | `compare_patch_cache`, keyed `(repo, base, head)` |
| Budget of 3 bases per snapshot | `presenceCompareBudget` |
| Merge concurrent fetches of one pair | `compareGate.group` (singleflight) |
| 10 min backoff per failed pair (cancellations excluded) | `compareFailureBackoff` |
| No network inside the lock | pass 1 vs pass 2 |
| Branch compares cached without hunks | `paths_only` (migration 00051); the PR diff view upgrades the row, a full row is never downgraded |
| Forges with no line data (Forgejo) | `ComparePatch` returns `PathsOnly`; presence uses it, patch coverage degrades, and `forge.PathsOnlyComparer` stops the diff view from re-asking |

`lazyChangeChecker` serves the PR delta, which runs outside any
transaction. It has the same budget but keeps hunks, because the PR's diff
view reads the same cache row.

### 4.6 PR delta

[`delta.ComputeDelta`](../internal/delta/delta.go) gives the PR its own
classification. A PR snapshot is usually the first of its ref, so nothing
was carried into it:

- `splitNotRechecked` runs `presence.Plan` with the **target** snapshot as
  "previous" and the PR's runs as "current". The checker comes from the
  server hook (`delta.SetPresenceOptions`, wired in server.go).
- Carries go into `NotRechecked`. Resolutions stay in `Resolved`, each with
  a non-persisted `resolution_reason`.
- Only `fixed` and `file_removed` count as fixes: in the PR comment, in the
  compare view headline, and in the "fix in #N" claims
  (`isClaimableFix`).
- Unresolved assertions on the target are reported as not re-checked
  (reason `assertion`); decided ones stay resolved.

### 4.7 Assertions (manual and agent findings)

Nothing re-runs an assertion, so `Plan` carries it until a decision ends
it. The lifecycle lives in `finding_assertions`, keyed by fingerprint like
`finding_acceptances`.

| Action | Endpoint | Who | Effect |
|---|---|---|---|
| Re-assert | `POST …/findings/{fingerprint}/reassert` | `vulnerabilities:write` | `last_confirmed_*`; reopens a closed one, copying its last row back into the branch's latest snapshot (`reopenAssertion`) |
| Resolve | `…/resolve` | admin + `triage:write`, reason required | closes; rows in each ref's latest snapshot → `resolved` now |
| Retract | `…/retract` | filer, filing token, token owner, or admin | same, `closed_kind = retracted` |

Filing the same finding again (`POST …/findings`) counts as a re-assert.

---

## 5. Bundled scanners (ADR-035/036)

### 5.1 Catalog

[catalog.json](../internal/scancatalog/catalog.json) is data embedded in
the binary. `scancatalog.Load` validates it, and a test fails on any
invalid entry. Each scanner declares:

- distributions, pinned by **sha256**, for binaries per OS and arch and for
  Maven artifacts;
- rulesets, with a status (only `approved` rulesets are selectable);
- language × capability pairs with **evidence**: `measured:<where>` or
  `declared`;
- applicability predicates, stage prerequisites, a resource budget, an
  exit-code map, a command template (no shell syntax allowed), and SARIF
  quirks.

`scanner_distribution` (server config, validated at startup) decides where
artifacts come from. `DistributionConfig.Resolve` applies:

```
offline mode ─► <bundle_dir>/<scanner>/<version>/<asset>            (file://, no network)
approved per-scanner location ─► <location>/<version>/<asset>
installation mirror ─► <mirror>/<scanner>/<version>/<asset>         (Maven: maven_mirror_url)
upstream ─► only in upstream mode; mirror mode fails with ErrUnavailable
```

### 5.2 Detection, policy, plan

```
forge.TreeLister.ListTree(commit) ─► applicability.Detect ─► repo_applicability
                                                     │
repo_scanner_settings + scanner_requirements + coverage_exceptions
                                                     ▼
                                            scanpolicy.Resolve ─► []Decision
                                                     ▼
                         scanplan.Build(+ distribution policy, runner os/arch)
                                                     ▼
                                     scan_plans (digest-stable document)
```

- **Detection** is path-only. A truncated or unavailable listing gives
  status `truncated` or `unknown`, never "nothing applies". It runs on
  every push to the default branch, off the webhook path, and again when
  an owner changes a scope override (`repo_scope_overrides`: excluded
  paths, declared module roots). An exclusion that would hide code in a
  language the org requires scanned is applied only once an exception
  with that path as scope is approved (`scopeOverrides`, `DetectWithOverrides`).
- **Policy order:**
  - A requirement matches when the repo has code in its language and a
    candidate scanner provides the capability. Pre-releases count only
    when named.
  - A repo's `disabled` does not apply to a required scanner; an approved,
    unexpired exception for scope `.` waives the requirement.
  - Otherwise the repo's own setting applies.
  - Otherwise the org default: every applicable, non-preview scanner.
- **Plan:**
  - Each job has its targets (module roots, `.` means full scope),
    exclusions, prerequisites, resolved artifact, and ruleset, or an exact
    `blocked_reason`.
  - Mode is `baseline` (first plan, or catalog or detection changed),
    `full` (no adapter has validated incremental support) or `sweep` (on
    request).
  - A CI request's `scanners` list can add scanners, never drop a required
    one.

### 5.3 Execution in CI

`hibou scan` ([cmd/scan.go](../cmd/scan.go)):

1. `GET /scanner-catalog` gets every artifact with its resolved location.
2. `POST …/scan-plans` returns the plan.
3. Ready jobs run with bounded concurrency (`--jobs`) through
   `scanrun.Run`:
   - `Fetcher.Fetch` accepts https or `file://` only, verifies the sha256
     before use, re-hashes cache hits, caps size, and refuses cross-host
     redirects (except upstream → GitHub's asset CDN).
   - Adapters build argument lists; nothing goes through a shell.
     - The OpenGrep adapter needs an approved ruleset, or `--opengrep-rules`;
       a run with local rules is uploaded **unbound**.
     - The SpotBugs adapter runs the plugin goal with the verified Find
       Security Bugs jar. Missing `target/classes` is a prerequisite
       failure, not a clean pass. Afterwards it checks the jars Maven
       resolved against the catalog.
4. Each report goes through the same upload path as `hibou upload` (path
   rewrite, content fingerprints), with `plan_id` and `plan_job_id`. The
   server checks the job exists and that the plan was made for this
   commit, then takes the job's scope as the declared scope.

Offline installations use `hibou scanners bundle export` on a connected
machine and `… import` on the air-gapped one. Import verifies everything
against the catalog before copying anything.

A bundle's age is the age of what its scanners check, so it is judged
against the org freshness policy rather than hidden behind a scanner that
starts fine ([scanner_bundle.go](../internal/server/scanner_bundle.go)).
The server reads `<bundle_dir>/hibou-scanner-bundle.json` (re-read when the
file changes) and `GET /scanner-catalog` reports its export date and whether
it matches the pinned catalog. A required cell whose requirement sets
`freshness_days` turns `stale` when the bundle is older than that, even if
the latest run is recent. The org's Scanner requirements page shows the
bundle against its strictest requirement.

### 5.4 Coverage: configured vs observed

[`scancoverage.Compute`](../internal/scancoverage/scancoverage.go) gives
one state per scanner: `covered`, `pending`, `missing`, `missing_setup`,
`failed`, `partial`, `stale`, `unverified`, `unsupported`, `exempt`,
`disabled`, `not_applicable` or `unknown`.

- **Attribution** (`attributeRuns`): a plan-bound run is attributed through
  its plan job. An unbound run is attributed by catalog producer name and
  is never counted as bound.
- **Bulk changes**: `POST /orgs/{p}/{s}/scanner-settings/bulk` (with
  `dry_run`) enables or disables a scanner on every repository where it
  applies, from the inventory; it never disables a required scanner.
- **Inventory**: `scan_coverage` is recomputed when a default-branch
  snapshot completes, a plan is created, a setting or exception changes,
  and org-wide in the background when a requirement changes. It is read by
  the org **Scanners** tab and the CSV export.
- **PR check**: `prCoverageCheck` runs the same computation on the PR
  head's own runs. `GatePublisher.SetCoverageCheck` turns blocking gaps
  into gate reasons prefixed `Scan coverage:`, and advisory gaps or pending
  jobs into notes.

---

## 6. Data model (migrations 00043–00053)

| Table / column | Written by | Read by |
|---|---|---|
| `producer_runs` | SARIF ingest, secret scans, failed artifacts | presence, Scan coverage panel, tool catalog, coverage |
| `snapshot_artifacts.{scope,scope_paths,tool_version,config_digest,plan_id,plan_job_id}` | upload | ingest (declaration), plan binding |
| `vulnerabilities.{presence,presence_reason,last_seen_snapshot_id,last_seen_commit,consecutive_absences}` | reconcile (carried rows), upsert reset | everything that lists findings, `presence:` filter |
| `finding_resolutions` | reconcile | finding timeline |
| `producer_policies` | Settings → Tools | presence |
| `finding_assertions` | reassert / resolve / retract / create | presence (closed set), detail drawer |
| `repo_applicability` | detection | policy, plan, coverage |
| `scan_plans` | `POST …/scan-plans` | upload binding, coverage |
| `repo_scanner_settings`, `scanner_requirements`, `coverage_exceptions` | settings UIs and APIs | policy |
| `repo_scope_overrides` | Scanners tab, API | detection |
| `scan_coverage` | coverage refresh | org matrix |
| `compare_patch_cache.paths_only` | presence compares | PR diff view (upgrades) |

---

## 7. API surface

Repository-scoped routes are under `/orgs/{provider}/{slug}/repos/{repo}`.

| Route | Purpose |
|---|---|
| `GET …/snapshots/{id}/producer-runs` | runs vs previous snapshot (Scan coverage panel) |
| `POST …/findings/{fp}/reassert` · `…/resolve` · `…/retract` | assertion lifecycle |
| `GET …/applicability` · `POST …/applicability/refresh` | detection |
| `POST …/scan-plans` (`dry_run`) · `GET …/scan-plans/{id}` | plans |
| `GET/PUT …/scanner-settings` · `POST …/coverage-exceptions` | repo policy |
| `GET/POST/DELETE …/scope-overrides` | owner exclusions and module roots |
| `GET …/scan-coverage` | repo coverage (recomputed) |
| `GET/PUT/DELETE /orgs/{p}/{s}/producer-policies` | resolution policies |
| `GET/PUT/DELETE /orgs/{p}/{s}/scanner-requirements` · `POST …/coverage-exceptions/{id}/decision` | org policy |
| `GET /orgs/{p}/{s}/scan-coverage` (`format=csv`) · `POST …/refresh` | org matrix |
| `POST /orgs/{p}/{s}/scanner-settings/bulk` (`dry_run`) | bulk enable or disable |
| `GET /scanner-catalog` | catalog with resolved locations |
| `POST /upload` (+ `scope`, `paths`, `tool_version`, `config_digest`, `plan_id`, `plan_job_id`) | evidence in; `scope`/`paths` override `.hibou.yaml` |

Delta responses carry `not_rechecked_vulnerabilities`, and resolved
entries carry `resolution_reason`. Findings carry `presence`,
`presence_reason` and `last_seen_commit`.

---

## 8. How to change things

### Add or upgrade a scanner in the catalog
1. Download each artifact and compute its sha256. Cross-check with the
   publisher's digest; never trust a version string.
2. Edit `catalog.json` and bump `revision`. A new catalog revision forces
   every repository's next plan into `baseline` mode.
3. Mark a capability `measured:` only with a fixture run behind it.
4. Add or adjust the adapter in `internal/scanrun` if the engine is new.
   Map its exit codes, and never build a shell command.
5. Capture a real SARIF into `internal/sarif/testdata` and test what
   ingestion relies on: driver name (the producer key), version field,
   fingerprints, paths, code flows.
6. Check that the producer name matches `producer_names`. If it differs
   from an existing entry's, presence treats it as a different producer.

### Add a server-side producer
Write a `producer_runs` row per snapshot (`UpsertSnapshotProducerRun`) and
map the finding type to its key in `presence.ProducerOf`. Then call
`reconcileFindingPresenceLate` after it lands. Without that, its findings
read as `producer_missing` forever.

### Change a presence rule
Edit `presence.Plan` or `coveringRun` and extend `presence_test.go` with a
table case. Then check, in this order:

- the PR delta (`not_rechecked_test.go`);
- the DB tests in `internal/server/finding_presence_test.go`;
- reason wording in both `ReasonText` and `site/src/lib/presence.ts`.

Any new path that resolves a finding must have evidence behind it
(invariant 1).

### Add compare support for a forge
Implement `ComparePatch`, returning `(nil, nil)` only when the forge truly
cannot compare. An error means "deferred", and a `nil` diff means
"coverage alone". Getting this wrong turns outages into false fixes. Set
`Truncated` when the file list is capped.

---

## 9. Tests to run after a change

| Area | Tests |
|---|---|
| Rules | `go test ./internal/presence/ ./internal/delta/` |
| Reconcile, budget, assertions, timeline | `internal/server`: `TestReconcile*`, `TestPresenceComparison*`, `TestReconcileForgeBudget`, `TestAssertionLifecycle`, `TestFindingTimelineShowsPresenceGap`, `TestArtifactProcessingCarriesMissingProducer` |
| SARIF evidence on real captures | `TestOpenGrepCaptures`, `TestRunEvidence*` |
| Catalog, distribution, bundles | `./internal/scancatalog/ ./internal/scanrun/ ./internal/scanbundle/` |
| Policy, plan, coverage | `./internal/scanpolicy/ ./internal/scanplan/ ./internal/scancoverage/`, `TestScanPlan*`, `TestScanCoverageInventoryAndPRCheck`, `TestBulkScannerSetting`, `TestScopeOverridesRespectRequirements` |
| Real scanner reports end to end | `TestIngestRealScannerCaptures`, `TestPathsOnlyForgeIsAskedOnce`, `TestReconcileRetiredProducer` |
| CLI end to end (stub server) | `TestScanRunsPlanAndUploads` |

DB-backed tests need the local Postgres (`make test-db`). Locally, run
`go test . ./cmd/... ./internal/...` rather than `./...`, and see the swag
note below.

---

## 10. Knobs and known limits

| Constant / config | Value | Where |
|---|---|---|
| Absence threshold N | 3 | `presence.DefaultAbsenceThreshold`, per producer in `producer_policies` |
| Compare budget per snapshot | 3 | `presenceCompareBudget` |
| Forge failure backoff | 10 min | `compareFailureBackoff` |
| Pending window for a planned job | 2 h | `scancoverage.pendingWindow` |
| Max exception duration | 365 days | `maxExceptionDays` |
| Detection / tree listing cap | 100k files | `maxTreeListingFiles` |
| Distribution policy | `scanner_distribution` | `hibou-server.example.yaml` |

Known limits (tracked in the plan):

- No OpenGrep ruleset is approved yet (licence review), so OpenGrep jobs
  are blocked.
- Forgejo compares are paths-only (no line data): presence works, patch
  coverage degrades. Instances older than the compare API answer 404 and
  fall back to coverage alone.
- A predecessor completing after its successor is not re-chained.
- The "pending" window expiring does not re-trigger the PR check.

**Local codegen:** `make generate`'s swag step crawls the untracked nested
checkouts and fails. Run swag with
`--exclude opengrep,castor,hibou-sample-project,hibou-upload-action,node_modules,site`.
