# ADR-049: Findings stored once per repository, presence per snapshot

## Status

Proposed (2026-10-17). Follows [ADR-045](045-built-in-dependency-inventory.md)
(inventory sets: the same move for inventories), [ADR-034](034-absence-is-not-resolution.md)
(presence, carry-forward, assertions) and [ADR-012](012-unified-vulnerability-model.md)
(the unified read model and statuses). Changes nothing visible in the API
or the UI; the deliverable is a storage shape that survives a company of
several hundred repositories, among them one to ten monorepos with
hundreds of open pull requests each, and a scan pipeline that works per distinct inventory
rather than per snapshot.

**Implemented (2026-10-17, rollout steps 1 to 5).** Migration `00068`
creates `findings` and `snapshot_findings`, backfills one finding per
identity (keeping the newest row's id so transitions and external issues
re-key without loss) and one snapshot row per old row, re-keys the two
history tables, replaces `vulnerabilities` with a view of the same
columns and rebuilds `finding_cwes` per finding. Every writer goes
through the store's unchanged Go API: one statement upserts the finding
and its snapshot row; carry-forward, scan reuse, stale marking,
reachability, assertions and retention's rollup write the snapshot rows;
triage writes the finding. The retention pass collects orphan findings
after a month; automatic scans run through a bounded pool
(`advisory_scan.max_concurrency`, default 2 per replica); the 6-hourly
pass costs one matching per distinct inventory set through scan reuse,
the rest copy pointer rows. The instance storage page counts findings
and snapshot rows. Three readers were adjusted, none rewritten: the
by-id lookups return the newest occurrence, the latest-by-fingerprint
lookup orders by `detected_at`, and the timeline reads the per-snapshot
status below. Measured on the test corpus the view returns exactly the
old row count (6,226 rows, 5,009 findings) and every suite passes.

Where the implementation differs from the design below:

- **The status a producer reported stays per snapshot** (`scan_status`
  on the snapshot row), next to the as-scanned rating, because the
  timeline and the in-source suppression comment (ADR-023) are facts of
  the occurrence, not of the finding; the finding's `status` is a
  person's decision only. The effective status is the person's if any,
  else "resolved" when the scan stopped matching it on that snapshot,
  else the producer's.
- **Stale matches are marked, not deleted.** A snapshot row the scan
  stopped matching gets `resolved_at` rather than being removed, so the
  "resolved" filter and counts of a snapshot keep today's meaning and
  presence's own resolution records are not disturbed.
- **`last_seen_commit` is derived** from `last_seen_snapshot_id`, not
  stored twice; the CVSS score stays a `numeric(4,2)`.
- **One statement, not a batch**: the finding upsert and the snapshot
  row insert are one SQL statement per finding, the same call count as
  before; a batched writer stays available if measured.
- **The scan pass is not rewritten per set**: scan reuse (ADR-045)
  already makes the second and later snapshots of a set copy the first
  scan within the pass, so the matching cost is per set while the pass
  loop stays per ref.

## Context

### What multiplies today

A finding is a row of `vulnerabilities` **per snapshot**. Every build of
every branch and pull request writes its own copy of every finding it
carries:

- the advisory scan writes one row per matched (advisory, component)
  pair, and with ADR-045's scan reuse still copies them from the prior
  scan;
- SARIF ingestion writes one row per code finding the tool reported;
- presence (ADR-034) copies every finding the producer did not re-check
  from the previous snapshot, every column of it, with the presence
  fields set.

The row is wide: about fifty columns, free text (title, description,
solution), a jsonb `metadata`, and 23 indexes including two trigram
indexes on free text. Measured on the development database it costs
about 5.9 KB with its indexes; at scale, with repeated titles, count on
2 to 3 KB. The same development database holds 2,836 rows for 859
distinct findings per (repository, type, fingerprint): the ratio is the
number of snapshots a finding lives through, and a pull-request-heavy
repository pushes it far higher.

```text
rows per day = snapshots per day × findings per snapshot
snapshots per day ≈ open pull requests × builds per pull request per day
                    + release branches × merges per branch per day
                    + merges to the default branch
```

Every merge to a maintained release branch is a push to an eager branch:
a snapshot, an extraction (reused by digest unless a manifest changed)
and a scan (reused unless the inventory changed). Forty release branches
at ten merges a day each are 400 snapshots a day on their own, at twenty
a day 800. For one monorepo with 40 release branches, at 3 KB per row:

| Open PRs | Builds per PR per day | Release merges per day | Snapshots per day | Findings per snapshot | Rows per day | Disk per day | 100 M rows after |
|---|---|---|---|---|---|---|---|
| 500 | 1 | 100 | ~650 | 500 | 325,000 | ~1 GB | ~10 months |
| 1,000 | 1 | 400 | ~1,450 | 500 | 725,000 | ~2.2 GB | ~4.5 months |
| 1,000 | 2 | 400 | ~2,450 | 500 | 1,225,000 | ~3.7 GB | ~3 months |
| 1,000 | 2 | 800 | ~2,850 | 1,000 | 2,850,000 | ~8.5 GB | ~5 weeks |

The sizing case of this ADR is the **last row**, on purpose: a design
that holds at 1,000 open pull requests built twice a day, 40 release
branches merging twenty times a day each and 1,000 findings per build
holds everywhere below it, and a company with one to ten such
monorepos cannot plan on the best case. Ten monorepos at that row are
28.5 M rows a day, about 85 GB, before the other 600 to 1,000
repositories; a single one reaches 100 M rows in five weeks, ten of them
in four days. The second row, the likely case today, is given so the
gap between likely and worst is visible: a factor of four. Past about 100 M rows the organisation-wide queries (dashboard
counts, trends, the findings search with its `ILIKE` filters) run over
every retained row of the organisation and degrade to seconds; past a few
hundred million the table needs partitioning and the trigram indexes on
free text cannot stay. Retention (ADR-014) rolls archived snapshots up and
deletes their rows, which bounds the retained set, but `auto_purge` ships
off and an instance reclaims nothing until an operator opts in.

### What a scan costs today

The advisory scan pass runs every six hours (`advisory_scan.interval`)
over the latest snapshot of **every ref of every repository**, plus the
release-pinned snapshots, sequentially. For a monorepo of the sizing
case (1,000 open pull requests, 40 release branches) that is some 1,040
scans per pass, per monorepo, each writing a `scans` row and its provider rows; with
ADR-045's reuse the matching itself runs once per distinct inventory set
and the rest copy, but the copies are still full rows and the pass is
still per snapshot. Automatic scans after an upload run in a goroutine
per snapshot, unbounded: a thousand repositories finishing CI in the same
hour start a thousand scans.

### What already keys on the finding, not the row

Triage was built on the finding's identity, not on its row:
`finding_acceptances (repo_id, fingerprint)`, `finding_assertions
(repo_id, fingerprint)`, `finding_resolutions (repo_id, ref_id, …,
fingerprint)`, VEX statements by (organisation, advisory, repository,
purl). Two tables key on the row id, `vulnerability_state_transitions`
and the finding comments, and so lose their history every time the
finding is copied into the next snapshot: a comment made on Tuesday's
snapshot is not on Wednesday's row. That is a defect of the per-snapshot
copy, not a feature to preserve.

ADR-034 chose the copy deliberately ("counts, gates, trends and org views
keep working unchanged") to avoid rewriting every reader. ADR-045 then
showed the alternative at the inventory level: keep the per-snapshot
shape as a **view** over a shared table, so readers keep their queries
while writers stop copying.

### Goals

- A snapshot costs one narrow row per finding it carries, never a copy of
  the finding.
- A scan of an inventory set other snapshots share costs one matching and
  one pointer row per finding per snapshot.
- The 6-hourly pass costs one matching per distinct inventory set, not one
  per ref.
- Comments and state transitions follow the finding across snapshots.
- Every existing reader, gate and export keeps its answer.

### Non-goals

- Changing what a finding is (ADR-012), when it is resolved (ADR-034), or
  how it is triaged (ADR-023). Statuses, presence states, acceptances and
  assertions keep their meaning.
- Cross-repository identity. A finding is still scoped to one repository;
  the same CVE in two repositories is two findings.
- Retention policy (ADR-014). Retention keeps deciding which snapshots
  stay; this ADR makes the ones that stay cheap.

## Decision

### 1. One `findings` row per (repository, type, fingerprint)

The wide row moves to `findings`, keyed by the identity the triage tables
already use. It holds what is true of the finding regardless of the
snapshot: type, identifiers, title, description, the advisory and
component references, the rating (`original_severity`, `severity` and
its override, CVSS, `rated_by`), the triage status and its denormalised
milestones (`status`, `state_comment`, `resolved_at/by`, `due_date`), the
producer attribution (`scanner_*`), origin and principal (ADR-009), the
assertion fields, `first_seen_at` and `last_seen_at` (repository-wide; the
per-branch facts are on the pointer rows, §2), and the latest known
location (`file_path`, `start_line`, `end_line`, `location_hash`).

`status` on the finding is the **triage** status: `detected`, `suppressed`,
and the ADR-012 milestones. "Resolved on this ref" is not stored on the
finding; it is what presence says (§2) and what `finding_resolutions`
records as evidence, exactly as ADR-034 defines it. `present_on_default_branch`
and `resolved_on_default_branch` stay as denormalisations maintained from
the default branch's latest snapshot.

### 2. One `snapshot_findings` row per (snapshot, finding)

The narrow table says which findings a snapshot carries and how:

| Column | Notes |
|---|---|
| `snapshot_id`, `finding_id` | primary key; index on `(finding_id, snapshot_id)` for "where is this finding" |
| `presence` | `reported`, `not_rechecked`, `unconfirmed` (ADR-034 §3), as a `smallint` |
| `presence_reason` | the ADR-034 reason, `smallint` code with a lookup, or NULL for `reported` |
| `consecutive_absences` | `smallint` |
| `last_seen_snapshot_id` | where the producer last reported it **on this ref**, carried along the chain as ADR-034 §3 defines; NULL on a `reported` row. The commit is that snapshot's, not stored twice |
| `reachability` | per snapshot: the classification reads the snapshot's code references (ADR-019) |
| `file_path`, `start_line`, `end_line`, `location_hash` | NULL when equal to the finding's latest location; an occurrence at another path or line keeps its own per snapshot. The view coalesces them with the finding's, so the drawer, the forge link at the snapshot's commit and the VS Code extension read the location this snapshot had, as today |
| `severity`, `cvss_score`, `confidence` | **as scanned**: the rating the scan or the carry wrote for this snapshot (§6). The scan pass refreshes them on the snapshots it stamps, as it refreshes rows today; older snapshots keep theirs |
| `metadata` | NULL unless this occurrence's per-run data differs from the finding's latest (§6): a taint trace through other files, a DAST request, a secret's entropy |
| `severity_rank` | `smallint`, from the as-scanned severity, for the per-snapshot sort |

Sized from the columns, with the 24-byte tuple header and the three
indexes below: about 210 bytes for a reported row with no override (the
common case), about 230 for a carried row, up to about 500 when the
location or the metadata differs. Against 2 to 3 KB today at scale, about
**twelve times less** per snapshot. A pull request that carries the same
500 findings as its base writes 500 pointer rows, some 100 KB, where it
wrote 1 to 1.5 MB. The win that is not arithmetic is elsewhere: each
finding exists once for the organisation-wide readers, the three narrow
indexes replace 23 wide ones on every write, and the pass runs per
inventory set.

The unique key the writers rely on today, `(snapshot_id, type,
fingerprint)`, is implied: `finding_id` determines type and fingerprint.

### 3. Writers

- **Advisory matching** produces a set of (type, fingerprint) with their
  attributes; it upserts `findings` rows that do not exist yet (by
  identity, never overwriting triage), then inserts the `snapshot_findings`
  rows. A finding the scan no longer produces gets no pointer row; the
  stale-marking step becomes "pointer rows of this snapshot not in the
  fresh set are deleted", and `finding_resolutions` records the evidence
  as today.
- **Scan reuse** (ADR-045) copies pointer rows, not findings.
- **SARIF ingestion** does the same per code finding, with the location
  on the pointer row when it differs from the finding's.
- **Carry-forward** (ADR-034) inserts pointer rows with the presence
  fields; nothing else is copied.
- **Manual findings and assertions** create the finding once; reassert
  adds the pointer row.
- **Triage actions** (status, severity override, comments, transitions)
  write the finding row once and are visible from every snapshot that
  carries it.
- **Descriptive text** (title, description, solution, remediation link,
  language, confidence, secret type) is written when the finding is
  created and then only by a scan of the default branch (§6). A scan of
  any other branch upserts the identity and stamps the pointer rows
  without touching the text.

### 4. The scan pass works per inventory set

The 6-hourly pass lists the distinct inventory sets of the latest
snapshots of every ref plus the pinned releases, matches each set once,
and stamps the pointer rows onto every snapshot that points at the set.
For each sizing monorepo the pass drops from some 1,040 matchings to the
number of distinct dependency states across its refs, typically tens.
Code findings are untouched by the pass, as today.

Automatic scans after an upload go through a bounded worker pool
(`advisory_scan.max_concurrency`, default 2 per replica) with one entry
per inventory set in flight, so a burst of uploads with the same
inventory is matched once and the rest wait for the pointer stamp.

### 5. Readers keep their shape

`vulnerabilities` becomes a **view** of `snapshot_findings JOIN findings`
with today's columns, in the migration that creates the tables. The 36
queries of `vulnerabilities.sql` and the eleven other files that read the
table keep working. Per-snapshot reads plan as a primary-key prefix scan
on the pointer table followed by primary-key lookups on `findings`;
organisation-wide aggregates read `findings` once per finding instead of
once per snapshot, which is the point. The queries the view serves worse
than a direct read are rewritten one by one, measured with
`EXPLAIN (ANALYZE, BUFFERS)` as `00035` and ADR-045 were; the hot ones are
the per-snapshot list, the gate's severity counts and the organisation
dashboard.

`vulnerability_state_transitions` and the comments re-key to `finding_id`
in the migration, by the row's (repository, type, fingerprint), which
merges each finding's history across its copies.

### 6. What keeps its state at the snapshot, and what does not

The question of this ADR is not storage; it is which facts about a
finding are facts about *the snapshot* and must stay as they were, and
which are facts about *the finding* and should be current everywhere.
Today's copy keeps everything as written, with one exception: the
6-hourly pass re-matches the latest snapshot of every ref and refreshes
those rows' rating, so "as it was" today means "as it was, unless it is
the latest snapshot". The rule below keeps exactly that behaviour.

| Attribute | Today | After | State at the snapshot |
|---|---|---|---|
| Identity: type, fingerprint, advisory, affected range, component, purl, version, rule, primary identifier | per row, never changes | on the finding | **kept** (immutable by definition) |
| Severity and CVSS score | per row; refreshed on the latest snapshot at each pass, frozen on older ones | as scanned on the pointer row, refreshed on the snapshots the pass stamps; current on the finding | **kept**, same rule as today. Per-snapshot lists, counts, trends and release reports read the pointer; the drawer shows the current rating and "scanned as X" when they differ; organisation views use the current. For rule findings (SAST, DAST, secrets) the as-scanned value is normally the rule's severity and a tool that changes a rule's severity is right to change it everywhere; it still differs per occurrence when a SARIF `result.level` overrides the rule's default, when a secret is verified, or when a DAST tool rates an instance by its confidence. For dependency findings it differs whenever an advisory is re-scored (NVD, ADR-038), which is what would rewrite trends and release reports retroactively. Two bytes per pointer row and no extra write buy the same rule for every type |
| Presence, presence reason, consecutive absences | per row | on the pointer row | **kept** |
| Reachability | per row | on the pointer row | **kept** |
| File path, line numbers, location hash | per row | the latest on the finding; on the pointer row whenever this occurrence's location differs | **kept**. A rename is normally a new fingerprint anyway (the context hash of ADR-034 §7 includes the path), so the override is rare; when a tool's own fingerprint ignores the path, the old snapshot still shows the old path with its lines, and its forge link still resolves at that commit |
| Triage: status, comment, resolved by and at, due date, severity override, dismissal reason | per row, but acceptances, assertions and disputes already key on the fingerprint and apply to every snapshot at read time | on the finding, with the full history in `vulnerability_state_transitions` keyed by finding | **kept through history**: the state at any instant is reconstructable from the transitions, which today are lost at every copy. "Resolved on this ref" is presence, as ADR-034 defines it |
| Scanner name and version | per row | the name is part of the fingerprint and cannot change; the version on the finding is the latest that reported it | **kept** per snapshot in `producer_runs` (one row per producer per snapshot with its `version`, ADR-034) and on the artifact's `tool_version`. Nothing reads the finding's copy per snapshot |
| Confidence (a tool's certainty about this occurrence: ZAP rates each alert instance, SAST tools rate per rule) | per row; nothing writes it yet, ADR-012 reserved it | as scanned on the pointer row, next to severity | **kept** once a producer writes it; today always NULL |
| Title, description, solution, remediation link, language, secret type | per row | on the finding, written when first seen and afterwards **only by scans of the default branch**; other branches never rewrite it | **lost** per snapshot: every snapshot of every branch shows the default branch's current wording. A rule's description or a fix hint improves over time and should read the same everywhere; nothing decides on it. "Latest wins" by write order would let two release branches on different scanner versions rewrite each other at every scan, which is why the default branch is the only writer. For dependency findings the text is the advisory's, which is global anyway |
| `metadata`, the per-run data producers attach. Today it holds: for code findings `trace_files` (the files a taint flow crosses, read by presence to decide whether a partial scan covered the finding, ADR-034 §5) and `suppression` (a scanner's own suppression kind and justification, ADR-023); for DAST findings `web` (`url`, `method`, `route`, `param`, `attack`: the request that proved it, ADR-044); for secrets the gitleaks fields (`Commit`, `Date`, `Entropy`, `File`, lines and columns); nothing for dependency, malware and manual findings | per row | the latest on the finding; **on the pointer row whenever this occurrence's value differs from the finding's latest** | **kept**. The common case (the same trace, the same route, the same secret every run) costs nothing; a run that proved the finding through a different request or a different trace keeps its own. Presence reads the previous snapshot's pointer metadata, coalesced with the finding's, so the coverage decision sees what that snapshot had |
| First seen, last seen (repository) | per row, copied along | on the finding: earliest first-seen, latest last-seen | **kept** (the per-snapshot `detected_at` is the snapshot's own timestamp) |
| Branch history: when it appeared on a ref, how long it was carried, where the producer last reported it, when it left | the chain of copied rows of that ref's snapshots, plus `finding_resolutions` | the chain of pointer rows of that ref's snapshots (presence, reason, `last_seen_snapshot_id`, as-scanned severity), plus `finding_resolutions` | **kept**: the same facts in the same order, a few hundred bytes each instead of a copy. The timeline and the delta read pointers where they read rows. Retention bounds it exactly as today: a branch's history lives as long as its snapshots |
| EPSS, KEV, package signals, VEX | not stored on the row: looked up live by advisory or purl at read time | unchanged | **never kept, today or after**. The EPSS of a finding as it was on the day of a release or of a gate verdict is not recorded by either model; if a report or a verdict must be reproducible with the numbers it used, that is a record of the decision (the signed reports of ADR-031 and ADR-041), not of the finding, and this ADR neither creates nor removes it |

Everything a per-snapshot reader needs to say "what this snapshot had,
where, at the severity it had" stays on the pointer row, and the
`vulnerabilities` view coalesces it with the finding, so the UI, the
forge links and the VS Code extension keep reading the same columns
with the same meaning. Everything that is a
description of the finding or a decision about it lives once and keeps
its own history.

## Database

```sql
CREATE TABLE findings (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        uuid NOT NULL,
    repo_id       uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    type          vulnerability_type NOT NULL,
    fingerprint   text NOT NULL,
    -- the wide columns of today's vulnerabilities row, minus the
    -- per-snapshot ones listed in §2
    ...
    UNIQUE (repo_id, type, fingerprint)
);
CREATE TABLE snapshot_findings (
    snapshot_id          uuid NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    finding_id           uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    presence             smallint NOT NULL DEFAULT 0,
    presence_reason      smallint,
    consecutive_absences smallint NOT NULL DEFAULT 0,
    last_seen_snapshot_id uuid,
    reachability         smallint,
    file_path            text,                      -- only when it differs from the finding's (§6)
    start_line           integer,
    end_line             integer,
    location_hash        text,
    severity             severity_level NOT NULL,   -- as scanned (§6)
    cvss_tenths          smallint,                  -- CVSS × 10, as scanned
    confidence           text,
    severity_rank        smallint NOT NULL,
    metadata             jsonb,                     -- only when it differs from the finding's (§6)
    PRIMARY KEY (snapshot_id, finding_id)
);
CREATE INDEX snapshot_findings_finding_idx ON snapshot_findings (finding_id, snapshot_id);
CREATE INDEX snapshot_findings_rank_idx ON snapshot_findings (snapshot_id, severity_rank DESC);
```

Lifecycle: a `findings` row lives while any snapshot of its repository
points at it or triage references it (an acceptance, an open assertion, a
transition within retention); a collector in the retention pass deletes
the rest, after ADR-014 has deleted or rolled up the snapshots. The
rollup table of ADR-014 keeps its role for archived snapshots.

Sizing, the worst row of the Context table (about 2,850 snapshots a day
with 1,000 findings each): 2.85 M pointer rows a day, about 650 MB at
the blended 230 bytes, plus the new `findings` rows the day's pushes
introduced, which is the number of findings the repository has never
seen before, typically tens. Ten such monorepos write 28.5 M pointer
rows a day, about 6.5 GB, 330 inserts a second sustained and a few
thousand a second in a CI burst, which a single Postgres instance
absorbs on one narrow table with three indexes; the same traffic today
is 28.5 M wide rows, about 85 GB, against 23 indexes. With retention thinning pull requests within a week,
a steady state of a few million pointer rows and a `findings` table that
grows with the number of distinct findings the company has ever had,
which is the figure that actually matters to anyone.

## Rollout

1. Create `findings` and `snapshot_findings`; backfill `findings` from
   `vulnerabilities` grouped by (repository, type, fingerprint), taking the
   attributes of the newest row and the earliest `first_seen_at`; backfill
   the pointer rows; re-key transitions and comments. Replace
   `vulnerabilities` with the view. Readers unchanged.
2. Writers: the scanner (match set, upsert, stamp), scan reuse, SARIF
   ingestion, carry-forward, manual findings and assertions, triage.
3. The scan pass per inventory set; the bounded worker pool with
   per-set coalescing.
4. The findings collector in the retention pass.
5. Rewrite the hot readers against the tables, measured; drop the view
   when nothing reads it.

Steps 1 and 2 ship together (a view is not writable); 3 to 5 each stand
alone.

## Consequences

### What we gain

| | Today | After | Factor |
|---|---|---|---|
| Rows a snapshot writes per finding | 1 wide row, ~2 to 3 KB with 23 indexes | 1 pointer row, ~210 bytes with 3 indexes (~230 carried, up to ~500 when location or metadata differ) | ~12× less |
| Ten monorepos of the worst case (1,000 open PRs built twice a day, 40 release branches at 20 merges a day, 1,000 findings) | 28.5 M rows, ~85 GB a day | 28.5 M rows, ~6.5 GB a day | ~13× less |
| Ten monorepos of the likely case (second row) | 7 M rows, ~22 GB a day | 7 M rows, ~1.6 GB a day | ~13× less |
| Worst case, retained set with pull requests and release snapshots thinned in a week | ~600 GB | ~45 GB | |
| Finding rows an organisation-wide query reads | one per snapshot the finding lived through (3.3× on the dev corpus, hundreds on a PR-heavy repository) | one | the ratio |
| Matchings in the 6-hourly pass, per monorepo of 1,040 refs | ~1,040 | the distinct inventory sets, typically tens | ~20 to 100× |
| Post-upload scans in a burst with the same inventory | one full scan each | one matching, pointer stamps for the rest | |
| Comments and state transitions | on one snapshot's row, lost at the next copy | on the finding, visible from every snapshot | a defect fixed |
| A finding's id | one per snapshot copy: a link or an API call made today names a row the next push replaces | one per finding, stable across pushes; the three handlers that take a finding id keep working | |
| Index maintenance | 23 indexes updated per copied row, two of them trigram on free text | 3 narrow indexes per pointer row; the finding's indexes once | |

### What we lose or pay

- **Descriptive text is current, not as scanned.** Title, description
  and solution live once per repository; every branch's snapshots show
  the default branch's current wording, and a branch that never reaches
  the default branch keeps the wording of its first report. The rating and the per-run metadata are kept per snapshot
  (§6), so counts, trends, release reports and presence decisions do not
  change retroactively; the text does.
- **The storage win is twelve times, not sixty.** Keeping the as-scanned
  rating, the presence chain, a moved location and a differing
  `metadata` per snapshot is what makes the state table above read
  "kept" almost everywhere, and it costs a pointer row of about 210
  bytes rather than 80. A design that lost those would be five times
  smaller again and would lose trends, presence decisions and DAST
  evidence; the ADR takes the twelve.
- **One join more on every reader until step 5.** Per-snapshot reads
  become a pointer scan plus a primary-key lookup per finding; for the
  gate's and the drawer's few hundred findings that is noise, for an
  organisation listing of 100,000 findings it must be measured, which is
  why step 5 exists.
- **Every writer changes at once.** The scanner, scan reuse, SARIF
  ingestion, carry-forward, manual findings, assertions and triage all
  write the new tables in the same release (a view is not writable). The
  stale-marking step changes meaning from "set status resolved on this
  row" to "delete the pointer row and record the resolution", which is
  what ADR-034 says it means, but every test of ADR-034 and ADR-012 has to
  pass on the new writers before the release.
- **A backfill in one transaction**, grouping every existing row by
  identity and re-keying two tables.
- **Deleting a finding deletes its presence everywhere.** The collector
  only removes findings no snapshot and no triage record references, so
  this is a correctness property rather than a risk, but repository and
  organisation deletion now cascade through two tables instead of one.
- **Nothing for the small instance.** A team with twenty repositories and
  a few builds a day gains a smaller database and loses the frozen
  history, with no performance difference they could notice. The ADR is
  for the instance size in Context; it is not free.

## Alternatives considered

- **Retention alone.** Turning `auto_purge` on with pull-request thinning
  bounds the table and is the right first move on any instance. It does
  not change what a snapshot costs, depends on an operator setting, and
  keeps the copy semantics that lose comments.
- **Partition `vulnerabilities` by snapshot date.** Buys time on the
  aggregate queries and on vacuum; keeps the copies, the index cost and
  the per-snapshot scan pass.
- **Findings per inventory set**, mirroring ADR-045 exactly. Works for
  dependency findings, which are a function of the set, and not for code
  findings, which are a function of the commit; two models for one table
  is worse than one.
- **Keep the copy, intern the text.** Moving title, description and
  solution to a side table halves the row and leaves the multiplication.

## Open questions

- Reachability: per snapshot (chosen, since the classification reads the
  snapshot's code references) or per finding with a "latest" rule.
- Whether `severity_rank` on the pointer row is worth maintaining on
  severity overrides, or the per-snapshot sort should join `findings`.
- The retention of transitions and comments once a finding has no
  snapshot left: keep with the finding for the audit retention window
  (proposed), or delete with the finding.
