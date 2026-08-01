# ADR-019: New-code coverage lens (forge-computed old/new classification)

## Status
Proposed

## Context

The coverage diff answers "how did coverage move between two snapshots", but
reviewers think in terms of **new code vs old code**: "is the code this change
introduced tested?" matters on every review, while the absolute number mostly
reflects history nobody is editing. Today only the PR compare shows a
new-code signal (ADR-018 patch coverage); the branch↔branch coverage diff and
the coverage tab treat every line as equal, and the annotated source view
cannot say which lines are recent.

Two ways to know which code is new:

1. **Compute it ourselves** — clone, `git diff` / blame, classify lines.
   Costs a clone per view or a per-line blame store, exactly the disk/CPU class
   of work the worker guardrails exist to bound, and it rots (blame changes on
   every push).
2. **Ask the forge** — `Provider.ComparePatch(owner, repo, base, head)`
   already fetches the compare between two commits and parses the changed
   new-side line numbers per file (built for ADR-018). The forge has the diff
   pre-computed; commits are immutable so the answer is cacheable forever.

## Decision

**New code is defined relative to the comparison the user is already looking
at, and the forge computes it.** No clone, no blame table, no second source of
truth: `changed lines of base..head` *is* the new code of that view.

### One classification, three surfaces

`ComparePatch(base_sha, head_sha)` yields `changed: map[path][]line`. Every
coverage surface reuses that one map:

1. **Coverage diff (compare page, branches or PRs).** Each file row gains
   `new_lines`, `new_covered`, and a `new_line_rate`; the header gains the
   aggregate — this is patch coverage generalized beyond PRs. The existing
   file-level movement (improved/regressed) stays; the new-code columns answer
   the question the movement number can't.
2. **Annotated source & diff views.** Lines carry `is_new` in the comparison
   context. The four-color scheme already used on PR patch files applies
   everywhere: green covered, red uncovered, **blue new-covered, orange
   new-uncovered** — old code stays muted so new code pops.
3. **Gate.** `coverage.diff_minimum` already evaluates patch coverage on PRs;
   no change, it simply becomes one instance of the general lens.

### UX: the lens is a toggle, not a mode

- The compare page's coverage tab gets a **"New code only"** toggle
  (default **on** for PR comparisons, off for plain branch comparisons):
  filters the tree/list to files with changed lines and swaps the headline to
  new-code coverage. One click back to the full picture — never a separate
  page, never a config file.
- The single-branch coverage tab gets a **baseline selector** ("New code
  since: <ref or tag>") reusing the existing ref selector. Picking a baseline
  runs the same forge compare between the baseline's latest snapshot commit and
  the current head. Default: no baseline, classic view — teams that want a
  SonarQube-style "since last release" pick their release tag once (persisted
  per user in the URL, later in `.hibou.yaml` `coverage.new_code_baseline`).
- Empty states must say why: "no measurable new code in this comparison"
  (docs-only change) rather than 100% or —.

### Cost and caching

One compare API call per (base_sha, head_sha) pair. Both endpoints are
immutable inputs → cache the parsed changed-line map in the existing
Postgres-backed advisory-cache pattern, keyed `(provider, repo, base_sha,
head_sha)`, no TTL needed, evicted with snapshot retention. First page load
pays one forge round-trip; everything after is a cache hit. This also
absorbs GitHub's 300-file compare truncation: the truncated flag is stored and
surfaced ("new-code stats cover the first N files"), same as ADR-018.

With installation-token authentication now applied to repo-level REST calls
(cached per owner), the compare call runs against the App rate limit
(thousands/hour), not the anonymous 60/hour that made source fetches flaky.

## Alternatives rejected

- **Local clone + diff per view**: disk/CPU on request-serving pods, the exact
  load class ADR-015 pushes to workers; and it re-does work the forge already
  did.
- **Per-line age/blame storage**: a large mutable table invalidated by every
  push; answers "how old is this line" when the product question is only
  "is it part of what I'm reviewing".
- **CI-computed diffs uploaded as artifacts**: burdens every CI pipeline and
  drifts from the forge's own truth (force-pushes, rebases).

## Consequences

- GitLab/Forgejo `ComparePatch` are still stubs; the lens degrades to the
  classic view there until they are implemented — same degradation path as
  ADR-018, one method to fill in per forge.
- The compare-patch cache is the first immutable-keyed cache; retention must
  delete rows when either snapshot is purged.
- The coverage tab's baseline selector adds one query parameter and no schema
  change in phase 1; `.hibou.yaml` persistence is phase 2.
