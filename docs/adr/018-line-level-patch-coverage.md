# ADR-018: Line-level patch coverage

## Status
Accepted

## Context
ADR-008 defined coverage ingest and a PR coverage *delta* at the file level, and ADR-016 added
a file-level `coverage_diff` to the compare endpoint (added/removed/improved/regressed by
per-file line rate). Neither answers the question reviewers actually ask on a pull request:

> "Of the lines this change *added or modified*, which ones are untested?"

That is **patch coverage** (a.k.a. diff coverage) — the headline number Codecov and SonarQube's
"new code" view show. It needs two things the platform did not yet have:

1. **Per-line hit data.** Coverage parsers extracted per-line hits from every format
   (Cobertura `<line>`, LCOV `DA:`, JaCoCo `<line>`, Go cover blocks) and then discarded them;
   only aggregate per-file counts were stored.
2. **The set of changed lines.** The forge clients could open a PR but not fetch its diff, so
   there was no way to know which lines a PR touched. ADR-008's `diff_minimum` gate had nothing
   to evaluate against.

## Decision

### Persist per-line hits (opt-out)
`coverage.FileCoverage` gains `Lines []LineCoverage{Number, Hits}`, filled by all four parsers
(deduped by line number, max-hits-wins). A new `coverage_lines(coverage_file_id, line_number,
hits)` table (migration `00024`) stores them sparsely — only instrumented lines; `hits = 0`
means instrumented-but-uncovered, an absent line means not instrumented. Persistence is gated
by `HIBOU_COVERAGE_STORE_LINES` (default **on**); very large monorepos can opt out. This is the
only real storage cost and it is explicit, never silent. Rows are replaced per file on
re-upload so a shrinking report never leaves stale lines.

### Fetch the changed lines from the forge
`Provider.ComparePatch(owner, repo, base, head)` fetches the diff between the two snapshot
commits. GitHub uses the compare API and parses each file's unified-diff `patch` into the
new-side line numbers a change added or modified; it also carries the raw hunk text through
(see "Annotated diff" below). GitLab/Forgejo are no-op stubs for now, so patch coverage simply
degrades to the existing file-level diff. This reuses the transient installation token and adds
zero CI-side work (cf. ADR-017 PR-ref resolution).

### Compute patch coverage as a pure function
`comparison.BuildPatchCoverage(changes, headLines, exclude, truncated)` intersects the PR's
changed lines with the head snapshot's per-line hits (primary report, mirroring
`BuildCoverageDiff`). Only **instrumented** changed lines count — an added blank line, comment,
or a file with no coverage is not measurable and is excluded from the ratio, so the number
matches what a reasoning reviewer would compute by hand. `coverage.exclude` globs are honored.
The result is `nil` when nothing is measurable (e.g. a docs-only PR), letting the UI show "—".

**Path reconciliation** is the subtle part: coverage tools emit paths at different roots (Go
cover profiles carry the module path; JaCoCo the package path) while the forge diff is
repo-root-relative. Matching is exact-first, then longest-common-suffix by path segment, which
reconciles module/package prefixes without cross-matching same-basename files in other
directories. This is the most likely source of a wrong-but-plausible number and is covered by a
decoy-basename regression test.

### One request, on the existing compare endpoint
Patch coverage rides the existing `compare` response as `patch_coverage` (ADR-016's "one
request powers the page"). The PR branch of the handler fetches the patch, loads head per-line
hits, and computes it. The `min_coverage` / `grace` / `diff_minimum` coverage gate (previously
dead config) is evaluated in the same pass and merged into the existing quality-gate reasons.

### Annotated diff without storing source
The raw unified-diff hunk text the forge already returned is passed straight through to the
client next to the covered/uncovered line sets. The client renders the annotated diff by tinting
each added line. This avoids a second forge round-trip, avoids storing source, and avoids the
browser needing forge credentials (which it does not have — tokens stay server-side). Only diff
hunks are needed, never full-file blobs.

## Consequences
- One `compare` request now returns security, file-level coverage, **patch coverage**, and test
  deltas together.
- Per-line storage is the one new cost; it is bounded to instrumented lines and opt-out.
- Coverage quality gates (`min_coverage`, `grace`, `diff_minimum`) are finally enforced.
- Posting a coverage **status check / PR comment** from the annotator is a follow-up: the
  annotator is being reworked by the forge-native PR-checks effort and this should build on it.
- Deferred: branch-level patch coverage (needs a per-line `branch` flag), indirect coverage
  changes (per-line on both snapshots), and GitLab/Forgejo `ComparePatch`.
