# ADR-016: Snapshot comparison for coverage and tests

## Status
Accepted

## Context
Hibou already lets users compare any two refs/snapshots of a repository for **security**:
the `GET /orgs/{provider}/{slug}/repos/{repoSlug}/compare?base=&head=` endpoint
(`handleCompareRefs`) returns a vulnerability delta (`internal/delta.ComputeDelta`) and an
SBOM component diff (`buildComponentDiff`). The `CompareView.vue` page renders those two
sections.

Security posture is only one quality signal. Reviewers and release managers also want to
know, when moving from one snapshot to another, whether **code coverage** and the **test
suite** improved or regressed — and they want it in the same place, without opening Codecov,
a CI dashboard, or three separate Hibou tabs.

Two concrete questions came up repeatedly:

- "Which files gained or lost coverage between these two refs, and by how much?"
- "Did someone add, delete, skip, or *significantly slow down* a test?"

Coverage (`coverage_reports` / `coverage_files`) and test data (`test_reports` /
`test_cases`) are already ingested per snapshot. The gap is purely in *comparing* two
snapshots and presenting the deltas.

## Decision

### Extend the existing compare endpoint
We extend the existing `compare` response rather than adding new endpoints, so the UI makes
a single request and the three signals stay visually and semantically aligned. The response
gains two optional objects:

- `coverage_diff`
- `test_diff`

Both are `null` when neither snapshot has the relevant data, so the UI can hide empty
sections.

### Pure diff logic in `internal/comparison`
Diff computation lives in a new `internal/comparison` package as pure functions
(`BuildCoverageDiff`, `BuildTestDiff`) operating on plain inputs, with no database access.
This follows ADR-005 (internal package architecture) and keeps the logic unit-testable in
isolation. The server handler loads rows from the store and feeds them in.

### Coverage diff
- **Identity** is `file_path`.
- Snapshot-level totals come from the **primary** coverage report per snapshot — the report
  with the most `lines_valid` — mirroring how `CoverageTab` already picks a primary report
  when multiple formats exist. This avoids double-counting overlapping formats.
- Per-file classification:
  - `added` — present only in head.
  - `removed` — present only in base.
  - `improved` — line rate increased beyond a small epsilon.
  - `regressed` — line rate decreased beyond a small epsilon.
  - `unchanged` — within epsilon.
- We surface base/head line rate, covered/valid line counts, and the per-file and overall
  line-rate delta. Unchanged files are summarized as a count (not listed) to keep payloads
  and the UI focused on what moved.

### Test diff
- **Identity** is `suite | classname | name`.
- Report-level totals (total/passed/failed/skipped/errors and total duration) are diffed so
  the UI can show suite-wide deltas.
- Per-case classification:
  - `added` — only in head.
  - `removed` — only in base.
  - `status_changed` — same case, different status (e.g. `passed -> skipped`,
    `failed -> passed`).
  - `slower` / `faster` — same status but a **significant** duration change (see heuristic).
- A case is reported under at most one bucket; status change takes priority over a timing
  change.

### Timing-significance heuristic (proportional)
"A lot slower" is proportional, not absolute, but a purely relative threshold makes
millisecond unit tests noisy. We combine both:

A duration change is significant when:
- `abs(head - base) >= ABS_FLOOR_SECONDS` (default `0.05s`), **and**
- one of:
  - `base > 0` and `abs(head - base) / base >= REL_THRESHOLD` (default `0.50`, i.e. 50%), or
  - `base <= SMALL_BASE_SECONDS` (default `0.01s`) and `head >= NEW_COST_SECONDS`
    (default `0.20s`) — a test that went from ~free to noticeably expensive.

Constants live in the `comparison` package so they are easy to tune and are covered by
tests. This directly addresses the goal of flagging changes that materially increase
execution time while ignoring sub-threshold noise.

## Consequences
- The single `compare` endpoint now returns security, coverage, and test deltas together;
  one request powers the whole page.
- `internal/comparison` is pure and unit-tested; the server handler stays thin (load rows,
  call builders, serialize).
- Coverage totals intentionally use a single primary report per snapshot; mixing formats is
  out of scope and would require coverage-merge semantics we do not yet have.
- The timing heuristic is a deliberate, tunable default rather than a configurable gate.
  Promoting it to a `.hibou.yaml` quality gate (fail a PR on large test-time regressions) is
  a natural follow-up but is not part of this ADR.
- Per-file `unchanged` coverage rows and unchanged test cases are summarized as counts to
  keep the payload proportional to what actually changed.
