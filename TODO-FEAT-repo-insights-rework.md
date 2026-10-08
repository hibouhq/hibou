# Repository Insights: Repair and Useful Redesign

Status: initial implementation completed on 2026-10-07; remaining evidence work is listed below.

## Implemented Scope

- Backend-shaped `vulns_*`/`findings_*` contracts, strict numeric validation, request error/retry, stale-response guard, and single-observation support.
- Chart.js timestamp axis, 7/30/90-day windows, observed date range, observation table, and exact-snapshot finding links.
- Neutral component deltas and separate dependency/code finding totals, including informational findings.
- Nullable current KEV risk counts in repository/organization Overview and Insights; zero remains visible, unknown is unavailable, partial org evidence shows a lower bound.
- KEV drill-down uses server-side `risk_only=true` before pagination, preserving accepted risks and disputed suppressions while excluding false positives and resolved findings.
- Organization repository rows show KEV counts; urgency sorting keeps malware and KEV distinct from severity.
- GitHub-style repository underline tabs with a responsive disclosure, a single topbar organization/repository identity, and a modal navigation drawer.

Remaining: readiness-aware historical points, retained baseline/truncation metadata,
batch trend aggregation, historical change attribution, and optional coverage/test
series. Current KEV membership is not plotted as a historical series. No synthetic
health or compliance score was added. Browser screenshots and interactive focus
verification still require a working browser runtime; component/contract tests,
lint, and typechecking are executable in the current container.

## Purpose

Repository Insights should answer four practical questions:

1. Is risk increasing or decreasing on the default branch?
2. Which urgent findings still need action, especially KEV, malware, and secrets?
3. Are the measurements complete, comparable, and recent enough to trust?
4. Which scans or changes explain a movement, and where can I investigate it?

Keep Overview for the latest snapshot, Vulnerabilities for triage, and Insights
for changes over time. Do not duplicate the whole findings table or organization dashboard.

## Confirmed Problems

These observations come from source inspection, not a live production reproduction.

| Priority | Problem | Evidence | Consequence |
| --- | --- | --- | --- |
| P0 | API field names do not match the frontend | [TrendPoint and getTrends](site/src/api/client.ts) and [InsightsTab](site/src/views/repo/InsightsTab.vue) use `vuln_critical`, etc.; [trendPointResponse](internal/server/repos.go) emits `vulns_critical`, etc. | Undefined values produce NaN totals, invalid SVG coordinates, and missing numbers. |
| P0 | Request failures look like insufficient history | Insights catches every error and clears `points`. | A 403, 404, or server failure looks like a normal empty repository. |
| P1 | The visible history is not a calendar window | Frontend requests the latest 60 snapshots with no `since`. | A busy repository shows hours while a quiet one shows months; deltas are not comparable. |
| P1 | Chart spacing does not represent time | `xAt` uses array index. | Scans minutes apart and weeks apart occupy equal space, hiding stale periods. |
| P1 | Charts omit axes, values on hover, and drill-down | Hand-built SVG polylines have unlabeled grid lines and no point interaction. | Users cannot identify when a change occurred or which scan caused it. |
| P1 | One snapshot has no meaningful trend rendering | A polyline with one point has no visible segment. | Existing data can look like a blank chart. |
| P1 | Dependency count changes are presented as good/bad | `componentsDelta <= 0` is considered good. | Removing instrumentation or uploading a smaller SBOM can look like improvement. |
| P1 | Historical points use today's triage decisions | Handler fetches active acceptances and disputes once and applies them to all snapshots. | Old values change after triage; this is not an immutable record of past decisions. |
| P1 | Metric scope is unclear and incomplete | Backend separates `findings_*` and `vulns_*`; page consumes only the latter. Trend counting excludes secret/manual types and treats container findings outside dependency vulnerabilities. | "Open vulnerabilities" is not the total risk shown elsewhere in the repository. |
| P1 | Snapshot eligibility does not prove dependency scan readiness | Trends include complete/active snapshots, without checking advisory scan readiness for each point. | A completed artifact upload with pending/failed advisory analysis can resemble zero dependency risk. |
| P2 | Scan cadence promised by the earlier plan is absent | [Previous Insights plan](TODO-FEAT-insights-settings-tabs.md) marks scan cadence complete, but the current view has only risk and component charts. | Users cannot tell whether apparent stability is simply lack of scanning. |
| P2 | Responses can race when switching repositories | Watcher has no cancellation or latest-request guard. | An older request can replace data for the newly selected repository. |

## Recommended First Screen

Use the existing repository shell and its visual language. Keep Insights a
repository-level tab, not a snapshot-level tab. Start with the default branch;
show its actual name and do not imply that the hidden global ref selector applies.

```text
Insights                         main    [7d | 30d | 90d]    refreshed ...
Latest usable scan ...           evidence: complete / partial / stale

Open risk     Critical + high     Known exploited     Accepted risk
value + delta value + delta       current value       current value

Risk over time                         [Dependencies | Code findings]
labeled time/count axes, gaps, points, tooltips, baseline/end markers

Changes in this period
introduced / no longer observed / reintroduced / triage / catalog changes
dated rows, finding or snapshot links, source attribution

Scan evidence
last usable scan, gaps, missing sources, provider failures, sampled history

Dependency footprint
component count and changes, neutral colors, SBOM availability
```

Use compact metric strips and full-width sections, not a wall of floating cards.
On mobile, wrap controls, stack metrics, and allow horizontal scrolling only
inside the event table. Use existing Chart.js and vue-chartjs instead of adding
another chart dependency or maintaining a custom chart engine.

## Metric Rules

| Metric | Definition | Interaction |
| --- | --- | --- |
| Open risk | Findings still considered real risk under the shared repository triage rules; accepted risk remains risk, false positives are excluded, suppression disputes count. Explicitly expose type breakdown. | Open Vulnerabilities with matching branch and filters. |
| Critical + high | Same risk population, restricted to those severities. | Open filtered findings. |
| Known exploited | Current open risk matching any enabled KEV catalog, deduplicated by finding fingerprint. A catalog removal is not proof that exploitation stopped. | Open exploited findings, not a generic source homepage. |
| Accepted risk | Open risk with an active risk-accepted decision; not counted as fixed. | Open accepted-risk findings. |
| Introduced / no longer observed | Fingerprint differences between comparable snapshots, not subtraction of aggregate totals. "No longer observed" is not automatically "fixed". | Exact snapshot comparison and finding history. |
| Dependency footprint | Comparable SBOM component counts; increases and decreases are neutral. | Dependencies for the relevant snapshot or comparison. |
| Scan freshness | Age of the latest usable measurement, plus actual provider/artifact readiness. | Snapshot evidence or existing scan detail surface. |

Do not label every severity series as vulnerabilities. Keep dependency
vulnerabilities, code findings, malware, secrets, and manual findings explicit.
Reuse shared risk semantics rather than inventing another classification in Insights.

### Historical Meaning

For the first release, show observed snapshot counts evaluated with current
triage, and return that basis explicitly in API metadata. Do not present these
values as what the gate decided at the time. A triage change may affect old points.

Keep dated triage and catalog events separate from observed scan changes. Do not
derive a historical KEV trend from current catalog membership. Historical gate
verdicts, if later added, must use persisted checks rather than recomputation.

Risk-accepted findings remain part of risk. A waiver or false-positive decision
must never create a "fixed by code" event. Reclassification, scanner changes,
and newly published advisories must not be silently attributed to a commit.

## Data and API Plan

### Phase 1: Make the Existing Page Trustworthy

- Align frontend types and consumers with backend `vulns_*` and `findings_*` fields.
- Add a contract test using an actual backend-shaped JSON fixture. Typechecking alone cannot catch this mismatch.
- Separate loading, request failure with Retry, zero history, one usable snapshot, and multi-snapshot states.
- Render one snapshot as current values with a point/table, not an empty trend or invented delta.
- Use actual timestamps on the X axis and labeled counts on the Y axis.
- Keep component deltas neutral and label the actual first/last dates and snapshot count.
- Prevent stale requests from overwriting a new repository's state.

### Phase 2: Add Useful Evidence and Navigation

Extend the authorized repository trends response, or introduce a narrowly scoped
repository Insights endpoint if the response becomes more than trend points.
Decide the shape before adding unrelated fields to `TrendPoint`.

Required response concepts:

- Repository/default-ref identity and server evaluation time.
- Requested period, actual covered period, truncation/sampling flags, and a baseline before the period when available.
- Snapshot ID, commit SHA, observation timestamp, and readiness per measurement domain.
- Separate severity counts for the agreed finding groups, with explicit counting unit.
- Artifact/provider evidence states; unknown metrics are null, not zero.
- Current urgency summary and bounded, repository-matched change events.
- Metric basis such as current triage, retained scan observations, and current catalog membership.

The existing API already supports `ref`, `since`, and `limit`. Reuse those for
the first repair, but do not silently call a truncated 60-point result "30 days".
Calendar ranges need an upper bound, a retained baseline, and explicit truncation.
If a range has no new scans, show the last known observation with its age rather
than manufacturing daily samples or implying zero findings.

For dependency counts, artifact processing completion and advisory scan completion
are separate checks. Reuse the existing scan-readiness rules. Coverage-only or
SARIF-only snapshots must not become zero-valued dependency observations.

Batch aggregation over the selected snapshot IDs should replace the current
per-snapshot full finding read and component count as the range grows. Bound
work, use repository/ref indexes, and avoid one request per chart point or finding.
Cache only with a key/invalidation strategy that includes snapshot ingestion,
triage changes, rescans, and catalog updates where those affect results.

All links must preserve repository, ref, and exact snapshot IDs. Do not send a
historical chart click to today's default snapshot. Read authorization remains
server-enforced; do not expose the admin audit log as a member-visible event stream.

### Phase 3: Optional Signals, Only With Reliable Evidence

- Coverage and test trends, with missing reports shown as gaps and coverage deltas in percentage points.
- Fix lead time and finding age, only after first-observation, reintroduction, and censoring rules are defined.
- Persisted gate history, separated from scans without a published verdict.
- Export of the displayed series/table after the counting semantics are stable.

Do not add a synthetic health score, compliance percentage, leaderboard, predicted
exploitation score, or MTTR based on accepted risks. Defer multi-branch comparisons
to the existing Compare workflow rather than blending unrelated refs into one line.

## Implementation Order

1. Repair the JSON contract and error states first; keep scope in the current view and trend tests.
2. Replace chart plumbing with the existing chart library, add timestamp axes, point tooltips, and snapshot links.
3. Add calendar windows, explicit evidence readiness, baseline/truncation metadata, and batch aggregation.
4. Add the urgent-risk strip and source-attributed change table using repository-scoped queries.
5. Add optional coverage/tests only after scan and risk series are correct.

This proposal supersedes the repository Insights completion claim in the earlier
plan, not its Settings or organization Insights work. No changes to those surfaces
are required for the first iteration.

## Acceptance Checks

- Backend-shaped payload renders finite values and valid chart coordinates.
- HTTP failure is distinguishable from no scans; Retry works without losing selected period.
- No scans, one scan, all-zero scans, and many scans each render correctly.
- Irregular scan times occupy proportional time-axis positions.
- Info findings appear in totals and breakdowns, even if their series is hidden by default.
- Missing SBOM, pending advisory scan, failed provider, and absent coverage remain unknown/gaps, not healthy zeros.
- A coverage-only snapshot cannot create a fake dependency-risk drop.
- Current and trend population differences are explicit and tested across finding types.
- Acceptance, expiry, false-positive, and suppression-dispute changes follow shared semantics.
- KEV listing/removal is source-attributed; present-day KEV data is never portrayed as a historical series.
- Partial periods and retention gaps report baseline availability and truncation honestly.
- Drill-down opens the exact finding/snapshot comparison, and remains repository-scoped.
- Slow previous-repository responses cannot replace the active repository's results.
- Member access does not expose admin-only audit entries; inaccessible repositories return no data.
- Desktop and mobile support keyboard-accessible chart alternatives, readable labels, and no page-level overflow.
- Contract, aggregation, interaction, and missing-evidence tests precede release; no schema migration is assumed for Phase 1.