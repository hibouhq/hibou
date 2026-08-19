# ADR-026: In-source suppressions — native scanner directives, justification as the triage comment

## Status

Accepted — implemented (2026-08-19). Extends the scanner-suppression pass of
[ADR-023](023-triage-acceptance-ux.md) (migration `00015`, `suppressions[]`
parsing, `-track-suppressions`).

Implementation notes:

- Repo-wide conversion of `//nolint:gosec` → `// #nosec <RuleID…> -- <reason>`
  across 38 files (103 directives; 2 left in `internal/provider/osv/osv.go`
  where no rule fires and no rule ID was named — removal candidates). Rule IDs
  per site taken from the gosec SARIF, falling back to the rule ID written in
  the directive's explanation; no blanket `#nosec` introduced.
- `ListFindingTransitions` (queries/vulnerabilities.sql) selects
  `metadata #>> '{suppression,justification}'`; `scanHistoryEvent`
  (internal/server/finding_history.go) attaches it as `detail.comment` on the
  suppressed transition; `FindingTimeline.vue` already renders
  `detail.comment`, so no frontend change.
- Verified with gosec v2.27.0: before the conversion 169 active SARIF results
  and 0 suppressed; after, 46 active (all pre-existing findings that never had
  a directive) and 123 suppressed, every one carrying its justification.
  `make lint` 0 issues.

## Context

Commit `031236f` suppressed the G122 finding on
`internal/callgraph/java.go:55` with:

```go
file, err := os.Open(path) //nolint:gosec // G122: CI-side scan of the caller's own checkout; no trust boundary.
```

`make lint` went green, but hibou kept reporting the finding as open. The two
tools that scan this repo speak different suppression dialects:

| Directive | Understood by | Role in this repo |
|---|---|---|
| `//nolint:gosec // reason` | golangci-lint only | `make lint` (CI Lint step) |
| `// #nosec G122 -- reason` | gosec itself, and golangci-lint's embedded gosec | CI Security suite → SARIF → hibou |

The finding hibou displays comes from the Security suite, which runs the
**standalone gosec binary** (`gosec -track-suppressions -fmt sarif ./...`).
Standalone gosec only recognizes its own `#nosec` directive; `//nolint` is a
golangci-lint convention, filtered by golangci-lint after gosec runs embedded
in it. The standalone binary never sees the nolint comment, so the SARIF
result was emitted as a plain active finding with no `suppressions` property
at all. Hibou's ingestion (ADR-023) was not at fault — it was never handed a
suppression.

Reproduction with gosec v2.27.0 on an `os.Open(path)` inside a `WalkDir`
callback:

| Comment form | G122/G304 in SARIF |
|---|---|
| `//nolint:gosec` | active, no suppression |
| `//nolint:gosec // G122: justification` | active, no suppression |
| `// #nosec G122 G304 -- justification` | suppressed, `kind: inSource`, justification carried |

Every one of the repo's 103 `//nolint:gosec` directives had this failure mode,
invisible because golangci-lint honored them and lint stayed green. Note also
that one line can fire several rules — `java.go:55` fires G122 **and** G304 —
so a directive must name every rule it means to suppress.

Separately, backlog item: when a developer suppresses in code, the reason they
write after the directive is the triage comment — it should appear as the
comment of the finding's state change, not stay buried in source.

## Decision

1. **gosec findings are suppressed with `// #nosec <RuleID…> -- <reason>`,
   never `//nolint:gosec`.** `#nosec` is honored by both pipelines
   (standalone gosec and golangci-lint's embedded gosec), so one directive
   serves both. Always name the exact rule IDs (a bare `#nosec` suppresses
   every rule on the line) and always write a reason after `--` — gosec
   carries it into the SARIF as `suppressions[].justification`.
   `//nolint:<linter>` remains for linters that exist only inside
   golangci-lint (the split sites in `internal/rbac/adapter.go` pair
   `// #nosec G202 -- …` with `//nolint:perfsprint // …`).

2. **The in-source justification becomes the comment of the state change.**
   The scan-observed `suppressed` transition in the finding timeline carries
   the justification the scanner extracted, rendered exactly like a UI triage
   decision's comment. This keys on SARIF's standard
   `result.suppressions[].justification` (§3.35.3), not on anything
   gosec-specific: any tool that records in-source suppressions in its SARIF
   (semgrep, ESLint, checkov — already classified by `internal/sarif`) gets
   the same timeline comment with no further code.

## Consequences

- The suppressed state and its reason now travel end to end: directive in
  code → SARIF justification → ingest metadata → timeline comment. A reviewer
  reads why a finding is suppressed without opening the source.
- Findings suppressed by this conversion flip to `suppressed` on the first
  scan of a commit containing it.
- The 46 remaining active gosec findings never had a directive; they are open
  triage work, not conversion leftovers.
- Tools whose SARIF marks a suppression `inSource` but leaves `justification`
  empty (semgrep `# nosemgrep`, eslint-disable) show a suppressed transition
  without a comment. Extension point, tracked in backlog.md: extract the
  trailing comment from the source line at ingest time.
- **An in-source suppression cannot be reopened from the UI — by design.**
  UI "Reopen" undoes an *acceptance*: the human axis of ADR-023's two-axis
  model, fingerprint-keyed, owned by hibou. `suppressed` is the machine axis —
  the observation status every scan re-asserts from the directive in the code.
  A UI reopen would be overwritten by the next scan; the real reopen is
  removing the directive and rescanning. The recourse is the **dispute**
  (implemented 2026-08-19): a fingerprint-keyed human-axis override in its own
  `finding_disputes` table (migration `00030`) — deliberately NOT an
  acceptance reason kind, because an acceptance row means "not gating" and a
  consumer that forgot a special case would silently turn a dispute into a
  suppression; with a separate table a forgotten join degrades to "dispute not
  surfaced", never to "gate wrongly passes". A disputed suppression renders as
  "Disputed", counts as open risk, and gates again until the directive is
  removed or the dispute withdrawn. Wiring: PUT/DELETE
  `vulnerabilities/{vulnID}/dispute` (422 on non-suppressed findings, reason
  required, audited as `finding.dispute`, gate recomputed immediately); the
  delta drops suppressed-undisputed rows from both sides of the diff — which
  also fixes a pre-existing bug where a NEW `#nosec` finding counted against
  the weakness gate, violating ADR-023; risk counts and trends treat
  suppressed-disputed as open; the finding drawer shows the suppression
  (justification, `file:line`, "remove the directive to reopen") with
  Dispute/Withdraw as its only triage verbs — Accept is not offered on
  suppressed findings. An org/repo policy "in-source suppressions require
  approval before they stop gating" remains future work (backlog.md).

## Alternatives considered

- **Run gosec through golangci-lint so `//nolint` works.** Loses
  `-track-suppressions` and the SARIF pipeline hibou ingests; suppressed
  findings would vanish instead of being visible-but-suppressed (ADR-023's
  explicit goal).
- **Keep both directives on each line.** Redundant, drifts, and nolintlint
  would demand explanations on directives that exist only as duplicates.
- **Teach gosec a custom tag (`-nosec-tag nolint:gosec`).** The tag match is
  textual; rule scoping and justification parsing break on the
  `//nolint:gosec // G122: …` comment shape, degrading to blanket
  suppressions without justifications.
- **A hibou-side source parser to honor nolint at ingest.** Duplicates
  scanner semantics hibou would then own forever, for every tool; the
  scanners already do this extraction correctly when given their native
  directive.
