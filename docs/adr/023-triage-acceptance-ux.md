# ADR-023: Triage = Accept or Reopen, with acceptance reasons

## Status

Proposed (2026-08-05). Supersedes the three-way triage actions in the
vulnerabilities views; feeds [TODO-FIX-gate-triage-notifications.md](../../TODO-FIX-gate-triage-notifications.md).

## Context

Triage today exposes **three peer actions** per finding — *Accept risk*,
*False positive*, *Reopen* — and "false positive" doubles as a **status**.
Dogfooding shows the model failing on every axis it was meant to serve:

- **UI**: three buttons per row truncate ("Accept risk…", "False positi…"),
  the status chip wraps and breaks, and a 400-row table becomes a wall of
  buttons. Bulk triage multiplies the mess.
- **Model**: "false positive" and "accepted" are the same *decision* — "the
  gate must ignore this finding" — with different *justifications*. Modeling a
  justification as a status forks every downstream consumer: filters, gate
  evaluation, VEX export, compliance reports, and the delta view each need to
  know that two statuses mean "dismissed".
- **Escape hatch rot**: because triage felt heavy, the PR gate grew a manual
  *override* — an unaccountable, finding-less "make it green" switch that
  contradicts the provenance/audit story of ADR-020. It is being removed.

## Decision

Triage has two orthogonal axes, and only one of them belongs to humans:

```
observation (machine-owned):  detected ⇄ resolved       — the scanner sees it, or no longer does
decision    (human-owned):    open ⇄ accepted           — the only triage transition, both directions
reason      (on accept):      risk_accepted | false_positive   (required WHY — closed enum)
labels      (on accept):      free-form tags                   (organization — open, no semantics)
```

**`resolved` is a status, never a button.** It is derived from scans (a new
snapshot stops reporting the fingerprint) and cannot be set by hand — the old
model's confusion came precisely from mixing observations and decisions in one
status field. A finding can be resolved-while-open (fixed before anyone
triaged it) or resolved-while-accepted (fixed anyway); the acceptance is
fingerprint-scoped and stays **dormant on resolve**, so a reappearing finding
resurfaces with its old decision instead of demanding re-triage.

**Why the reason enum is closed and labels are open.** `reason_kind` encodes
*behavior* — every row of the semantics table below is machine-decidable only
because the kinds are finite. Tracking needs are served by **labels** instead:
free-form tags on the acceptance (`waiting-upstream-fix`, `q3-review`,
`team-payments`) that filter, group, and export but never change what the
gate, VEX, or risk reporting do. If org-specific kinds ever become a real
need, the extension point is org-defined kinds that must *map onto* one of
the two base semantics — never a third behavior.

**Secrets are exempt from resolve-by-absence.** A leaked secret is not fixed
when the line disappears — the value is compromised until a human verifies
revocation/rotation. Invariant: `type=secret` findings **never** auto-resolve
from scan absence; resolution is an explicit, audited attestation. This is
already the code's philosophy (only the human `revoked`/`rotating` states map
to `resolved`, and history-walking scans keep detecting past leaks) — this
ADR makes it a rule no future "cleanup" may break. In the UI it costs no
third button: the split menu is type-aware, so for secrets it reads
**Mark revoked** (→ resolved, attested) / *Accept risk* / *False positive*
(test fixture, dummy value). A secret vanishing from a PR diff may appear in
the diff's "resolved" column (that is a statement about the diff); the repo's
finding stays open until attested.

**Scanner-native exclusions** (`.gitleaksignore`, `nosemgrep`,
`.trivyignore`): for most tools the finding silently disappears from output,
which Hibou cannot distinguish from a fix — v1 reports it as `resolved`
(**except secrets**, per the invariant above), documented caveat. The lie is
at least symmetric and self-correcting: adding an ignore reads as resolved;
*removing* it makes the finding reappear under the same fingerprint —
re-opened as detected, with any dormant acceptance resurfacing automatically. SARIF's `suppressions[]` is the escape from that lie, and
it is real: see the per-tool table in the appendix (verified by running the
tools). Two hard consequences:

1. **Parser requirement (bug today)**: tools that emit suppressed results —
   ESLint's SARIF formatter does it *by default*, gosec with
   `-track-suppressions` — currently get those ingested as **open findings**,
   because `internal/sarif` does not parse `suppressions[]`. The parser must
   read it; a result with a non-empty, non-rejected suppression maps to the
   `suppressed` observation state (kind + justification preserved), never to
   an open finding. Empty array = active (that is SARIF semantics, not
   absence of data).
2. Guidance stays: triage in Hibou, not in scanner configs — one is
   auditable and gate-aware, the other is invisible (and for gitleaks/trivy,
   *provably* invisible — see appendix).

## Appendix — scanner suppression behavior in SARIF (verified 2026-08-05)

Every row except CodeQL was **verified by experiment** in this repo's
devcontainer: one suppressed + one active finding, SARIF inspected.

Two mechanisms must never be conflated:

- **Occurrence-level exclusion** — "this specific detected finding, here, is
  fine" (`#nosec`, `nosemgrep`, `eslint-disable`, `checkov:skip`,
  `.gitleaksignore` fingerprint). The finding *was detected*; SARIF
  `suppressions[]` exists exactly for this, and it is the only thing that can
  map to Hibou's `suppressed` observation state.
- **Rule/path/config-level exclusion** — "never evaluate this rule / this
  path" (`gosec -exclude=`, ESLint rules config, `.semgrepignore`,
  `--skip-check`, trivy severity filters, removed rules). Nothing is ever
  detected, so *no tool can and no tool does* leave a SARIF trace —
  **invisible by nature, universally** (verified for `.semgrepignore`: the
  finding simply does not exist in the output). That is config-review
  territory, not triage.

### Occurrence-level exclusions, per tool

| Tool (version tested) | Inline mechanism | Suppressed finding in SARIF? | `suppressions[]` detail | Status |
|---|---|---|---|---|
| **semgrep** (1.172.0) | `# nosemgrep[: rule]` | **included by default** | ✅ `kind:inSource` — no justification text carried | **verified** |
| **ESLint** (10.8.0 + MS formatter 3.1.0) | `eslint-disable*` | **included by default** | ✅ `kind:inSource` + justification from the `--` comment; active results carry `suppressions: []` | **verified** |
| **checkov** (3.3.9) | `# checkov:skip=CKV_X: reason` (per resource) | **included by default**, level downgraded `error`→`warning` | ✅ `kind:inSource` + justification | **verified** |
| **gosec** (2.27.0) | `//#nosec [rule] -- reason` | omitted by default; included with `-track-suppressions` | ✅ `kind:inSource` + justification | **verified** |
| **bandit** (1.9.4 + sarif-formatter) | `# nosec [rule]` | **omitted, no trace** (other rules on the same line still report) | ❌ | **verified** |
| **gitleaks** (8.30.1) | `#gitleaks:allow`, `.gitleaksignore` fingerprint | **omitted, no trace** (0 results) | ❌ | **verified** |
| **trivy vuln** (0.72.0) | `.trivyignore` (per-CVE) | **omitted**; `--show-suppressed` affects table/JSON only, not SARIF | ❌ | **verified** |
| **trivy misconfig** (0.72.0) | inline `#trivy:ignore:AVD-…` (per-occurrence) | **omitted, no trace** — the same rule still reports on unsuppressed resources | ❌ | **verified** |
| **CodeQL** | suppression comments + alert-suppression queries | included when suppression queries run | ✅ per GitHub/SARIF docs | not run locally (toolchain too heavy) |
| betterleaks / native providers | provider-specific | n/a — ingested via provider API, not SARIF | n/a | n/a |

### Consequences

- **Three of the most common tools — semgrep, ESLint, checkov — ship
  suppressed findings by default.** Until the parser reads `suppressions[]`
  (TODO-FIX item 9), Hibou displays their in-source-suppressed findings as
  open. This is a today-bug, not a future concern.
- gitleaks/trivy/bandit suppressions are *provably* invisible — the
  "indistinguishable from a fix" caveat is permanent for them, which is the
  strongest argument for triaging in Hibou instead. For trivy this was
  verified on **both** scanner paths (vuln `.trivyignore` and misconfig
  inline `trivy:ignore`) — the filtering happens before rendering, so its
  secrets/license paths are expected to behave the same (same layer, not
  separately verified).
- For **gitleaks the stakes exceed auditability**: an ignored secret is
  still a compromised credential. Hibou-side this is contained by the
  secrets invariant (no resolve-by-absence, resolution = attestation), but a
  `.gitleaksignore` hides the leak from Hibou entirely — the one exclusion
  mechanism that should genuinely never be used outside of fixtures.
- checkov's level downgrade means severity mapping must read `suppressions`,
  not `level`, to classify a result as suppressed.
- Hibou's own CI runs `gosec` without `-track-suppressions`; add the flag
  once the parser handles the field.

- **Two actions only.** *Accept ▾* — a split button whose menu carries the
  justification (*Accept risk* / *False positive*), one click for the default,
  two for the other — and *Reopen* on accepted findings. Nothing else on the
  row.
- **One status.** A finding is `open` or `accepted`. On screen the single
  status renders as one of two plain-words labels — no abbreviations,
  no `Accepted ·` prefix: **`Risk accepted`** (amber: a real debt someone
  owns) or **`False positive`** (gray: noise, filtered from risk reporting).
  Both are the same `accepted` status underneath; the label *is* the
  `reason_kind`. Chips are `white-space: nowrap` with fixed short labels —
  the current UI's wrapped, truncated chips are exactly what this bans.
- **Reason is data, not prose.** `finding_acceptances.reason_kind`
  (`risk_accepted` | `false_positive`) next to the existing free-text reason
  and optional expiry. Fingerprint-scoped as today, so decisions survive
  snapshots.
- **The gate has exactly one lever.** Both reasons neutralize the finding for
  the quality gate (that is what "accepted" means); the manual gate override
  is deleted. Making a PR green means triaging its findings — every green has
  an accountable, finding-scoped trail.

### Semantics per consumer

| Consumer | `risk_accepted` | `false_positive` |
|---|---|---|
| Quality gate | ignored | ignored |
| VEX export | `affected` + accepted-risk statement | `not_affected` (justification from reason text) |
| Risk reporting / dashboards | **counts as open risk, flagged accepted** | excluded (it is not a vulnerability) |
| Expiry | supported (re-opens on lapse) | discouraged — an FP does not expire |
| Delta ("resolved") | not resolved — accepted | not resolved — reclassified |
| On observation `resolved` | acceptance dormant; resurfaces if finding reappears | same |

That table is the point of the split: the gate treats them identically, but
risk math must not — an accepted risk is still risk, a false positive never
was.

### UX requirements (the "irreprochable" bar)

- **Row**: `Accept ▾` + (when accepted) `Reopen`. No third button, ever; any
  future action goes in the split menu.
- **Accept flow**: click → inline popover with reason-kind preselected from
  the menu choice, optional comment, optional expiry (risk only) → Enter
  confirms. Two interactions worst case; optimistic UI; gate recompute rides
  the existing `GateRecomputeRequested` event.
- **Type-aware justification** — one workflow, VEX specificity exactly where
  VEX applies, standard-conformant so exports never need a lossy remap:
  - **The internal vocabulary IS the standard, verbatim.** Our
    `vex_justification` enum is CISA's five machine-readable Status
    Justifications (shared by OpenVEX) and `vex_status` is the canonical
    four — already true in the schema. No invented values, ever; if the
    standard grows a label, we add it, never the reverse.
  - **Standard rules the popover must encode** (CISA minimum requirements):
    a justification is only legal on `not_affected`; an `affected` statement
    carries an **action statement** instead. Mapping:
    - `false_positive` on a dependency finding → VEX `not_affected` + one of
      the five justifications (picker), free text as impact detail.
    - `risk_accepted` on a dependency finding → VEX `affected` + an action
      statement synthesized from the reason (and expiry when set:
      "risk accepted until …"). No justification field — the standard
      forbids it here.
  - **Exports map from this one vocabulary**: OpenVEX emits it as-is;
    CycloneDX VEX maps mechanically (`false_positive` → analysis state
    `false_positive` + justification; `risk_accepted` → `exploitable` +
    response `will_not_fix`). One canonical form, N encoders.
  - **VEX applicability is a property of the finding, and the UI never
    lies about it.** VEX describes exploitability of *components in a
    product* — so it applies to component-backed findings (`dependency`,
    container-image packages) and to nothing else. For SAST, secrets, IaC,
    licenses: the popover shows the same two kinds with a plain reason
    field, **zero VEX vocabulary on screen**, and no VEX row is generated —
    excluded from export, not shoehorned in. The detail drawer says why in
    one line ("VEX not applicable — VEX describes third-party component
    exploitability; this is a first-party code finding"), so any user
    understands the boundary without reading a spec.
  - Out of scope, noted: first-party product advisories (emitting VEX about
    *our* product for downstream consumers, via clients/deployments) is a
    different feature — it must not blur this per-finding triage boundary.
- **Bulk**: same split button above the selection; one reason applies to all.
- **Filters**: `status:accepted`, `acceptance:risk`, `acceptance:fp` in the
  filter bar and `q=` grammar — saved views like "all accepted risk expiring
  this quarter" must be one query.
- **Everything keyboardable**; buttons never truncate (labels are fixed-width
  short forms, details live in the popover/tooltip).

### Branch semantics

Acceptances are **repo-scoped** (`UNIQUE (repo_id, fingerprint)`), deliberately:

- **Any branch inherits triage for free** — release, dev, hotfix, whatever
  it is named. Branch names carry no semantics here: a branch cut from
  `master` starts with every decision already applied (same code → same
  fingerprints → same acceptances), and a scan of any branch resolves
  decisions the same way. No re-triage, ever, on a branch cut.
- **The mirror follows**: accepting on master accepts on release too. This is
  correct for `false_positive` (a truth about the finding, not about a
  branch) and it is what divergence handles naturally — fingerprints are
  content-derived, so when branches actually diverge the old acceptance stops
  matching and the changed finding re-opens on its own.
- **Extension point, not default**: `risk_accepted` can be a *policy* with a
  blast radius ("accepted to ship 1.4, stays open on master"). If that need
  materializes, the acceptance gains an optional ref scope
  (`refs: all | pattern`, default `all`) — offered in the accept popover for
  risk only; false positives are always repo-wide. Not built until asked for.

### Performance: DB → UX

Branch inheritance must stay O(decisions), never O(branches × decisions) —
the guarantees, layer by layer:

- **Storage**: one row per decision per repo, `UNIQUE(repo_id, fingerprint)`.
  A branch cut writes **nothing** — inheritance is the *absence* of copies.
  The new fields (`reason_kind`, `labels`, `vex_justification`) are in-row;
  row count is unchanged. Forbidden by this ADR: materializing acceptance
  copies per branch, per ref, or per snapshot — that turns a policy table of
  thousands of rows into millions and makes reopening a decision a fan-out.
- **Findings list (the hot read)**: decision status is computed **server-side**
  with a `LEFT JOIN finding_acceptances USING (repo_id-equivalent, fingerprint)`
  — an index nested loop off the unique composite index, O(page size) lookups
  per request. This replaces today's implementation, where the UI downloads
  the *entire* acceptance list as a second request and joins client-side
  (`acceptanceFor`) — O(all acceptances) per page view and a status column
  the server can't filter on. With the join, `status:accepted`,
  `acceptance:fp`, and `label:x` become real SQL predicates in the
  filter-query grammar, and facet counts ride the same query.
- **API**: one request returns rows *with* their acceptance projection
  (kind, labels, expiry, who/when) — page-sized payloads, one round trip.
  The standalone acceptances endpoint remains only for the history/detail
  view.
- **Gate evaluation**: unchanged and already right — a single indexed
  repo-wide fetch of active acceptances (`expires_at IS NULL OR > now()`)
  joined in memory against the delta; acceptances per repo are thousands at
  worst. No per-fingerprint queries anywhere (N+1 is forbidden).
- **Labels**: filtering by label gets a GIN index on `labels` **when the
  filter ships**, not speculatively.
- **UX**: accept/reopen updates the row optimistically (no list refetch —
  the response carries the new projection); bulk accept stays one batch
  call; the accept popover needs no prefetch. Net effect of a branch cut on
  the user: zero clicks, zero waiting, decisions just show.

Scale sanity check: 50k findings in a snapshot, 5k acceptances → a 50-row
page costs 50 index lookups for the join; the old client-side join shipped
all 5k rows on every page load.

### Data & migration

- Migration: `finding_acceptances` gains `reason_kind` enum, `labels text[]`
  (default `{}`), and a nullable `vex_justification` (dependency findings
  only); existing rows backfill `status='false_positive'` → `accepted` +
  `reason_kind='false_positive'`, `'accepted'` → `reason_kind='risk_accepted'`.
  The `false_positive` acceptance status disappears (alpha: no compat window).
- API: `PUT …/acceptance` takes `{status: accepted|open, reason_kind, reason,
  expires_at?}`; rejects `accepted` without a `reason_kind`.
- Provenance/audit unchanged: acceptances already record actor (human or
  token via ADR-020); `triage:write` continues to gate the transition.
- Compliance export includes `reason_kind`, so "how much accepted risk are we
  carrying vs how noisy are our scanners" is a GROUP BY, not archaeology.

## Consequences

- The vulnerabilities table drops from 3 buttons+2 statuses to 1–2 buttons+1
  status with a qualifier — fixes the broken layout by removing what broke it.
- Scanner-quality feedback becomes measurable (`reason_kind='false_positive'`
  per tool/rule feeds the tool catalog).
- Removing the gate override deletes a privileged write surface
  (`quality_gates:write` shrinks to gate-definition CRUD) — net security win.
- One-time migration touches acceptance consumers (gate evaluation, VEX
  export, facets, filter grammar, UI) — bounded, listed in the TODO file.

## Alternatives considered

- **Keep three statuses, fix the CSS** — leaves every consumer forked on
  "which statuses mean dismissed" and the model debt grows with each new
  consumer.
- **Free-text reason only** (no kind) — reads fine per-finding, aggregates as
  nothing; "exploitable afterward" was a hard requirement.
- **VEX statements as the only mechanism** — maximal standards purity, but a
  4-field VEX form per dismissal fails the speed bar; instead acceptances
  *generate* VEX.
