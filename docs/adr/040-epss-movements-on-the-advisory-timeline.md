# ADR-040: EPSS movements on the advisory timeline

## Status

Proposed (2026-10-10). Builds on the EPSS mirror of
[ADR-038](038-cvss-and-epss-risk-metrics.md) §4 and the advisory timeline
(`advisory_events`, [ADR-028](028-cve-subscriptions-with-manual-purl-triage.md))
that already carries KEV listings ([ADR-032](032-kev-catalog-and-exploited-gate.md)).
Answers ADR-038's open question "EPSS history".

## Context

ADR-038 mirrors FIRST's EPSS file daily and keeps only the latest scores: the
`epss_scores` table is cleared and reloaded on every new `score_date`. A
finding shows today's probability and nothing else.

That hides the one thing about EPSS a developer acts on: **change**. A CVE
whose exploitation probability went from 0.4% to 62% this week has become a
different problem, with no code change, no advisory revision and no new
finding. Today nothing records it, so nobody can answer "why is this
dependency suddenly at the top of the Risk sort?".

EPSS is not an advisory. An advisory states facts about a flaw: what is
affected, what fixes it, how severe it is. EPSS is a daily model output about
attacker behaviour. But the advisory timeline already holds one fact of the
same kind: `kev_listed` ("listed as actively exploited") is about attackers,
not about the flaw, and it lives there because it explains why a finding's
urgency changed. A large EPSS move belongs beside it.

Recording every change is not an option. Scores drift slightly for nearly all
~385k CVEs every day; a timeline entry per drift would bury the entries that
matter, and the table would grow by hundreds of thousands of rows a day.

Two properties of the data shape the design:

- **Most CVEs score very low.** Raw probabilities are hard to read
  ("is 10% a lot?"); the percentile says where a score stands. A move into the
  top few percent is what changes priorities.
- **Models change.** FIRST retrains periodically (the file header names the
  model, e.g. `v2026.06.15`). A new model shifts scores across the board for
  reasons unrelated to exploitation. A "movement" across a model change is an
  artefact, not news.

## Decision

### 1. Two event kinds, recorded on thresholds only

| Kind | Recorded when, comparing the previous file to the new one |
|---|---|
| `epss_rose` | the percentile crosses up to **≥ 0.95** (into the top 5%), **or** the score at least **triples** and lands at **≥ 0.01** (1%) |
| `epss_fell` | the percentile drops from ≥ 0.95 to below **0.90** |

- **Top 5%** matches ADR-038's highlight in the UI (the EPSS cell turns orange
  at the 95th percentile) and the `epss-percentile:>=95%` suggestion, so an
  event and the list agree on what "high" means.
- **Tripling to ≥ 1%** catches a sharp rise that has not reached the top 5%
  yet; the floor keeps 0.01% → 0.03% from counting.
- **Falling below 0.90, not 0.95** (hysteresis): a CVE oscillating around the
  95th percentile would otherwise emit a rose/fell pair every few days.

The thresholds are constants in one place (`internal/epss`), not
configuration: an instance tuning them would make its timeline incomparable
with the documentation.

### 2. Only CVEs this instance cares about

Movements are computed for the CVEs hibou's advisories reference: every
advisory's canonical ID and aliases that are CVE IDs (`advisory_aliases`).
That is a few thousand CVEs on a typical instance, not 385k. A CVE no
advisory references has no finding to explain, and its movement would be
recorded for nobody.

### 3. Computed in the daily swap

The EPSS sync (ADR-038 §4) already replaces the mirror in one transaction.
Before clearing `epss_scores`, the sync reads the previous scores of the
referenced CVEs, compares them with the incoming file in memory, and writes
the events in the same transaction as the swap. No history table: the
previous day's scores are exactly what the table holds until the swap.

- **First load:** an empty mirror records nothing, like the first KEV sync.
  Day one is not a day on which thousands of CVEs "rose".
- **Model change:** when the incoming `model_version` differs from the
  mirror's, the swap happens and no movement is recorded. The timeline gets a
  single instance-level log line instead, not one event per CVE.
- **A CVE new to EPSS** (no previous score) records nothing: it is not a
  movement. A CVE entering straight into the top 5% is still visible through
  the list's EPSS column and the Risk sort.
- **Skipped days:** the comparison is always previous file vs new file, so a
  sync that missed a day compares two days apart. Fine for thresholds; the
  event's detail carries both score dates.

### 4. Event shape

Stored in `advisory_events` like `kev_listed`: keyed by `cve_id`,
`advisory_id` NULL (one CVE may back several advisories; the timeline is
read by CVE, as the drawer's "Advisory history" already does).

```json
{
  "from": {"score": 0.004, "percentile": 0.71, "date": "2026-10-03"},
  "to":   {"score": 0.62,  "percentile": 0.98, "date": "2026-10-10"},
  "model_version": "v2026.06.15",
  "reason": "entered_top_5_percent"
}
```

`occurred_at` is the new file's `score_date` (FIRST's clock, the same rule as
upstream revisions); `observed_at` is when the sync ran. Both kinds are
external (`AdvisoryEventKind.External`): nobody here did anything.

### 5. Display

The drawer's "Advisory history" (`DependencyFindingDetails`) renders:

- `epss_rose`: "Exploitation likelihood rose to 62% (EPSS, top 2%)", with
  "from 0.4%" in the secondary text.
- `epss_fell`: "Exploitation likelihood fell to 3% (EPSS, out of the top 5%)".

The finding history (`FindingTimeline`) is unchanged: it records what
happened to the finding here, not to the advisory.

### 6. Not in this ADR

- **Notifications.** Notifying on `epss_rose` for open findings, like KEV
  listings, is the natural next step, but it needs a notification rule and a
  quiet default; it gets its own change once the events have been seen.
- **Gates.** ADR-038 already defers EPSS gates.

## Consequences

- A developer can see why a dependency climbed the Risk sort: the drawer
  says when its exploitation likelihood jumped, and from where.
- The timeline grows by the number of threshold crossings among referenced
  CVEs: a handful to a few dozen events a day on a typical instance, far
  below the KEV and CVE-feed volumes it already absorbs.
- The daily swap reads the referenced CVEs' previous scores before clearing
  the table: one indexed query of a few thousand rows, inside the existing
  transaction.
- A model change is silent on the timeline by design. Someone looking for
  movement across that day sees none and has to read the model version in the
  sync health (`epss_last_sync`).
- The thresholds become part of what an event means. Changing them later
  changes what future events mean, not what past ones recorded; the detail
  carries the reason so an old event stays readable.

## Alternatives considered

- **Keep daily history** (`epss_history(cve_id, date, score, percentile)`)
  and derive movements on read. It answers more questions (trend charts,
  arbitrary windows) but stores ~385k rows a day, or a few thousand a day if
  restricted to referenced CVEs, forever, to show what a few dozen events
  say. Rejected for now; ADR-038 explicitly kept "latest only".
- **Record every change for referenced CVEs.** Daily noise on every
  advisory's timeline. Rejected.
- **A fixed score threshold only** (e.g. crossing 10%). Ignores that most
  scores are tiny: a CVE going from 0.1% to 8% is a 80× rise that never
  crosses 10%. Rejected in favour of percentile plus relative rise.
- **Show EPSS as a separate sparkline instead of events.** Needs the history
  table above. Rejected with it.
- **Treat EPSS as an advisory source.** EPSS states nothing about affected
  versions or fixes, and an advisory row per CVE per day would make no sense.
  Rejected; this is why movements go on the timeline, not into
  `advisory_sources`.

## Open questions

- **Thresholds.** Top 5% with a fall back below the 90th percentile, and
  "tripled to ≥ 1%", are first guesses. Revisit after a few weeks of events on
  real data: too many events means raising the bar, none means lowering it.
- **Notifications** on `epss_rose` for open findings (§6).
