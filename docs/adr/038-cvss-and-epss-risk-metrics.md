# ADR-038: Risk metrics — CVSS done right, EPSS added

## Status

Proposed (2026-10-09). Builds on the canonical advisory model
([ADR-007](007-canonical-advisory-model.md)), the CVE feed
([ADR-028](028-cve-subscriptions-with-manual-purl-triage.md)) and the
exploited-catalog mirror and gate
([ADR-032](032-kev-catalog-and-exploited-gate.md)). Breaking changes are
accepted (alpha): severity values, API fields and the severity enum change.

## Context

A developer triaging a dependency finding asks two questions: *how bad is it
if exploited* and *how likely is it to be exploited*. Hibou answers the first
badly and the second not at all.

### What hibou shows today

Measured on a working dev database (838 advisories, 2026-10-09):

| Fact | Value |
|---|---|
| Advisories with a CVSS score | 246 / 838 (29%) |
| Advisories with severity `info` | 458 / 838 (55%) |
| OSV advisory sources carrying a CVSS score | **0 / 820** |
| Trivy advisory sources carrying a CVSS score | 246 / 250 |
| CVE-feed records (`cve_records`) with a CVSS score | 212,817 / 403,689 |
| Unscored advisories whose CVE is scored in the CVE feed | 310 / 592 |
| EPSS data | none |

The worst single example is **CVE-2020-0601** (CurveBall, Windows crypto
spoofing). Hibou shows it as severity **info** with no CVSS. In reality it is
CVSS 8.1 (high), EPSS **89.4%** (99.8th percentile), and CISA KEV-listed. The
KEV badge (ADR-032) is the only signal hibou surfaces for it.

Three defects produce this:

1. **The OSV provider throws every CVSS score away.** The OSV schema defines
   `severity[].score` as a *CVSS vector string*
   (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`), never a number.
   `osv.parseCVSS` only accepts a number (`strconv.ParseFloat`), so it stores
   the vector but no score. Severity then falls back to GitHub's coarse
   `database_specific.severity` label, or to nothing.
2. **Data hibou already has goes unused.** The Go vulnerability database
   (`GO-*`) deliberately publishes no severity. Its advisories therefore
   arrive unscored, while the CVE feed already holds the CNA/ADP CVSS for the
   same CVE (ADR-028 parses it in `cvefeed.bestSeverity`). The two are never
   joined.
3. **"Unscored" is stored as `info`.** `MergeSeverity` returns `info` when no
   source has a signal. `info` means "informational, low risk". An unscored
   CVE is the opposite: unknown, possibly critical. It sorts last, never trips
   a severity gate, and looks harmless in every list.

On top of that, the vulnerability list shows no score at all. The finding
drawer showed CVSS only under *Details* until this work started.

### Prior art (as of 2026-10)

| Tool | CVSS | Severity when unscored | EPSS | Combined score |
|---|---|---|---|---|
| **Dependency-Track** | v2, v3 and (4.14) v4 vectors and scores per vulnerability; severity from the source, else derived from CVSS | "Unassigned", kept distinct from low | mirrored from FIRST into a table keyed by CVE ID; non-CVE IDs inherit the score of their CVE alias; OSV/GHSA/Snyk IDs without a CVE alias get none | no per-finding blend; project "risk score" weights severity counts |
| **Grype** | per-source CVSS | `Unknown` | score and percentile shown per match, e.g. "94.4% (99th)" | 0–10 risk score: EPSS or KEV for threat, CVSS for impact, extra weight for ransomware use; default sort order |
| **Trivy** | `CVSS` map per vendor (nvd, ghsa, redhat…) | `UNKNOWN` | none | none. Severity comes from the advisory source chosen for the package (OS packages: the distro vendor), falling back to CVSS bands and then NVD |
| **GitHub Advisory DB / Dependabot** | 3.0, 3.1 and 4.0 vectors | — | score and percentile per advisory with a CVE | none |
| **GitLab** | CVSS shown as a severity baseline | — | GA in 17.7; per-vulnerability `cveEnrichment` (EPSS score, KEV status) | none. Its Vulnerability Prioritizer orders by KEV, then EPSS, then severity |
| **Snyk** | CVSS input | — | daily EPSS input | proprietary 0–1000 Risk Score (EPSS, exploit maturity, reachability, CVSS, …) |
| **DefectDojo Pro** | per finding | — | daily EPSS score and percentile by CVE | threat score; exploit evidence sets EPSS-scale floors |

These are the readings that shaped this ADR:

- **CVSS and EPSS are shown side by side, never merged into each other.**
  Every tool that shows both keeps them separate. GitLab's guidance names the
  reason: a medium-severity vulnerability with a high EPSS may need action
  before a high-severity one with a low EPSS.
- **Unscored is its own state** (Dependency-Track "Unassigned", Trivy and
  Grype "Unknown"). Nobody files it under informational.
- **EPSS is keyed by CVE and reached through aliases**, as Dependency-Track
  does. A GHSA- or GO-canonical advisory with a CVE alias gets its CVE's
  score.
- **Blended risk scores are proprietary and opaque** (Grype, Snyk,
  DefectDojo). The transparent consensus is an *ordering*: KEV, then EPSS,
  then CVSS (GitLab; Grype's sort).

## Decision

### 1. CVSS is computed from vectors, in one place

A new package `internal/cvss` parses vectors and computes base scores:

- **v3.0 and v3.1:** the FIRST specification formulas, including the v3.1
  `Roundup`.
- **v2:** the NVD v2 base equation.
- **v4.0:** the vector is parsed and stored. Its score is computed only when
  the source supplies the number; the v4 macro-vector lookup table is not
  implemented in this ADR (Open questions). When a source carries both v3
  and v4, the v3 score is used, matching how CVE records are scored today.

The calculator is pinned by tests against published NVD scores for
representative vectors, including scope-changed v3 vectors and v2 partial
impacts. `osv.parseCVSS` uses it, which fixes defect 1 for every
GHSA/PyPI/npm/Go advisory OSV serves. Every other provider that receives a
vector without a number (Trivy's per-vendor map, the CVE feed) goes through
the same function.

### 2. The CVE feed is a severity source

When an advisory's canonical ID or any alias is a CVE that the CVE feed holds
with a score, that score joins the advisory's sources as provider `cve`
(CNA/ADP, the source named by the record). It goes through the existing
`MergeSeverity` rule: NVD first if present, else the strongest scored source.
A Go advisory therefore inherits its CVE's CNA score, which fixes defect 2.
The merge runs:

- whenever an advisory is ingested, as today;
- after each CVE-feed sweep, for advisories whose CVE records changed in that
  sweep (the sweep already knows which records it wrote).

### 3. `unknown` is a severity

`severity_level` gains **`unknown`**, used when no source carries a score or
a label. `info` is reserved for findings their producer genuinely rates
informational. This fixes defect 3.

- **Ordering:** unknown sorts between medium and low. It must not hide at the
  bottom like info, nor claim to be high. Sorting by risk (§6) moves it by
  EPSS and KEV anyway.
- **Gates:** severity thresholds (`max_critical`, `max_high`, …) do not count
  unknown. A new optional `max_unknown` lets a team gate on it. KEV still
  blocks any exploited finding whatever its severity (ADR-032), so the
  dangerous case is covered without guessing a severity.
- **Display:** a neutral grey "unknown" badge, with the tooltip "No source
  rates this vulnerability yet".

### 4. EPSS is mirrored daily from FIRST

```sql
CREATE TABLE epss_scores (
    cve_id      text PRIMARY KEY,
    score       numeric(6,5) NOT NULL,  -- probability of exploitation in 30 days
    percentile  numeric(6,5) NOT NULL,
    score_date  date NOT NULL
);
CREATE TABLE epss_catalog (             -- one row: what the mirror holds
    model_version text NOT NULL,
    score_date    date NOT NULL,
    row_count     integer NOT NULL,
    synced_at     timestamptz NOT NULL DEFAULT now()
);
```

- **Source:** `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz`,
  FIRST's published daily file. It is ~2.7 MB gzipped and ~300k rows. Its first
  line carries the model version and score date
  (`#model_version:v2026.06.15,score_date:2026-10-09T12:00:22Z`), followed by
  `cve,epss,percentile`. The URL is configurable (`HIBOU_EPSS_URL`), so an
  air-gapped install can point it at an internal mirror, and
  `HIBOU_EPSS_ENABLED=false` turns the sync off.
- **Sync:** a leader-locked loop, like the KEV sync (`store.WithLeaderLock`),
  checks once a day. If the file's `score_date` is not newer than the mirror's,
  nothing is written. Otherwise the file is streamed into a temporary table and
  swapped in one transaction (`DELETE` + `INSERT … SELECT`), so readers never
  see a half-loaded mirror. The sync refuses a file with fewer than 100k rows,
  keeps the previous day's data on any error, and logs the model version.
  Models change (EPSS v4 since 2025-03), and a score from a newer model is not
  comparable with one from an older model.
- **Lookup:** a finding's EPSS is the highest score among its advisory's
  canonical ID and CVE aliases (Dependency-Track's alias inheritance). It is
  attached per page, like KEV, and never copied onto vulnerability rows: the
  scores change daily.

### 5. No blended score

Hibou does not invent a combined number. CVSS, EPSS and KEV stay three
labelled facts. The list offers a **Risk** sort that orders KEV-listed
first, then by EPSS, then by CVSS. This is GitLab's documented order and
Grype's default, and a developer can verify it by reading the row.

### 6. API and query language

- **List rows** (repo and org), attached per page:
  - `cvss: {score, version, vector}`, the advisory's headline score;
  - `epss: {score, percentile, date}`.
- **Finding detail:** the same, plus the per-source CVSS list (provider,
  version, vector, score), so a reader can see why the headline won.
- **Filter qualifiers with comparisons:** `cvss:>=7`, `epss:>=0.1` (also
  accepted as `epss:>=10%`) and `epss-percentile:>=0.95`. A comparison is the
  value's first characters (`>=`, `>`, `<=`, `<`, `=`). Both compile like any
  qualifier, so they combine with `cwe-tree:`, exclusion and the rest.
  `cvss:none` / `epss:none` find unscored findings.
- **Sort:** `sort=risk_desc` (§5) and `sort=epss_desc`, alongside the
  existing severity and date sorts.

### 7. UI

- **Vulnerability list** (repo and org): a compact **CVSS** column (score
  coloured by band, version and vector in the tooltip) and an **EPSS** column
  (percentage, percentile in the tooltip), next to severity. Unscored cells show
  "–".
- **Finding drawer, Overview:** the Score block (shipped with this ADR's
  first step) shows CVSS, EPSS ("89.4% · 99.8th percentile · scored
  2026-10-09") and, when listed, the KEV line. These are the three questions in
  one place.
- **Filter-bar completion** offers `cvss:` and `epss:` with ready-made
  thresholds (`cvss:>=9 critical`, `epss:>=0.1 top exploitation risk`).

## Consequences

- Severities change on upgrade. Hundreds of advisories move from `info` to a
  real CVSS-derived severity: CVE-2020-0601 becomes high, and GitHub-sourced
  advisories take the band of their real score instead of GitHub's label.
  PR gates with `max_high` / `max_critical` can start failing on code that
  passed before. This is intended: those findings were misrated.
- Advisories with no source signal anywhere become `unknown` instead of
  `info`. Dashboards and severity counts gain an *unknown* bucket.
- The open-findings list is re-severitied by the existing advisory scan pass
  (dependency rows are upserted with the advisory's current severity), and a
  one-off backfill rescores the advisories already stored. Manual severity
  overrides (`severity_override_reason`) are preserved.
- A daily ~2.7 MB download and ~300k-row table refresh. Air-gapped installs
  can disable it or mirror it, as for KEV.

## Alternatives considered

- **Per-CVE EPSS lookups through FIRST's API** (`api.first.org/data/v1/epss`).
  It needs no table, but means one request per CVE per page, rate limits, and
  no offline use. Rejected: the full file is smaller than a page of scanner
  output.
- **EPSS only from GitHub advisories** (Dependency-Track 4.14 added this for
  GHSA). It covers only GHSA-backed findings and misses every OS-package and
  Go advisory. Rejected in favour of the full mirror.
- **A blended risk score** (Grype, Snyk). It is opaque, model-dependent, and
  invites gaming thresholds on a number nobody can explain. Rejected for now
  (§5); the Risk sort gives the same ordering transparently.
- **Keep `info` for unscored and only fix the inputs.** That still files
  every advisory no source scores under "harmless". Rejected.

## Open questions

- **CVSS v4 scoring.** Implement FIRST's macro-vector lookup so v4-only
  advisories get a number. More GHSA advisories ship v4-only each month.
- **Distro vendor precedence.** Trivy prefers the distro's own rating for OS
  packages (Red Hat "Low" vs NVD "High" on CVE-2023-0464). Hibou's merge
  takes NVD first, then the strongest score. Revisit when container findings
  carry vendor ratings.
- **EPSS in gates.** `vulnerabilities.min_epss` or a "new finding above the
  95th EPSS percentile" block, alongside KEV. Deferred until the data has
  been visible for a while.
- **EPSS history.** Keep daily scores to show a trend ("tripled this week"),
  or only the latest. Latest only for now.
