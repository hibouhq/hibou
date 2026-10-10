# ADR-038: Risk metrics — CVSS done right, EPSS added

## Status

Accepted — implemented (2026-10-09). Builds on the canonical advisory model
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

Measured on a dev instance whose advisories come from live provider queries
(OSV: 422 `GO-*`, 205 `GHSA-*`, 193 `PYSEC-*` records; Trivy: 250), on
2026-10-09. The seed data's own fixtures are excluded: they carry no scores
by construction (§8).

| Fact | Value |
|---|---|
| Advisories with a CVSS score | 246 / 838 (29%) |
| Advisories with severity `info` | 458 / 838 (55%) |
| OSV advisory sources carrying a CVSS score | **0 / 820** |
| OSV advisory sources carrying a CVSS **vector** but no score | **243** |
| Trivy advisory sources carrying a CVSS score | 246 / 250 |
| CVE-feed records (`cve_records`) with a CVSS score | 212,817 / 403,689 |
| Unscored advisories whose CVE is scored in the CVE feed | 310 / 592 |
| EPSS data | none |

The worst single example is **CVE-2020-0601** (CurveBall, Windows crypto
spoofing). Hibou shows it as severity **info** with no CVSS. In reality it is
CVSS 8.1 (high), EPSS **89.4%** (99.8th percentile), and CISA KEV-listed. The
KEV badge (ADR-032) is the only signal hibou surfaces for it.

Four defects produce this:

1. **The OSV provider throws every CVSS score away.** The OSV schema defines
   `severity[].score` as a *CVSS vector string*
   (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`), never a number.
   `osv.parseCVSS` only accepts a number (`strconv.ParseFloat`), so it stores
   the vector but no score. Severity then falls back to GitHub's coarse
   `database_specific.severity` label, or to nothing. Confirmed on the live
   record of Log4Shell, `GHSA-jfh8-c2jp-5v3q`, whose vector is
   `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H` (base 10.0): `parseCVSS`
   returns the vector and a nil score. That vector also carries a temporal
   metric (`E:H`), so the calculator must accept and ignore non-base metrics.
2. **Data hibou already has goes unused.** The Go vulnerability database
   (`GO-*`) deliberately publishes no severity. Its advisories therefore
   arrive unscored, while the CVE feed already holds the CNA/ADP CVSS for the
   same CVE (ADR-028 parses it in `cvefeed.bestSeverity`). The two are never
   joined.
3. **Each source keeps one rating out of several.** `advisory_sources` holds
   one score, version and vector per source, but sources publish several.
   Trivy's `cvss` map carries `nvd`, `redhat` and `ghsa` entries, each with
   v2, v3 and v4 (`trivy.preferredCVSS` keeps one); an OSV record lists v3.1
   and v4 side by side (`parseCVSS` keeps one). For OS packages, Trivy's own
   `Severity` is the distro vendor's rating, and hibou replaces it with NVD's.
   The full record survives in `raw_data`, so nothing is lost for good, but
   none of it can be shown, queried or used.
4. **"Unscored" is stored as `info`.** `MergeSeverity` returns `info` when no
   source has a signal. `info` means "informational, low risk". An unscored
   CVE is the opposite: unknown, possibly critical. It sorts last, never trips
   a severity gate, and looks harmless in every list.

The advisory's merged severity also records nothing about which rating won,
so a reader cannot tell an NVD 7.5 from a GitHub "high" label.

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
- **v4.0:** FIRST's MacroVector algorithm and lookup tables, ported from the
  reference calculator (https://github.com/FIRSTdotorg/cvss-v4-calculator,
  BSD-2-Clause; notice in `THIRD_PARTY_NOTICES.md`). Threat, environmental
  and supplemental metrics are honoured as the reference does. When a source
  carries both v3 and v4, the v3 score is still preferred, matching how CVE
  records are scored today.

The same scoring exists twice, in `internal/cvss` (scoring vectors at ingest:
OSV ships vectors without numbers) and in `site/src/lib/cvss` (the in-app
calculator, which explains any vector and builds new ones). Both reproduce
`internal/cvss/testdata/v4-golden.json`, scored by running FIRST's own
calculator unmodified, so a vector scores identically in both places.

New findings filed by people or agents are scored in v4.0 only; older
versions are read and explained, never created.

The calculator is pinned by tests against published NVD scores for
representative vectors, including scope-changed v3 vectors and v2 partial
impacts. `osv.parseCVSS` uses it, which fixes defect 1 for every
GHSA/PyPI/npm/Go advisory OSV serves. Every other provider that receives a
vector without a number (Trivy's per-vendor map, the CVE feed) goes through
the same function.

### 2. Every rating is kept; the one used is chosen per finding

**Storage is lossless** (defect 3). A source contributes one row per rating it
publishes, instead of the single score `advisory_sources` holds today:

```sql
CREATE TABLE advisory_ratings (
    advisory_source_id uuid NOT NULL REFERENCES advisory_sources(id) ON DELETE CASCADE,
    rater         text NOT NULL,            -- nvd, cna, ghsa, redhat, debian, ubuntu, oracle...
    cvss_version  cvss_version,             -- NULL for a label-only rating
    cvss_vector   text NOT NULL DEFAULT '',
    cvss_score    numeric(4,2),             -- computed from the vector (§1)
    label         severity_level,           -- the rater's own severity word, if it publishes one
    UNIQUE NULLS NOT DISTINCT (advisory_source_id, rater, cvss_version)
);
```

The `cvss_*` columns move off `advisory_sources`. Providers map what they
receive:

- **Trivy:** one row per vendor of the `cvss` map and per version in it, each
  carrying that vendor's label from `vendor_severity`, plus a label-only row
  for every vendor that publishes no CVSS. The Trivy server returns
  `severity_source` and `vendor_severity` with every vulnerability; hibou now
  decodes and keeps them. Spellings fold: `oracle-oval` → `oracle`,
  `suse-cvrf` → `suse`.
- **OSV:** one row per `severity[]` entry, the rater named by the record's ID
  prefix (`GHSA` → `ghsa`, `PYSEC` → `pypa`, `CVE` → `nvd`, `DSA`/`DLA` →
  `debian`, `UBUNTU`/`USN` → `ubuntu`, `RHSA` → `redhat`...). GitHub's
  `database_specific.severity` becomes that rater's label; an `Ubuntu`-typed
  entry is Ubuntu's priority word.
- **CVE feed:** the feed keeps the strongest container's rating per CVE
  (`cvefeed.bestSeverity`) and now records which container gave it
  (`cve_records.cvss_source`). When one of an advisory's aliases is a CVE the
  feed rates, that rating is stored as the advisory's `cve` source, rater =
  the container's short name (a CNA such as `redhat` or `GitHub_M` → `ghsa`,
  or `CISA-ADP`). A Go advisory, which `GO-*` publishes without a severity,
  therefore gets its CVE's CNA score, which fixes defect 2. Authored triage
  advisories (ADR-028) carry no ratings of their own for the same reason.

Ratings are rebuilt (`advisory.Rerate`, the one place a severity is derived):

- whenever an advisory is ingested, in the ingest transaction;
- by an hourly reconcile, for advisories whose `cve` source differs from what
  the CVE feed now holds (`ListAdvisoriesWithStaleCVERating`). The sweeper
  stays unaware of advisories; the reconcile compares the two tables.

The §8 backfill rebuilds `advisory_ratings` from each source's `raw_data`, so
existing installs get every rating without refetching. `advisory_sources`
gains `ratings_version`: a source below `advisory.RatingsVersion` is rebuilt
at startup, so a future mapping fix reaches stored data the same way.

**A rating's severity** is the rater's own label when it publishes one,
otherwise the band of its CVSS score. A vendor label can disagree with its own
score (Red Hat rates impact separately from CVSS), and the label is the
vendor's verdict. Debian's "unimportant" and Ubuntu's "negligible" map to
**low**, not info: the vendor still calls it a flaw, only not one that matters
in their build.

**The rating used is chosen per finding,** because the right answer depends
on the package. Dependency findings already copy their severity at match time
(`scanner.createMatchedVulnerability`), and gates, sorting and counts read
that copy, so the choice happens there and nothing downstream changes:

1. **OS package matched on a distro range:** that distro's rating, when it
   published one.

   | Distro of the package (purl namespace) | Raters used, in order |
   |---|---|
   | RHEL, CentOS | `redhat` |
   | Rocky, Alma | their own (`rocky`, `alma`), then `redhat`: both publish ratings of their own (Trivy's data carries them), and fall back to Red Hat's since they rebuild RHEL |
   | Oracle Linux | `oracle` |
   | Debian | `debian` (label only) |
   | Ubuntu | `ubuntu` (label only) |
   | Amazon Linux, Azure Linux / CBL-Mariner, Photon OS, SUSE, Fedora | their own |
   | Alpine | none: Alpine publishes no severities, so rule 2 applies |

   This is Trivy's choice for the same reason: a distro rates the flaw as it
   affects the build it ships. Red Hat's "Low" for an OpenSSL CVE NVD rates
   "High" is not a disagreement about the code but about its exposure in RHEL.
2. **Otherwise:** NVD first if present, else the strongest score (today's
   `MergeSeverity` rule, over ratings instead of sources). Within one rater,
   v3 is preferred over v4 (§1) and v4 over v2.
3. **Always:** the finding copies the rating it used — `cvss_score`,
   `cvss_version`, `cvss_vector` and `rated_by` — next to
   `original_severity`, so `cvss:` filters and the CVSS sort read a column. A
   manual severity override still wins over all of it and keeps its reason;
   the rating and `original_severity` keep following the data.

When an advisory's ratings change (provider refresh, CVE-feed sweep), its open
findings are recomputed with the same rule, so a copied severity never goes
stale. Without this a rating published after the match would never reach the
finding.

### 3. `unknown` is a severity

`severity_level` gains **`unknown`**, used when no source carries a score or
a label. `info` is reserved for findings their producer genuinely rates
informational. This fixes defect 4.

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
    percentile  numeric(6,5) NOT NULL
);
CREATE TABLE epss_catalog (             -- one row: what the mirror holds
    id            boolean PRIMARY KEY DEFAULT TRUE CHECK (id),
    model_version text NOT NULL,
    score_date    date NOT NULL,        -- one date for the whole file
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
  checks once a day (`HIBOU_EPSS_INTERVAL`, default 24h). If the file's
  `score_date` is not newer than the mirror's, nothing is written. Otherwise
  the mirror is cleared and reloaded in 10,000-row batches inside one
  transaction, so readers never see a half-loaded mirror. The sync's health
  is stored like KEV's (`epss_last_sync`). The sync refuses a file with fewer than 100k rows,
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

- **List rows** (repo and org):
  - `cvss: {score, version, vector}` and `rated_by`, the rating the finding
    uses (§2), read from the row;
  - `epss: {cve_id, score, percentile, date}`, attached per page.
- **List rows** also carry `rated_by: {rater, version}` and `ratings_disagree`
  (true when the finding's ratings fall in different severity bands), enough
  for the list's marker and hover without a second request.
- **Finding detail:** the same, plus every rating
  (`ratings: [{rater, version, vector, score, label, severity, used}]`), so a
  reader can see who said what and why one won.
- **Filter qualifiers with comparisons:** `cvss:>=7`, `epss:>=0.1` (also
  accepted as `epss:>=10%`) and `epss-percentile:>=0.95`. A comparison is the
  value's first characters (`>=`, `>`, `<=`, `<`, `=`). Both compile like any
  qualifier, so they combine with `cwe-tree:`, exclusion and the rest.
  `cvss:none` / `epss:none` find unscored findings.
- **Sort:** `risk`, `epss` and `cvss`, each `_desc` or `_asc`, alongside the
  existing severity and date sorts. Unscored findings sort last when
  descending. `risk_desc` pins KEV first like the default sorts;
  `risk_asc` is its reverse without the pin.

### 7. UI

- **Vulnerability list** (repo and org): a compact **CVSS** column (score
  coloured by band) and an **EPSS** column (percentage, percentile in the
  tooltip), next to severity. Unscored cells show "–".
- **Disagreement is visible without hovering.** When a finding's ratings fall
  in different severity bands, its CVSS cell carries a small marker (◆).
  Hovering lists who rated what ("Low · Red Hat — NVD: High 7.5 · GHSA: High
  7.5"). Agreement shows no marker, so the list stays quiet. Listing every
  rating on hover for every row, with no marker, was rejected: noise
  where nothing disagrees, and invisible where something does.

  ```
  CVSS
  5.9 ◆      ← raters disagree: hover to see who
  9.8        ← everyone agrees
  ```
- **Finding drawer, Overview:** the Score block (shipped with this ADR's
  first step) shows CVSS, EPSS ("89.4% · 99.8th percentile · scored
  2026-10-09") and, when listed, the KEV line. These are the three questions in
  one place.
- **The drawer lists every rating, always visible.** Hover is the quick look;
  it does not exist on touch or for keyboard users, so the full breakdown is
  in the Score block. Each row names the rater, its score, its severity and
  its vector; the rating in use is marked; metrics where a vector differs from
  the one in use are pointed out, because that explains a gap better than two
  numbers do. Illustrative, for an RHEL package:

  ```
  Severity  Low   rated by Red Hat · distro rating for RHEL 9    used for gates and sorting
    ▸ Red Hat  5.9  Low     CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H   label: Low
      NVD      7.5  High    CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H   differs: AC:L
      GHSA     7.5  High    CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H   differs: AC:L
      Debian   —    low     label only, no CVSS score
  ```

  Every vector opens hibou's own CVSS calculator in place, every metric
  explained; no external calculator is linked. The calculator is also a Tool
  (`/tools/cvss#<vector>`), next to SBOM compare, in the navigation menu.
- **Filter-bar completion** offers `cvss:` and `epss:` with ready-made
  thresholds (`cvss:>=9 critical`, `epss:>=0.1 top exploitation risk`).

### 8. Local and demo data

- `seed.go` advisories get the real CVSS vector, score and version for the
  CVEs they represent: CVE-2023-44487 (7.5), CVE-2023-39325 (7.5),
  CVE-2024-21626 (8.6), CVE-2023-45853 (9.8). The demo then shows the same
  shape of data production does. Malware advisories (`MAL-*`) stay unscored:
  they are blocked unconditionally, not rated.
- A one-off backfill (migration + `hibou-server` startup rescore) rebuilds
  `advisory_ratings` from each source's stored `raw_data`, scores every vector
  (§1), and recomputes every open dependency finding's severity (§2), so an
  existing instance — a dev database included — is fixed without waiting for
  the next provider refresh.

### 9. Implementation map

| Piece | Where |
|---|---|
| Vector parsing and base scores | `internal/cvss` |
| Ratings model, headline, per-finding choice, re-rating | `internal/advisory` (`rating.go`, `rerate.go`) |
| Provider mappings | `internal/provider/osv`, `internal/provider/trivy` (`RatingsFromRaw` for stored records) |
| Backfill and seed mapping | `internal/provider/rawratings` |
| EPSS file parsing | `internal/epss` |
| Backfill, CVE reconcile, EPSS sync loops | `internal/server/risk_loop.go` |
| Per-page EPSS and ratings | `internal/server/risk_metrics.go` |
| Schema | migrations 00041 (`unknown`), 00042 (ratings, finding rating columns, EPSS) |
| Qualifiers | `internal/filterquery` (`riskQualifierToSQL`) |
| UI | `RiskScoreBlock.vue`, `CvssCell.vue`, `EpssCell.vue`, `lib/riskMetrics.ts`, `lib/riskFilters.ts` |

## Consequences

- Severities change on upgrade. Hundreds of advisories move from `info` to a
  real CVSS-derived severity: CVE-2020-0601 becomes high, and GitHub-sourced
  advisories take the band of their real score instead of GitHub's label.
  PR gates with `max_high` / `max_critical` can start failing on code that
  passed before. This is intended: those findings were misrated.
- OS-package findings on RHEL-family, Oracle, Debian and Ubuntu images take
  the distro's rating. Many move *down* (vendor "Low" against NVD "High"), and
  the list's marker shows each one where that happened.
- Hovering or opening a finding shows who rated it what; hibou no longer
  hides the ratings it did not pick.
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
- **Pick one rating at ingest, as today.** Cheap, but each refresh
  discards what the next precedence rule would need, and a reader cannot see
  why a finding is "High". Rejected: storage keeps every rating, and the
  choice is a function over it that can change without refetching.
- **Distro rating per advisory instead of per finding.** One advisory covers
  npm, RHEL and Debian packages at once, so no single rating is right for it.
  Rejected; the per-finding copy already exists.
- **Keep `info` for unscored and only fix the inputs.** That still files
  every advisory no source scores under "harmless". Rejected.

## Open questions

- **EPSS in gates.** `vulnerabilities.min_epss` or a "new finding above the
  95th EPSS percentile" block, alongside KEV. Deferred until the data has
  been visible for a while.
- **EPSS history.** Latest scores only; significant movements are recorded
  on the advisory timeline instead of a history table
  ([ADR-040](040-epss-movements-on-the-advisory-timeline.md)).
