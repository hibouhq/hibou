# ADR-037: CWE as a first-class dimension across every finding type

## Status

Accepted — implemented (2026-10-09). Supersedes the CWE handling in the SARIF parser
(`extractCWEs`) and the three independent `cwe_ids text[]` columns. Extends the
filter grammar of [ADR-013](013-boolean-filter-expressions.md) /
[ADR-021](021-intelligent-search-bar.md), the finding model of
[ADR-012](012-unified-vulnerability-model.md), the finding origin model
(migration 00009) and the gate of
[ADR-018](018-forge-native-quality-gate-checks.md). No backward compatibility
is kept: columns, JSON fields and response shapes listed here are replaced, not
aliased.

**Naming.** This ADR says "CWE" for the dimension and never "weakness". The
existing `quality_gates[].weaknesses` section is renamed to `code` and its
scope is fixed (§8), so "weakness" no longer names a gate concept.

## Context

A developer asks "show me every SQL injection in my code **and** in my
dependencies". Hibou cannot answer that today. CWE data is collected in three
places and used in none of them.

### What reaches the database today

`internal/sarif/parser.go` builds `scan_rules.cwe_ids` from one source only: a
regex (`\bCWE-\d+\b`) over `rule.properties.tags`. Each scanner below was run on
2026-10-09 against the sample project or a small triggering fixture, and its
SARIF output was inspected. Three conventions exist in practice.

**A. SARIF taxonomy** (`rule.relationships[]` → a `toolComponent` named `CWE`):

| Scanner (version) | Shape | Extracted today |
|---|---|---|
| gosec 2.27.0 | `target.id: "327"`, `kinds: ["superset"]`, inline `run.taxonomies` (CWE 4.4) | **nothing** |
| SpotBugs 4.9.8 + Find Security Bugs 1.14.0 | `target.id: "78"`, `superset`, inline taxonomy (CWE 4.10); 12/14 rules mapped | **nothing** |
| KICS 2.1.20 | `target.id: "250"`, **no `kinds`** (= `relevant`), next to a second, custom `Categories` taxonomy on the same rule; duplicate `taxa[]` entries | **nothing** |
| ZAP 2.17.0 (DAST, `sarif-json` report) | `target.id: "829"`, `superset`, inline taxonomy (CWE 4.8) | **nothing** |
| Flawfinder 2.0.20 | `target.id: "CWE-120"` (**prefixed**), `kinds: ["relevant"]` plus `["incomparable"]` for the broader CWE; taxonomy only by `externalPropertyFileReferences` (no inline `taxa`) | **nothing** |

Every tool uses its own GUID for "the CWE taxonomy" (gosec `f2856fc0…`, KICS
`1489b0c4…`, SpotBugs `b8c54a32…`, ZAP `b000a760…`, Flawfinder `FFC64C90…`),
so no GUID can identify CWE. Only `toolComponent.name == "CWE"` is common to
all of them.

**B. Tags** (`rule.properties.tags[]`):

| Scanner (version) | Shape | Extracted today |
|---|---|---|
| semgrep 1.172.0 (registry `p/python`, `p/javascript`: 225/225 rules) | `"CWE-79: Improper Neutralization of …"` | the id; the title is discarded |
| CodeQL 2.27.2 (`*-security-extended`) | `"external/cwe/cwe-079"`, **zero-padded**; 57/103 JS rules carry several CWEs; rules are in `driver.rules` (the 3 `extensions` carry none) | stored as `CWE-079`, so it never matches `CWE-79` |
| bandit 1.9.4 | `"external/cwe/cwe-78"` | yes |
| mobsfscan 1.0.1, njsscan 1.0.1 | `"external/cwe/cwe-327"`, also repeated as `result.properties.cwe: "CWE-327: …"` | yes |

**C. No CWE in SARIF:**

| Scanner (version) | Note |
|---|---|
| Bearer (latest image) | native JSON has `cwe_ids: ["78"]`; the SARIF export drops it |
| Brakeman 8.1.0 | native JSON has `cwe_id: [89]`, `[913, 95]`; the SARIF export drops it |
| golangci-lint (gosec linter) | its SARIF writer emits **no rule descriptors at all**, so the gosec taxonomy is lost. Run gosec standalone, as hibou's CI already does |
| ESLint 9.39 + eslint-plugin-security + `@microsoft/eslint-formatter-sarif` | none |
| Trivy 0.72.0 (misconfig and vuln SARIF), Checkov 3.3.9 | none. For dependencies hibou reads Trivy **JSON**, whose `CweIDs` were present for 8/9 CVEs in the sample `package-lock.json` (jQuery CVE-2020-11022/11023 → CWE-79) |
| gitleaks 8, govulncheck 1.6.0 | none (secrets are CWE-798 by type, §4; Go advisories get CWE from OSV server-side) |

Not verified: Nuclei produced no result against the test target. Opengrep
uses the same rule metadata as semgrep but was not run separately. PMD,
Sobelow and Security Code Scan were not run. These results match the "CWE in
SARIF" column of [SAST-SCANNERS.md](../SAST-SCANNERS.md) for every tool both
cover.

Dependency findings get CWE from the advisory (`advisories.cwe_ids`: OSV
`database_specific.cwe_ids`, Trivy `CweIDs`, merged across providers). CVE feed
records have their own `cve_records.cwe_ids` (CNA/ADP `problemTypes`). All three
are free text with no normalization. Values seen include `CWE-79`, `CWE-079` and
NVD's `NVD-CWE-Other` / `NVD-CWE-noinfo`. The last two mean "no mapping" but
are stored as if they were CWEs.

Manual findings (`type = manual`, `origin = human | agent`, filed through
`POST …/findings`) have no CWE input at all. An AI agent that knows it found
a SQL injection has no field to say so.

`vulnerabilities.owasp_top_10` is read and displayed but no code ever writes
it.

### What the user sees today

- **SAST finding detail:** no CWE. `CodeFindingDetails.vue` reads
  `detail.advisory?.cwes`, and a SAST finding has no advisory.
- **Dependency finding detail:** a list of bare IDs with no titles. The
  component modal shows the *first* CWE only (`advisoryResponse.cwe`).
  `cwe_name` is declared but never filled.
- **Filters and gates:** no CWE qualifier, facet, list or gate condition. Free
  text `CWE-79` searches only `title` and `primary_identifier_value`.

## Decision

CWE becomes one normalized dimension that every finding type can carry:

- **Scanner findings:** from their rule.
- **Dependency findings:** from their advisory.
- **Secrets:** by definition (CWE-798).
- **Manual findings** (human or agent): from what the author declares.

It is extracted to the SARIF 2.1.0 spec and stored as integers. Titles, the
View 1000 hierarchy, named sets (Top 25, OWASP Top 10) and MITRE's
developer-facing categories come from an embedded MITRE catalog. One
definition of "which CWEs a finding carries" is used by the list API, facets,
the CWE list, the filter bar and the quality gate.

### 1. Identity: a CWE is an integer

`CWE-79`, `cwe-079`, `79` (a SARIF `taxa[].id`) and `external/cwe/cwe-79` all
normalize to `79`. `NVD-CWE-Other`, `NVD-CWE-noinfo` and anything that does not
parse to a positive integer are dropped. They mean "unmapped", which is
represented by the absence of a row (`cwe:none`). The text form `CWE-79`
exists only at the edges: API JSON, the UI, the query grammar and
`.hibou.yaml`.

One normalizer, `internal/cwe.Parse(string) (int, bool)`, is used by the SARIF
parser, the advisory providers (OSV, Trivy), the CVE feed, manual-finding
input, gate config validation and the query compiler. No other code parses CWE
strings.

### 2. SARIF extraction follows the spec, tags are the fallback

For each result, the CWE set is the **union** of:

1. **Rule-level taxonomy relationships** (§3.49.15
   `reportingDescriptor.relationships`). A relationship counts when its
   `target.toolComponent` is the CWE taxonomy and its `kinds` include `equal`,
   `superset` or `relevant`. An absent `kinds` defaults to `["relevant"]`
   (§3.53.3). The CWE is stored on the rule, so every result of that rule
   carries it.
   - `equal` and `superset` are membership by definition: §3.27.8 says a
     result "SHALL implicitly be taken to fall into" those taxa.
   - `relevant` is not membership in the strict spec reading. It is accepted
     because it is how KICS (implicitly) and Flawfinder declare their
     primary mapping. Excluding it would drop both tools.
   - `subset` and `incomparable` mean the rule only *overlaps* the CWE. Per
     §3.27.8, a result falls into such a taxon only if `result.taxa` lists it.
     They are not stored on the rule. Flawfinder's `incomparable` CWE-119 is
     still reachable through `cwe-tree:119`, because its `relevant` CWE-120 is
     a View 1000 child of 119.
   - `disjoint`, `canPrecede`, `canFollow`, `willPrecede` and `willFollow` are
     never a classification.
2. **Result-level taxa** (§3.27.8 `result.taxa[]`). Same reference resolution.
   These CWEs belong to that occurrence only, so they are stored per finding
   (`finding_cwe_assertions`, source `sarif_result`, §4), not on the rule. No
   tool tested above emits them; they are supported because the spec defines
   them and they are the only correct home for `subset`/`incomparable` claims.
3. **Tags** (fallback convention, not spec): `external/cwe/cwe-<n>` (CodeQL,
   bandit, mobsfscan, njsscan) and tags *starting with* `CWE-<n>` (semgrep's
   `"CWE-78: title"`). These two anchored forms replace the current "anywhere
   in any tag" regex.

**Identifying the CWE taxonomy.** A `toolComponentReference` is the CWE
taxonomy when either of these holds:
- its `guid` equals the `guid` of an entry named `CWE` in `run.taxonomies` or
  in `run.externalPropertyFileReferences.taxonomies` (Flawfinder);
- its `name` is `CWE` (case-insensitive).

§3.54.3 says `name` "does not participate in the lookup". It is used anyway:
GUIDs differ per tool, and `name` is the only signal all five
taxonomy-emitting tools share.

**Reading the CWE.** Read `target.id` through the normalizer, which accepts
both `"327"` and `"CWE-120"`. If `id` is absent, resolve `target.index` /
`target.guid` into the inline `taxa[]`. When the taxonomy is external, there is
no inline `taxa[]`, so a target without `id` is skipped. Deduplicate the
result: KICS repeats `taxa[]` entries.

**Titles.** The taxonomy's own `taxa[]` names are **not** stored. Titles come
from the MITRE catalog (§3). Tools ship CWE catalogs from 4.4 (2021) to 4.13,
so one ID would otherwise get different titles depending on the tool.

**Rule resolution.** The parser resolves `result.rule` (§3.27.7) per §3.54.2:
`toolComponent.index` points into `tool.extensions`, and a missing index means
`tool.driver`. Then it resolves `rule.index`, then `result.ruleIndex`, then
`ruleId`. Every tool tested keeps rules in `driver.rules`, including CodeQL
2.27.2. The `extensions` path is there for spec conformance (query packs can
legally define rules there), not for a known producer.

New types in `internal/sarif/types.go`: `Run.Taxonomies []ToolComponent`,
`Tool.Extensions []ToolComponent`, `ToolComponent.GUID` and `.Taxa`,
`ReportingDescriptor.Relationships`, `Result.Rule` and `Result.Taxa`, plus
`ReportingDescriptorReference`, `ToolComponentReference` and
`ReportingDescriptorRelationship`. `RuleDescriptor.CWEs` becomes `[]int`.

**Fixtures.** One real SARIF output per convention and per quirk is committed
under `internal/sarif/testdata/` and asserted with exact CWE sets:
- gosec and ZAP (`superset`)
- KICS (no `kinds`, two taxonomies, duplicate taxa)
- Flawfinder (prefixed IDs, `incomparable`, external taxonomy)
- CodeQL (padded, multi-CWE tags)
- semgrep (titled tags)
- bandit (`external/cwe`)
- Brakeman (no CWE)

Plus one synthetic file for `result.taxa` and rules in `extensions`, which no
tested tool produces. Fixtures are trimmed to a few rules and results, with
paths scrubbed.

**Not in SARIF.** Bearer and Brakeman have CWEs only in their native JSON.
Hibou ingests SAST as SARIF only, so their findings arrive without CWE and
show up under `cwe:none`. Writing per-tool native importers to recover them is
out of scope (Open questions).

### 3. An embedded MITRE catalog: titles, hierarchy, sets, categories

`internal/cwe/catalog.json` (CWE 4.20, 2026-04-30; 1,391 entries, ~210 KB) is
generated by `go generate ./internal/cwe` from the MITRE CWE XML, so it works
offline (no runtime download). It contains:

- **Entries:** `id`, `name` (the title shown everywhere), `abstraction`
  (pillar/class/base/variant, or category), `status` (including deprecated),
  `ChildOf` parents in **Research View 1000**, and the entry's **category**.
- **Named sets** (`cwe-set:`), taken from MITRE's own views, so no
  hand-maintained lists. The generator picks the latest final edition by view
  name and skips release candidates ("OWASP Top Ten RC1 (2025)"):

  | Slug | Source | Members |
  |---|---|---|
  | `top25` | View 1435, "2025 CWE Top 25" | 25 CWEs, ranked by member order |
  | `owasp-top10` | View 1344, "OWASP Top Ten (2021)" | union of its 10 categories |
  | `owasp-a01` … `owasp-a10` | the 10 OWASP categories of that view | category members |

- **Categories** (`cwe-category:`), from View 1400 "Comprehensive
  Categorization for Software Assurance Trends". It places **every
  non-deprecated weakness (944/944) in exactly one** of 22 categories:
  injection, encryption, access-control, memory-safety, file-handling,
  sensitive-information-exposure, and so on. The AI/LLM weaknesses
  (CWE-1426, CWE-1427) land under Injection. The generator fails if a
  weakness appears in two categories. These are the developer-facing groups a
  hand-written table ("Injection: CWE-89, 77, 78…") would approximate, but
  complete and maintained by MITRE.

The slug always points at the latest edition in the embedded catalog, and the
display name carries the edition ("CWE Top 25 (2025)"), so a reader can tell
which list a filter or gate used.

**The catalog is not mirrored into the database.** An earlier draft synced it
into `cwe_entries` / `cwe_ancestry` / `cwe_sets` at startup when the stored
version differed. That fails during a rolling upgrade: an old replica that
restarts rewrites the tables with its older catalog. Instead, everything that
needs the catalog reads it in Go:
- titles are attached to responses;
- `cwe-tree:` and `cwe-set:` / `cwe-category:` selectors are **expanded to
  concrete ID lists** before they reach SQL (§5);
- the gate matches in memory.

This means no sync, no lock, no drift.

Deprecated entries stay. They are shown as deprecated and never remapped. A
CWE ID not in the catalog, if a *scanner* reports it, is still stored and shown
as `CWE-<n>` without a title. The catalog is reference data, not a constraint
on scanner claims.

### 4. Schema: link tables replace the arrays

```sql
-- Producer claims (scanner rule, advisory, CVE record).
CREATE TABLE scan_rule_cwes (
    scan_rule_id uuid    NOT NULL REFERENCES scan_rules(id) ON DELETE CASCADE,
    cwe_id       integer NOT NULL CHECK (cwe_id > 0),
    PRIMARY KEY (scan_rule_id, cwe_id)
);
-- Covering reverse index: filters resolve "which rules carry CWE x" once per
-- query, index-only.
CREATE INDEX scan_rule_cwes_cwe_idx ON scan_rule_cwes (cwe_id, scan_rule_id);

CREATE TABLE advisory_cwes (
    advisory_id uuid    NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
    cwe_id      integer NOT NULL CHECK (cwe_id > 0),
    PRIMARY KEY (advisory_id, cwe_id)
);
CREATE INDEX advisory_cwes_cwe_idx ON advisory_cwes (cwe_id, advisory_id);

CREATE TABLE cve_record_cwes (
    cve_id text    NOT NULL REFERENCES cve_records(cve_id) ON DELETE CASCADE,
    cwe_id integer NOT NULL CHECK (cwe_id > 0),
    PRIMARY KEY (cve_id, cwe_id)
);

-- Per-occurrence CWEs, keyed like finding_acceptances — (repo_id, fingerprint)
-- — so they follow the finding across snapshots instead of living on one
-- snapshot row. Two sources:
--   sarif_result: SARIF result.taxa (§2), replaced on every ingest of the finding;
--   declared:     the author of a manual finding (human or agent token).
CREATE TYPE finding_cwe_source AS ENUM ('sarif_result', 'declared');
CREATE TABLE finding_cwe_assertions (
    repo_id     uuid    NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    fingerprint text    NOT NULL,
    cwe_id      integer NOT NULL CHECK (cwe_id > 0),
    source      finding_cwe_source NOT NULL,
    declared_by uuid    REFERENCES users(id) ON DELETE SET NULL,
    declared_api_key_id uuid REFERENCES api_keys(id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (repo_id, fingerprint, source, cwe_id),
    -- A SARIF row never names a principal; a declaration must (enforced by
    -- the store, which refuses a declaration without user or token).
    CONSTRAINT finding_cwe_assertions_principal CHECK (
        source = 'declared' OR (declared_by IS NULL AND declared_api_key_id IS NULL))
);
CREATE INDEX finding_cwe_assertions_cwe_idx
    ON finding_cwe_assertions (cwe_id, source, repo_id, fingerprint);

-- The definition of "which CWEs does this finding carry" (point reads).
CREATE VIEW finding_cwes AS
    SELECT v.id AS vulnerability_id, rc.cwe_id, 'rule'::text AS source
      FROM vulnerabilities v JOIN scan_rule_cwes rc ON rc.scan_rule_id = v.rule_ref_id
    UNION ALL
    SELECT v.id, ac.cwe_id, 'advisory'
      FROM vulnerabilities v JOIN advisory_cwes ac ON ac.advisory_id = v.advisory_id
    UNION ALL
    SELECT v.id, fa.cwe_id, fa.source::text
      FROM vulnerabilities v JOIN finding_cwe_assertions fa
        ON fa.repo_id = v.repo_id AND fa.fingerprint = v.fingerprint
     WHERE fa.source = 'sarif_result' OR v.type = 'manual'
    UNION ALL
    SELECT v.id, 798, 'type'
      FROM vulnerabilities v WHERE v.type = 'secret';
```

The migration drops `scan_rules.cwe_ids`, `advisories.cwe_ids`,
`cve_records.cwe_ids`, `idx_scan_rules_cwe_ids` and the never-written
`vulnerabilities.owasp_top_10`. OWASP is now derived from CWE through the
`owasp-*` sets. The link tables are backfilled from the arrays through the
normalizer's SQL equivalent, so advisory CWEs are available immediately
instead of after the next provider refresh.

Design choices:

- **CWEs are read through the rule, advisory or assertion, not copied onto
  each snapshot row.** `vulnerabilities` has one row per finding *per snapshot*. A
  per-finding copy would multiply rows and go stale whenever an OSV refresh
  re-maps an advisory. With the join, an advisory re-mapped upstream re-labels
  every affected finding immediately.
- **Declarations are limited to `manual` findings.** A scanner finding's CWE is
  the scanner's claim. Letting triagers overwrite it would make the CWE filter
  answer "what someone typed" instead of "what the tool says". Declarations are
  keyed on `(repo_id, fingerprint)` because a manual finding is carried
  across snapshots like any other.
- **Declared CWEs must exist in the catalog** (400 otherwise). Typed or
  agent-generated input is validated, unlike scanner claims, which are kept
  because the producer said so. `declared_by` / `declared_api_key_id` follow
  the 00009 origin rule: every non-scanner fact names an accountable
  principal.
- **No catalog table, so no FK.** An ID missing from our catalog is still the
  producer's real claim; it is stored and shown without a title.
- **Leaked secrets are CWE-798** (Use of Hard-coded Credentials) by
  definition. A type-level mapping is used because no secret scanner emits CWE.
  This is the only implicit mapping. Other findings without a CWE stay
  unmapped rather than being guessed.
- Rule upsert **replaces** the rule's CWE set: the scanner's current rule
  definition is authoritative. Advisory upsert keeps the existing **union
  across providers**, as `mergeStrings` did.

**Write path built for re-ingestion.** Every upload re-reports the same rules
and findings, so the writes must cost nothing when nothing changed:

- Every "replace" is one statement: a data-modifying CTE deletes only the
  pairs that disappeared, then inserts with `ON CONFLICT DO NOTHING`
  (`SyncScanRuleCWEs`, `SyncCVERecordCWEs`, `SyncDeclaredFindingCWEs`,
  `SyncSnapshotSARIFResultCWEs`). An unchanged resync writes **no tuples**:
  no dead rows, no vacuum pressure, no WAL. A store test checks this through
  `xmin`.
- Rule CWEs and SARIF result CWEs are written in **one batch per artifact**,
  not per result.
- The ingester now upserts each scan rule **once per ingest**. It used to run
  `ON CONFLICT DO UPDATE` per SARIF result, which left one dead tuple per
  occurrence.

**Read paths: one definition, three shapes.** The view above is the reference
and serves point reads: a page's CWEs and a gate delta select from it by
`vulnerability_id`, which pushes down into each branch as an index lookup
(~5 ms for 50 IDs). Set-oriented paths encode the same four branches against
their own rows instead, because joining a whole snapshot through the view
re-reads `vulnerabilities` per branch:

- **Filters** (`filterquery.CWESQL`) compile an ID set to uncorrelated
  `v.rule_ref_id IN (SELECT scan_rule_id FROM scan_rule_cwes WHERE cwe_id = ANY($n))`
  branches, plus the advisory and assertion equivalents. Under the OR that
  joins them, Postgres turns each into a **hashed SubPlan**: computed once
  from the covering index, then one hash probe per row. `cwe:any` / `cwe:none`
  have no ID to drive from, so they probe the claim tables' primary keys per
  row. The secret → CWE-798 mapping is folded in Go (`OR v.type = 'secret'`
  only when 798 is selected).
- **Aggregation** (`store.findingCWERowsSQL`, used by the CWE facet and the
  CWE list) joins a filtered CTE to each claim table with hash joins.

`TestFindingCWEFormsAgree` pins the three shapes to identical results over
every source and every selector form.

Measured on 2M findings (20 snapshots × 100k: 60% dependency, 35% SAST, 5%
secrets; 200k advisories, 274k advisory CWE rows, 5k rules), in a dev
container on WSL, without parallel workers:

| Query (one 100k snapshot) | Time |
|---|---|
| page of 50 with `cwe:89` / `cwe-tree:74` / `cwe-set:top25` / `cwe:none` | 3–58 ms |
| total count with a CWE filter | 220–730 ms (the same count with no CWE filter: 260 ms) |
| CWE facet, set-oriented | 350–570 ms |
| CWE facet joined through the view (rejected) | 7.0 s |
| CWEs of a 50-finding page, through the view | 4.6 ms |
| CWE facet over all 20 snapshots (2M findings, the org CWE list) | 4.7 s |

The org-wide aggregate is the only slow path. It is loaded once per visit of
the org CWE tab, never per keystroke. Precomputing it is left open (Open
questions). An "aggregate-first" variant (count per rule/advisory, then join)
was measured: it is only faster when it double-counts findings with
overlapping sources, and the exact version (~1 s per snapshot) is slower than
the shape above.


### 5. Query grammar

New qualifiers in `filterquery` (server) and `filterBarQuery.ts` (client):

| Query | Meaning |
|---|---|
| `cwe:79` / `cwe:CWE-79` | carries CWE-79 exactly |
| `cwe:79,89` | carries any of them (existing comma-OR rule) |
| `cwe-tree:74` | carries CWE-74 **or any descendant** in View 1000 (all injection) |
| `cwe-set:top25` / `cwe-set:owasp-a03` | carries a member of the named set |
| `cwe:none` | carries no CWE (coverage gap: checkov/trivy misconfig, unmapped advisories) |
| `cwe:any` | carries at least one |
| bare `CWE-79` text token | rewritten to `cwe:79` (ADR-021 entity detection, server and client) |

The qualifier combines with everything else. For example,
`cwe-set:owasp-a03 (type:sast OR type:dependency OR type:manual) severity:high`
returns injection findings from the repo's code, from its dependencies' CVEs,
and from agent-filed findings in one list.

| `cwe-category:injection` | carries a weakness of that View 1400 category |

Every qualifier expands in Go (§3) to an ID list and compiles to the
hashed-subplan predicate of §4. The SQL is the same whatever the qualifier
was.

A malformed value (`cwe:abc`) or an unknown set or category slug returns 400
with the existing "invalid filter query" error. A well-formed CWE ID that is
not in the catalog is valid: a scanner may report it.

**The plain dialect.** The discrete filter model has no CWE field, and adding
one to every static list query would duplicate the compiler. The bar marks
CWE qualifiers as *server-only* instead:
- their presence sends the whole bar as `q`, while the discrete model stays
  live, so dropdowns keep working;
- a dropdown change rebuilds the bar and keeps the CWE tokens;
- the hidden `status:detected` default is added to every server-side query
  (`withHiddenDefaults`), so adding `cwe:79` — or an OR — never silently widens
  the list to resolved findings.

The facets request keeps the discrete params only. Each facet excludes its
own dimension, so the CWE facet is not narrowed by the bar's own `cwe:`
tokens. The facets endpoint also accepts `q` for API callers.

The quality gate (§7) uses the **same** selector type (`cwe.Selector`), so a
gate rule and the filter reproducing it match the same findings. Saved
presets (ADR-033) work unchanged: they store the bar text. **A saved preset is
also the way to keep a custom CWE list** ("Our banned list" =
`cwe:89,78,502`) without new storage. Set lookup goes through a `SetLookup`
interface, so org-defined lists can be added later without touching the
compiler or the gate.

### 6. API

The CWE shape returned everywhere is
`{id: 89, name: "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"}`.
Findings add `abstraction`, `deprecated`, `source`, `category` and, on the
detail, `sets` (for example `[{slug: "top25", name: "CWE Top 25 (2025)", rank: 2}]`).

- **List rows** (repo and org `…/vulnerabilities`): `cwes: [{id, name,
  category, source}]`, attached per page in one batched query. Titles are
  inlined so a list needs no second request.
- **Finding detail**: `cwes: [{id, name, abstraction, deprecated, source:
  "rule"|"advisory"|"sarif_result"|"declared"|"type", category, sets}]` at the finding level. It replaces
  `advisory.cwes`, so SAST, SCA and manual details render CWEs the same way.
  `advisoryResponse.cwe` / `cwe_name` and `owasp_top_10` are removed; advisory
  responses carry `cwes` with the same shape.
- **Rules endpoint**: `cwe_ids` becomes `cwes` (same shape).
- **Manual findings**: `POST …/findings` accepts `cwes: ["CWE-89", "79"]`
  (any form the normalizer accepts). Unknown IDs are a 400 that names the bad
  value. The finding and its declaration are written in one transaction.
  `PUT …/findings/{fingerprint}/cwes` replaces the set on an existing manual
  finding; it needs vulnerabilities write access (the same as filing), is
  audited (`finding.cwes`), and shows up in the finding's history as
  "CWEs changed". On a scanner or dependency finding it returns 409.
  Humans in the UI and AI agents with an API token use the same endpoints;
  origin is derived from the principal as today.
- **Facets** (`…/vulnerabilities/facets`): a `cwe` dimension, `{"79": 4, …}`,
  with the busiest 20 under the current filter. Titles come from the catalog
  endpoint. An optional `q` scopes the facets like the list.
- **CWE list**: `GET {repoRoute}/cwes?q=` and `GET {orgRoute}/cwes?q=`. These
  return one row per CWE present in scope: `{id, name, abstraction, category,
  sets, total, by_type: {sast: n, dependency: n, manual: n, …}, max_severity}`,
  plus `no_cwe` and `total_findings`. The response accepts the same `q`, so it
  always agrees with the list; without `q` it counts open findings. It uses the
  existing `CapVulnerabilities` read scope.
- **Catalog**:
  - `GET /api/v1/cwe?q=sql&limit=20`: search by ID or title.
  - `GET /api/v1/cwe?ids=79,89`: batch title lookup for hover (with category,
    sets and descendant count).
  - `GET /api/v1/cwe/sets`: the named sets and the categories, each with
    slug, name and member count.

  These return reference data only. Any authenticated caller, scoped API
  tokens included, may use them. Responses are cached privately for an hour.

The SARIF upload contract is unchanged: producers keep sending standard SARIF.
`findings.GenericFinding` (non-SARIF importers) carries `CWEs []int`.

### 7. Quality gate: deny CWEs

A new `cwe` section in a `.hibou.yaml` quality gate:

```yaml
quality_gates:
  - branches: [main]
    enforcement: blocking
    cwe:
      deny: [CWE-89, CWE-78]          # exact
      deny_tree: [CWE-74]             # CWE and all descendants
      deny_sets: [top25, owasp-a03]   # named sets
      deny_categories: [injection]    # View 1400 categories
      types: [sast, dependency, manual]   # optional; default: every type
      min_severity: medium            # optional; default: any severity
```

- **Scope is the delta.** Only **new** findings in the PR are evaluated, like
  the `vulnerabilities` and `secrets` sections. Accepted findings are already
  filtered out upstream, so acceptance with a reason (ADR-023) remains the way
  to merge past a denied CWE.
- **Reasons name the CWE by title.** For example: `new finding G201 in
  db/query.go:42 carries CWE-89 (Improper Neutralization of Special Elements
  used in an SQL Command), denied by quality_gates[0].cwe.deny_tree CWE-74`.
  The forge check (ADR-018) shows the same text, so the developer reads what
  was denied without leaving the PR.
- **Lookup fails closed.** The gate reaches the store through an optional
  `cweLister` interface (batch `finding_cwes` lookup for the delta's IDs). It
  gets the ADR-029 compile-time assertion on `StoreAdapter`. A lookup error, a
  store that cannot resolve CWEs, or a policy that cannot be compiled each fails
  the evaluation instead of skipping the section, like the KEV and
  license-policy reads.
- **Config is validated on load.** Each of these is a config error, reported
  the way existing `quality_gates[i]…` errors are:
  - a malformed CWE, an ID not in the catalog, or an unknown set or category;
  - `none`/`any` in a deny list;
  - an unknown type or severity;
  - a section that denies nothing.

  A typo must not turn into a gate that never fires. The effective-config view
  lists every rule with its title and member count.
- **Selectors share the query compiler** (§5), so a gate rule and the filter
  that reproduces it (`cwe-tree:74 severity:medium,high,critical`) always
  match the same findings. The gate failure links to that filter.

### 8. Rename `weaknesses` → `code` and scope it to code findings

`.hibou.yaml` and `DefaultYAML()` describe `quality_gates[].weaknesses` as the
gate "for code findings". However, `evaluateRepoWeaknessThresholds` counts
**every** new finding (`countNewVulnerabilitySeverities` has no type filter),
while `vulnerabilities` already counts dependency/container/malware findings
(`isDependencyFinding`). A new high-severity dependency CVE therefore trips
both `weaknesses.max_high` and `vulnerabilities.max_high`. New secrets also
count against `weaknesses` on top of `secrets.max_new`.

Breaking change (alpha):

- The YAML key `weaknesses` becomes `code` (`CodeThresholds` / `CodeGate`, with
  the same `enabled`, `max_critical`, `max_high`, `max_medium` fields). The old
  key is a config validation error with a hint to rename it, not an alias.
- `code` counts only first-party findings: `sast`, `dast`, `fuzzing`, `manual`,
  `generic`. Each finding type now belongs to exactly one severity section:
  `code`, `vulnerabilities` (dependency/container/malware) or `secrets`. The
  `cwe` section (§7) is the only cross-type section, by design.
- Reason text says "code findings" ("repo config exceeded max high code
  findings: 2 > 0"). `effective_config.go`, `ConfigSettings.vue` ("Code"
  label), `DefaultYAML()`, the repo's own `.hibou.yaml`, the JSON schema
  published at `hibou.dev/schemas/v1/hibou-config.schema.json` and the tests are
  updated in the same change.
- The stored-gate fallback (`evaluateStoredFindingGates` over
  `quality_gates.max_new_findings` when no file section exists) gets the same
  type scope.

## UX (as built)

- **A CWE ID never appears without its title.**
  - *Chips* on list rows (repo and org): `CWE-89`, two per row plus "+n". The
    tooltip carries the title, the category and the set ranks ("CWE Top 25
    (2025) #2"). A click adds `cwe:<id>` to the current bar. Deprecated CWEs
    are struck through.
  - *Filter-bar completion*: `cwe:` and `cwe-tree:` suggest rows of
    `CWE-89` with the title on a second line. Groups:
    - *In this view*: the facet, with counts;
    - *All CWEs*: catalog search by ID **or** title, so `cwe:sql` finds CWE-89;
    - *Coverage*: `none` / `any`.

    Picking a suggestion inserts the numeric form. `cwe-set:` and
    `cwe-category:` suggest names with member counts.
  - *Filter-bar hover*: hovering a `cwe:`, `cwe-tree:`, `cwe-set:`,
    `cwe-category:` or bare `CWE-79` token shows a card with the title,
    category and sets. An ID unknown to the catalog says so and stays valid.
    Titles are fetched once per ID (batched) and cached client-side.
- **Finding drawer**: one "Weakness (CWE)" section for every finding type,
  with each CWE's title, category, set badges and source ("from the scanner
  rule", "from the advisory", "declared by the author", "leaked secrets are
  CWE-798"). Each CWE links to cwe.mitre.org. On a manual finding the section
  has an inline editor; the list row updates after a save.
- **CWE tab** next to Vulnerabilities, at repo and org level. It is a table of
  CWE, title, total, per-type counts (Code / Dependencies / Secrets / Manual)
  and max severity, sorted by total. Grouping: All, By category (View 1400,
  with a header link to `cwe-category:`), or Top 25 (in rank order, then the
  rest). Clicking a title opens the findings with `cwe:<id>`; "whole class →"
  opens them with `cwe-tree:<id>`. A `No CWE` row sits at the bottom, so
  scanners that classify nothing stay visible.
- **Settings**: the gate summary shows the `code` and `cwe` sections. The
  effective-config view lists the CWE rules with titles.

Deferred from the draft:
- the View 1000 parent chain in the CWE tab;
- a CWE picker with a live preview in gate settings (the gate is configured in
  `.hibou.yaml`);
- a manual-finding creation form: none exists in the UI. Manual and agent
  findings are filed through the API, and their CWEs are editable in the
  drawer.

## Implementation notes

- `internal/cwe`: normalizer (`Parse`, `ParseTag`), the embedded catalog, the
  selector compiler (`ParseSelector`, `SetLookup`), and the generator
  (`go generate ./internal/cwe`; `-in` takes a local `cwec_*.xml.zip`).
- Migration `00040_cwe_model`: claim tables, `finding_cwes` view, backfill
  from the arrays (round-tripped up/down/up against legacy data), drops the
  three arrays and `owasp_top_10`.
- SARIF fixtures: real outputs of gosec, SpotBugs, KICS, ZAP, Flawfinder,
  CodeQL, semgrep, bandit and Brakeman, plus a synthetic file for
  `extensions`, guid-only references, non-classifying kinds and `result.taxa`.
- `seed.go` gives demo rules and advisories the CWEs those scanners and NVD
  report. It leaves ESLint, Checkov and Trivy misconfig rules unmapped on
  purpose, so the demo shows real `cwe:none` gaps.

## Consequences

- gosec, SpotBugs/Find Security Bugs, KICS, ZAP and Flawfinder findings get
  CWEs for the first time. CodeQL's padded IDs match the same CWE as everyone
  else. Bearer, Brakeman, ESLint, Checkov and Trivy misconfig findings stay
  under `cwe:none`, because their SARIF has no CWE. The CWE tab's `No CWE` row
  makes that visible.
- One query, one list and one gate rule cover code, dependency, container,
  secret and manual/agent findings by CWE. `cwe-tree:` and `cwe-set:` answer
  class-level questions ("all injection", "anything in the Top 25") without
  the developer knowing the CWE hierarchy.
- Agents filing findings can classify them in a form the gate and filters
  use, and the declaration is attributed to the token that made it.
- Breaking API changes: `advisory.cwes`, `advisoryResponse.cwe`/`cwe_name`,
  `rules[].cwe_ids` and `owasp_top_10` are removed in favor of `cwes`. The site
  is updated in the same change, and there are no other in-tree consumers.
- Breaking config change: `quality_gates[].weaknesses` → `code`, now limited
  to code findings. A repo that relied on `weaknesses` also catching dependency
  CVEs must set `vulnerabilities` thresholds, which it should have had anyway.
- CWE filters cost one hashed subplan per claim table, built from covering
  indexes and applied only when requested. Measured costs are in §4.
- The catalog and sets are release-bound. A new Top 25 edition needs a
  regenerate and a release, and the slug then silently moves to the new
  edition. This is intended: the edition is in the set name shown in the gate
  reason.

## Alternatives considered

- **Keep `text[]` and fix the regex.** It fixes CodeQL padding but not gosec,
  and does nothing for cross-type filtering, titles, hierarchy, sets or gating.
  It also leaves three formats in three tables.
- **`integer[]` columns with GIN instead of link tables.** Writes are cheaper,
  but facets and the CWE list need `unnest` everywhere, and a finding still
  needs the union view to combine its sources. Link tables index the same
  lookups and keep the view trivial.
- **Store CWEs per finding row.** This multiplies by snapshots and goes stale
  on advisory re-mapping. Rejected (§4).
- **Let triagers override scanner CWEs.** It mixes claims with opinions in
  one filter. Rejected: declarations are for manual findings only.
- **Use the tool's own `taxa[]` names.** Titles would differ by tool and
  version for the same ID. Rejected in favor of one catalog.
- **Hand-maintained Top 25 / OWASP lists.** MITRE publishes both as views
  in the catalog XML we already parse. Rejected.
- **Fetch the catalog at runtime from MITRE.** It breaks offline/air-gapped
  installs. Rejected.
- **Generic "deny if query matches" gate section.** It is more powerful, but
  it is a second gate language and makes reasons hard to explain. Rejected in
  favor of a CWE section that shares the compiler. Revisit if other dimensions
  need the same thing.

## Open questions

- **Org-level CWE policy.** Should security teams be able to set a deny list
  once per org, inherited by repos, following the org license policy of
  [ADR-030](030-org-license-policy-and-repo-override.md)? Same shape as the
  `cwe` section, with repos allowed to add to it but not remove from it.
- **Notification rules on CWE** (for example, "notify #appsec on any new
  `cwe-set:top25` finding"). The predicate is reusable; only the rule UI is
  missing.
- **Organization-defined CWE lists** (for example, "our banned list"). Today a
  saved search preset (`cwe:89,78,502`) covers filtering, and `.hibou.yaml`
  deny lists cover gating. If org-shared lists are needed, store them next to
  the presets and plug them in through `cwe.SetLookup`.
- **Precomputed org-wide CWE aggregate.** The org CWE list scans every
  repository's current findings (4.7 s for 2M findings on a dev box). A
  per-snapshot rollup would be cheap to read but must stay correct across
  triage changes. Revisit when an org's current findings pass ~1M.
- **Tools whose CWE is only in native JSON** (Bearer `cwe_ids`, Brakeman
  `cwe_id`). There are two options:
  - fix their SARIF exporters upstream, so they emit taxonomy relationships;
  - have the hibou CLI / upload action convert their JSON into SARIF with a
    CWE taxonomy before upload.

  Upstream is preferred: the server stays SARIF-only, and everyone using those
  tools benefits.
