# ADR-027: CPE-identified components — matching software that has no package coordinates

## Status

Proposed (2026-08-24). **See also [ADR-028](028-cve-subscriptions-with-manual-purl-triage.md)**,
which addresses the same gap by curating product → package identity by hand
instead of inferring it, and recommends being built first. Extends the canonical advisory model of
[ADR-007](007-canonical-advisory-model.md) with a second identifier universe,
the component inventory of [ADR-012](012-unified-vulnerability-model.md), and
the triage surfaces of [ADR-023](023-triage-acceptance-ux.md).

## Context

Hibou identifies every component by **PURL** and matches advisories by
`(ecosystem, package_name, version)`. That is correct and precise for anything a
package manager installed. It is structurally blind to everything else.

### The reproducible case

The `images/tomcat` fixture in `hibou-sample-project` pins Tomcat 11.0.22. That
image reads **clean** in Hibou and in Trivy — and in every other purl-based
scanner — while five CRITICAL/HIGH CVEs apply to it. Verified 2026-08-24 against
the live public records:

| Source | Coordinates for CVE-2026-59084 (and -53404, -53434, -55276, -59083) |
|---|---|
| CVE record, `containers.cna` (`apache`) | `affected`: product "Apache Tomcat", `11.0.0-M1` → `lessThanOrEqual: 11.0.23`, semver. **Product name, not a package coordinate. No CPE.** |
| CVE record, `containers.adp[]` (`CISA-ADP`) | `metrics` only (CVSS 9.1). No `cpeApplicability`. |
| NVD (`vulnStatus: Analyzed`) | `cpe:2.3:a:apache:tomcat:*` + `versionStartIncluding 11.0.0`, `versionEndIncluding 11.0.23` — **the only machine-usable affected range with an identifier** |
| GHSA | advisory exists, `severity: critical`, but `type: unreviewed` with an **empty `vulnerabilities` array**: no ecosystem, no package, no range |
| OSV | entry exists by CVE ID, but every `affected` entry is `type: GIT` commit ranges only — **no `package`, no `ecosystem`** |

So `osv.QueryPackages({ecosystem: "maven", name: "org.apache.tomcat:tomcat-catalina", version: "11.0.22"})`
returns zero results. Not a bug in our query, and not lag that resolves itself:
the advisory has no Maven coordinates for anyone to match on. The last *reviewed*
Tomcat GHSAs are dated 2026-05-12 and their ranges stop at `< 11.0.22`, so
11.0.22 actively looks like the fixed version to a purl matcher. It reads clean,
confidently — the worst failure mode we have.

This is not Tomcat-specific. It is the general shape of any software installed
outside a package manager (app servers, web servers, language runtimes, vendored
binaries) combined with any CNA that publishes product names rather than package
coordinates. CPE-based scanners report this class of finding; we do not.

### Where every scanner lands on that same image

The same matrix is maintained beside the fixture in
`hibou-sample-project/SECURITY-FIXTURES.md`, so a comparison run can be checked
against it without re-deriving any of this. Verified 2026-08-24.

| Tool | Result on 11.0.22 | Why |
|---|---|---|
| **Hibou today** | none | purl-only matching; the GHSA/OSV entries carry no coordinates |
| **Hibou after this ADR** | **all five** | CPE fallback lane (§6) against an NVD provider (§4) |
| **Trivy** (`image --scanners vuln`) | none | purl-only; its Java DB is GHSA-derived |
| **Dependency-Track** | none *from a Trivy or Syft CycloneDX SBOM* | its internal analyzer **does** match CPEs against a mirrored NVD, but ["matching against data from the NVD requires components to have a valid CPE"](https://dependencytrack.github.io/docs/next/reference/analyzers/) and DT will not infer one from a purl. Hand-add `cpe:2.3:a:apache:tomcat:11.0.22` and it reports all five |
| **Grype** | none *by default*; reports if CPE matching is re-enabled for Java | consumes Syft's CPE *candidate set*, which contains the matching `apache:tomcat` — but `match.java.using-cpes` defaults to **false**, so the candidate is never used |
| **Snyk / Dependabot** | none | purl-only |
| **Wiz** | **all five** — *reported, not reproduced here* | agentless disk/layer inventory feeding an NVD-backed catalog: it fingerprints Tomcat from the image filesystem rather than a manifest, then matches `cpe:2.3:a:apache:tomcat`. The only row in this table not run locally — we have no Wiz access, so treat it as the motivating report rather than a measurement |
| **Other CPE-based scanners** (NVD-backed CSPM/agentless) | **all five** | same mechanism: `cpe:2.3:a:apache:tomcat`, `versionEndIncluding 11.0.23`, straight from NVD |

Every row except Wiz was run against our test image locally (in hibou-sample-project); the Wiz row is the
report that prompted the ADR, kept in the table because it is the behaviour we
are trying to reach, and marked so nobody mistakes it for a measurement.

Two rows carry the decision. **Dependency-Track** is the near-miss: it has the
advisory half of this ADR already — NVD mirror plus CPE matching — and still
reports nothing, because nothing puts a correct CPE on the component. That is
§3's entire subject, and it is why §3 is about SBOM *format* rather than about
adding a data source. **Grype** is the existence proof that the remaining half
works, and the source of §6's per-ecosystem switch.

### Why we cannot fix this on the purl side

Two independent gaps, and closing either one alone changes nothing.

**Advisory side.** We register two providers, `osv` and `trivy`
([internal/provider/](../../internal/provider/)). Neither carries CPE
applicability. There is no NVD provider, so the one database that has the range
above is not consulted.

**Component side.** [internal/sbom/cyclonedx.go:156](../../internal/sbom/cyclonedx.go#L156)
drops any component whose PURL is absent or unparseable, and nothing reads the
CycloneDX `cpe` field. The schema enforces the same assumption:

```sql
purl text NOT NULL,                                              -- 00001:492
CONSTRAINT components_purl_version_key UNIQUE (purl, version)    -- 00001:1377
```

And a detail that decides the implementation: **Trivy's CycloneDX output
contains no `cpe` field at all.** On a Tomcat image SBOM, all 177 components
carry `purl` + `hashes` + `properties` and zero CPEs. So "parse the CPE field we
already receive" is not available — there is nothing to parse. Syft *does* emit
candidate CPEs per component, which is how Grype performs NVD matching and why
it catches cases Trivy misses.

### Why not simply switch to CPE

CPE's weaknesses are real and are the reason we are purl-first today:

- **Curated, not derived.** CPE names are assigned by NVD analysts; no algorithm
  maps installed software to a CPE. Vendor renames leave duplicates alive —
  `cpe:2.3:a:f5:nginx` and `cpe:2.3:a:f5:nginx_open_source` are two products for
  one daemon, so a scanner keyed to one silently misses the other.
- **Coarse.** `cpe:2.3:a:apache:tomcat:*` with a wide range flags an entire
  install regardless of whether the vulnerable component ships or is reachable.
- **No ecosystem.** Vendor/product collisions across ecosystems are unavoidable.

PURL keeps every one of those problems away for declared dependencies, which are
the majority of what we scan. The conclusion is not "replace" but "add, and keep
them separable".

### What other tools learned the hard way

We are late to this problem, which means the failure modes are documented.

**Dependency-Track**
([discussion #4180](https://github.com/DependencyTrack/dependency-track/discussions/4180))
hit our exact case with Telerik UI for WPF: the SBOM carried per-submodule
NuGet PURLs, the NVD record carried one monolithic
`cpe:2.3:a:telerik:ui_for_wpf`, and nothing matched. Maintainer `nscuro`'s
verdict on the obvious fix:

> The viability of matching PURLs to CPEs is somewhere between impractical and
> impossible.

Their guidance is to prefer PURL-native sources and, where a CPE is required, to
have **the SBOM carry it** rather than infer it downstream. Two lessons we take
directly: do not build a purl→cpe mapper, and treat the *granularity mismatch*
(one product CPE vs many component PURLs) as a first-class problem rather than an
edge case.

**Grype/Anchore** have run CPE matching in production for years and then largely
switched it off. Their stated root cause is **cross-ecosystem collision**: CPE
has no ecosystem dimension, so `cpe:2.3:a:*:foo` cannot distinguish a Python
`foo` from an npm `foo`, while GHSA is ecosystem-partitioned. Their published
example is Protobuf — the **C++ CVE matched against the Go implementation**.
Keith Zantow's summary:

> After experimenting with a number of options for improving vulnerability
> matching, ultimately one of the simplest solutions proved most effective: stop
> matching with CPEs.

The change was **not** Java-specific: they disabled CPE matching for *every*
ecosystem GHSA covers, and kept it only for artifact types GHSA does not —
**binaries and Alpine-only entries**, precisely where there is no ecosystem to
collide on ([Say Goodbye to False Positives](https://anchore.com/blog/say-goodbye-to-false-positives/)).
The result across their corpus was **2,000+ false positives removed for 11 false
negatives**.

How they know that is as important as the number. Grype runs a **quality gate on
every commit** against a repository of **manually labelled** match data,
comparing the previous release to the change under test. The trade-off is
measured, not asserted — see §12, which adopts the same requirement.

Their open issues preview ours: CPE configurations with `AND`-ed nodes
mishandled into false positives
([grype#1349](https://github.com/anchore/grype/issues/1349)), and generated CPEs
carrying the wrong vendor
([grype#1490](https://github.com/anchore/grype/issues/1490)).

**Where we deliberately differ.** Anchore's rule is *per ecosystem*: if GHSA
covers Maven, do not CPE-match Maven at all. Applied here that would miss our
motivating case, since `tomcat-catalina` is a Maven artifact GHSA nominally
covers but has no advisory for — and indeed **Grype's own default
(`match.java.using-cpes: false`) means Grype misses Tomcat 11.0.22 too.** §6's
rule 1 is instead *per component, per query*: CPE fires only where the PURL path
returned nothing **for that specific component**. That is strictly more
permissive than Anchore's rule, on purpose — it exists to catch the false
negative they accept — and it follows that we should expect a higher false
-positive rate than Grype and cannot skip the measurement in §12.

### Is PURL or CPE the future?

Complementary, indefinitely — with PURL winning where it applies and CPE
surviving as the only identifier for the class of software that motivated this
ADR. The trajectory is not ambiguous, but neither does it close our gap:

- **PURL has won institutionally.** It was adopted as **ECMA-427** in December
  2025 and is fast-tracked toward ISO ([TC54](https://tc54.org/purl/)). `VERS`,
  its version-range companion, is due at Ecma later in 2026 — worth watching,
  since it targets exactly the range semantics our `versioncmp` package
  implements by hand.
- **PURL is now in the CVE record** — `packageURL` on `affected` since CVE
  Record Format **5.2.0** (October 2025). But it is **optional for CNAs**, and
  the format **disallows a version inside the PURL**, so a PURL gives identity
  while ranges still come from `versions[]`. It is not a drop-in replacement for
  a CPE applicability statement.
- **Nobody indexes it yet.** The OSSF vulnerability-disclosures WG's roadmap
  ([issue #177](https://github.com/ossf/wg-vulnerability-disclosures/issues/177))
  lists "vulnerability databases and scanners index CVE records by PURL" as
  *task one*, still outstanding, with adoption currently at zero.
- **PURL structurally cannot cover this case.** It identifies software
  distributed through package managers. Software installed from a tarball into
  an image, and commercial software generally, has no PURL to assign. The
  proposed `scid` PURL type for commercial software is speculative and years out.

So CPE is not a stopgap we retire when PURL matures. For non-package-manager
software it is the *only* identifier that will exist for the foreseeable future,
and this ADR should build it as a permanent, narrow fallback lane rather than a
bridge. Conversely, we should expect PURL coverage in advisories to keep
improving, which is an argument for making the CPE lane easy to *switch off* per
ecosystem as coverage arrives — Grype's design, and the reason §6 makes CPE a
fallback rather than a parallel path.

### The advisory-database PR queue, and what is already in it

Measured 2026-08-24 against `github/advisory-database`:

| | |
|---|---|
| Open PRs | **352** |
| Of the most recent 100, touching `advisories/unreviewed/` | 35 |
| Median merge lag on recently-merged PRs | **0 days** (max 7) |

A community PR **already exists** for one of our five —
[#8960](https://github.com/github/advisory-database/pull/8960), adding Maven
coordinates to `GHSA-hcjr-322h-429r` (CVE-2026-59083). Opened 2026-08-03, still
open three weeks later, with no labels, no reviews and no comments.

Two things follow, and they pull in opposite directions.

**The data we want exists before it is merged.** That is the opportunity: a PR
carries exactly the `ecosystem` + `package` + range coordinates whose absence
makes the advisory unmatchable, often weeks ahead of curation.

**But the open queue is adversely selected.** Median merge lag is *zero days* —
curators merge good contributions almost immediately. So a PR sitting open for
three weeks is not "the newest data", it is data that was passed over. Harvesting
open PRs preferentially samples the contributions curators did **not** accept
quickly.

#8960 shows why that matters even with an honest contributor. Every range it
proposes looks like this:

```json
"ranges": [{ "type": "ECOSYSTEM", "events": [{ "introduced": "11.0.0-M1" }] }],
"database_specific": { "last_known_affected_version_range": "< 11.0.24" }
```

The upper bound lives **only** in `database_specific`, which by definition no
generic OSV consumer interprets. Evaluated per the OSV spec, that range says
"introduced at 11.0.0-M1, never fixed" — it matches 11.0.24, 11.0.25 and every
future release **forever**. This is GHSA house style for EOL branches, and it is
still a live false-positive generator for anyone consuming the file directly.

### What breaks in the product, not just the backend

Verified against the running UI rather than assumed. The first thing that check
corrected: **the surface is already called "Components", not "Dependencies"**
([DependenciesTab.vue:112](../../site/src/views/repo/DependenciesTab.vue#L112)),
and it already lists image contents — `rpm` packages from a `redhat-8.5` image
sit next to npm and Maven libraries today. The unifying premise is not "declared
in a manifest"; it is **"has a PURL, and a package manager can upgrade it."** A
CPE-only component breaks the second clause as hard as the first, but it does not
need a new home.

What genuinely breaks, with the behaviour rather than the guess:

| Surface | Today | With a CPE-only component |
|---|---|---|
| Components — Vulns column ([:260](../../site/src/views/repo/DependenciesTab.vue#L260)) | `isScannableEcosystem(ecosystem) ? vuln_count : '—'` | renders **`—` even when the component has findings** — the allowlist in [purl.ts:106](../../site/src/lib/purl.ts#L106) has no `cpe` |
| Components — Ecosystem facet ([:330](../../site/src/views/repo/DependenciesTab.vue#L330)) | options derived from data, not an allowlist | a literal `cpe` option self-populates beside `npm` and `rpm` |
| Components — row subtitle ([:232](../../site/src/views/repo/DependenciesTab.vue#L232)) | renders `component.purl` unconditionally | blank line under the name (same at [org:175](../../site/src/views/org/DependenciesTab.vue#L175)) |
| `parsePurl` (5 call sites) | assumes a parseable PURL | returns `null`; grouping, colouring and the dependency graph degrade |
| `packageFacts` ([facts.ts](../../site/src/components/finding/facts.ts)) | "Manifest — *the file the dependency was declared in*" | there is no manifest; the truth is an install path like `usr/local/tomcat/lib/catalina.jar` |
| Finding → Remediation | "Fixed in 11.0.23" | correct and useless — you cannot bump Tomcat in `pom.xml`; the fix is rebuilding on a newer base image |
| Finding → Reachability | hides the section when `unknown` | permanently hidden, implying analysis is pending when it is *impossible* |
| [gate.go:99](../../internal/delta/gate.go#L99) | "only `not_reachable` is exempt — unknown stays counted" | permanently `unknown`, therefore permanently **merge-blocking** |
| [filterquery.go:345](../../internal/filterquery/filterquery.go#L345) | filters on `language` | ADR-012 leaves `language` null for a `cpe` ecosystem → **unfilterable** |
| [compare.go:151](../../internal/sbom/compare.go#L151) `componentKey` | keys on normalized PURL | a component that later gains a CPE reads as churn in the SBOM diff |

Two surfaces already handle it correctly and need no work — worth recording so
nobody "fixes" them: the **Sources facet** is derived from `component.sources`,
so an `NVD` badge appears on its own and `sourceKey` already styles it; and
`LibraryDetailModal` guards the purl line with `v-if="component.purl"`
([:28](../../site/src/components/LibraryDetailModal.vue#L28)), so it degrades
gracefully.

The last two rows of the table are the ones that matter most, and they point in
opposite directions. **Unfilterable** plus **unconditionally merge-blocking** is
the combination that turns a correctness win into an outage: the moment CPE
matching ships, every repo that scans an image acquires a wave of CRITICAL
findings that cannot be triaged in bulk, cannot be fixed in the PR that trips
them, and cannot be exempted by reachability because reachability can never be
computed for them.

One existing convention constrains the answer, and it is a good one. From
[FindingOriginBadge.vue](../../site/src/components/FindingOriginBadge.vue):

> Scanner output is the norm and stays unbadged — a badge on everything says
> nothing. Only a finding a person or an agent put there is called out.

Whatever marks a CPE match must follow that rule: mark the exception, never the
norm.

## Decision

**Support components identified by PURL, by CPE, or by both**, with CPE as a
narrow fallback lane over one advisory model — and treat "installed software" as a
first-class inventory kind rather than a dependency with missing fields.

### Data and matching

#### 1. Component identity (migration `00031`)

```sql
ALTER TABLE components ALTER COLUMN purl DROP NOT NULL;
ALTER TABLE components ADD COLUMN cpes text[] DEFAULT ARRAY[]::text[] NOT NULL;
ALTER TABLE components DROP CONSTRAINT components_purl_version_key;
ALTER TABLE components ADD CONSTRAINT components_identity_present
  CHECK (purl IS NOT NULL OR cardinality(cpes) > 0);
CREATE UNIQUE INDEX components_identity_key
  ON components (coalesce(purl, ''), coalesce(cpes[1], ''), version);
CREATE INDEX idx_components_cpes ON components USING gin (cpes);
```

`cpes` stores every **CPE 2.3 formatted string** Syft proposes, verbatim and in
Syft's order — §3 shows why a single column loses the only candidate that
matches. Vendor and product are extracted at match time, never stored pre-split,
so a parsing fix needs no backfill.

`ecosystem` carries the literal `cpe` for CPE-only components — the
pseudo-ecosystem pattern [distro.go:22](../../internal/distro/distro.go#L22)
already uses for OS packages. **This value is storage-internal and must never
reach the UI as an ecosystem** (see §7).

#### 2. SBOM ingestion

`ParsedComponent` gains a `CPE` field. The drop condition at
[cyclonedx.go:156](../../internal/sbom/cyclonedx.go#L156) becomes "drop only
when the component has neither a parseable PURL nor a CPE". SPDX ingestion reads
`externalRefs` of category `SECURITY` / type `cpe23Type`.

`componentKey` ([compare.go:151](../../internal/sbom/compare.go#L151)) prefers
the PURL and falls back to the primary CPE, so gaining CPE candidates never
registers as churn in the SBOM diff.

#### 3. Emitting CPEs — consume `syft-json`, not Syft's CycloneDX

Trivy stays the source for repo (`fs`) SBOMs. **Add Syft for image SBOMs** — but
the output format is not a free choice, and testing it changed this section.

Syft assigns each artifact a **set** of CPE candidates, not one. For
`tomcat-coyote@11.0.22` (verified 2026-08-24, Syft v1.51.0):

```
cpe:2.3:a:apache:tomcat-coyote:11.0.22:*:*:*:*:*:*:*    ← wrong product
cpe:2.3:a:apache:tomcat_coyote:11.0.22:*:*:*:*:*:*:*    ← wrong product
cpe:2.3:a:apache:tomcat:11.0.22:*:*:*:*:*:*:*           ← the one NVD matches
```

**Syft's CycloneDX output keeps only one, and picks a wrong one.** In
`cyclonedx-json` the same artifact carries `cpe:2.3:a:apache:tomcat-catalina:…`;
other jars come out worse still, with the *spec* version rather than the release
(`cpe:2.3:a:apache:tomcat-el-api:6.0`) or invented products
(`cpe:2.3:a:apache:catalina-tribes`). None of those exist in NVD's dictionary, so
a CycloneDX-fed pipeline would ingest CPEs, look correct in the inventory, and
still match **nothing** — the original bug wearing a new coat.

So: ingest **`syft-json`** and store the full candidate array; a component's CPE
identity is a set. `components.cpe` becomes `components.cpes text[]`, and §1's
identity index keys on the *primary* candidate with the rest carried alongside.
No CPE inference of our own — the SBOM stays the contract, which is also
Dependency-Track's conclusion.

#### 4. NVD as an advisory provider

A new `internal/provider/nvd` implementing the existing `AdvisoryProvider`
interface, translating NVD `configurations[].nodes[].cpeMatch[]` into
`advisory.AffectedRange` rows. NVD is the right source *here* specifically
because it is the one that assigns CPE applicability — but note its cost:
**5 requests / 30s unauthenticated, 50 / 30s with a free key**, and legacy feeds
have been deprecated since 2023. [ADR-028 §2](028-cve-subscriptions-with-manual-purl-triage.md)
carries a full source matrix; `CISA Vulnrichment` and `VulnCheck NVD++` are the
mirrors worth considering if NVD's limits bite. **No schema change to `affected_ranges`** — the
existing model already fits:

| NVD field | `affected_ranges` column |
|---|---|
| `criteria` vendor+product (`apache:tomcat`) | `package_name` |
| — (constant) | `ecosystem` = `cpe` |
| `versionStartIncluding` | `introduced` |
| `versionEndExcluding` | `fixed` |
| `versionEndIncluding` | `last_affected` |

`PackageQuery` ([provider.go:11](../../internal/provider/provider.go#L11)) gains
a `CPE string` field; `buildPackageQueries`
([scanner.go:701](../../internal/scanner/scanner.go#L701)) emits one query per
identifier a component carries. Advisory ingestion, alias resolution, and the
global package cache are unchanged — an NVD CVE and its OSV counterpart converge
on one canonical advisory via ADR-007 aliases, so this adds a matching path
without inflating counts.

#### 5. Version comparison

Register a `cpe` comparator in
[versioncmp.go:15](../../internal/versioncmp/versioncmp.go#L15). NVD version
strings are loosely dotted-numeric; `Semver` is the starting point, behind its
own registry entry so a dedicated comparator can replace it without touching
callers.

`InRange` ([versioncmp.go:40](../../internal/versioncmp/versioncmp.go#L40))
models an **inclusive** lower bound only. NVD also emits
`versionStartExcluding`, which has no representation today. Add an exclusive
lower bound rather than coercing it — coercion turns "after 1.2.3" into "at or
after 1.2.3" and produces a false positive on exactly the fixed version.

#### 6. CPE is a fallback lane, not a parallel path

The original draft ran PURL and CPE matching side by side and deduplicated
afterwards. Measuring the fan-out killed that design.

**18 of the 180 artifacts** Syft finds in the Tomcat image carry
`cpe:2.3:a:apache:tomcat:*` as a candidate — including `tomcat-i18n-cs`, a Czech
resource bundle. Five applicable CVEs against 18 artifacts is **90 findings for
5 vulnerabilities**, nearly all of them on components that cannot contain the
flaw. Across the image, 180 artifacts carry 597 candidates: a match surface 3.3×
the component count. This is the Telerik granularity mismatch from
[DT#4180](https://github.com/DependencyTrack/dependency-track/discussions/4180),
reproduced exactly.

Three rules, in order:

1. **Query CPE only when the PURL path returned nothing for that component.**
   `lodash` has good OSV coverage, so its CPE candidates are never queried;
   `tomcat-coyote` has none, so they are. This alone removes the FP surface for
   every well-covered ecosystem, and is the mechanism behind Grype's
   per-ecosystem `using-cpes` switch.
2. **Collapse fan-out to one finding per `(advisory, cpe product, image)`**, not
   per component. The 90 collapse to 5. The affected component list is retained
   on the finding as evidence, so the detail view can still show which artifacts
   carried the candidate — but the user triages the product once.
3. **PURL match wins** on any overlap: where both paths reach the same canonical
   advisory, keep one finding with the PURL provenance.

Vendor-rename duplicates (`f5:nginx` / `f5:nginx_open_source`) collapse through
the same canonical-advisory join.

**Distro ecosystems are excluded from the CPE lane outright**, regardless of
rule 1. Vendors backport fixes without changing the upstream version: RHEL ships
a patched `openssl-1.1.1k-*.el8` long after NVD marks
`cpe:2.3:a:openssl:openssl` vulnerable below `1.1.1n`, so an upstream CPE range
flags a package that is not vulnerable. This is the false-positive class
[ADR-007](007-canonical-advisory-model.md) already singles out as "the primary
source of false positives in other tools", and the reason `apk`/`deb`/`rpm`
matching is release-scoped against distro advisories. A CPE fallback that fired
on OS packages when OSV happened to return nothing would reintroduce it.

**Accepted trade-off:** strict fallback means a component whose PURL matches
CVE-A will never be CPE-queried for CVE-B. We take the false negative. The
alternative is the 18× fan-out on every component in every image, which
Anchore's 2000:11 ratio says is the worse trade by two orders of magnitude.

Expose the switch per ecosystem (`match.<ecosystem>.using_cpes`) so the lane can
be closed as PURL coverage improves — the direction §"Is PURL or CPE the future?"
expects.

This is convergent with Grype's documented architecture, which is reassuring
rather than coincidental: its matcher runs ecosystem matching (package name +
version), distro matching (release-scoped), and **"CPE fallback: uses CPE
identifiers when ecosystem data isn't available"**
([Grype architecture](https://oss.anchore.com/docs/architecture/grype/)). Two
independent designs arriving at fallback-not-parallel is the strongest evidence
available that the parallel design was wrong.

### Product surfaces

#### 7. Components stays one surface; add a `kind` facet

The Components table already holds image contents alongside declared
dependencies, so CPE-only components belong there too. **No new surface.** What
they need is a way to say what they are:

- Add a **`kind`** attribute on components — `package` (a package manager owns
  it: npm, maven, rpm, deb, apk) or `installed` (present in an image, no package
  manager owns it) — derived from the identifiers the component carries.
- Expose `kind` as a facet next to Ecosystem / Sources / Severity / Vulnerable
  ([DependenciesTab.vue:334](../../site/src/views/repo/DependenciesTab.vue#L334)),
  in both the repo and org variants.
- **Do not surface `cpe` as an ecosystem.** The Ecosystem facet self-populates
  from the data, so leaving `ecosystem = 'cpe'` visible puts an identifier
  scheme in a list of ecosystems. Render the ecosystem cell from `kind` for
  installed components (`installed`), keeping `cpe` storage-internal.
- Extend `isScannableEcosystem` — or replace its allowlist with "has a
  scannable identifier" — so the **Vulns column shows the real count** instead
  of `—`. This is the one row in the Context table that actively hides findings
  we just went to the trouble of producing.
- Fall back to the CPE in the row subtitle and the `:title` tooltip where the
  PURL is empty, in both variants.

The finding-detail copy still needs the `installed` variant (§9); that is where
the dependency-shaped assumptions actually live, not in the inventory table.

#### 8. Evidence strength, marked once

CPE-only findings carry an `identifier_source` of `cpe`, rendered following the
FindingOriginBadge rule — **the exception is badged, the norm is not**:

- PURL-matched findings: unchanged, unbadged.
- CPE-only findings: a `cpe match` badge whose hover text states what is weaker
  about it — matched on vendor/product and version range, not on a package
  coordinate, so it flags the installed product without confirming the vulnerable
  component ships.

The badge is the honest signal that a CPE match is weaker evidence, and it must
not be presented as equivalent to a PURL match.

#### 9. Remediation and reachability copy

Both sections in `DependencyFindingDetails` need a CPE-only variant:

- **Remediation** leads with the action that exists: rebuild on a base image
  providing ≥ the fixed version. The fixed version stays, demoted to supporting
  evidence; "bump it in your manifest" is never implied.
- **Reachability** gains a third state, `not_analyzable`, distinct from
  `unknown`. Today the section hides on `unknown`, which reads as "pending". For
  a CPE-only finding the verdict will never arrive, and saying so plainly beats
  an absence the user waits on.
- The `Manifest` fact becomes `Location` for `installed` components, carrying the
  install path from Trivy's `FilePath` / Syft's location data.

#### 10. Gating: advisory by default, opt-in to block

CPE-only findings are **excluded from blocking quality gates by default**, and
counted only when a repo opts in:

```yaml
quality_gates:
  - branches: ["main"]
    vulnerabilities:
      max_critical: 0
      include_cpe_matches: true   # default false
```

The reason is [gate.go:99](../../internal/delta/gate.go#L99): only
`not_reachable` is exempt, `unknown` stays counted. A CPE finding is permanently
unanalyzable, so under today's rule it would block forever, on a fix that is not
available in the PR that trips it. Default-blocking would make the feature's
first impression an unfixable red check across every repo that scans an image.

`not_analyzable` from §9 is *not* granted the `not_reachable` exemption — that
would silently discard real risk. The exemption is explicit and configured, never
inferred.

#### 11. Filtering and search

Add `identifier:purl|cpe` and `kind:package|installed` to the filter grammar
([filterquery.go:335](../../internal/filterquery/filterquery.go#L335)). Without
this, CPE findings are unfilterable — ADR-012 leaves `language` null for a `cpe`
ecosystem, so no existing axis reaches them, and bulk triage is impossible.

This ships **in the same release as the findings themselves**, not after. Bulk
triage is the pressure valve for CPE's false-positive rate; shipping the findings
first would flood [ADR-023](023-triage-acceptance-ux.md)'s accept/dispute flow
with no way to work through it.

#### 12. Rollout in three phases

The false-positive risk is real enough that the phases are part of the decision,
not a delivery detail:

| Phase | Ships | Visible effect |
|---|---|---|
| **1 — Inventory** | §1–3, §7 | CPE-only components appear in Components with a `kind` facet, correct counts, and no blank subtitles. **No findings, no gates.** Proves ingestion end-to-end at zero noise. |
| **2 — Advisory findings** | §4–6, §8–9, §11 | CPE findings appear, badged, filterable, triageable — advisory only, never blocking. |
| **3 — Opt-in gating** | §10 | `include_cpe_matches` available once phase 2 has produced a real false-positive rate to judge. |
| **4 — PR harvesting** | §13 | Optional, off by default, advisory-only. Only if phase 2's FP rate leaves headroom — and not before the MCP text-handling in §13 is fixed. |

Phase 2 does not begin until phase 1's inventory is accurate on the fixture
images — including the Vulns column, which shows `—` today and would otherwise
hide phase 2's output on the very components it was built for.

**Phase 3 requires a labelled corpus, not an impression.** Anchore's 2,000:11
result exists because Grype runs a quality gate on every commit against manually
labelled match data. Since §6 deliberately runs a more permissive rule than
theirs, we need the same instrument or we are guessing: label the matches
produced across the fixture images (`alpine`, `debian`, `rhel`, `tomcat`, and the
11.0.2 control) as true or false positive, and gate changes to the CPE lane on
that set. Their [`vulnerability-match-labels`](https://github.com/anchore/vulnerability-match-labels)
corpus and `yardstick` tooling are the prior art to copy rather than reinvent.
Without it, `include_cpe_matches` should not ship at all.

#### 13. Unmerged advisory PRs — opt-in, and never trusted

The PR queue is a real early source, and it is also the only place in this design
where we would ingest **attacker-controlled data**. Anyone with a GitHub account
can open a PR; merged content is curator-reviewed, open-PR content is reviewed by
nobody. The whole section exists to keep that distinction load-bearing.

**The design rule that makes it defensible: take the coordinate from the PR, take
the ranges from the CNA.**

A PR is useful for the one thing that cannot be derived — the product → package
mapping. It is *not* needed for version ranges, which the CNA record already
publishes exactly (`scripts/ghsa-contrib/` does this conversion mechanically).
So we never adopt a PR's ranges. We read only `affected[].package`, then rebuild
the ranges from `cveawg.mitre.org`. This alone:

- neutralises #8960's unbounded-range hazard, honest or not;
- reduces the attacker's control surface to "which package name gets attached to
  a CVE that GitHub already imported" — they cannot invent a vulnerability,
  fabricate a range, or change a severity.

Hard constraints, all of them fail-closed:

1. **Disabled by default**, instance-level, with the risk stated at the toggle —
   not repo-level, so enabling it is a deliberate operator act.
2. **Enrichment only.** Accept a PR only if it modifies an advisory that already
   exists as `unreviewed` and whose `affected` is empty. Never accept a PR that
   creates an advisory, and never let one modify a `github-reviewed` file.
3. **CNA cross-check.** Drop the PR unless the CVE resolves at
   `cveawg.mitre.org` and the ranges we rebuild are non-empty and bounded. A
   range with no upper bound is discarded, never widened to "all versions".
4. **Never gate.** PR-sourced findings are advisory-only *even when
   `include_cpe_matches` is on*. There is no configuration that lets unreviewed
   third-party data block a merge.
5. **Never malware.** PR-sourced data cannot create or alter a malware verdict.
   A malware finding says "remove this package, there is no safe version" — the
   single highest-consequence output we have, and it must never rest on an
   unreviewed PR.
6. **Never enter alias resolution.** This one is specific to us:
   [ADR-007](007-canonical-advisory-model.md) resolves aliases *transitively* —
   "if A=B and B=C, then A=B=C". Attacker-controlled `aliases` would let a PR
   union itself into an unrelated canonical advisory and inherit its
   credibility. PR-sourced records stay in their own namespace, keyed on the
   CVE we verified against the CNA, and never merge.
7. **Pin the head SHA.** A PR branch can be force-pushed after ingestion, and a
   PR can be closed after we read it. Record the SHA, re-verify on refresh, drop
   the data if it moved or the PR closed.

**Provenance is mandatory, not decorative.** A finding sourced this way is
labelled at every surface — list row, detail view, API and MCP payloads — as
derived from an **unreviewed, unmerged community pull request**, with a link to
the PR and its author. §8's rule still applies (badge the exception, not the
norm), and this is emphatically the exception. It must be filterable and bulk
-dismissible from day one, and it should read as weaker than a CPE match, which
is itself weaker than a PURL match.

##### Threat analysis

Written against what the code does today, not a generic checklist.

| Vector | Exposure | Handling |
|---|---|---|
| **False-positive injection / build DoS.** PR attaches a real CVE to a widely-used package (`org.springframework:spring-core`), every harvesting instance lights up | High value, anonymous, cheap | Rules 1, 4 — advisory-only, never gates. Damage is noise, never a blocked merge |
| **Reputation attack via malware verdict** | Highest consequence output we have | Rule 5 — categorically excluded |
| **Advisory-graph poisoning via `aliases`** | Real, and specific to ADR-007's transitive resolution | Rule 6 — separate namespace, no merge |
| **Range widening** (`introduced` with no bound → matches all future versions) | Present in #8960 *without any attacker* | Rules 3 — ranges come from the CNA; unbounded is dropped |
| **Stored XSS via `details` / `summary`** | **Already mitigated.** `MarkdownText.vue` renders without `v-html`, `innerHTML` or any equivalent, and says so with tests | No new work; do not regress it |
| **Prompt injection** — `details` is free text that reaches an LLM | **Real and unmitigated today.** [internal/mcp/tools.go](../../internal/mcp/tools.go) exposes `advisory lookup` and vulnerability summaries to agents; advisory prose lands directly in agent context. An advisory description is a *perfect* carrier: technical instruction text is exactly what belongs there, so injected directives do not look anomalous | See below |
| **Resource exhaustion** — thousands of PRs, oversized payloads | Moderate | Cap PR count and body size; poll on a schedule, not per-scan |
| **TOCTOU** — force-push or close after ingestion | Moderate | Rule 7 — pin and re-verify the head SHA |

**On prompt injection specifically**, since it is the one vector this feature
genuinely worsens. Today an attacker wanting their text in a hibou agent's
context must get an advisory merged into GHSA or NVD. Harvesting open PRs removes
that barrier entirely: anyone could put arbitrary prose in front of any agent
using our MCP tools, targeted at organisations by choosing which package to
attach it to. Mitigations, in order of value:

- **Do not pass PR-sourced free text to MCP consumers at all.** Return the
  package, the ranges and the PR link; drop `details` and `summary`. The
  coordinates are the useful part — the prose adds nothing an agent needs, and
  it is the entire attack surface.
- If the text must be carried, **delimit it as untrusted** in the payload and
  never interpolate it into an instruction position.
- Note that this hardening is worth doing for *merged* advisory text too — GHSA
  and NVD prose is lower risk, not no risk. This feature makes the gap urgent
  rather than creating it.

**Recommendation:** ship §13 last, after the CPE lane has a measured
false-positive rate (§12). If the shadow-mode data shows the CPE lane already
noisy, adding an unreviewed-PR source on top is the wrong next move.

## Consequences

**Gained**

- Software installed outside a package manager becomes visible: app servers, web
  servers, runtimes, vendored binaries.
- CVEs enriched by NVD but never curated into GHSA/OSV are matched. On current
  evidence that is not a narrow tail.
- The parity gap against CPE-based scanners closes for the class of finding that
  motivated this ADR.
- The `kind` facet is useful independently of CPE matching: it separates "a
  package manager can fix this" from "rebuild the image" across the whole
  inventory, including the `rpm`/`deb`/`apk` components already listed.
- Adding NVD makes ADR-007's "no provider is privileged" claim true in practice;
  today it holds for two providers sharing one identifier scheme.

**Cost**

- **False positives increase**, though far less than a parallel-path design would
  have caused. A wide CPE range flags an install whether or not the vulnerable
  component ships. Fallback-only querying, fan-out collapse, badging, filtering
  and advisory-by-default reduce the damage; none eliminate it. This is the main
  risk and the reason for phasing.
- **An attacker-controlled input path**, if §13 is ever enabled: the first place
  hibou would ingest data no curator has reviewed. The constraints in §13 bound
  the blast radius to advisory-only noise, but the prompt-injection exposure
  through the MCP tools is real and must be fixed first.
- **A deliberate false negative**: a component whose PURL matched one advisory is
  never CPE-queried for another (§6). Accepted on Anchore's 2000:11 evidence, but
  it is a real hole and should be revisited if the CPE lane proves quiet.
- **Candidate sets, not single identifiers.** `components.cpes` is an array and
  matching is set-valued; every query, index and UI affordance has to hold that,
  and a naive `WHERE cpe = ?` will silently under-match.
- **Product-name splits cause silent misses**, and they come in two kinds that
  need different answers (verified against NVD's CPE Dictionary, 2026-08-24):
  - *Deprecation chains* — `arm:mbed_tls` → `trustedfirmware:mbed_tls`,
    `haxx:curl` → `curl_project:curl`. NVD marks these with `deprecated` /
    `deprecatedBy`, so they are mechanically fixable: expand a vendor lookup to
    its declared predecessors and successors. Dependency-Track is adopting
    exactly this ([DT#6494](https://github.com/DependencyTrack/dependency-track/issues/6494)),
    where mbed_tls 2.28.8 splits 16/2 across the two vendors and **neither name
    alone finds all 18 CVEs**. We should mirror the dictionary's deprecation
    fields alongside the CVE data and do the same.
  - *Co-existing siblings* — `f5:nginx` (582 entries) and
    `f5:nginx_open_source` (504 entries) are **both live and neither is
    deprecated**. No dictionary metadata links them, so the deprecation-chain
    fix does not help; this needs curation and stays out of scope. Canonical
    -advisory dedup handles the duplicate-finding symptom, never the
    missed-match cause.
- **NVD API rate limits** (5 req/30s unkeyed, 50 with a key) make per-package
  queries impractical at scale. The provider must use the bulk feed and the
  ADR-007 global cache; mirror mode becomes more important than it is today.
- **`components.purl` becoming nullable** touches every query assuming it is
  present — an audit of `internal/store/queries/`, not just the DDL. This is the
  migration's real cost.
- **Frontend work is spread thin rather than deep**: a facet, an allowlist, two
  row-subtitle fallbacks, and three copy variants across repo and org views. Less
  than a new surface would have cost, but touching more files.
- **Two SBOMs per image** (Trivy + Syft) increases CI time and upload size.

**Explicitly not solved**

- Reachability for CPE-only components. Call-graph analysis needs package
  coordinates; `not_analyzable` is an honest label, not a deferred feature.
- Whether an installed product's *vulnerable component* actually ships. CPE
  cannot express it and we will not guess.

## Alternatives considered

**A separate "Installed software" surface, sibling to Components.** This was the
first draft of §7, on the reasoning that an image-installed product is not a
dependency and should not sit in a dependency list. Rejected once the running UI
was checked: the surface is already named *Components* and already carries `rpm`
packages from images, so the category error was in the ADR, not the product.
Splitting would have fragmented one inventory into two for a distinction a facet
expresses, and left the org-level roll-up with two lists to reconcile.

**Ship findings first, filters and triage later.** Rejected outright — it is the
combination that breaks. Unfilterable findings plus an existing `max_critical: 0`
gate is an unfixable red check with no bulk remedy.

**Derive CPEs from PURL + group/name ourselves.** No Syft dependency, works on
SBOMs we already ingest. Rejected, and more firmly than the first draft had it —
Dependency-Track's maintainer, having tried, calls PURL→CPE matching
"[somewhere between impractical and impossible](https://github.com/DependencyTrack/dependency-track/discussions/4180)",
and Grype ships the same generation logic with open bugs for wrong vendors
([#1490](https://github.com/anchore/grype/issues/1490)). We would inherit CPE's
naming ambiguity with none of the upstream curation and own the mapping table
forever. Existing `purl2cpe` datasets could seed a *supplement* for high-value
vendors later; they are not a foundation.

**Ingest cvelistV5 CNA ranges directly, skipping CPE.** Attractive on the
evidence above: Apache's own CNA record carries clean semver ranges
(`11.0.0-M1` ≤ `11.0.23`) with no CPE involved, upstream of both NVD and GHSA.
Rejected *for now* only because the affected-product identity is a free-text
product name with no ecosystem — matching it to a component needs the same
vendor/product normalization CPE already provides, so it is strictly more work
for the same result. Worth revisiting once CPE matching exists, since it would
also cover CVEs NVD has not analyzed.

**Adopt Grype instead of extending Hibou.** Grype already does Syft-CPE → NVD
matching, and §6 borrows its per-ecosystem switch. Rejected as a *replacement*:
findings would arrive as a third SARIF stream outside the canonical advisory
model, defeating ADR-007's one-record-per-vulnerability guarantee and the alias
resolution that prevents count inflation. It would also arrive with no identity
axis and no fan-out collapse — the 18-findings-per-CVE problem in §6 is one Grype
exhibits rather than solves — so every UX problem in the Context table would land
unsolved.

**Contribute the missing coordinates to GHSA ourselves.** The GitHub Advisory
Database accepts community pull requests, reviewed by GitHub Security Lab; an
accepted PR adding `org.apache.tomcat:*` ranges to those five advisories would
promote them from `unreviewed` to `reviewed` and make them matchable by *every*
purl-based scanner on earth — Hibou included, with no code change at all. Worth doing, and far cheaper than this ADR — `scripts/ghsa-contrib/` drafts the
patches mechanically, and [#8960](https://github.com/github/advisory-database/pull/8960)
shows someone has already done it for CVE-2026-59083 (unmerged after three
weeks). Rejected as *the* answer because it does
not generalise: it fixes five advisories, on GitHub's review timetable, for
software that happens to have Maven coordinates to contribute. It does nothing
for the tarball-installed and commercial software that has no package coordinate
to assign. Treat it as a complementary action, not a substitute.

**Do nothing; wait for GHSA curation.** Rejected. The advisories in question are
2–3 months old, CRITICAL, and still `type: unreviewed`. There is no commitment
that unreviewed GHSA entries are ever enriched, and the failure mode meanwhile is
a confident clean result.
