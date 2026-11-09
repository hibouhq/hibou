# ADR-051: Third-party notices, generated from the inventory

## Status

Proposed (2026-10-17).

Implementation status verified 2026-11-09:

- **To be implemented if adopted, not scheduled:** licence-evidence
  collection/storage, classifier integration, inventory-derived notices,
  gap/override workflows and CLI/API/UI/CI generation and checks.
- **Existing but not this feature:** the repository's
  [THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md) records attribution
  for the ported CVSS calculator. It is not a generated inventory-wide
  notices document.
- **Deferred/excluded from initial scope:** container OS-package notices,
  legal advice, automatic fulfilment of source/relinking obligations, and
  optional third-party evidence databases.
- The proposal has **not been dropped**.

Builds on [ADR-045](045-built-in-dependency-inventory.md) (inventory, `shipped`
attribute, provenance), [ADR-046](046-dependency-cli.md) (CLI, release
deliverables, `deps verify`), [ADR-029](029-license-policy-model.md) and
[ADR-030](030-org-license-policy-and-repo-override.md) (licence policy),
[ADR-031](031-cra-compliance-automation.md) (CRA evidence) and
[ADR-024](024-release-tracking.md) (releases).

## Context

Distributing software means distributing its dependencies, and most open-source
licences attach conditions to that, even the permissive ones:

| Licence family | What a distributor must do |
|---|---|
| MIT, BSD, ISC, zlib | Keep the copyright notice and the licence text with every copy, including binaries and minified bundles |
| Apache-2.0 | The above, plus pass on the contents of the dependency's `NOTICE` file, if it has one (§4(d)) |
| MPL-2.0, EPL-2.0 | The above, plus make the source of the covered files available |
| LGPL, GPL, AGPL | The above, plus offer the corresponding source; LGPL also requires that users can relink |

Teams usually meet this with a hand-maintained `NOTICE` or
`THIRD_PARTY_NOTICES` file. It goes stale with the first dependency bump and
is rarely complete: copyright lines are missing, Apache `NOTICE` contents are
forgotten, and the JavaScript bundled into a web UI is overlooked because no
lockfile sits next to the binary.

Hibou itself is in that situation. It is licensed AGPL-3.0 and its single
binary embeds Go modules and the web UI's npm packages, several under
Apache-2.0 with `NOTICE` files (OSV-SCALIBR among them). The repository has
an attribution-only notices file, not the inventory-derived generator proposed
here.

Hibou already knows most of what a notices file needs, which is why it should
produce one:

- **What ships**: the inventory and its `shipped` attribute (ADR-045 §6), per
  release, with provenance.
- **Under which licence**: component licences from SBOMs, manifests and
  registries, and the licence policy that decides what is allowed.
- **For which release**: releases, their deliverables (ADR-046) and the CRA
  export (ADR-031).

What it lacks is the evidence a notice is made of: the **licence text and
copyright lines as the dependency ships them**, and its **`NOTICE` file**. An
SPDX identifier is not enough: `MIT` names a template, but the obligation is
to reproduce *this* package's copyright line.

### Goals

1. A correct notices document for every release, generated, never typed.
2. Built into the deliverable at build time, since that is where the
   obligation applies, and checkable in CI so it never goes stale.
3. Gaps are explicit, actionable and few: "3 components have no licence
   text", with the one-line fix for each.
4. Zero configuration for the common case; overrides only where a package is
   wrong.
5. Obligations beyond attribution (source offers, relinking) are surfaced to a
   person, never silently "handled".
6. Works offline and for private packages, consistently with ADR-035 and
   ADR-045.

### Non-goals

- Legal advice. Hibou reports what licences require in general and what it
  could not establish; a person decides.
- Choosing licences or replacing licence policy (ADR-029/030 stay the place
  where a licence is allowed or denied).
- Compliance for the operating-system packages of container images in the
  first phases (§9).
- Copyright headers in the project's own files (REUSE-style compliance).

## Options

### 1. Where the evidence comes from

| # | Source | Text and copyright | Coverage | Network | Trust |
|---|---|---|---|---|---|
| S1 | **Local package caches in CI**: Go module cache, `node_modules`, `~/.m2`, `site-packages`, Cargo registry | Exact files of the version built | Everything the build resolved, private packages included | None | The build's own inputs |
| S2 | **Delivered artifacts** (ADR-046): `META-INF/LICENSE`/`NOTICE` in JARs, `*.dist-info/licenses/` in wheels, `node_modules` in images | Exact files of what shipped | Good for JVM and Python; Go binaries and minified JS carry none | None | What clients received |
| S3 | **Registry archives**: module zips from the Go proxy, npm tarballs, Maven JARs/POMs, PyPI sdists/wheels, crate files | Exact files of that version | Public packages | Yes, through operator-approved mirrors (ADR-035) | Public package content |
| S4 | **Curated public databases** (ClearlyDefined) | Licence plus copyright statements, sometimes curated | Popular public packages | Yes, third-party API | Third party, varying freshness |
| S5 | **Registry metadata** (deps.dev, `package.json` `license`, POM `<licenses>`) | SPDX identifier or URL, no text | Broad | Yes or none | Declared, not verified |
| S6 | **SPDX licence templates** | Generic text, no copyright line | Every SPDX licence | None (bundled) | Only a fallback |

**Decision: S1 first, S2 for releases scanned from deliverables, S3 as the
server-side fallback for public packages, S5 and S6 only to fill identifiers
and generic texts, always flagged as gaps. S4 is not used by default.**

- S1 is exact, private-safe and offline, and it runs where notices belong:
  in the build, before packaging.
- S3 lets the server produce notices for releases it inventoried without a
  build (ADR-045 §4.3) or an older Hibou, through the mirror rules of ADR-035.
  It never fetches a package the lockfile resolved from a private registry
  (`registry: private`, ADR-048).
- S4 would send dependency names to a third party and adds an availability
  dependency for data S1/S3 already provide. An operator may enable it later
  as one more evidence source.
- A text built from S6 has no copyright line. It is never presented as
  complete: the component is listed as a gap until a real file or an override
  supplies the line.

### 2. Engine: reuse or write

| # | Option | Pros | Cons |
|---|---|---|---|
| E1 | Per-ecosystem tools in CI (go-licenses, license-checker for npm, cargo-about, pip-licenses, Maven license plugin) | Mature per ecosystem | One tool and one output format per ecosystem; no merged document, no release history, no link to policy or to what ships; each tool needs its own CI step |
| E2 | OSS Review Toolkit (ORT) | Covers analysis, scanning, policy and notice generation end to end | JVM runtime, heavy configuration, runs package managers (executes builds); duplicates Hibou's inventory and policy rather than using them |
| E3 | ScanCode Toolkit on artifacts | Best licence and copyright detection in arbitrary files | Python, slow (minutes to hours on large trees), a second inventory |
| E4 | **Hibou-native generator on the ADR-045 inventory, with a licence classifier library** | One document for every ecosystem; reuses inventory, `shipped`, policy, releases and the CLI; same code server-side and in CI | Licence and copyright detection must be accurate; Hibou owns the rendering |

**Decision: E4**, using a maintained classifier rather than our own matching:
`github.com/google/licenseclassifier/v2` (Go, Apache-2.0, the classifier behind
go-licenses) identifies the licence of each text found, and a small
copyright-line extractor keeps the `Copyright …` lines verbatim. The spike
(Rollout step 1) measures it against a fixture corpus per ecosystem, as
ADR-045 did for the extractor.

E1–E3 stay usable: their SPDX or CycloneDX output with licence texts can be
uploaded as evidence like any SBOM.

## Decision

### 3. Evidence model

For each component version, Hibou records **licence evidence**:

- the concluded licence expression (`MIT`, `Apache-2.0 OR MIT`, …);
- the licence texts as found, verbatim;
- the copyright lines extracted from them;
- the `NOTICE` file contents, verbatim, when present;
- where they came from (S1–S6 or an override), the file paths, and the
  classifier version.

Evidence for a **public** package version is the same for every tenant, so it
is stored once per instance, content-addressed, like the inventory sets of
ADR-045. Evidence for a **private** package stays in its organization. Texts
are deduplicated by digest: thousands of MIT packages share a handful of
distinct texts, but each keeps its own copyright lines.

Precedence when sources disagree, for one component version: **override**
(§5) > **delivered artifact** (S2) > **package archive** (S1 or S3) >
**declared identifier** (S5) > **SPDX template** (S6). Disagreements between a
declared identifier and the detected text are kept and shown ("declared MIT,
licence file is BSD-3-Clause"): they are a common sign of a mislabelled
package.

### 4. The notices document

**Which components.** Only `shipped: yes` components of the release
(ADR-045 §6). Development and build dependencies carry no distribution
obligation; including them would bury the notices that matter and contradict
the shipped view. Components marked shipped by an uploaded SBOM or a
deliverable are always included.

**Dual licences.** For an `OR` expression, the generator picks the
alternative the licence policy prefers (allowed, then the least demanding
obligation), records the choice, and shows it. A project can pin the choice
per package (§5).

**Content**, deterministic and sorted, so a diff shows exactly what changed:

1. A summary: number of shipped components, licences, and gaps.
2. Per component: name, version, purl, licence expression, copyright lines,
   and a reference to its licence text.
3. Licence texts, each distinct text once, with the components that use it.
4. `NOTICE` contents, verbatim, per component (Apache-2.0 §4(d)).
5. **Obligations beyond attribution**, listed for a person to act on: "LGPL-2.1:
   `libfoo` 1.2 — provide the source and allow relinking", "MPL-2.0: `bar` —
   make the source of covered files available". Hibou never claims these are
   fulfilled.

**Formats**: Markdown (readable in a repository and on a docs site), plain
text (for `/usr/share/doc`, installers and embedding), HTML (for an
application's About page), and machine-readable: SPDX 2.3 with licence texts
as `hasExtractedLicensingInfos`, and CycloneDX with licence `text`. The
release SBOM Hibou exports (ADR-031) carries the same texts, so one artifact
can serve both compliance and SBOM needs.

### 5. Gaps and overrides

A component is a **gap** when no real licence file was found, the text has no
copyright line, the licence is unknown or `NOASSERTION`, or the declared and
detected licences disagree. Each gap says what is missing and how to fix it:

```text
Notices for v1.4.0: 212 shipped components, 209 complete, 3 gaps

  ✖ github.com/acme/legacy v0.3.1   no licence file in the module; declared MIT
       fix: add an override with the copyright line, or ask upstream to add a LICENSE
  ⚠ left-pad 1.3.0                   licence text has no copyright line (SPDX template used)
  ⚠ commons-x 2.1                    declared Apache-2.0, LICENSE file is BSD-3-Clause
```

**Overrides** live in `.hibou.yaml`, reviewed like any change, and an org can
keep shared ones in its settings for packages many repositories use:

```yaml
notices:
  path: THIRD_PARTY_NOTICES.md          # file the check compares (§6)
  formats: [markdown, text]
  overrides:
    - purl: "pkg:golang/github.com/acme/legacy@v0.3.1"
      license: MIT
      copyright: "Copyright (c) 2019 Acme Corp"
      reason: "upstream has no LICENSE file; confirmed in issue acme/legacy#12"
    - purl: "pkg:cargo/serde"           # any version
      choose: "Apache-2.0"              # pick from "MIT OR Apache-2.0"
  exclude:
    - purl: "pkg:npm/@internal/*"       # first-party packages, no notice needed
      reason: "our own code"
```

An override must carry a `reason`. It applies to the versions it names (or
all, without a version) and is shown as the evidence source in the document.

### 5.1 Status, not just a file

Every release and every eager branch has a **notices status**: complete, or
the number of gaps. It appears where people already look:

- **Releases tab**: "Notices ✓" or "Notices: 3 gaps", a download menu (each
  format), and the gap list with the fix for each.
- **Dependencies tab**: a "Licence evidence" column and filter: complete, gap,
  override.
- **Pull requests** (ADR-045 §4.1.2): when a PR changes dependencies, the
  existing Dependencies section adds one line: "Notices: +2 components need
  attribution, 1 with a NOTICE file; THIRD_PARTY_NOTICES.md is out of date".
- **Licence policy** (ADR-030) can make a gap blocking for releases, like any
  other policy condition; it is informational by default.

### 6. Where it runs

**In CI, through the CLI (primary).** Notices must be inside what ships, so
they are produced before packaging, from the caches the build just filled
(S1):

```text
hibou deps notices --write THIRD_PARTY_NOTICES.md      # generate (local, nothing stored)
hibou deps notices --check THIRD_PARTY_NOTICES.md      # exit 1 if it would change, with the diff
hibou deps notices --format html --write dist/licenses.html
```

The usual setup is two lines: the build runs `--write` before packaging, and
the PR job runs `--check`, so a dependency change that forgets the notices
fails with the exact diff and the command to fix it. The file is committed,
so reviewers see notice changes next to the dependency change that caused
them. `--check` runs offline; `--write` needs only the build's own caches.

**On the server.** For each release, Hibou renders the same document from the
release inventory and the evidence store, fetching missing public evidence
from the registry mirror (S3) in a background job. This covers releases built
without the CLI, older releases backfilled by ADR-045 §4.3, and releases
recorded from deliverables (S2). The Releases tab downloads it; `hibou release
notices v1.4.0 --format text` fetches it.

**Optional automation**: when the committed notices file is stale on the
default branch, Hibou can open the pull request that updates it, with the
same mechanism and safeguards as guided remediation (ADR-050). Off by default.

**Verification** (ADR-046 §5): `hibou deps verify` gains a notices check: for
a deliverable and its notices file, every shipped component found inside must
be attributed. A client can run it offline.

### 7. Security and privacy

- Package archives are untrusted input. Only licence and notice files are
  read (by name patterns and size limits), nothing is executed, archives are
  extracted with the limits of ADR-045 §7.
- Registry fetches go only through operator-approved locations, never for a
  package the lockfile resolved privately, and are disabled in offline mode
  (ADR-035).
- Private evidence never leaves its organization; public evidence is shared
  across the instance by digest only.
- The classifier and the copyright extractor run on text; their versions are
  recorded so a document can be reproduced.

### 8. Storage

```sql
-- One row per distinct text, shared instance-wide (public packages) or
-- scoped to an org (private ones).
CREATE TABLE license_texts (
    digest     bytea PRIMARY KEY,           -- sha256 of the normalized text
    text       text NOT NULL,
    spdx_id    text,                         -- classifier result, NULL if unknown
    confidence real
);

-- Evidence per component version and source.
CREATE TABLE license_evidence (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id           uuid REFERENCES organizations(id) ON DELETE CASCADE,  -- NULL = public, shared
    component_id     uuid NOT NULL REFERENCES components(id),
    source           smallint NOT NULL,      -- override, artifact, cache, registry, declared, template
    expression       text,
    copyright_lines  text[] NOT NULL DEFAULT '{}',
    license_digests  bytea[] NOT NULL DEFAULT '{}',
    notice_digest    bytea,                  -- Apache NOTICE contents, in license_texts
    paths            text[] NOT NULL DEFAULT '{}',
    detector_version text NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE NULLS NOT DISTINCT (org_id, component_id, source, detector_version)
);
CREATE INDEX license_evidence_component_idx ON license_evidence (component_id);
```

A rendered document is not stored: it is a pure function of the release
inventory, the evidence and the overrides, cached by the digest of those
inputs. Immutable evidence rows follow ADR-045's rules (no updates; a new
detector version adds rows).

### 9. Containers

Images add operating-system packages, whose obligations live in
`/usr/share/doc/*/copyright` (Debian, Ubuntu), RPM headers, or APK metadata.
The image scan of ADR-045 §10 can read those files as S2 evidence. That is a
later phase: distribution formats differ, and the base image's notices are the
base image publisher's responsibility unless the image is redistributed as
part of the product.

### 10. Hibou itself

Hibou is the first user, and the reason for this ADR:

- The release workflow runs `hibou deps notices --write` for the Go module
  and the web UI's npm packages, and embeds the result in the binary.
- The server serves it at `/third-party-notices` (linked from the UI's About
  dialog), and release archives, the container image (`/usr/share/doc/hibou/`)
  and the docs site carry the same file.
- CI runs `--check` on pull requests.

## UX summary

| Who | What they do | What they see |
|---|---|---|
| Developer | Bumps a dependency | PR check: notices file out of date, the diff, the one command to fix it |
| Maintainer | Sets up a repository | Two CLI lines in CI; no configuration until a package needs an override |
| Release manager | Ships a release | "Notices ✓" or the gap list on the release; downloads in every format |
| Compliance reviewer | Audits a release | Notices, obligations needing action, overrides with their reasons, all reproducible from recorded inputs |
| Client | Receives a deliverable | `hibou deps verify` confirms every shipped component found inside is attributed |

## Rollout

1. **Spike**: classifier accuracy and copyright extraction on a fixture corpus
   (Go modules, npm packages including scoped ones, Maven JARs with and without
   `META-INF/LICENSE`, wheels with PEP 639 `licenses/`, crates with dual
   licence files). Measure misclassification and missing copyright lines.
2. `hibou deps notices --write/--check` from local caches (S1), Markdown and
   text output, gaps, `.hibou.yaml` overrides.
3. Hibou dogfoods it (§10).
4. Server evidence store, release notices on the Releases tab, PR section,
   licence-policy condition.
5. Registry fetch through mirrors (S3) for releases without a CLI run; S2 from
   deliverables.
6. HTML, SPDX and CycloneDX outputs; release SBOM export with texts.
7. Optional update pull requests (ADR-050); `deps verify` notices check.
8. Container OS packages (§9).

## Consequences

- Notices become a build output with a status, not a document someone
  remembers to edit. Stale notices fail CI with a fixable diff.
- Hibou meets its own Apache-2.0 `NOTICE` obligations, which open-sourcing
  requires.
- Gaps are visible from the first run; some projects will see dozens until
  overrides or upstream fixes land. The gap list says how to fix each.
- A new instance-wide store of public licence evidence grows with the number of
  distinct package versions across tenants, deduplicated by text digest.
- The licence classifier becomes a dependency of the server and the CLI, with
  its accuracy measured before adoption.
- Obligations beyond attribution are surfaced, not fulfilled: a person still
  has to provide source offers where licences require them.

## Alternatives considered

- **Hand-maintained NOTICE file**: the status quo; goes stale, misses
  copyright lines and Apache `NOTICE` contents.
- **One tool per ecosystem in CI** (E1): works, but several outputs to merge
  by hand, no release history and no link to what ships.
- **ORT or ScanCode as the engine** (E2, E3): thorough, but heavy runtimes and
  a second inventory beside Hibou's.
- **SPDX templates only**: no copyright lines, so not compliant for most
  permissive licences.
- **Including every component, shipped or not**: simpler, but buries real
  obligations under development tooling and contradicts the shipped view.
- **A curated third-party database by default** (S4): network dependency and
  data sent off-site for information the package archives already hold.
