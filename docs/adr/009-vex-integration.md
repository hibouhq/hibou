# ADR-009: Standards-compliant VEX integration

## Status
Accepted

## Context
Modern dependency analysis produces large volumes of vulnerability matches, but raw CVE presence is not the same as exploitable risk. A typical product can inherit thousands of CVE references through transitive dependencies, container base images, and vendored libraries. In practice, many of those advisories are not exploitable in the deployed product because the vulnerable component is not present at runtime, the affected code path is never reached, the vulnerable feature is disabled, or a fix has already been applied downstream.

The current platform model uses a boolean suppression toggle on `vuln_matches` (`suppressed`, `suppressed_reason`). That model is intentionally simple but too limited for long-term use. It cannot express whether a vulnerability is actually affected or not affected. It does not distinguish manual analyst decisions from imported vendor attestations or automated conclusions derived from platform evidence. It does not model expiry, provenance, supplier attribution, remediation guidance, or standards-aligned status categories. It is also not interoperable with the formats that vendors and downstream consumers already use to exchange exploitability statements.

VEX (Vulnerability Exploitability eXchange) exists to solve exactly this problem: conveying whether a known vulnerability affects a specific product in a machine-readable way.

Two standards dominate the current VEX landscape:

### OpenVEX
OpenVEX is the OpenSSF format published at `openvex.dev`. It is intentionally small and pipeline-friendly: JSON-LD documents with lightweight structure, minimal ceremony, and semantics optimized for automation. One document generally describes one product and contains multiple statements about vulnerabilities that affect or do not affect that product.

Each statement carries:
- a vulnerability identifier
- a status (`not_affected`, `affected`, `fixed`, `under_investigation`)
- a justification when the status is `not_affected`
- optional impact and action text

OpenVEX is well suited to CI systems, SBOM-adjacent workflows, and internal generation from scan evidence. It is easy to produce, easy to validate, and easy to attach to build artifacts. The current version is v0.2.0. Its simplicity is a feature, not a limitation, for teams that need fast exchange and straightforward machine processing.

### CSAF VEX
CSAF VEX is not a separate ecosystem from CSAF; it is Profile 5 of the OASIS Common Security Advisory Framework 2.0, identified by `document.category == "csaf_vex"`. CSAF is **product-centric** — it describes products and their dependency relationships, not individual components. This is structurally different from OpenVEX and CycloneDX VEX, which are component-centric and work with PURLs.

A valid CSAF VEX document (Profile 5) has mandatory requirements from the spec:
- `document` metadata: publisher (category, name, namespace), tracking (ID, status, initial/current release dates, revision history), distribution (TLP label), title, and `csaf_version: "2.0"`
- `product_tree` (**mandatory**): lists all products referenced in the document — structured as vendor → product → version branches with product IDs. Products can be related (e.g., "installed on", "default component of")
- `vulnerabilities` (**mandatory**): each entry must have at least one `product_status` bucket:
  - `known_not_affected` → MUST have an impact statement, either as machine-readable `flags` (with `label` matching VEX justification codes: `component_not_present`, `vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`, `vulnerable_code_cannot_be_controlled_by_adversary`, `inline_mitigations_already_exist`) **or** as human-readable `threats` (with `category: "impact"`)
  - `known_affected` → MUST have an action statement in `remediations` (vendor_fix, workaround, mitigation, `no_fix_planned`, or `none_available`)
  - `fixed`, `first_fixed`, `first_affected`, `last_affected`, `under_investigation` — no additional mandatory fields
- `scores`: CVSS vectors and severity per product
- `threats`: additional context (exploit status, impact justification)

The `flags` mechanism is important: it carries the same justification codes as OpenVEX but in a machine-readable label enum. This enables automated consumers to process `known_not_affected` decisions without parsing free-text. Flags also carry a `date` field recording when the assessment was made.

CSAF also defines a **provider infrastructure** for automated distribution (RFC 8322 ROLIE — Resource-Oriented Lightweight Information Exchange):
- `provider-metadata.json` at a well-known URL (e.g., `/.well-known/csaf/provider-metadata.json`) describing the publisher, distribution URLs, PGP keys, and aggregator permissions. Example: Red Hat publishes theirs at `https://www.redhat.com/.well-known/csaf/provider-metadata.json` with `role: "csaf_trusted_provider"`, separate distribution directories for advisories (`/data/csaf/v2/advisories/`) and VEX documents (`/data/csaf/v2/vex/`), and PGP signing keys
- **ROLIE feeds** (built on Atom Syndication Format): JSON feed documents listing available CSAF documents per TLP level. Each entry has a self link to the document, hash links for integrity verification, and metadata. Enables automated discovery — aggregators and consumers can poll the feed for new advisories without scraping directories
- **Directory-based distribution**: year-organized folders (`2026/cve-2026-45104.json`), `index.txt` (flat list of all documents), `changes.csv` (filename + last-modified timestamp for incremental sync), and SHA-256/SHA-512 hash files per document for integrity
- Reference from `/.well-known/security.txt`
- Optional: ROLIE service document and category document for richer feed discovery

This infrastructure means the platform could act as a CSAF provider — not just import CSAF documents, but publish them at standardized endpoints so downstream consumers and aggregators can discover and ingest advisories automatically. Red Hat, Cisco, Siemens, and others already operate this way; the platform would enable any organization to become a CSAF provider for their own products.

This format is heavier but carries the surrounding context large organizations need for governance, legal review, and downstream redistribution. It is used by vendors such as Red Hat, Cisco, and Siemens. It also supports digital signatures and publication practices that fit supplier ecosystems better than a minimal CI document.

### CycloneDX VEX
CycloneDX also carries VEX data, but not as a separate document standard. Instead, VEX is **component-centric** and embedded in the SBOM itself, primarily under `vulnerabilities[].analysis` with fields such as `state`, `justification`, `detail`, and `response`. Components are identified by PURL, making it simpler for ecosystems where component-level assessment suffices. This matters because some ecosystems distribute exploitability context only inside the BOM rather than as a standalone artifact. The platform already accepts CycloneDX uploads, so VEX extraction from those embedded fields should be treated as a first-class ingestion path.

### Format comparison

| Dimension | OpenVEX | CSAF VEX | CycloneDX VEX |
|-----------|---------|----------|---------------|
| **Approach** | Component-centric | Product-centric | Component-centric |
| **Identification** | PURL, CPE | Product tree (vendor → product → version) | PURL, CPE |
| **Justification** | `justification` field | `flags.label` (machine) or `threats` (human) | `justification` field |
| **Standalone** | Yes (JSON-LD) | Yes (JSON) | No (embedded in BOM) |
| **Distribution** | Ad-hoc / CI artifacts | ROLIE feeds, well-known URLs, provider metadata | With SBOM |
| **Complexity** | Low | High | Low |
| **Best for** | CI automation, internal attestation | Enterprise advisory feeds, regulated industries | SBOM-attached context |

Supporting only one of these formats would create an avoidable blind spot. OpenVEX is ideal for internal automation, CI output, and lightweight attestation. CSAF VEX is required for enterprise interoperability, compliance workflows, and ingestion of supplier-published security advisories. CycloneDX VEX matters because exploitability data may arrive piggybacked on the SBOM already flowing through the platform. The platform therefore needs an internal model that is format-agnostic while preserving the richer information available from CSAF when present.

The platform is also in a strong position to automate VEX production. It already knows:
- which components exist in a repository snapshot
- which versions were observed over time
- which advisory ranges are fixed by later versions
- which dependency trees and snapshots changed between scans

That means VEX should not be treated only as a manual analyst workflow. The system can derive a meaningful subset of exploitability statements automatically and attach provenance that explains why the statement exists.

## Decision

### 1. Data Model
The boolean suppression model on `vuln_matches` is replaced by a dedicated `vex_statements` table. Because the project is still pre-alpha, migration compatibility is not required; the original migration file is updated directly rather than adding a compatibility migration.

```sql
CREATE TYPE vex_status AS ENUM (
    'not_affected',
    'affected',
    'fixed',
    'under_investigation'
);

CREATE TYPE vex_justification AS ENUM (
    'component_not_present',
    'vulnerable_code_not_present',
    'vulnerable_code_not_in_execute_path',
    'vulnerable_code_cannot_be_controlled_by_adversary',
    'inline_mitigations_already_exist'
);

CREATE TYPE vex_source AS ENUM (
    'manual',
    'imported',
    'propagated',
    'automated'
);

CREATE TABLE vex_statements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    advisory_id UUID NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
    repo_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    component_purl TEXT,
    status vex_status NOT NULL,
    justification vex_justification,
    impact_statement TEXT NOT NULL DEFAULT '',
    action_statement TEXT NOT NULL DEFAULT '',
    source vex_source NOT NULL DEFAULT 'manual',
    source_document_url TEXT NOT NULL DEFAULT '',
    supplier TEXT NOT NULL DEFAULT '',
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT vex_justification_required CHECK (
        status != 'not_affected' OR justification IS NOT NULL
    )
);
```

Statements are scoped using three levels, with the most specific match winning during evaluation:
- component-level: `component_purl + repo_id`
- repo-level: `repo_id` only
- org-wide: `repo_id IS NULL` and `component_purl IS NULL`

`vuln_matches` remains the scan result table linking snapshots, components, and advisories, but it no longer stores suppression state. Gate evaluation, API rendering, and UI display must resolve the effective VEX status for each vulnerability match by querying `vex_statements` according to that precedence model.

### 2. Ingestion
The unified upload pipeline is extended so `detectArtifactType` in `internal/server/uploads.go` can recognize VEX documents:
- OpenVEX: JSON where `@context` references `openvex.dev`
- CSAF VEX: JSON where `document.category == "csaf_vex"`

A new `internal/vex/` package owns parsing and normalization:
- `vex.go`: common types and the internal `Statement` domain model
- `openvex.go`: parses OpenVEX documents and maps statements into internal VEX rows
- `csaf.go`: parses CSAF VEX documents, resolves `product_tree` nodes to repositories and components, maps `product_status` into internal `vex_status`, extracts remediations into `action_statement`, and extracts threats into `impact_statement`
- `cyclonedx.go`: extracts embedded VEX fields from CycloneDX `vulnerabilities[].analysis` during SBOM ingestion

The internal model is the normalization boundary. All external formats map into the same statement representation so downstream logic remains independent from source format.

### 3. Export
The platform exposes VEX generation endpoints:

`GET /orgs/{p}/{s}/repos/{repo}/vex?format=openvex|csaf&ref=...`

Stored VEX statements are exported as valid documents:
- OpenVEX export is a direct mapping from internal statements to a single document for the selected product scope
- CSAF 2.0 export builds a complete `csaf_vex` document, including publisher metadata with Hibou as publisher, a `product_tree` derived from repository and component inventory, and `vulnerabilities` grouped into the appropriate `product_status` buckets with remediation data

Export is part of the product, not only import. Users should be able to publish their own exploitability assessments downstream.

### 4. Automation
Automation is a primary goal of the design, not an afterthought.

#### Auto-fixed
When a new snapshot shows that a component version has moved beyond a known advisory fix version, the platform automatically creates `status=fixed, source=automated`. Provenance is recorded in the statement context, for example: "Component upgraded from v1.2.3 to v1.2.4 which includes fix."

#### Auto-not-present
When a component disappears from the SBOM between snapshots, the platform can create `status=not_affected`, `justification=component_not_present`, `source=automated` for the relevant scoped component statement. Provenance captures the snapshot transition that proved absence.

#### Supplier propagation
When a VEX statement is imported from a supplier and includes supplier identity, the platform can propagate that statement to every repository in the organization that consumes the same component. This is controlled by an organization setting, `vex_auto_propagate`, enabled by default. The default operating mode is auto-apply with notification and no manual review gate because the feature is intended to remove repeated per-repo triage.

#### Expiry and re-evaluation
Statements may carry `expires_at`. A scheduled job re-evaluates expired entries, downgrades them to `under_investigation`, and sends notifications. This prevents stale exploitability assertions from silently hiding live risk forever.

#### Source code reachability analysis
The strongest VEX justification is `vulnerable_code_not_in_execute_path`, but asserting it manually is slow and error-prone. The platform can derive this automatically by analyzing application code against known vulnerable call sites.

Reachability analysis only works for languages where static call graph construction is precise enough to safely assert non-reachability. Dynamic languages (Python, JavaScript, TypeScript) and C/C++ produce call graphs too imprecise to guarantee that a vulnerable path is truly unreachable — a false `not_affected` is worse than no statement at all. OS-level packages (dpkg, rpm, apk) have no application source to analyze; version comparison is the only available signal and reachability does not apply.

Two languages are viable targets today, with different source access models:

##### Go — server-side, fully automated
Go has the best ecosystem support for reachability. `golang.org/x/tools/go/callgraph` provides mature RTA and VTA algorithms that build precise call graphs directly from source. OSV publishes affected function and method symbols for Go advisories in `affected[].ecosystem_specific.imports[].symbols`. The combination means the platform can prove non-reachability with machine evidence.

**Source access**: the platform already holds forge app credentials for all three supported providers (GitHub, GitLab, Forgejo/Gitea). After SBOM ingestion, the server clones the repository at the snapshot's commit SHA using the existing `forge.Provider` interface — the same credentials and code path used for webhook validation and PR annotation. The clone is shallow (`--depth 1`), written to a temporary directory, analyzed, and deleted. No new credentials or permissions are required.

**Analysis flow**:
1. Clone repo at commit SHA via forge provider
2. Load packages with `golang.org/x/tools/go/packages` (respects build tags and module configuration)
3. Build call graph from entry points (`main.main`, `init`, exported API surface) using RTA or VTA
4. For each advisory with affected symbol data, walk the call graph to check reachability
5. Unreachable → `status=not_affected`, `justification=vulnerable_code_not_in_execute_path`, `source=automated`
6. Reachable → no statement (leave as-is; the advisory is genuinely relevant)
7. Incomplete graph (reflection, `unsafe`, CGo, missing module) → `under_investigation` with analysis gap surfaced

**Implementation**: `internal/reachability/` package with `reachability.go` (engine interface, result types), `go_analyzer.go` (Go-specific call graph construction), `symbol_matcher.go` (advisory symbol matching), and `report.go` (result model).

This runs as a background job after SBOM ingestion. Results are cached per snapshot and invalidated when source changes. Opt-in per org via `vex_reachability_analysis` setting. Works identically across all forges because the clone path uses the existing provider abstraction.

##### Java — CI-side, opt-in via CLI
Java reachability requires compiled bytecode (`.class` files or JARs), not source code. The platform cannot compile Java projects server-side — that would require Maven/Gradle/Ant, JDK versions, private artifact repositories, and build environment parity. Instead, the CLI provides a command that runs in CI where the build has already happened:

```
hibou analyze reachability --lang java --org acme --repo backend --ref refs/heads/main --sha abc123
```

The CLI auto-discovers bytecode by recursively walking the working directory for `target/classes`, `build/classes`, and `*.jar` files. This is designed to work out of the box on large multi-module projects (hundreds of Maven modules, Gradle subprojects, mixed builds) without any additional configuration:

- **Fast discovery**: the walker only stats directory entries matching known output patterns (`target/classes`, `build/classes`), skipping source trees, test resources, and irrelevant directories. On a 200-module Maven project, discovery completes in under a second.
- **Dependency-scoped analysis**: the analyzer does not build a call graph for the entire project. It first resolves which modules transitively depend on the vulnerable library (via `pom.xml` / `build.gradle` dependency declarations or JAR manifest inspection), then only loads and analyzes bytecode from those modules. A CVE in `commons-text` touching 12 out of 200 modules means only 12 modules are analyzed.
- **Parallel module analysis**: discovered modules are analyzed concurrently with bounded parallelism (default: `GOMAXPROCS`), so large projects scale linearly with available cores.

Explicit paths are only needed for non-standard build layouts (e.g., Ant with custom output dirs, relocated build artifacts):

```
# Auto-discover — works for Maven, Gradle, and most build systems, even with hundreds of modules
hibou analyze reachability --lang java

# Explicit paths only for non-standard layouts
hibou analyze reachability --lang java --bytecode "custom-output/*/classes"
```

This command:
1. Collects all `.class` files and JARs from discovered or specified paths
2. Builds a call graph using an embedded analyzer (ASM-based class hierarchy analysis — lighter than Soot, sufficient for reachability)
3. Resolves entry points from manifest, Spring Boot annotations (`@RestController`, `@Service`), servlet declarations, or explicit `--entry` flags
4. Matches against advisory affected symbols (OSV has partial Java symbol coverage; the platform also extracts symbols from NVD CPE data where available)
5. Uploads the reachability report to the server as a structured artifact attached to the current snapshot

The server receives the report and creates automated VEX statements the same way as Go reachability. The difference is only in where the analysis runs.

This is strictly opt-in. Teams that do not add the CI step get no Java reachability analysis — they still have all other VEX automation (auto-fixed, auto-not-present, supplier propagation) and manual VEX statement creation.

##### Rust — CI-side, opt-in via CLI
Rust reachability is feasible but with important caveats that make server-side analysis impractical.

**Why not server-side like Go**: Cargo builds execute arbitrary code via `build.rs` scripts and procedural macros. Running `cargo check` or `cargo build` on untrusted repos is a sandbox problem the platform should not take on. Additionally, Rust's call graph tooling (e.g., `cargo-call-stack`, `reachsec`) requires nightly toolchains, and the ecosystem has no stable first-party call graph API equivalent to Go's `x/tools/go/callgraph`.

**RustSec symbol coverage**: RustSec advisories support structured function metadata via `[affected.functions]`, and OSV exports these under `affected[].ecosystem_specific.affects.functions`. However, only ~13% of RustSec advisories currently include function-level data. When symbol data is absent, reachability analysis cannot run for that advisory — it falls back to version-only matching.

**CI-side approach**: like Java, the CLI runs in CI where the Rust toolchain, registry credentials, and dependency caches are already present:

```
hibou analyze reachability --lang rust
```

This command:
1. Runs `cargo metadata` to resolve the dependency graph and workspace structure
2. Uses tree-sitter to parse source files and extract `use` declarations, function calls, and qualified paths to dependency symbols
3. For advisories with affected symbol data, checks whether any imported or called symbol matches
4. When a match is ambiguous (trait dispatch, macros, reexports), marks the advisory as `under_investigation` rather than asserting `not_affected`
5. Uploads the reachability report to the server

**Confidence model**: because Rust source-level analysis is less precise than Go's compiler-backed call graph or Java's bytecode analysis, the platform uses a two-tier confidence model:
- **High confidence** (auto-VEX): advisory has function metadata AND no source-level reference to the affected symbols AND no dynamic dispatch or macro-generated calls to the affected crate → `not_affected / vulnerable_code_not_in_execute_path`
- **Low confidence** (triage hint): advisory has function metadata but analysis is inconclusive (macros, trait objects, reexports) → reported as a triage recommendation in the UI, not an automated VEX statement

This is honest about the limitations. Rust reachability provides value when symbol data exists and the code path is straightforward, but it does not claim soundness it cannot deliver.

##### Multi-language repositories
Real repositories often contain multiple languages (Go backend + TypeScript frontend, Java services + Python scripts, etc.). The reachability system handles this naturally:

- **Server-side Go analysis** runs automatically when enabled, regardless of other languages present. The server detects Go modules by the presence of `go.mod` in the cloned source.
- **CI-side analysis** supports `--lang` flags that can be specified multiple times or comma-separated:

```
# Analyze both Java and Rust in a polyglot repo
hibou analyze reachability --lang java --lang rust

# Or comma-separated
hibou analyze reachability --lang java,rust
```

Each language analyzer runs independently and uploads its own section of the reachability report. The server merges results per snapshot — a Go advisory is resolved by the Go analyzer, a Java advisory by the Java analyzer, and so on. There is no cross-language call graph analysis (a Go function calling a Java service via HTTP is not modeled).

The CI action exposes this via the `reachability` input:

```yaml
# GitHub Action / Forgejo Action
- uses: hibou/upload@v1
  with:
    file: sbom.json
    reachability: java,rust  # comma-separated languages for CI-side analysis
```

Go reachability is not listed here because it runs server-side. The CI action only needs to specify languages that require local build artifacts or toolchains.

##### Languages explicitly out of scope for reachability
- **Python, JavaScript, TypeScript**: dynamic dispatch, duck typing, `eval`, monkey patching, and prototype manipulation make static call graphs too imprecise. A reachability proof requires soundness; these languages cannot provide it statically. False `not_affected` risk is unacceptable.
- **C/C++**: function pointers, macros, complex build systems. Not viable for automated reachability.
- **OS packages** (dpkg, rpm, apk): no application source to analyze. These are binary packages referenced by version in the SBOM. Version comparison against advisory affected ranges is the only available signal. Reachability analysis is structurally inapplicable.

For all out-of-scope languages and ecosystems, the other VEX automation paths (auto-fixed, auto-not-present, supplier propagation, manual statements, VEX import) remain fully available.

#### Bulk operations
The API supports creating an org-wide VEX statement for an advisory. This covers cases such as "this advisory does not affect us because we do not expose the vulnerable JNDI path" without requiring analysts to repeat the same action across every repository.

### 5. CSAF Depth
CSAF VEX support is implemented as full CSAF 2.0 Profile 5 compliance, not a shallow field scrape.

#### Ingestion
The platform supports:
- complete `product_tree` parsing, including branches, relationships, and product identification helpers. Product IDs are resolved to platform repositories and components via PURL matching, CPE matching, and name heuristics
- `product_status` mapping: `known_affected → affected`, `known_not_affected → not_affected`, `fixed → fixed`, `under_investigation → under_investigation`
- `flags` extraction: machine-readable VEX justification labels (`component_not_present`, `vulnerable_code_not_in_execute_path`, etc.) mapped directly to internal `vex_justification` enum — these take priority over human-readable threats as justification source
- `threats` with `category: "impact"` mapped into `impact_statement` when no machine-readable flag is present
- `remediations` mapped into `action_statement`, including `vendor_fix`, workarounds, mitigation, `no_fix_planned`, and `none_available`. The remediation category is preserved as metadata
- retention of `first_fixed` and `recommended` data as fix-related metadata for future remediation UX
- `scores` used to enrich canonical advisory scoring when additional CVSS context is present
- TLP distribution labels preserved as metadata for access control and redistribution decisions

#### Export
Generated CSAF VEX documents satisfy Profile 5 requirements:
- `document` metadata with Hibou as publisher (category: `tool`), tracking ID derived from org + export scope, revision history tracking re-exports, TLP label configurable per org (default: `TLP:CLEAR`)
- `product_tree` built from platform repository and component inventory, with product IDs generated from PURLs
- `vulnerabilities` with proper `product_status` buckets and mandatory companion data: `flags` for `known_not_affected` products (using platform justification codes), `remediations` for `known_affected` products
- `notes` with vulnerability details from the advisory database

#### CSAF Provider Infrastructure (future)
The platform can optionally act as a CSAF provider (or CSAF trusted provider with signing) by serving:
- `/.well-known/csaf/provider-metadata.json` — publisher metadata (category, name, namespace, contact), distribution URLs, PGP signing keys, aggregator permissions (`list_on_CSAF_aggregators`, `mirror_on_CSAF_aggregators`), and `metadata_version: "2.0"`
- **ROLIE feeds** (RFC 8322) — one JSON Atom feed per TLP level listing all CSAF documents. Each entry includes self link, hash links, summary, and timestamps. Consumers poll the feed for incremental sync rather than scraping directories
- **Directory-based distribution** — year-organized folders (`/csaf/v2/vex/2026/cve-2026-xxxxx.json`), `index.txt` (flat file list), `changes.csv` (filename + last-modified for delta sync), SHA-256/SHA-512 hash files per document
- Reference in `/.well-known/security.txt`
- Optional PGP signatures per document for integrity verification

This follows the same pattern as Red Hat's production CSAF infrastructure (separate `/advisories/` and `/vex/` directories, `csaf_trusted_provider` role, PGP-signed documents). It allows downstream consumers and CSAF aggregators to automatically discover and ingest advisories published through the platform.

This is a future feature, deferred until core VEX CRUD and export are stable. The directory layout and ROLIE feed generation can be built incrementally on top of the export endpoints.

#### CSAF Consumer / Upstream Sync (future)
The platform can also act as a CSAF consumer, ingesting VEX documents from upstream suppliers automatically:
- Configure a supplier's CSAF `provider-metadata.json` URL (e.g., Red Hat's `https://www.redhat.com/.well-known/csaf/provider-metadata.json`)
- Poll their ROLIE feed or `changes.csv` for new/updated VEX documents
- Auto-import relevant statements for components present in the org's repositories
- This closes the supply chain loop: Red Hat publishes `known_not_affected` for CVE-X on their product → the platform auto-imports it → all repos using that Red Hat component get the VEX statement via supplier propagation

This is also deferred but is the natural complement to the provider infrastructure.

This depth increases implementation complexity but is necessary to interoperate with enterprise vendor feeds correctly and to produce valid CSAF VEX documents that pass automated validation.

### 6. Quality Gate Integration
Quality gates resolve effective VEX state before counting vulnerabilities:
- `not_affected`: excluded from gate counts
- `fixed`: excluded from gate counts because the platform has evidence that the issue is remediated
- `affected`: counted normally because the statement explicitly confirms exploitability or impact
- `under_investigation`: configurable per gate; default behavior is to skip rather than count

This moves gating from a binary suppression toggle to an auditable exploitability-aware model.

### 7. API Endpoints
The API surface for VEX is:
- `POST /orgs/{p}/{s}/repos/{repo}/vex` — create manual VEX statement
- `PUT /orgs/{p}/{s}/repos/{repo}/vex/{id}` — update statement
- `DELETE /orgs/{p}/{s}/repos/{repo}/vex/{id}` — revoke statement
- `GET /orgs/{p}/{s}/repos/{repo}/vex` — list statements, filterable by advisory, status, and source
- `GET /orgs/{p}/{s}/repos/{repo}/vex/export?format=openvex|csaf` — export generated VEX
- `POST /orgs/{p}/{s}/vex` — create org-wide statement
- `POST /orgs/{p}/{s}/vex/import` — import a VEX document with automatic format detection

## Consequences
- The simple suppression model is replaced with standards-compliant exploitability tracking.
- Two primary standalone format parsers must be maintained, OpenVEX and CSAF, plus CycloneDX VEX extraction during SBOM ingestion.
- The internal statement model remains format-agnostic, so import/export complexity is isolated from the rest of the platform.
- Automation can materially reduce manual triage volume because many `fixed` and `component_not_present` cases are derivable from scan history.
- Source code reachability analysis is viable for Go (server-side, fully automated via forge clone), Java (CI-side, auto-discovers multi-module bytecode), and Rust (CI-side, best-effort with two-tier confidence model — ~13% of RustSec advisories have function data). Dynamic languages and OS packages are structurally out of scope — explained and documented rather than promised. The compute cost for Go is bounded per snapshot (shallow clone + call graph construction) and amortized by caching. Multi-language repos are supported naturally: Go runs server-side, Java/Rust run CI-side with `--lang java,rust`.
- CSAF `product_tree` resolution adds non-trivial complexity, but it unlocks interoperability with enterprise supplier feeds and richer downstream export.
- VEX documents can be distributed alongside SBOMs, improving supply-chain transparency for both internal consumers and external dependents.
- Expiry-based re-evaluation prevents stale exploitability assertions from becoming a permanent blind spot.
