# ADR-045: Built-in dependency inventory (without an uploaded SBOM)

## Status

Proposed (2026-10-15). First of three related ADRs:

- **ADR-045 (this one)**: how Hibou builds a dependency inventory itself,
  what is shipped, how evidence is recorded and stored.
- [ADR-046](046-dependency-cli.md): the CLI: local scans, release
  deliverables, SBOM verification.
- [ADR-047](047-inventory-evidence-governance.md): approval workflows for
  actions that can hide a vulnerability. Deferred until a need appears; this
  ADR ships with the baseline rules of §5.3.

Builds on [ADR-024](024-release-tracking.md) (releases),
[ADR-034](034-absence-is-not-resolution.md) (producer runs, absence is not
resolution), [ADR-035](035-bundled-scanners-and-coverage-policy.md) and
[ADR-036](036-automatic-scan-planning-and-verification.md) (catalog,
applicability, `hibou scan`), and reuses the clone path of
[ADR-010](010-secret-scanning.md).

## Context

Hibou only knows a repository's dependencies when someone uploads a CycloneDX
or SPDX SBOM. Repositories without an SBOM step in CI have an empty
Dependencies tab, no advisory matching, no license policy and no CRA
inventory. Releases tagged before a repository was onboarded have no SBOM at
all, so "which shipped versions are affected by CVE-X" cannot be answered for
them.

Most of the plumbing already exists:

- The server clones repositories for secret scanning, with the owner-binding
  checks of `resolveSecretScanTarget`
  (`internal/server/secret_scan_processing.go`).
- `internal/applicability` detects manifests and module roots from the tracked
  path list; `internal/scancatalog` and `hibou scan` run catalogued producers
  in CI.
- `components`, `snapshot_components` and `snapshot_dependency_roots` store an
  inventory; `producer_runs` records what ran and with which scope.
- The Dependencies tab already lists the **Sources** of each component
  (`site/src/views/repo/DependenciesTab.vue`), so provenance has a home.
- Releases pin a snapshot (ADR-024); the advisory pass already rescans pinned
  release snapshots.

What is missing is a producer that builds the inventory itself from the
repository content. Repository content alone cannot reveal OS packages (rpm,
apk, deb); that needs an image (§10) or a delivered artifact (ADR-046).

### Goals

1. Inventory for every onboarded repository with no CI change, at least for
   Java, Go, Python, JavaScript/TypeScript and Rust.
2. The same producer runs in CI through `hibou scan` when the repository wants
   build-accurate results.
3. On-demand inventory for existing release tags from the tag's content.
4. Uploaded SBOMs keep working; every component traces back to each source
   that reported it, and the database tells manual evidence from detected
   evidence.
5. No false history: an old release's inventory reflects what was resolved
   then, never what a registry would resolve today.
6. The server never executes repository code.

### Non-goals

- Dependency update pull requests: that is the job of Dependabot or Renovate.
- IaC misconfiguration scanning (Checkov, KICS, Trivy config): a SAST-like
  producer under ADR-035, not an inventory (§9).
- C/C++ vendored sources, Bazel, Nix and other build systems without a
  standard manifest (unsupported, shown as such).
- Reachability. A separate ADR may cover it.
- The CLI and deliverable analysis (ADR-046); approval workflows (ADR-047).

## Decision

### 1. Detection techniques

| # | Technique | Indirect deps | Exact versions | Executes repo code | Network | Valid for an old tag |
|---|---|---|---|---|---|---|
| T1 | Parse lockfiles (incl. `go.mod`, `Cargo.lock`) | Yes, **recorded** | Yes | No | No | **Yes** |
| T2 | Parse manifests (declared requirements) | No | Only when pinned | No | No | Yes, for direct deps |
| T3 | Manifests + resolver against registries **today** | Yes, **re-resolved** | Approximated | No | Yes | **No** |
| T4 | Run the native tool (`mvn dependency:tree`, `gradle dependencies`, `pip install --dry-run --report`, `npm ls`, `go list -m all`, `cargo metadata`) | Yes | Yes | **Yes** | Yes | Only at build time |
| T5 | Build plugins emitting SBOMs (CycloneDX Maven/Gradle plugins, `cyclonedx-npm`…) | Yes | Yes | **Yes** | Yes | Only at build time (today's upload path) |
| T6 | Graph export files from an earlier CI step (`mvn dependency:tree -DoutputType=json`, `pipdeptree --json`) | Yes | Yes | Yes, in CI | In CI | Only if produced at build time |
| T7 | Delivered artifacts: JAR/WAR/EAR, Go and Rust binaries, wheels, `site-packages`, `node_modules`, images | Yes, **as shipped** | Yes | No | No | **Yes** |

Trade-offs:

- **T1** is the default. It is deterministic, offline and fast, and a pure
  function of a few files, so it can be cached by file digest. Lockfiles are
  the ecosystem best practice; Hibou rewards them (§2.1). The caveat is that a
  build can ignore its lockfile (`npm install` instead of `npm ci`), which the
  evidence label makes visible.
- **T2** gives *requirements*, not versions (`^4.17.0`, `>=2.0`,
  `[1.2,2.0)`). See §2.2.
- **T3** is what OSV-Scanner does for `pom.xml` (effective POM, then the
  deps.dev resolver). Resolving an old manifest today returns today's versions
  of every range-matched and indirect dependency: false positives (a
  vulnerable version released after the tag) and false negatives (a vulnerable
  version that shipped then, since superseded). Following repository-declared
  `<repositories>` is also an SSRF and dependency-confusion vector, which is
  why OSV-SCALIBR classifies this extractor as "unsafe". **Rejected on the
  server, for both automatic and release extraction.**
- **T4/T5/T6** are the reference for accuracy at the time they run, because
  they use the real resolver. They execute build scripts, so they belong to the
  repository's own trust domain (CI). GitHub reached the same conclusion: its
  static dependency graph does not run builds, and "automatic dependency
  submission" for Maven, Gradle and pip runs the real tool on an Actions
  runner. Run at build time, their output is recorded history. Rebuilding an
  old tag today has the same problem as T3.
- **T7** reports what actually shipped, including what a lockfile does not
  show (shaded or vendored jars, bundled runtimes). It is the most accurate
  source for old releases and is analysed by the CLI (ADR-046).

#### 1.1 Indirect dependencies: recorded, never re-resolved

Indirect dependencies are kept only when they were **recorded at the commit**
(lockfile, `go.mod`, `Cargo.lock`, an SBOM or graph export produced by that
build) or **observed in a delivered artifact**. These are the versions that
were resolved then, so they are not false positives, even for a
five-year-old tag.

When a module has no lockfile, Hibou lists its **direct dependencies only**
with a warning: "indirect dependencies unknown: no lockfile at this commit".
It never fills the gap by resolving. This is the common case for old release
tags whose builds no longer exist; for those, the only sources of indirect
dependencies are the deliverable (ADR-046) or an SBOM kept from that time.

Resolving is rejected for two reasons:

- **Time**: registries return today's versions for ranges, `LATEST`,
  `SNAPSHOT` and floating indirect requirements.
- **Method**: indirect resolution depends on the tool and its settings, so any
  resolver other than the project's own build gives a different graph. Maven
  picks the nearest declaration, Gradle the highest version; BOMs,
  exclusions, profiles, `settings.xml` mirrors and Gradle resolution rules
  change the result. pip's resolver depends on the interpreter version and
  platform markers. npm and pnpm install OS- and CPU-specific optional
  packages, and different versions of npm itself produce different trees.

Even a lockfile is evidence of one resolution, not proof of what shipped, so
each indirect component carries how it was obtained, and the UI shows it:

- **`indirect · lockfile`**: what the repository's own build resolved,
  provided the build honoured the lockfile (`npm ci`, `poetry install`, Go
  modules always; `npm install` or an unpinned `pip install` may not).
- **Conditional entries** (npm `os`/`cpu` optional packages, Python
  environment markers, Cargo target-specific dependencies) are listed with
  their condition. Hibou does not guess the target platform.
- **Libraries**: a library is a repository published as a package that other
  projects depend on (an npm package, a Maven artifact, a Go module), as
  opposed to an application deployed or delivered as a whole. A library's
  lockfile only pins indirect versions for its own tests and CI; each
  consumer resolves its own. Hibou does not try to detect libraries. The
  `indirect · lockfile` badge carries a note, always shown:

  > Resolved by this repository's own build. If this repository is a library
  > used by other projects, each of them resolves its own versions: check
  > their inventories for what actually runs.

  A `kind: library` setting that would mark these entries `shipped: no` was
  considered and left out; it can be added without changing the data model.
- **`indirect · artifact`** (found in a deliverable) and **`indirect · build
  SBOM`** (recorded by the build, T4–T6) are the only indirect sources that
  prove what clients received.
- **Gates count `indirect · lockfile` findings by default.** Ignoring them
  could let a vulnerability that really ships through; counting them at worst
  blocks on a version the build did not use, which a person can check. A
  repository can switch them to informational
  (`dependencies.gate_lockfile_indirect: inform`, §8), for example when its
  build is known not to use its lockfile. An org can forbid that.

### 2. Coverage per ecosystem with static techniques

| Ecosystem | Recorded with (T1) | Declared only (T2) | Notes |
|---|---|---|---|
| Go | `go.mod` (+ `go.sum`), `vendor/modules.txt` | — | Since Go 1.17 `go.mod` lists every module needed to build the main module's packages and MVS is deterministic, so it is effectively a lockfile. The `go`/`toolchain` directive gives the stdlib version (`pkg:golang/stdlib`), which carries many advisories. |
| Rust | `Cargo.lock` | `Cargo.toml` | Cargo now recommends committing `Cargo.lock` for libraries too; older libraries lack it. Workspaces share one lockfile. |
| JS/TS | `package-lock.json` (v1–v3), `npm-shrinkwrap.json`, `yarn.lock` (v1 and Berry), `pnpm-lock.yaml` (v5–v9), `bun.lock` | `package.json` | Workspaces from the lockfile. `deno.lock` later. |
| Python | `poetry.lock`, `uv.lock`, `Pipfile.lock`, `pdm.lock`, `pylock.toml` (PEP 751), fully pinned `requirements*.txt` (pip-compile output, `--require-hashes`) | `pyproject.toml` (PEP 621, Poetry), unpinned `requirements.txt`, `setup.cfg` | `setup.py` is code and is never executed. Environment markers are kept as labels; all branches are listed. `-r`/`-c` includes are followed inside the repo only. |
| Java (Maven) | — (no standard lockfile) | `pom.xml`: direct deps after property, in-repo parent and `dependencyManagement` interpolation | A literal `<version>` is an exact version for the direct dependency. Indirect deps need an SBOM, a graph export, or the artifact. Parent POMs and BOMs outside the repo stay unresolved. |
| Java (Gradle) | `gradle.lockfile` (dependency locking), `gradle/verification-metadata.xml` | `libs.versions.toml`, literal coordinates in build scripts | Build scripts are code. Verification metadata lists every resolved artifact with checksums but no graph edges or configuration. |
| Scala/sbt, Mill | — | — | Unsupported at first. |

Java is where static extraction is weakest: Maven has no lockfile
convention. Java modules are labelled partial (direct only) until a recorded
source exists. For old releases, the artifact (ADR-046) is the best route.

#### 2.1 Lockfile hygiene

Lockfiles are best practice and they make Hibou's results exact. Hibou
surfaces their absence as a finding of its own kind (not a vulnerability):
"module `web/` has no lockfile". Orgs can require lockfiles through the
coverage policy of ADR-035, which makes a missing lockfile a coverage gap
like a missing scanner.

#### 2.2 Version ranges

Mainstream open-source scanners (OSV-Scanner, Trivy, Grype) match
vulnerabilities against exact versions from lockfiles, installed packages or
artifacts, and do not match bare manifest ranges. GitHub documents Dependabot
alerts for dependencies "where the version can be determined from a manifest
or lockfile". Hibou follows that practice:

- An **exact pin** in a manifest (`==1.2.3`, `"1.2.3"` in `package.json`, a
  literal Maven version) is a version and is matched.
- A **range** is stored with its constraint, shown as "unresolved", and
  excluded from advisory matching and license evaluation.
- Rejected: picking the lowest or highest version in the range (guessing);
  a "possibly affected" state (rarely provable, one more lifecycle state).

#### 2.3 Licenses

Uploaded SBOMs usually carry license data; static extraction mostly does
not. Lockfiles record versions, not licenses, and the library's license
enrichment (OSV-SCALIBR's `license/depsdev`) is a network call to deps.dev,
disabled on the server (§7). Extraction reads licenses only where the
repository files state them (`package.json` of workspace packages,
`pyproject.toml`, `Cargo.toml`, `pom.xml` of in-repo modules). License policy
(ADR-029/030) therefore shows **unknown license** for most extracted-only
components instead of a verdict, and the Dependencies tab says why. An
operator may enable license enrichment through an approved mirror of
deps.dev or an internal license database; that is a later step.

### 3. Engine: reuse or write

| # | Option | Language / license | Pros | Cons |
|---|---|---|---|---|
| E1 | Own parsers in Go | Go / ours | No dependency weight; exactly our data model; `golang.org/x/mod` covers `go.mod` | Many formats with subtle versions (yarn Berry, pnpm v9, npm v1, PEP 751); permanent maintenance |
| E2 | **OSV-SCALIBR** as a library | Go / Apache-2.0 | Built as a library; one plugin per extractor, so an allowlist is easy; explicit "unsafe plugin" flag for network or execution; covers every target ecosystem incl. `bun.lock`, `uv.lock`, `pylock.toml`, `cargo auditable`, Go binaries, JARs; OS package databases, container filesystems and tar archives; used by OSV-Scanner v2 | Pre-1.0 API churns; large dependency tree; output is its own inventory type, not CycloneDX |
| E3 | **Syft** as a library | Go / Apache-2.0 | Mature catalogers; native CycloneDX/SPDX output; best-in-class image and archive support; Java remote POM lookups optional and off by default | Heavier tree (container and image libraries even for source scans); cataloger selection by tags rather than a strict allowlist; pre-1.0 API |
| E4 | Trivy as a subprocess | Go / Apache-2.0 | Already integrated for advisories (`internal/provider/trivy`); one binary for fs and images | Separate process and version to pin and distribute (ADR-035); geared to vulnerability scanning; startup cost per run |
| E5 | cdxgen | Node.js / Apache-2.0 | Widest ecosystem coverage, rich CycloneDX evidence | Needs Node + JDK + Python…; runs package managers by default (T4); CI only |
| E6 | OSV-Scanner CLI | Go / Apache-2.0 | Same engine as E2 behind a process boundary | Subprocess plus vulnerability-oriented defaults; E2 gives the same in-process |
| E7 | dependabot-core | Ruby / MIT (since May 2024) | Very mature parsers (`FileParser` per ecosystem) | Ruby plus native toolchains per ecosystem (several Python versions, forked Yarn, patched npm…), images of several GB; built for update jobs; shells out to package managers. Not what GitHub's dependency graph uses either (separate parsers) |
| E8 | Renovate in extract-only mode (`--platform=local`, `dryRun=extract`) | TypeScript / **AGPL-3.0** | ~90 managers incl. non-package deps (Docker, Actions, Helm, Terraform); extraction is pure parsing | Node runtime; AGPL needs legal review before redistribution; extracts declared and locked *direct* versions, not a full indirect graph; log-shaped output |
| E9 | Forge-provided inventory (GitHub dependency graph SBOM export, GitLab dependency list) | API | Free when enabled; includes auto-submission results | Forge-specific; current default branch only, so no tags or history; must be enabled; third-party trust |
| E10 | deps.dev API for resolution | API | No resolver to maintain | This is T3 (rejected); sends dependency names off-site and fails offline (ADR-035) |

**Decision: embed a library behind our own `internal/depinventory` interface,
with OSV-SCALIBR as the primary candidate and Syft as the fallback.** A
fixture benchmark confirms the choice before implementation (Rollout step 1),
the same way ADR-035 measured OpenGrep. Criteria: recall and precision
against T4 ground truth per ecosystem, artifact support (fat JARs, WARs,
binaries, image tars), dependency-tree and binary size delta, memory on the
largest fixture.

**Spike result (2026-10-16, rollout step 1): E2 confirmed.** OSV-SCALIBR
v0.5.3 behind `internal/depinventory`, fifteen offline extractors built by
direct constructor rather than through the engine's registry (the registry
links every extractor, detector and container reader: 55 MiB; the direct
constructors: about 20 MiB on the binary, 160 modules added to the tree).
On the fixture corpus (Go, npm v3, pnpm v9, Yarn v1, uv, Poetry,
pip-compile, Cargo, Maven, Gradle lockfile, a monorepo with a `node_modules`
decoy) every component, relationship and scope matched the hand-written
ground truth. On this checkout, nested repositories included: 2,341
components over 23 modules in 230 ms, 22 MiB allocated, 4 MiB of heap
growth, no file errors. Relationship rules (§5.1) are hibou's own, read
from the module's manifest or lockfile root, because the engine does not
expose the declared set; Maven's property and `dependencyManagement`
interpolation and npm's dev scope come from the engine. Syft stays the
fallback only if a later engine upgrade breaks the allowlist contract.

**Increment 1 (2026-10-16, rollout steps 2–4 in part).** Implemented:
`dep_extraction_jobs` (one coalesced job per push to the default branch or
a release tag, at enrolment, or on the admin endpoint
`POST .../dependencies/extract`), a worker loop with the secret-scan lease
and attempt rules, a blobless single-ref clone with only the recognised
manifest paths checked out (`secretscan.CheckoutManifests`), an input
digest over the selected blobs plus the extractor version with reuse of
the earlier document on a hit, the CycloneDX document ingested directly into
the snapshot's components, labels and graph (no object is stored: the
rows are the inventory and exports regenerate a document from them) so
the advisory scan, releases, coverage and gate follow, the producer run `dependency-inventory:hibou` with the modules as
scope paths and partial reasons, and the queue on the instance jobs view.
On repositories with CI uploads the extracted artifact waits on the
pending placeholder for CI to adopt the commit, the same rule as secret
scanning.

**Increment 2 (2026-10-16, rollout steps 4–6 in part).** Implemented:
eager branch patterns (`dependencies.branches`) and lazy extraction on the
first read of any other ref (§4.1.1); the PR dependency delta against the
target branch's inventory, judged by the package policy of ADR-048 and
published in the gate comment (§4.1.2); on-demand release extraction and
the backfill of every release (§4.3); per-component provenance read from
the document's properties into the snapshot's label set and exposed by the
API and the Dependencies tab: relationship, declared scopes, modules,
resolution, registry, and which artifacts reported the component (§5);
the `shipped` attribute with its reason, the repository `not_shipped` list
(purl globs, `re:` expressions, path globs), the uploaded-SBOM rule, the
filter and the "N shipped · M total" counts (§6).

**Increment 3 (2026-10-16, rollout steps 6–10).** Implemented: the
organization not-shipped list and the repository entries recorded in the
UI, with their source shown next to the built-in defaults and the
`.hibou.yaml` entries (§6); declared-scope suggestions ("N components are
declared dev or test: mark them?") and the organization's trusted
ecosystems; `sbom_covers`, the "not in the uploaded SBOM: shipped or not?"
note for undeclared modules, `shipped` overrides, `exclude`; the
`gate_not_shipped` rule (malware always, KEV by default, EPSS and
severity on request) with the informational note in the gate and the "not
shipped" badge and filter on findings (§6, §12); ranges as "unresolved"
with their constraint, never matched (§2.2); the `hibou-deps` catalog
entry running the extractor in-process from `hibou scan`, the server-side
skip when CI ran it, and resolve mode (`--deps-resolve maven|gradle`,
`--deps-graph FILE`) for Maven, Gradle and pip exports (§4.2); the
extractor-upgrade pass that re-extracts outdated inventories of the
default branch and pinned releases, additively, with the extractor version
shown per ref and per release source (§4.3.1); IaC and CI dependencies as
their own ecosystems: Terraform providers, Helm charts, GitHub Actions,
GitLab CI includes and components, Ansible, Dockerfile and Compose images,
with SHA and digest pins recorded and tags declared (§9); containers: C2
and C3 through the CLI's `--image` (OS packages via dpkg, apk and rpm
databases plus language packages of the squashed filesystem, from a
registry reference or a tarball) and C1 as metadata on the source
inventory (§10); the CLI of ADR-046 (`deps scan`, `deps list`, `vulns
list`, `deps diff`, `deps verify`, `release scan` with plausibility checks
and additive recording, `release sources` with revoke and restore); and
the Releases tab's sources panel with the ready-to-copy command; parent
edges read from npm, pnpm, Yarn, Cargo, uv and Poetry lockfiles, so an
indirect dependency traces back to the direct one that pulled it in and
"where is it used" answers for it (Maven, Gradle and Go carry no such
graph in their files; resolve mode or `go mod graph` would be the source).

**Increment 4 (2026-10-17, rollout step 10 completed).** Containers: every
component of an image is attributed to the layer that introduced it, with
the base image told apart from the application layers (the engine's
heuristic: the last `CMD` or `ENTRYPOINT` before the application's own
layers, plus the `org.opencontainers.image.base.name` label when the
builder set it), carried as `hibou:layer`, `hibou:layer_digest` and
`hibou:base_image` properties into the snapshot labels, shown in the
Dependencies tab's provenance and in the CLI (§10, C2 and C3); C5 through
the CLI's `--image`: the SBOMs the registry holds for the image are read
from OCI referrers, the cosign tag convention (`.sbom` and `.att`) and
BuildKit attestation manifests, in-toto statements and DSSE envelopes
unwrapped, and their components join the inventory as their own source
when the filesystem scan did not see them; the server never pulls images
(C4 stays out). Jars without Maven metadata can be identified by SHA-1
against Maven Central on explicit opt-in (`--maven-central`), since a hash
leaves the machine.

**Increment 5 (2026-10-17, rollout steps 2 and 11): the Database section,
option B.** Migration `00066` creates `inventory_sets`,
`inventory_set_components`, `inventory_set_edges` and `inventory_sources`,
points `snapshots.inventory_set_id` at the effective set, backfills one
effective set per snapshot deduplicated by digest within the organization,
and replaces the three per-snapshot tables with views of the same names,
so every reader keeps its query. Rows are staged under a key and sealed
by one SQL function that computes the digest, returns the known set or
copies the rows and the counts; ingestion, digest reuse, the development
seed and the backfill all go through it. A push whose inventory an
organization already holds writes one source row and one pointer; a
snapshot with one source points at that source's set directly; several
sources merge into an effective set, recomputed when a source is revoked.
Immutability is enforced by triggers (no update of sealed sets or their
rows; deletion by the collector only, or with the organization). Retention's
purge releases the snapshot's inventory, and the retention pass collects
unreferenced sets. Migration `00067` makes advisory matching run once per
distinct set: an automatic scan of a snapshot whose set another snapshot
of the organization scanned after the last advisory or range change, with
the same providers and within a day, copies that scan's matches and is
recorded as reused; a rescan a person asks for runs in full. See "As
implemented" under the Schema for where the shape differs from the one
written in advance. Throttling of the upgrade pass is a fixed page per
pass with one job per repository, rather than per-org accounting.

Rationale: both are Go and Apache-2.0, so they keep the single binary
(ADR-001), run in-process on the server and in the CLI with identical results,
and need no runtime. E1 is kept only for formats the library lacks. E7 and E8
are rejected as engines (runtime footprint, Ruby/Node, AGPL for E8) but are
the main sources of design ideas (§11). E9 may later become an optional
import producer.

Only allowlisted extractors are enabled; network and "unsafe" extractors are
never enabled on the server.

### 4. Where and when it runs

#### 4.1 Automatic, server-side, on push

Hibou analyses every onboarded repository without CI changes, the same way it
already does secret scanning.

- **Trigger**: a push to an *eager* branch (§4.1.1), a tag matching the
  release tag pattern, or a pull request whose diff touches a recognized
  lockfile or manifest (§4.1.2).
- **Skip when nothing changed**: the inventory is a pure function of the
  matched files plus the extractor version. Hibou stores an *input digest*
  (sorted path + blob SHA list + extractor version), computed from the tree
  listing alone, before any clone. The digest is looked up **across the whole
  repository**, not per branch: if any branch or tag already produced an
  inventory from the same files, the new snapshot points at that source and
  its inventory set (see Database). One row is written and no extraction
  runs. This is evidence, not assumption, because the inputs are
  byte-identical (ADR-034 compatible).
- **Fetching content**, options:
  - (a) Forge contents API per file: no clone, but one call per file, rate
    limits, and per-forge code.
  - (b) **Blobless partial clone + sparse checkout** of the recognized paths
    (`--filter=blob:none --no-checkout`, then checkout of manifest paths only):
    one transfer, forge-agnostic, and it reuses the secret-scan clone target
    and owner-binding checks. **Chosen.**
  - (c) Full shallow clone: simplest, but transfers the whole tree for a few
    small files.
- **Execution**: an instance job (ADR-025) on workers (ADR-015), never in the
  API request path. A failure is a failed producer run, not an empty
  inventory.

##### 4.1.1 Repositories with thousands of branches

Some repositories have 5,000, 40,000 or more branches, most of them stale or
short-lived. Work must grow with the branches people look at, not with the
branches that exist.

**Eager branches** are extracted on every push: the default branch; branches
matching `dependencies.branches` in `.hibou.yaml` or the org default (e.g.
`release/*`, `develop`); tags matching the release tag pattern (ADR-024).
Pull requests follow §4.1.2.

**Every other branch is lazy**: a push only records the new head commit on
the ref, as today. No tree listing, no job, no snapshot. The inventory is
computed **on first read**: when someone opens that branch in the
Dependencies tab, lists it from the CLI, or compares it. The request returns
at once with a "computing" state, and the digest reuse above makes most of
these reads instant.

| Risk | Control |
|---|---|
| Push storms (`git push --all`, mirrors, bulk branch creation) | Lazy branches cost one ref update. Eager pushes are coalesced per ref: only the latest head is extracted if several are queued |
| Thousands of eager branches from a broad pattern (`*`) | A per-repository cap on eager branches (operator setting, default 200). Beyond it, the most recently pushed branches stay eager and the rest become lazy, with a warning on the repository |
| Forge API rate limits | Tree listings only for eager pushes and lazy reads; per-installation token budget shared with secret scanning; backoff on rate-limit responses |
| Snapshot and row growth | Snapshots only for eager pushes and lazy reads. Inventory rows are shared by digest (Database). Deleted branches release their snapshots to retention (ADR-014) and their sets to GC |
| Advisory matching cost | Matching runs per distinct effective set, so 40,000 branches with 30 distinct dependency states cost 30 matchings |

Related but out of scope: secret scanning currently runs on every branch
push, and the ref selector must search refs server-side for such
repositories. Both can adopt the same eager/lazy split later.

##### 4.1.2 Pull requests: report what the PR changes in dependencies

Most pull requests do not touch dependencies, so reporting on those that do
is cheap and rarely noisy.

- **When**: on PR open and each push to its head, if the PR's diff (base…head)
  touches a recognized lockfile or manifest. The diff file list comes from
  the forge's compare data already used for patch coverage. Otherwise
  nothing runs and nothing is posted.
- **What**: the head inventory is extracted (digest reuse applies) and
  compared with the base's, extracting the base on the fly if it is lazy.
  The delta lists added components and version changes, each with its
  vulnerabilities, severity, KEV, EPSS and shipped status; removed components
  and the vulnerabilities removed with them (shown as fixed by this PR only
  when the head inventory is complete for that module, ADR-034); direct
  changes first, then the indirect ones they pulled in.
- **Where**: a "Dependencies" section in Hibou's existing PR comment and
  check (`internal/forge/gate_publisher.go`, ADR-018), updated in place on
  each push, not a second comment.
- **Blocking vs informational**: every newly vulnerable dependency is
  **printed**, including not-shipped ones. Only those matching the gate rules
  block (§6). The others are marked "informational: not shipped".

```text
Dependencies: 2 added, 1 updated, 0 removed

  ✖ blocking   lodash 4.17.20 (direct, shipped)          CVE-2021-23337 high · EPSS 0.12
  ⚠ info       vitest 1.2.0 → 1.6.0 (direct, not shipped) CVE-2025-24964 critical
  ✓            date-fns 3.6.0 (indirect via react-day-picker, shipped)
```

#### 4.2 In CI, through `hibou scan`

A catalog entry `hibou-deps` runs the same extractor in-process: no download,
no checksum, the version is the CLI's. It uploads CycloneDX bound to its plan
job, like other producers.

Optional **resolve mode** runs the native tool (T4) or reads a graph export
(T6) for ecosystems without a recorded graph (Maven, unlocked Gradle and
Python). This is the repository's own trust domain, so executing its build
is acceptable there. The result is recorded at build time, so it remains
valid history for that commit.

When a repository runs `hibou-deps` in CI, the server-side run for the same
commit is skipped.

#### 4.3 On demand, for existing release tags

On the Releases tab (ADR-024):

- Each release whose snapshot has no inventory, or only a partial one, shows
  **"Extract dependencies"**. Release managers and admins
  (`requireReleaseManager`) can trigger it; the CLI equivalent is `hibou
  release scan <version>` without files (ADR-046).
- A bulk **"Backfill all releases"** action queues every release without an
  inventory, newest first, rate-limited per org.
- The job clones the tag's commit as in §4.1 and applies T1/T2 only (§1.1).
  If the release has no snapshot, it creates one for that commit and pins
  it, so the existing advisory pass covers it.
- Idempotent per (commit, extractor version, input digest).

#### 4.3.1 Extractor upgrades

Each `repository_scan` source records its `extractor_version` (Database).
A newer Hibou may extract more (a new lockfile format) or differently (a
parser fix).

- Each release and ref shows the extractor version its inventory came from,
  and "current: vX" when it is older.
- After an upgrade, a low-priority instance job re-extracts the inputs of
  pinned releases and of the latest snapshot of each eager branch, once per
  distinct input digest. Same digest as before: nothing happens. Different:
  a **new `repository_scan` source is added**; the old one stays, immutable
  (§5.3). Among sources of the same origin and kind, the newer extractor
  version takes precedence.
- A vulnerability that disappears because of this is labelled **changed by
  extractor update**, with both versions, and is never marked resolved
  (ADR-034). Nothing waits on a person; the history explains itself.
- Dry runs are throttled per org and skipped when the extractor's changelog
  says no supported format of that inventory's ecosystems changed.

ADR-047 describes an optional review queue in front of this, for orgs that
want a person to approve extractor changes that remove components.

#### 4.4 Deliverables and the CLI

Delivered artifacts (T7: WARs, binaries, images, arbitrary zips) are
analysed by the CLI, never uploaded to the server, and recorded on a release
with `hibou release scan <version> <files>`. Local scans without storing
anything, listing stored data, and SBOM verification are also CLI features.
All of it is specified in ADR-046; the data model it writes into is §5 and
the Database section here.

### 5. Provenance and merge rules

Every component keeps **every source that reported it**: built-in extraction
(with the evidence file and line, e.g. `web/pnpm-lock.yaml:1234`), each
uploaded SBOM (tool name, file name), each deliverable (file name, sha256,
path inside the archive, e.g. `app.war!/WEB-INF/lib/jackson-databind-2.15.2.jar`).
This extends the existing **Sources** column of the Dependencies tab into a
per-component "how was this detected" view.

Each source is a **producer** in `producer_runs` (ADR-034):
`dependency-inventory:hibou`, `dependency-inventory:hibou-ci`,
`dependency-inventory:artifact`, or `sbom:<tool>` for uploads.

Per component, record the resolution level (`artifact` > `recorded` (T1,
build-time T4–T6) > `declared` (T2)), scope labels when declared, the
relationship (§5.1), whether it is shipped (§6), and the module path inside
the repository.

**Accuracy precedence**, inspired by GitHub's dependency submission (a
snapshot per detector and job correlator, the more accurate source wins per
manifest): per ecosystem and module path, the highest resolution level wins
for counting and matching. Lower levels stay visible as sources, so nothing
disappears without trace.

**Completeness** is visible per module: complete, partial (with reason: no
lockfile, unparseable file, over size limit, Maven without a recorded
graph), or unsupported. The producer run is `partial` accordingly.

**ADR-034 applies.** A vulnerability that disappears because the source
changed (an SBOM upload stopped and extraction with fewer indirect deps took
over) is **not re-checked**, not resolved. Resolution requires a complete run
of a producer with at least the same resolution level for that scope.

Options considered: pure union (double counts versions that differ by
resolution level); last-writer-wins (non-deterministic with concurrent
uploads); hiding lower sources entirely (loses traceability).

#### 5.1 Direct, indirect, unknown

Each component has a **relationship**: `direct`, `indirect` or `unknown`.
`unknown` is a first-class value, never guessed into one of the other two.

| Source | Direct / indirect known? |
|---|---|
| `package-lock.json`, `pnpm-lock.yaml` (importers), `yarn.lock` + `package.json`, `bun.lock` | Yes: root entries of each workspace are direct |
| `go.mod` | Yes: `// indirect` marks indirect requirements |
| `Cargo.lock` + `Cargo.toml`, `poetry.lock`/`uv.lock`/`pdm.lock` + `pyproject.toml`, `Pipfile.lock` + `Pipfile` | Yes: the manifest gives the direct set, the lockfile the rest |
| Pinned `requirements.txt` (pip-compile) | Yes when the `# via` comments are present, otherwise `unknown` |
| `pom.xml`, `package.json` alone (T2) | Direct only, by definition |
| `gradle.lockfile`, `verification-metadata.xml` | `unknown` (no graph), unless the build scripts' literal coordinates mark some as direct |
| CycloneDX SBOM with a `dependencies` graph and `metadata.component` | Yes: the root's dependencies are direct |
| CycloneDX without graph or root, SPDX without `DEPENDS_ON` relationships | `unknown` |
| JAR/WAR/fat JAR | Direct from the application's own `META-INF/maven/**/pom.xml` when present; others `indirect`; otherwise `unknown` |
| Go binary build info | `unknown` alone (flat list); combined with the tag's `go.mod`, known |
| Image layers, `site-packages`, `node_modules` archive | `unknown`, unless a lockfile or `package.json` inside gives the roots |

Merging: a source with a graph decides over one without. If two sources with
a graph disagree, `direct` wins, because some module or source declared it
directly. In a monorepo the relationship is per module: `lodash` can be
direct in `web/` and indirect in `api/`.

#### 5.2 Origin: CI, Hibou scan, or manual

Every piece of inventory evidence is stored as a **source** row with an
**origin**, so the database separates manual entries from detected ones.
Origin is decided by **when and how** the evidence was produced, never by who
uploaded it: the actor is recorded separately, and a pipeline that still uses
a personal token must not see its uploads demoted.

| Origin | What it covers |
|---|---|
| `ci` | Produced by the build and uploaded **while the snapshot is being built** (before completion): an SBOM, a `hibou-deps` report, CI resolve mode. Bound to a scan plan job or carrying CI run metadata when available |
| `repository_scan` | Hibou's own extraction of the repository content at the commit (§4.1, §4.3), whatever triggered it: a push, the Releases tab button, `hibou release scan` without files |
| `manual` | Evidence added **after the fact**: a deliverable or image scanned with the CLI (ADR-046), an SBOM uploaded to a snapshot that was already completed, any source created from a user session on an existing release |
| `legacy` | SBOMs ingested before this ADR. Backfill only |

- **The server derives the origin**, never from a field the client sends. A
  CLI cannot declare itself `ci`.
- `retroactive` is stored separately: true when the source was added after
  the snapshot completed or after the release date. A `repository_scan` of
  an old tag is retroactive but not manual: it reads files recorded at the
  commit.
- Every component shows its origins. The Dependencies tab gets an **Origin**
  filter (CI / Hibou scan / Manual). Exports (release SBOM, CRA) flag
  components backed only by manual sources.

#### 5.3 Rules for evidence, by origin

| | `ci`, `repository_scan`, `legacy` (build-time) | `manual` |
|---|---|---|
| Can be deleted, revoked or edited | **Never, by anyone**, through any API, CLI or UI path. A wrong CI upload is corrected by a new upload for the commit, which takes precedence; the wrong one stays as history. Only retention of unpinned snapshots (ADR-014) removes them | Revocable (below) |
| Precedence | Among themselves, by resolution level and extractor version | **Additive only**: adds components the release did not have; never changes the version, relationship or shipped status of an existing component, never removes one |
| Conflicts | — | Same component at another version than a build-time source: both versions are kept and matched, and the component is flagged as a **discrepancy**. A CVE can appear but never silently disappear |

The reason: a later scan is the most likely to be wrong (wrong file, wrong
version), and a release's inventory feeds client impact and exports. A
mistake must add noise that someone reviews, never remove a CVE that clients
are exposed to.

**Revocation of a manual source.** A manual source can be **revoked**, not
deleted: it stays in the release history, shown as revoked with who, when
and why, and stops counting in the inventory, client impact and exports.
Revocation can be undone. Vulnerabilities that only that source reported
become **not re-checked** (ADR-034), not resolved, so revoking evidence never
looks like a fix. A discrepancy is settled the same way: revoke the source
that is wrong.

| Action | Who | Recorded |
|---|---|---|
| Add a manual source (`hibou release scan` with files, ADR-046) | admin or release_manager on that repository, or an automation token scoped to it | actor, time, file digests, CLI and extractor versions |
| Revoke or restore a manual source | **admin**, with a reason, from a user session (web UI or CLI browser login, ADR-043); refused for automation tokens and service principals | audit log, notification to org admins, permanent entry in the release history |
| Revoke a build-time source | nobody | — |

The auditor role is read-only, for external compliance reviewers: it sees
the full history of sources and revocations with who, when and why, and
changes nothing. Two-person approval for revocations and a formal
discrepancy-resolution workflow are specified in ADR-047 and added only when
an org needs them; the schema below leaves room for them.

### 6. Shipped or not shipped

Every component stays in the inventory and its vulnerabilities stay listed.
Being shipped or not is an **attribute**, `shipped: yes | no`, with a
filter. It never hides anything.

**Naming.** "Production" and "dev" are avoided on purpose: in npm,
`devDependencies` is a declaration that bundled frontends routinely
contradict, so "dev dependency" would mean two different things on the same
screen. **Shipped** says what matters to a vendor: does this code reach
clients? Ecosystem declarations keep their own names as labels (`declared:
devDependencies`, `declared: test scope`).

**Default: everything is shipped.** Declared scopes are unreliable as a rule.
A bundler puts npm `devDependencies` into the shipped JavaScript. `go.mod`
does not separate test-only modules. Gradle without a lockfile says nothing.
Defaulting to shipped produces noise, never a silent gap.

What `shipped` drives:

- **Uses `shipped: yes` only**: client impact (ADR-024), release gates by
  default, CRA exports (ADR-031), license policy for distribution, and the
  SBOM Hibou exports for a release.
- **Uses everything**: the Dependencies and Vulnerabilities tabs (with the
  filter), search, CVE subscriptions, malicious-package alerts.

How `shipped` is decided:

| Situation | `shipped: yes` | `shipped: no` |
|---|---|---|
| Deliverables analysed for the release (ADR-046) | What they contain, **in addition to** what the other rows already mark shipped | Unchanged: a deliverable never turns an existing component to not shipped (§5.3) |
| An SBOM is uploaded for the snapshot | What **the SBOM** lists: the team built it for clients and it reflects the real packaging | Extraction components not in the SBOM, labelled "not in uploaded SBOM" |
| Neither | All components **except** those matching the not-shipped list | Components matching the list |

When an SBOM covers only some modules (Java uploaded, TypeScript not), the
repository declares what it covers (`sbom_covers`, §8); the other modules
follow the "Neither" row. Without that declaration, the SBOM is taken as the
whole shipped product, and the UI points out undeclared modules ("`web/` is
not in the uploaded SBOM: shipped or not?") instead of guessing.

**The not-shipped list** is a maintained list of patterns, the same
mechanism for every ecosystem (Go included):

- Patterns are purl globs (`pkg:npm/@types/*`,
  `pkg:golang/github.com/stretchr/testify`), regular expressions
  (`re:^pkg:npm/eslint(-.*)?$`), or repository paths (`tools/**`, `e2e/**`:
  everything a manifest under that path declares).
- **Org list** for common tooling, inherited by every repository; **repo
  list** in `.hibou.yaml` (reviewed in a PR, versioned with the code) and in
  the UI (admins and release managers, with a reason, audit-logged, in the
  style of triage acceptance, ADR-023). The UI shows both lists and where
  each entry comes from.
- Declared scopes (`devDependencies`, Maven `test`, `[dev-dependencies]`,
  Poetry/uv groups, Gradle test configurations) are **suggestions**: "37
  components are declared dev/test: mark them as not shipped?". Accepting
  creates explicit entries. An org can opt into trusting declared scopes for
  a given ecosystem (e.g. Maven `test`); the default is off.

Safeguards:

- The counts are always side by side: **34 shipped · 54 total**.
- A pattern matching a component that an uploaded SBOM or a deliverable
  reports is ignored for that component, with a warning: the evidence says it
  ships.
- **Gates on not-shipped components** (PR gates and release gates, ADR-018,
  ADR-032), configured per repository with `dependencies.gate_not_shipped`
  (§8). The default lets dev and build dependencies through, so ordinary
  CVEs in a linter or test framework never block a PR, but still blocks what
  is dangerous wherever it runs:

  | Finding on a not-shipped component | Blocks by default | Configurable |
  |---|---|---|
  | Malicious package (`MAL-*`) | **Yes** | **No**: malware runs on developer machines and CI runners the moment it is installed |
  | Known exploited (KEV, ADR-032) | Yes | Yes, per repository (`kev`) |
  | High exploitation probability (EPSS, ADR-038) | No | Yes: `epss_min`, e.g. `0.5` |
  | Severity at or above a threshold | No | Yes: `min_severity`, optionally `fixable_only` |

  Not-shipped findings that do not block stay listed with a "not shipped"
  badge. An org can set minimums (e.g. KEV always blocks). Following
  ADR-035's resolution order, a repository can be stricter than the org but
  not looser.
- Org policy can require an SBOM or a deliverable for releases, making the
  list-based `shipped` value a fallback only.

Options considered: automatic exclusion by declared scope (marks bundled
frontend code as not shipped); separate inventories for shipped and
non-shipped code (every screen needs two lists, and a component moving
between them looks like it appeared or disappeared); dropping non-shipped
components (loses supply-chain visibility).

### 7. Security of server-side extraction

The server parses untrusted content from every onboarded repository and every
inventory submitted to it. Deliverables are analysed by the CLI (ADR-046)
and never reach the server.

- **No execution**: no build tool, interpreter or package manager on the
  server. Extractors able to execute or reach the network are disabled by an
  allowlist checked in tests.
- **No network**. `<repositories>`, `.npmrc`, `pip.conf` and similar files
  never redirect requests; this rules out SSRF and dependency confusion.
  Optional lookups (license enrichment, Maven Central SHA-1 identification)
  are operator opt-ins through approved locations (ADR-035). As with
  Dependabot's credential proxy, credentials are attached by the fetch layer
  and never reach the extractor.
- **Parser hardening**: per-file and total size limits, file counts,
  timeouts and memory caps per job; YAML alias expansion limits
  (`pnpm-lock`, `Chart.lock`); no XML external entities (`pom.xml`);
  recursion limits for includes and parent chains; no symlinks followed out
  of the checkout.
- **Tenant isolation**: same owner-binding checks as secret scanning before
  any clone; per-job temporary directories deleted after the job; no
  cross-tenant cache.
- **Resource fairness**: per-org concurrency; queue priority below
  user-triggered jobs; release backfill throttled; the stateless matching
  endpoint used by the CLI (ADR-046) rate-limited per token.

### 8. Configuration

Org settings: enable automatic extraction (default **on** once stable), eager
branch patterns, org not-shipped list, ecosystems whose declared scopes are
trusted, require lockfiles (coverage policy), gate minimums.

Repository `.hibou.yaml` (`internal/repoconfig`, schema updated):

```yaml
dependencies:
  auto: inherit          # inherit | enabled | disabled
  branches: [develop, "release/*"]  # eager, besides the default branch (§4.1.1)
  ecosystems: [maven, npm, pypi, golang, cargo, terraform]   # default: all detected
  exclude: [examples/**, testdata/**]          # not inventoried at all
  sbom_covers: [backend/**]                    # §6; omitted = whole product
  not_shipped:                                 # §6
    - "pkg:npm/@types/*"
    - "re:^pkg:npm/eslint(-.*)?$"
    - "pkg:golang/github.com/stretchr/testify"
    - "tools/**"
  gate_lockfile_indirect: count                # §1.1; count (default) | inform
  gate_not_shipped:                            # §6; malware always blocks
    kev: true                                  # default: true
    epss_min: 0.5                              # default: off
    min_severity: off                          # off | low | medium | high | critical
    fixable_only: true
```

`exclude` removes paths from the inventory (fixtures, examples).
`not_shipped` keeps components listed with `shipped: no`. As in ADR-035, org
requirements override repository choices, and exclusions that remove
required scope need an approved exception. Directory scoping mirrors
Dependabot's `directories` and Renovate's `ignorePaths`.

### 9. Infrastructure as code and CI

IaC and CI files reference versioned third-party code. That is a dependency
inventory, distinct from IaC misconfiguration scanning (a separate producer
under ADR-035).

| Source | Recorded (exact) | Declared | Value |
|---|---|---|---|
| Terraform / OpenTofu providers | `.terraform.lock.hcl` (versions and hashes) | `required_providers` constraints | Providers are Go programs: Go advisories and EOL apply; hashes give integrity |
| Terraform modules | — (`.terraform/modules/modules.json` is not committed) | `source` + `version`, git refs (`?ref=v1.2.0` or a SHA) | Pinning hygiene, outdated modules; few advisories |
| Helm charts | `Chart.lock` | `Chart.yaml` dependencies | Subchart versions; the images they deploy (§10) |
| Kubernetes / Compose / Helm values / Kustomize | Image digests | Image tags, remote bases | Links to image inventories (§10) |
| Ansible | — | `requirements.yml` collections and roles | Inventory, pinning |
| GitHub Actions, GitLab CI `include`, reusable workflows | Full commit SHA pins | Tag or branch references | CI supply chain: an action pinned by tag can change under you |

Decisions:

- Extracted with the same pipeline (§1–5); Renovate's managers show the
  formats are mostly parseable without execution.
- No separate category: each source is its own ecosystem (`terraform`,
  `helm`, `githubactions`, `oci`, `ansible`), and the existing ecosystem
  filter (`ecosystem:terraform`) already isolates them. These ecosystems are
  `shipped: no` by default through entries in the org's default not-shipped
  list, not a special rule: a software vendor does not ship its Terraform or
  CI workflows to clients. Repositories whose deliverable *is* IaC (a
  published Terraform module, a Helm chart) remove the entry in
  `.hibou.yaml`.
- Advisory coverage is thin for these ecosystems. The main value is
  inventory, pinning hygiene (unpinned module refs, actions by tag) and the
  link to container images. Hibou says so rather than implying full
  vulnerability coverage.
- purl identifiers are used where the purl specification defines a type
  (OCI images, GitHub repositories); otherwise `pkg:generic` with
  qualifiers, revisited when the spec adds types.

### 10. Containers

Source analysis cannot see OS packages or anything added at image build time
(`apt-get install`, `COPY` of downloaded binaries, base image contents).

| # | Option | Gives | Pros | Cons |
|---|---|---|---|---|
| C1 | Parse Dockerfiles / Compose / Helm / K8s statically | Base image references, digests, `apk add`/`apt-get install` lines | Cheap, runs with §4.1 | Package lines rarely carry versions; multi-stage and `ARG`-built references are ambiguous; base image contents remain unknown |
| C2 | Scan the image in CI (`hibou scan --image <ref or tar>`) with the same library | OS packages (dpkg, apk, rpm databases), language packages in layers, Go/Rust binaries, layer attribution | Accurate; the image is already local in CI; same engine | Needs a CI step; large images cost time |
| C3 | The CLI analyses an image locally for a release (`hibou release scan v1.2.3 --image <ref>`, ADR-046) | Same as C2 | Works for old releases without CI changes; the CLI uses the user's own registry credentials and uploads only the inventory | Manual, per release |
| C4 | Server pulls images from registries on demand | Same as C2 | Automatic backfill | Registry credentials stored per org, GB-sized pulls, egress, storage; the release → image digest mapping must be known |
| C5 | Ingest SBOMs attached to images: OCI referrers API, cosign/in-toto attestations, BuildKit `--sbom` attestations | Whatever the builder produced | Cheapest, accurate, no scanning | Only if the builder attaches them; trust in the attestation signer |
| C6 | Runtime inventory (admission controller, node agent) | What actually runs | Ground truth for deployments (ADR-024 §8) | A different product; out of scope |

**Direction:** C5 and C2 first, C3 through ADR-046 (which covers most of
what C4 would), C1 as metadata on the source inventory ("this repository
builds on `eclipse-temurin:21-jre`"). C4 waits for demand and needs its own
ADR for registry credentials.

Data model: an image is a distinct subject identified by its digest, linked
to the commit (`org.opencontainers.image.revision`) and to the release. Its
inventory is a separate producer, with layer attribution (base image vs
application layers), so a base image update and an application fix are
distinguishable. `internal/distro` already resolves distribution advisories.

Hard parts: distroless and scratch images without package databases (binary
analysis only), back-ported distro patches (version strings not comparable
with upstream, handled by `internal/distro`), multi-arch indexes (one
inventory per platform), and image digests that change on every rebuild
without a code change.

### 11. What we take from Dependabot and Renovate

| Source | Idea | Applied here |
|---|---|---|
| Dependabot / GitHub dependency graph | Static graph never runs builds; build-time resolution happens on CI runners (automatic dependency submission) | §1, §4.1 vs §4.2 |
| GitHub dependency submission API | Snapshot per detector + job correlator; precedence between sources; `relationship` (direct/indirect) and `scope` per package | §5 |
| Dependabot alerts | Only versions determinable from a manifest or lockfile are matched | §2.2 |
| dependabot-core | Fetcher / parser split per ecosystem; stateless job with full context; credential proxy keeping secrets out of the job | §4, §7 |
| Dependabot config | `directories` globs, per-ecosystem entries, registries declared centrally | §8 |
| Renovate | Managers matched by file patterns; extraction is parsing, not execution | §2, §9 |
| Renovate | Custom regex managers for versions in arbitrary files | Later: user-defined extraction rules for `Dockerfile ARG`, Makefiles |
| Renovate | Admin (self-hosted) options vs repository options; commands run only when an admin allows them | §7, §8 |
| Renovate | Non-package dependencies (Docker, Actions, Helm, Terraform) | §9, §10 |

Neither tool is reused as an engine (§3, E7/E8).

### 12. UX

- **Dependencies tab**:
  - Counts in the header: **34 shipped · 54 total**, and **12 direct · 30
    indirect · 12 unknown**.
  - Filters: **Shipped** (yes / no), **Relationship** (direct / indirect /
    unknown), **Origin** (CI / Hibou scan / Manual), next to the existing
    Sources and ecosystem filters.
  - Columns: shipped, relationship (with module in monorepos), resolution
    level, sources.
  - Per component, the sources view (§5): every source with its evidence
    (file and line, SBOM file, deliverable and path inside it), and its
    origin.
  - Badges explain themselves on hover: `indirect · lockfile` carries the
    library note of §1.1, `unknown` says which source could not tell,
    "unresolved" shows the declared range, "unknown license" says why (§2.3).
  - Per module, a completeness banner with the reason and the fix ("no
    lockfile: indirect dependencies unknown").
  - "Mark as not shipped" per component or module; accepting declared-scope
    suggestions (§6). The empty state of a repository without an SBOM offers
    "Extract dependencies now".
- **Vulnerabilities tab**: the same Shipped, Relationship and Origin filters;
  findings on not-shipped components carry a "not shipped" badge and stay
  listed.
- **Releases tab**: "Extract dependencies" per release, "Backfill all
  releases", the extractor version per release, "Add deliverables" (shows
  the ready-to-copy `hibou release scan` command, ADR-046), progress, and a
  "no inventory" filter. Releases with discrepancies (§5.3) carry a badge;
  the release page lists each one with both versions and their sources, and
  the sources list with revoke/restore for admins.
- **Coverage view**: the inventory producers appear like other producers,
  with partial reasons and missing lockfiles.

## Database

### Current model and why it does not scale with this ADR

- `snapshot_components (snapshot_id, component_id, labels jsonb)` stores the
  whole inventory **once per snapshot**. Provenance is a flat jsonb key set
  (`"sbom:<filename>": true`).
- `component_dependencies` stores graph edges once per snapshot, with a
  random `uuid` surrogate key and a `created_at` column that nothing reads.
  `snapshot_dependency_roots` holds one root per snapshot.
- Eighteen queries read these tables (components, CVE feed, search, licenses,
  org aggregates, scans, snapshots, tool catalog).

With automatic extraction (§4.1), every snapshot of an eager branch gets an
inventory, and per-source rows (§5) multiply that again.

### Two workloads

- **Inventories that rarely change**: most commits do not touch
  dependencies. A commit without dependency changes should cost one row.
- **Inventories that change daily**: projects with automated updates
  (Renovate, Dependabot) and large repositories without lockfiles, such as
  a multi-module Maven project that bumps dependencies daily and uploads a
  full CI SBOM of thousands of components. Each bump changes a few
  components out of thousands.

Lockfiles are not assumed anywhere below. Without one, the input digest
(§4.1) covers the manifests (every `pom.xml`); for uploaded SBOMs it covers
the canonical component rows, never the file bytes, because SBOM files carry
per-build serial numbers and timestamps.

### Options

Sizing case: a Maven repository of 3,000 components, 50 eager snapshots a
day, 5 of them with a dependency bump. A component row with its indexes is
roughly 150 bytes.

| | A. Copy per snapshot (today's model, narrowed) | B. **Whole-inventory dedupe** | C. Chunked dedupe |
|---|---|---|---|
| Idea | Every snapshot stores its full component list | An inventory is an immutable object stored once, referenced by digest; snapshots point at it | Inventory split into ~32 buckets by component name; each bucket deduplicated separately |
| Rows/day, sizing case | 50 × 3,000 = 150,000 (≈ 22 MB) | 5 × 3,000 = 15,000 (≈ 2 MB); 1 row for each of the 45 other snapshots | ≈ 5 × (3,000/32 + pulled-in changes) ≈ 1,000–2,000 |
| Rows/day, worst case (every snapshot bumps) | 150,000 | 150,000 | ≈ 10,000–15,000 |
| Who does this | Dependency-Track (per project version), GitHub dependency graph (per snapshot), GitLab, Hibou today | git trees, Docker image layers, OCI artifacts: the standard pattern for immutable content; not seen in SCA products | restic, borg, backup deduplication; not seen in SCA or inventory products |
| Complexity | None | One digest, one indirection table | Bucket hash and split threshold as format constants, chunk lists per source and per snapshot, GC per chunk |
| Per-component lookup, PR deltas | Full scan of both snapshots | Same set id: free; else merge join of two sorted sets | Only differing buckets read |
| Advisory matching | Once per snapshot | Once per distinct inventory | Once per distinct chunk |

**Decision: B.** It is the standard immutable-object pattern, removes the
per-snapshot copy that this ADR would otherwise multiply, costs one
indirection, and keeps rows immutable. Its worst case equals A, and A is
what the industry runs on: at 150,000 rows a day the hottest repository adds
about 8 GB a year **before** ADR-014 retention, which already downsamples
snapshots per ref (GFS) and enforces a per-repository storage budget; the
storage usage view (ADR-039) counts each repository's share of inventory
sets so a high-churn repository is thinned like any other instead of growing
silently. Postgres handles hundreds of millions of narrow rows with the
indexes below.

**C is the escalation, not the default.** It is adopted only if the measured
rows-per-day of real high-churn repositories (Monitoring below) stays above
what retention keeps within budget. Bucketing is a partition of the same
rows, so moving from B to C rewrites sets once and changes no row content.

### Schema

```sql
CREATE TYPE inventory_origin AS ENUM ('ci', 'repository_scan', 'manual', 'legacy');

-- An immutable list of components. Identical content = same row, via digest.
CREATE TABLE inventory_sets (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id        uuid   NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    digest        bytea  NOT NULL,          -- sha256 of the canonical sorted rows
    kind          smallint NOT NULL,        -- 1 = source set, 2 = effective set
    root_component_id uuid REFERENCES components(id),  -- replaces snapshot_dependency_roots
    -- Header counts (§12), computed by SQL from the set's own rows when the
    -- set is sealed, never by application code. Immutable afterwards.
    total_count    integer,
    shipped_count  integer,
    direct_count   integer,
    indirect_count integer,
    unknown_count  integer,
    sealed_at     timestamptz,              -- NULL while rows are being written
    created_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, digest)
);

CREATE TABLE inventory_set_components (
    set_id        bigint   NOT NULL REFERENCES inventory_sets(id) ON DELETE CASCADE,
    component_id  uuid     NOT NULL REFERENCES components(id),
    module_path   text     NOT NULL DEFAULT '',
    relationship  smallint NOT NULL,        -- 0 unknown, 1 direct, 2 indirect (§5.1)
    resolution    smallint NOT NULL,        -- 1 declared, 2 recorded, 3 artifact
    flags         smallint NOT NULL DEFAULT 0,
        -- bit 0 shipped, bit 1 discrepancy, bit 2 declared dev/test scope,
        -- bit 3 conditional (markers, os/cpu); effective sets only for 0–1
    origins       smallint NOT NULL DEFAULT 0,
        -- effective sets: bitmask of contributing origins (ci, repository_scan,
        -- manual, legacy), so the Origin filter needs no join to sources
    declared_range text,                    -- unresolved ranges (§2.2), else NULL
    evidence      text,                     -- file:line or archive!path; source sets only
    PRIMARY KEY (set_id, component_id, module_path)
);
-- "Where is component X used?" (CVE feed, search, advisory matching).
CREATE INDEX inventory_set_components_component_idx
    ON inventory_set_components (component_id, set_id);

-- Graph edges, also per set; replaces component_dependencies.
CREATE TABLE inventory_set_edges (
    set_id            bigint NOT NULL REFERENCES inventory_sets(id) ON DELETE CASCADE,
    component_id      uuid   NOT NULL,
    depends_on_id     uuid   NOT NULL,
    PRIMARY KEY (set_id, component_id, depends_on_id)
);

-- One row per piece of evidence (§5.2). Small: no component rows here.
CREATE TABLE inventory_sources (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id        uuid   NOT NULL,
    repo_id       uuid   NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    set_id        bigint NOT NULL REFERENCES inventory_sets(id),
    origin        inventory_origin NOT NULL,   -- derived server-side (§5.2)
    kind          smallint NOT NULL,           -- sbom, repository_extraction, ci_resolve, deliverable, image
    retroactive   boolean NOT NULL,
    input_digest  bytea,                       -- repository_scan reuse key (§4.1)
    extractor_version text,
    tool_name     text,
    tool_version  text,
    producer_run_id uuid REFERENCES producer_runs(id) ON DELETE SET NULL,
    artifact_id   uuid REFERENCES snapshot_artifacts(id) ON DELETE SET NULL,
    actor_user_id uuid,                        -- recorded for every origin when known
    actor_token_id uuid,
    ci_run_url    text,
    file_name     text,                        -- deliverables (ADR-046)
    file_sha256   bytea,
    file_size     bigint,
    file_metadata jsonb,                       -- what the CLI checked (ADR-046); NULL otherwise
    force_reason  text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    revoked_at    timestamptz,
    revoked_by    uuid,
    revoke_reason text,
    CHECK (revoked_at IS NULL OR origin = 'manual')   -- §5.3
);
CREATE INDEX inventory_sources_reuse_idx
    ON inventory_sources (repo_id, input_digest, extractor_version)
    WHERE origin = 'repository_scan';
CREATE INDEX inventory_sources_set_idx ON inventory_sources (set_id);

-- Which sources a snapshot has. A source is shared by the snapshots that
-- reuse it, so a commit without dependency changes writes one row here.
CREATE TABLE snapshot_inventory_sources (
    snapshot_id uuid   NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    source_id   bigint NOT NULL REFERENCES inventory_sources(id),
    PRIMARY KEY (snapshot_id, source_id)
);
CREATE INDEX snapshot_inventory_sources_source_idx ON snapshot_inventory_sources (source_id);

-- The merged inventory of a snapshot (§5, §5.1, §6).
ALTER TABLE snapshots
    ADD COLUMN inventory_set_id bigint REFERENCES inventory_sets(id),
    ADD COLUMN inventory_policy_rev integer;   -- not-shipped list revision it was computed with
CREATE INDEX snapshots_inventory_set_idx ON snapshots (inventory_set_id);
```

ADR-047 adds its approval and candidate columns to `inventory_sources` and
its own small tables; nothing here changes for it.

### As implemented (2026-10-17)

Three choices differ from the schema above, each taken after reading what
the readers of the tables need:

- **Rows keep the flat label set** (`labels jsonb`) instead of `smallint`
  codes, flag and origin bitmasks and a module column. Provenance, the
  shipping policy, the gate, coverage and the UI all consume the label
  set, and the saving that matters is the deduplication, not the row
  width. The header counts (`total_count`, `direct_count`,
  `indirect_count`) are computed from the labels when the set is sealed.
  Narrow columns remain available as a later optimisation if measured.
- **`inventory_sources` is one row per (snapshot, source)** pointing at
  the shared set, in place of a shared source plus
  `snapshot_inventory_sources`. The cost is the same (one small row per
  snapshot per source), there is one join fewer, and origin, actor,
  metadata and revocation already live on `snapshot_artifacts`
  (migration `00065`), so the file and actor columns are not duplicated.
  Sources that predate the migration carry no set (`set_id` NULL) and are
  rebuilt from the rows that carry their label when they are reused or
  when a sibling source is revoked.
- **Scan reuse is a property of the scan, not of the set.** The matches of
  a complete scan are copied to a snapshot with the same set
  (`scans.reused_from_scan_id`), so findings stay per snapshot as ADR-012
  and ADR-034 expect; identical inventories are matched once per advisory
  change rather than once ever.

Not kept: the `inventory_origin` enum (the artifact's `origin` column
serves), the policy revision on snapshots (shipped is decided on read, so
a not-shipped list change never rewrites sets), and the shipped count.

### Why this shape

**Storage.** Rows are proportional to *distinct* inventories, not to
snapshots. A branch with 1,000 snapshots and 40 dependency changes stores 40
source sets and roughly 40 effective sets, instead of 1,000 copies. A
repository that changes dependencies on most commits gains nothing over A
and relies on retention, as A does.

**Writes.**

- **Counts cannot drift.** A set is written in one transaction: insert the
  set row, `COPY` its rows, then seal it with
  `UPDATE inventory_sets SET total_count = ..., sealed_at = now()`, where the
  counts come from a `count(*) FILTER (...)` over the rows just copied. The
  database computes them, not application code. After sealing, rows and
  counts are immutable (trigger), and readers ignore unsealed sets.
- Extraction computes the canonical digest in Go first.
  `INSERT ... ON CONFLICT (org_id, digest) DO NOTHING RETURNING id` decides
  whether the rows need writing at all.
- A push that touches no recognized file is matched by
  `inventory_sources_reuse_idx` and writes one `snapshot_inventory_sources`
  row. The effective set is usually the previous one, which costs one
  `UPDATE snapshots`.
- Sets and source rows are immutable, so their pages see no updates, no
  dead tuples and no vacuum pressure. The only mutable columns are the
  revocation columns of `manual` sources and two columns on `snapshots`.

**Reads.**

| Read | Path |
|---|---|
| Dependencies tab for a ref | `snapshots.inventory_set_id` → `inventory_set_components` by primary-key prefix → `components` |
| Header counts | Columns of `inventory_sets`; filter combinations (shipped *and* direct) use `count(*) FILTER (...)` over the set's rows by primary-key prefix |
| Comparing two snapshots or a PR delta (§4.1.2) | Same `set_id` on both sides: nothing to read. Otherwise a merge join of the two sets' rows, both already sorted by primary key |
| Shipped / Relationship / Origin filters | `flags`, `relationship`, `origins` on the effective rows; no join to sources |
| "How was this detected" for one component | `snapshot_inventory_sources` → source sets, `(set_id, component_id)` primary key; loaded on demand |
| Where is component X used (CVE feed, search) | `inventory_set_components_component_idx` → `snapshots_inventory_set_idx` |
| Advisory matching | Over **distinct effective sets** of latest and pinned snapshots, not over snapshots: identical inventories are matched once |

Narrow types keep the hot table small: `bigint` identity keys (sequential,
so btree inserts stay local, unlike random `uuid`), `smallint` codes and
bitmasks instead of text and booleans, `bytea` digests (32 bytes instead of
64 hex characters), and no per-row timestamps or surrogate keys on component
and edge rows, following the reasoning of migration `00035`.

**Policy changes without mass rewrites.** Editing a not-shipped list changes
`shipped` but not the sources. Hibou recomputes the effective set eagerly
only for the latest snapshot of each eager ref and for release-pinned
snapshots, which are the ones viewed, gated and exported. Other snapshots
carry an older `inventory_policy_rev` and are recomputed on read, then
cached by pointing them at the new set.

### Lifecycle and integrity

- **Garbage collection.** Retention (ADR-014) deletes snapshots. A periodic
  instance job deletes, in small batches, the sets that no snapshot and no
  source references any more, and sources no snapshot references
  (`NOT EXISTS` probes on the indexes above). The CASCADE on
  `inventory_set_components` and `inventory_set_edges` follows.
- **Immutability is enforced in the database.** Triggers reject:
  - any `UPDATE` of `inventory_set_components` and `inventory_set_edges`,
    and of `inventory_sets` once `sealed_at` is set;
  - any `UPDATE` of `inventory_sources` other than the revocation columns of
    a `manual` row;
  - any `DELETE` of these tables unless the transaction sets
    `SET LOCAL hibou.inventory_gc = 'on'`, which only the retention and GC
    jobs and repository or organization deletion do.

  A bug or a future endpoint cannot erase CI or Hibou-scan evidence (§5.3).
- **Monitoring** (ADR-039): set count, rows per set, the reuse ratio
  (snapshots per effective set) and **rows written per day per repository**.
  A collapsing reuse ratio means something writes non-canonical rows,
  typically an SBOM generator that changes purl qualifiers on every build.
  The rows-per-day figure decides whether option C is ever needed.
- Above roughly 100 million `inventory_set_components` rows, hash
  partitioning on `set_id` keeps every hot path on one partition. It is not
  needed at first.

### Escalation path: chunked sets (option C), only if measured

If a repository's rows per day stay above budget after retention, sets can
be split without changing row content: each component goes to a bucket
chosen by a stable hash of its purl without version (`mod 32`), per module
path; modules under 512 components stay unsplit. A dependency bump then
rewrites about 1/32 of a module's rows instead of all of them.
`inventory_chunks` replaces `inventory_sets` with one row per (module,
bucket) content; `inventory_source_chunks` and `snapshot_inventory_chunks`
map a source or snapshot to its chunk list; header counts move to a
per-snapshot row computed over the chunk list. Everything else (origins,
immutability triggers, GC, sealing) is unchanged. The bucket count and
threshold are format constants, benchmarked on real high-churn repositories
before adoption.

### Migration

1. Create the tables. Backfill one effective set per snapshot from
   `snapshot_components`, deduplicated by digest, and one source row per
   SBOM artifact and extraction run, known by its label. Done in
   `00066` as one transaction: the backfill is a loop per snapshot through
   the sealing function, atomic under the migration runner; an instance
   with hundreds of millions of rows runs it in a maintenance window.
2. Replace `snapshot_components`, `component_dependencies` and
   `snapshot_dependency_roots` with **views** of the same names and columns
   over the new tables. Done in `00066`; the old tables are dropped in the
   same migration, the views are a join on the snapshot's pointer and the
   set's primary key.
3. Rewrite the queries that the views serve worse than a direct read,
   measured with `EXPLAIN (ANALYZE, BUFFERS)` on a production-sized corpus
   as `00035` was. Measured on the development corpus, every per-snapshot
   read plans as a primary-key lookup on `snapshots` followed by a
   primary-key prefix scan on the set, and every per-component read as
   the component index followed by the pointer index; none needed a
   rewrite. Advisory matching reuses prior scans per set (`00067`).

## Rollout

1. **Spike** (decides E2 vs E3): fixture corpus per ecosystem (Maven
   multi-module with parent and BOM, WAR and Spring Boot fat JAR, Gradle with
   and without lockfile, Go workspace and binary, npm / yarn Berry / pnpm /
   bun workspaces, Poetry / uv / pip-compile / unpinned requirements, Cargo
   workspace), ground truth from T4. Measure recall, precision, direct/indirect
   accuracy, dependency-tree and binary size delta, memory.
2. Storage: migration steps 1–2, `inventory_sources` with origins, triggers.
3. `internal/depinventory` with the allowlisted extractors, CycloneDX output
   into the existing SBOM ingestion, per-source provenance, relationship
   (§5.1), producer runs with partial reasons and the "no lockfile" warning.
4. Automatic extraction of the default branch and release tags with
   input-digest reuse (§4.1); eager/lazy branches (§4.1.1).
5. On-demand release extraction and backfill (§4.3).
6. `shipped` attribute, not-shipped list, origin, filters and counts (§6,
   §12); ranges as "unresolved" (§2.2); PR report (§4.1.2).
7. ADR-046 CLI, starting with `hibou release scan` of deliverables.
8. `hibou-deps` catalog entry and CI resolve mode (§4.2); extractor-upgrade
   re-extraction (§4.3.1).
9. IaC and CI dependencies (§9).
10. Containers: C5, then C2, then C1 metadata (§10).
11. Migration step 3 (query rewrites), measured.

## Consequences

- Every onboarded repository gets an inventory without a CI change. Releases
  tagged before onboarding become answerable from their lockfiles or their
  deliverables (ADR-046).
- Old releases never show today's versions: indirect dependencies come only
  from records or artifacts. Modules without a lockfile show direct
  dependencies with a warning, which pushes teams toward lockfiles.
- Java from source is usually direct-only, because Maven has no lockfile
  convention. A deliverable or a CI SBOM closes the gap.
- Extraction-only inventories mostly lack licenses (§2.3); license policy
  shows unknown rather than guessing.
- Some components stay `unknown` for direct/indirect (Gradle without graph,
  SPDX without relationships, image layers). The filter makes the gap visible
  instead of guessing.
- Defaulting everything to shipped makes the first inventories noisy until the
  not-shipped lists are maintained. Suggestions from declared scopes and an
  org-wide list reduce that work.
- Manual evidence can only add; the worst a wrong file does is add components
  and discrepancies that an admin revokes. CI and Hibou-scan evidence cannot
  be erased by anyone.
- Server load grows: one sparse clone and parse per relevant push.
- The Go dependency tree grows noticeably (E2 or E3), in the server and the
  CLI. Adding the module needs network access to the module proxy once, since
  the development module cache is offline. API churn (both pre-1.0) is
  absorbed behind `internal/depinventory`.
- New attack surface: parsing untrusted manifests on the server. §7 applies,
  and `docs/THREAT-MODEL.md` gains a section.

## Alternatives considered

- **Keep SBOM upload only** and document how to produce one per ecosystem:
  zero server risk, but leaves most repositories and all old releases empty.
  This is the status quo.
- **Re-resolve old manifests against registries** (T3) to get indirect
  dependencies without a lockfile: produces today's versions for past
  releases, and a different graph than the project's own build tool.
  Rejected (§1.1).
- **Drop indirect dependencies entirely**, even from lockfiles: no ambiguity,
  but most advisories land on indirect dependencies, and a lockfile used by
  `npm ci` or Go modules is exact. Rejected; lockfile entries are kept with
  their provenance label (§1.1), and only resolved indirect dependencies are
  rejected.
- **Origin by token type** (personal token ⇒ manual): simple to implement,
  but demotes the uploads of every pipeline that still uses a personal token
  and floods them with discrepancies. Rejected for origin by timing (§5.2).
- **Run native build tools on the server** (T4 server-side): executes
  arbitrary repository code inside Hibou's trust boundary. Rejected.
- **Forge dependency graph only** (E9): no tags, no history, forge-specific.
- **dependabot-core or Renovate as the engine** (E7, E8): footprint, runtime,
  license, and both are built for updates rather than complete inventories.
- **Own parsers for everything** (E1): duplicates maintained open-source work
  across ~30 file formats.
- **One ADR for inventory, CLI and governance**: the first draft. Too large
  to review and nothing in it shipped as a unit; split into 045/046/047.
