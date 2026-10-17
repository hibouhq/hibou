# ADR-046: Dependency CLI: local scans, release deliverables, SBOM verification

## Status

**Implemented (2026-10-16, rollout steps 1–5).** `hibou deps scan` for
directories, lockfiles, archives (jars, zips, tars, wheels, mixed
deliveries with nested archives), binaries (Go build info, cargo
auditable), SBOM files, `--git-ref` worktrees and `--image` (registry
reference or tarball), with the stateless matching endpoint
`POST /orgs/{org}/advisories/match` (purls only, audit entry), `--offline`,
table, JSON, CycloneDX-with-VEX and SARIF outputs, `--filter` and
`--fail-on` in the UI's vocabulary, and the "not identified" list; `hibou
release scan` without files (server extraction), with files or an image
(local analysis, plausibility checks against the release, preview,
confirmation, additive and idempotent recording, forced recording with a
stored reason), and `--all`; `hibou release sources` with revoke and
restore (admins in a user session only), the Releases tab's sources panel
and command; `hibou deps list`, `hibou vulns list`, `hibou deps diff`;
`hibou deps verify` offline with the integrity check and the blind-spot
notes; and from ADR-048 `hibou deps check`, `hibou deps cooldown init`,
`hibou deps not-shipped`.

**Implemented (2026-10-17, rollout step 6 and the remaining holds).** The
offline advisory database: `hibou vulns db export` writes the
organization's advisories (ranges, ratings, aliases, exploited-catalog
flag, EPSS) as one newline-delimited JSON file, audit-logged, and `hibou
deps scan --advisory-db FILE` matches against it with the server's own
version comparison and rating choice, warning when the export is older
than seven days; what the file cannot carry (VEX, not-shipped lists,
package signals) is said in the output rather than guessed. `hibou deps
verify` accepts an in-toto attestation (a DSSE envelope as `cosign attest`
writes it, or a bare statement) in place of the SBOM, verifies the
signature against a PEM public key given with `--key` (ECDSA, Ed25519,
RSA), checks the statement's subject digest against the deliverable and
exposes `--fail-on signature`; keyless signatures are reported as not
checked, since they need the Sigstore trust root. Jars without Maven
metadata are identified by SHA-1 against Maven Central with
`--maven-central`, an opt-in because a hash leaves the machine. Images:
layer attribution and the attached SBOMs of ADR-045 §10 are read by
`deps scan --image` and `release scan --image` (`--no-attached-sbom` to
skip the registry lookups).


Proposed (2026-10-15). Second of three related ADRs; depends on
[ADR-045](045-built-in-dependency-inventory.md) for the data model (sources,
origins, shipped, relationship) and the extraction library. Approval
workflows around what this CLI records are in
[ADR-047](047-inventory-evidence-governance.md).

## Context

ADR-045 gives the server a dependency inventory from repository content. Four
needs remain that a server cannot meet on its own:

1. **Look before storing.** Developers want to see the dependencies and
   vulnerabilities of a directory, an old tag, a WAR or an image the way
   `trivy fs|image` shows them, without creating anything in Hibou.
2. **Old releases without lockfiles.** For a tag whose build no longer
   exists, the delivered artifact is the only reliable source of indirect
   dependencies (ADR-045 §1.1). Those artifacts are hundreds of MB to several
   GB, proprietary, and often only reachable from the customer's network.
   Uploading them to Hibou is the wrong shape.
3. **Mistakes on existing releases.** A release may already have components
   from its lockfile or a CI SBOM; attaching the wrong file to it must not
   damage that.
4. **Trust but verify.** A client receiving software, or a vendor before
   shipping, wants to check that an SBOM really describes the deliverable.

Existing CLI conventions: `hibou upload`, `hibou gate`, `hibou scan`
(ADR-035), `hibou secret-scan` (checks without persisting, ADR-010), `hibou
release list|deploy` (ADR-024), common flags `--org --repo --server --token`
auto-detected from CI and `hibou config set-org`.

## Decision

### 1. The noun says where results go

- `hibou deps ...` works on whatever you point it at and **never writes** to
  Hibou.
- `hibou release ...` works on a release (the noun already exists) and
  **records** on that release.

| Question | Command | Writes to Hibou |
|---|---|---|
| What is in this, and is it vulnerable? (a directory, an old tag, a WAR, a zip, an image) | `hibou deps scan` | **Never** |
| What does Hibou know about this branch, tag, release or PR? | `hibou deps list`, `hibou vulns list`, `hibou deps diff` | Never |
| Does this SBOM really describe this deliverable? | `hibou deps verify` | Never; works without a server |
| Scan release v1.2.3 and keep the result on it | `hibou release scan v1.2.3 [FILES...]` | Yes, additive, with confirmation |

Both commands that scan are called `scan`; the noun in front tells whether the
result is kept. The same split exists elsewhere: Snyk separates `test`
(check) from `monitor` (record), `trivy` scans without a server, and
`hibou secret-scan` checks without persisting. Writing is never a flag added
to a read-only command: forgetting or adding one flag must not change whether
data is stored.

### 2. `hibou deps scan`: local analysis, nothing stored

```text
hibou deps scan [TARGET...] [--image REF|TAR] [--git-ref TAG|BRANCH|SHA]
```

- **Targets**, auto-detected: a directory (default `.`), a lockfile or
  manifest, an archive (JAR/WAR/EAR, zip, tar), a binary, an SBOM file;
  `--image` for a local or remote image (user's own registry credentials);
  `--git-ref v1.2.3` checks the tag out of the local clone into a temporary
  worktree, so an old release can be inspected without touching the working
  copy.
- **Extraction** runs locally with the same library and rules as the server
  (ADR-045 §1–2, §5.1): same relationship, same "no lockfile" warnings, same
  `unknown` values.
- **Matching** uses a stateless server endpoint,
  `POST /orgs/{provider}/{slug}/advisories/match`, which receives purls and
  versions only, never file contents, and persists nothing beyond an audit
  entry (who, when, how many purls). This gives the org's advisory sources,
  KEV, EPSS and malicious-package data, and, when `--repo` is given or
  inferred from the git remote, the repository's triage decisions, VEX
  statements and not-shipped list, read-only.
- **`--offline`**: inventory only, no vulnerabilities. **`--advisory-db
  FILE`**: fully offline matching against a database exported from the
  server with `hibou vulns db export` (the organization's advisory view,
  no repository data), the counterpart of the ADR-035 offline bundles;
  querying public OSV.dev directly from the CLI is rejected because it
  bypasses org triage, VEX and egress policy.
- **Output**: a table on a terminal; `--format json|cyclonedx|sarif`.
  `cyclonedx` includes vulnerabilities as CycloneDX VEX, so the output is a
  valid SBOM that `hibou upload` accepts later.
- **Filters** use the UI's filter expressions (ADR-013) and vocabulary:
  `--filter 'severity:high shipped:yes relationship:direct'`, plus shortcuts
  `--severity`, `--kev`, `--fixable`.
- **Exit codes**: `0` by default, whatever is found; `--fail-on <filter>`
  returns `1` when something matches; `2` on errors. Like `hibou gate`, it
  never breaks a build unless asked.

```text
hibou deps scan                                   # this working tree
hibou deps scan --git-ref v1.2.3                  # an old tag from the local clone
hibou deps scan dist/app.war --repo api --release v1.2.3   # a deliverable, in that release's triage context (read-only)
hibou deps scan --image registry.example/app:1.2.3 --format cyclonedx > app.cdx.json
hibou deps scan --fail-on 'severity:critical shipped:yes'  # CI check without storing
```

### 3. Reading stored data

```text
hibou deps list  --repo api (--ref main | --tag v1.2.3 | --release v1.2.3 | --pr 42) [--filter ...]
hibou vulns list --repo api (--ref main | --tag v1.2.3 | --release v1.2.3 | --pr 42) [--filter ...]
hibou deps diff  --repo api v1.2.3 v1.3.0         # comparison of ADR-016
```

They read the existing per-ref endpoints (`.../components`,
`.../vulnerabilities`): the same data, filters and triage states as the web
UI, with the same output formats and exit codes as `scan`. `vulns list`
covers all producers (SCA, SAST, secrets), not only dependencies. Reading a
lazy branch (ADR-045 §4.1.1) triggers its extraction and reports "computing"
until it is done. `hibou release list` keeps its role as the release
overview.

### 4. `hibou release scan`: scanning a release and keeping the result

```text
hibou release scan v1.2.3                                   # no files: the server extracts from the tag (ADR-045 §4.3)
hibou release scan v1.2.3 dist/app.war --image REF [--yes] [--reason TEXT]   # files: analysed locally, recorded on the release
hibou release scan --all                                    # every release without an inventory
```

Without files, the command asks the server to extract the tag's lockfiles and
manifests, the same as the Releases tab button. With files or `--image`, the
CLI analyses them locally and records the inventory on the release. The
output always says which happens ("Analysing tag v1.2.3 on the server" /
"Analysing 2 files locally"). The rest of this section covers the files
case.

#### 4.1 Why the CLI analyses deliverables, not the server

| | CLI, local (chosen) | Upload to the server (rejected) |
|---|---|---|
| Transfer | A few KB of inventory | The whole file (hundreds of MB, GB for images) |
| Confidentiality | Binaries never leave the client's network (regulated environments, ADR-041) | Hibou receives proprietary binaries |
| Registry credentials | The user's own; Hibou stores none | Hibou would need them |
| Server load and attack surface | None: untrusted archives are parsed on the client | Archive parsing on workers, storage and retention rules for the files |
| Trust | Same as any SBOM upload: Hibou trusts the client's output. The source records the CLI and extractor versions and the file digests | Hibou computes everything itself |
| Who can use it | Needs the CLI and a token | Anyone with the release manager role, from the browser |
| Extractor version | The CLI's; an outdated CLI gets the version-mismatch error of `hibou scan` | Always the server's |

The browser's convenience does not outweigh moving GB-sized proprietary
binaries into Hibou. The Releases tab's "Add deliverables" shows the
ready-to-copy command with org, repository and release filled in.

#### 4.2 What a deliverable yields

| Deliverable | What it yields | Limits |
|---|---|---|
| JAR / WAR / EAR, Spring Boot fat JAR | Nested jars (`WEB-INF/lib`, `BOOT-INF/lib`) identified by `META-INF/maven/**/pom.properties` and manifests: the full shipped set, indirect included | Shaded/relocated classes may lose `pom.properties`. Identification by SHA-1 against Maven Central is a network lookup, operator opt-in only |
| Go binary | Build info: main module, every module and version, Go toolchain | Exact. Stripping symbols does not remove build info; `-trimpath` keeps versions |
| Rust binary | Full set when built with `cargo auditable` | Nothing otherwise |
| Python wheel, virtualenv or `site-packages` archive | `*.dist-info/METADATA` of every installed package | A single wheel only lists its own `Requires-Dist` ranges |
| `node_modules` archive, npm tarball with lockfile | Installed packages with exact versions | A minified bundle (webpack, Vite output) carries no package identity; license banners or source maps are partial hints only |
| Container image (`docker save` / OCI layout tar, or a reference) | OS packages and language packages in every layer (ADR-045 §10) | Size; distroless images rely on binary analysis |
| Source archive (zip/tar of the tag) | Same as lockfile/manifest extraction on the tag | For tags no longer on the forge |
| **Any archive with arbitrary content** (zip, tar, tar.gz) | Everything above, wherever it sits in the tree | See below |

**Mixed archives.** Following the model of commercial binary scanners such as
Veracode, the user can pass one zip containing whatever makes up the
delivery: JARs next to Go binaries, a `node_modules` folder, lockfiles,
wheels, nested zips, documentation, configuration. No layout is required.

- The CLI walks the archive recursively: every file and every nested archive
  (zip, jar, war, ear, tar, tgz, whl, nupkg) is offered to every allowlisted
  extractor, within the nesting-depth and size limits of §7.
- Each component found records its path inside the archive
  (`delivery.zip!/lib/app.war!/WEB-INF/lib/jackson-databind-2.15.2.jar`).
- **Nothing is silently ignored.** Files no extractor recognizes are listed
  as **not identified**, with path, size and detected type: a `.dll`, an
  `.so`, a JAR without Maven metadata, a minified bundle. The summary says
  "1,284 files, 212 components identified, 37 binary files not identified",
  so the coverage of the analysis is visible, as ADR-034 requires for any
  producer.
- Unidentified native libraries stay unidentified; that is a known limit,
  not a clean result.
- A packaging guide in the docs lists, per ecosystem, what to put in the
  archive for the best result (the built JAR or WAR rather than classes, Go
  binaries built with module mode, `cargo auditable` builds, the lockfile
  next to a JavaScript bundle).

Properties of what is recorded:

- Components from a deliverable have the `artifact` resolution level, the
  highest, and are **shipped by definition** (ADR-045 §6). A WAR does not
  contain jest, so the "is this shipped?" question does not arise.
- Several deliverables for one release form its shipped set together (a
  backend WAR plus a frontend image). Each stays a separate source with its
  file name and sha256.
- The source's origin is `manual` (ADR-045 §5.2), so it is additive only
  and revocable; Hibou stores the digest, size, name and derived inventory,
  never the file.

#### 4.3 Safeguards against the wrong file

A release may already have components from a lockfile, a CI SBOM or an
earlier scan, and people make mistakes: the WAR of another version, the
`latest` image instead of `1.2.3`, the same file twice.

1. **Additive, never overwriting** (ADR-045 §5.3). A release scan adds one
   source per file, with its sha256, who ran it, when, and the CLI and
   extractor versions. Existing sources are never replaced or edited, and
   existing components keep their version, relationship and shipped status.
   The worst a wrong file can do is add components and discrepancies; it
   cannot hide a CVE.
2. **Bound to the commit, not the tag name.** The release resolves to its
   commit at scan time. If the tag is later moved (ADR-024 divergence), the
   source stays with the commit it was made for.
3. **Plausibility checks before sending**, from metadata inside the files:

   | Deliverable | Checked against the release |
   |---|---|
   | Go binary | `vcs.revision` in the build info = the release commit; main module version = tag |
   | JAR / WAR | `Implementation-Version` / main `pom.properties` version = release version |
   | Image | `org.opencontainers.image.revision` / `.version` labels = commit / version |
   | npm tarball, wheel | Package version = release version |

   A mismatch stops the scan with the values found. `--force --reason ...`
   overrides it, and the reason is stored with the source. When the file
   carries no metadata, the CLI warns that the check was not possible.
4. **Preview and confirmation.** The CLI shows what the release already has
   and the effect of recording:

   ```text
   Release v1.2.3 (commit 3f9c2e1) already has:
     pnpm-lock.yaml (Hibou scan)  412 components
     sbom.cdx.json (CI, 2025-03-02)  96 components
   Scanned dist/app.war locally (sha256 9b1e…, Implementation-Version 1.2.3):
     + 31 components not known for this release
     ~ 4 components at a different version than recorded (e.g. jackson-databind 2.15.2 → 2.13.0)
     = 61 already known
   Effect on the release: +3 CVEs, 4 discrepancies, nothing removed
   Record on release v1.2.3? [y/N]
   ```

   Version differences against existing sources are the typical sign of a
   wrong file and become discrepancies if recorded. `--yes` skips the prompt
   for automation; the checks of point 3 still apply.
5. **Idempotent.** A file whose sha256 is already a source of the release is
   a no-op, reported as such.
6. **Retroactive evidence is labelled.** A source recorded after the release
   date shows "added on <date>, after the release", unlike sources recorded
   by the build itself.
7. **Reversible by revocation**, by an admin with a reason, audit-logged
   (ADR-045 §5.3): `hibou release sources revoke v1.2.3 <source-id> --reason
   ...`, `hibou release sources restore ...`. Build-time sources cannot be
   revoked by anyone. ADR-047 adds two-person approval in front of
   revocation for orgs that want it.
8. **Permissions.** Adding a source needs the admin or release_manager role
   on that repository, or an automation token scoped to it (ADR-020).
   Revocation needs an admin in a user session (web UI or CLI browser login,
   ADR-043) and is refused for automation tokens and service principals.

Checks 3 and 4 need the files, so they run in the CLI. The CLI sends the
metadata it checked (versions, revisions, digests) with the inventory; the
server stores it with the source and repeats checks 2, 5, 7 and 8 itself.

### 5. `hibou deps verify`: does an SBOM match the deliverable?

```text
hibou deps verify dist/app.war --sbom vendor-app-1.2.3.cdx.json [--format ...] [--fail-on undeclared]
```

Compares what the CLI finds inside a deliverable with what an SBOM declares.
It runs **fully offline, with no Hibou server or account**: only the CLI
binary, the file and the SBOM.

Two users:

- **A client receiving software**: checks that the vendor's SBOM describes
  what was actually delivered, and that nothing was left out. This matters
  more as SBOMs become contractual and regulatory deliverables (CRA,
  ADR-031).
- **The vendor itself, in CI before release**: checks that its own SBOM is
  complete before handing it to clients. With `--fail-on undeclared`, it
  works as a release gate.

| Category | Meaning | Strength of the evidence |
|---|---|---|
| **Undeclared** | Found in the deliverable, absent from the SBOM | Strong: the code is there. This is the "SBOM omits a dependency" case |
| **Version mismatch** | Same component, different version | Strong when the deliverable's metadata is exact (Go build info, `pom.properties`) |
| **Not found** | Declared in the SBOM, not found in the deliverable | Weak: extraction has known blind spots (shaded jars, minified JavaScript, stripped Rust binaries). Reported with the blind spot that applies, never as a lie |
| **Matched** | Same component and version | |
| **Integrity** | The file's sha256 against the SBOM's `metadata.component.hashes`, when present | Strong |

Exit codes follow §2: `0` by default, `1` when `--fail-on` matches
(`undeclared`, `mismatch`, `integrity`), `2` on errors.

Hibou's own exported release SBOMs include the deliverables' digests recorded
by `hibou release scan`, so a client can verify a Hibou-produced SBOM the same
way. `--sbom` also takes an in-toto attestation (a DSSE envelope or a bare
statement) and `--key` verifies its signature against the signer's public
key; the statement's subject digest is the integrity check. Keyless
(Fulcio and Rekor) verification is not done: without a key, `verify` says
what the attestation claims, not who signed it.

### 6. Every UI action has a CLI equivalent

| UI | CLI |
|---|---|
| Releases tab, "Extract dependencies" | `hibou release scan v1.2.3` (no files) |
| "Backfill all releases" | `hibou release scan --all` |
| "Add deliverables" | `hibou release scan v1.2.3 dist/app.war ...` |
| "Mark as not shipped" | edit `.hibou.yaml`, or `hibou deps not-shipped add 'pkg:npm/@types/*' --repo api --reason ...` |
| Sources of a release, revoke, restore | `hibou release sources v1.2.3`, `hibou release sources revoke|restore v1.2.3 <source-id>` |

Common flags are those of `upload` and `gate` (`--org`, `--repo`,
`--server`, `--token`), auto-detected from CI and from `hibou config
set-org`. The repository is also inferred from the git remote of the current
directory.

### 7. Security of local extraction

The CLI parses untrusted archives on the user's machine with the same
hardening the server applies to manifests (ADR-045 §7): archive size, entry
count and nesting depth limits (zip bombs, nested jars), zip-slip path
checks, no execution of anything inside, no symlinks followed out of the
extraction root, timeouts. Extractors that execute code or reach the network
are not compiled into the CLI either; `--image` pulls use the user's own
Docker/containerd credentials and nothing else.

## Rollout

1. `hibou deps scan` for directories and `--git-ref`, with the stateless
   matching endpoint and `--offline`.
2. Archives, binaries and images in `deps scan`; mixed archives.
3. `hibou release scan` with files: plausibility checks, preview, additive
   recording; `release sources` list/revoke/restore; Releases tab command.
4. `hibou deps list`, `hibou vulns list`, `hibou deps diff`.
5. `hibou deps verify`.
6. Offline advisory database (later, with the ADR-035 bundle mechanism).

## Consequences

- Deliverables never reach the server; Hibou stores digests and inventories.
  Users without the CLI cannot add deliverables from the browser.
- The CLI binary grows with the extraction library (shared with the server,
  ADR-045).
- Hibou trusts the CLI's output for deliverables, as it already trusts
  uploaded SBOMs. The recorded CLI and extractor versions and file digests
  make a scan reproducible by whoever has the file.
- A wrong file adds noise an admin revokes; it never removes a CVE.
- `deps verify` makes Hibou's own exported SBOMs checkable by clients, which
  raises the bar for their completeness.

## Alternatives considered

- **Upload deliverables to the server** (browser or API): no CLI needed,
  Hibou computes everything itself, but it moves GB-sized proprietary
  binaries and registry credentials into Hibou and adds archive parsing,
  storage and retention on the server (§4.1).
- **A `--record` flag on `deps scan`** instead of a separate command: one
  flag between a read and a write to a shipped release. Rejected (§1).
- **One `submit` verb**: did not say that it scans; renamed to `release
  scan`.
- **Querying OSV.dev from the CLI** for offline users: bypasses org
  advisory sources, triage, VEX and egress policy (§2).
- **A separate binary for client-side verification**: more to distribute;
  `deps verify` needs no account, so the same binary serves clients.
