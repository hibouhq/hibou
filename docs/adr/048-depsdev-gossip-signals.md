# ADR-048: deps.dev GOSSIP signals (cooldown, deprecation, low usage, recommended versions)

## Status

Proposed (2026-10-15). Implementation started 2026-10-16.

**Implemented (2026-10-16, rollout steps 1–5 in part):** the deps.dev
client with batch lookups, retries and fixtures; the `package_signals`
table, the daily leader-locked refresh over the inventory's distinct
versions, private namespaces (`depsdev.private_namespaces` and the
repository's `dependencies.private_namespaces`), the source health card
(§6); the Dependencies tab icons and Signal filter, the finding drawer's
signal facts and suggested version, the policy verdict on every
remediation target so a fix still in cooldown is marked before anyone
bumps to it, and the same icons on the vulnerability list (§8); the
package policy evaluator with single-flight on-demand lookups, the policy
endpoint and acceptances (§3); the PR dependency delta and cooldown gate
with the "fixes a resolved finding" exemption, `enforcement`
inherit/advisory/blocking, and the self-expiring recompute at cooldown end
(§3); install-time cooldown verification for npm, pnpm, Yarn, Bun, uv and
pip, the Renovate and Dependabot cooldown, the per-module status in the
Dependencies tab, and `install_config: require | warn | off` in the gate
(§3.1); MCP `check_packages` with its skill (§7); signal tags on the LSP
manifest diagnostics (§8).

**Implemented (2026-10-16, second increment, rollout steps 4b–6):** the
install-config generator `hibou deps cooldown init` for npm, pnpm, Yarn,
Bun, uv, pip and the Renovate or Dependabot cooldown, idempotent and
verified by the detector; the CI pre-install step `hibou deps check`
(every version the lockfiles declare asked of the policy before anything
is installed) and the `hibou-deps-check` composite action (§3.1);
organization-level policy (window, enforcement, install_config, private
namespaces, trusted declared scopes) in the organization settings with a
settings page, applied under the repository's `.hibou.yaml`, which can
only tighten (§3); the CLI column: `hibou deps scan` shows cooldown,
deprecation and the policy verdict per component and `--fail-on
'cooldown:true'` fails the build (§8, with ADR-046); the stateless match
endpoint returns the signals and the verdict (§7). The reference
Artifactory user plugin exists in its own repository
(`hibou-artifactory-plugin`, nested here as `hibou-artifactory-plugin/` while
developed, ignored by this repository's git): the Java core (decision
cache, circuit breaker, pre-filter, purl mapper, packument filter, policy
client), the Groovy adapter with `beforeDownload`, `altResponse` and the
reload, status and metrics executions, unit tests of the safety budget,
the bench compose file and the compatibility script; its CI builds and
tests it on GitHub and `v0.1.0-alpha.1` is published as a pre-release with
the jar, the Groovy adapter and the example properties. **Not yet:** the
plugin has not run against an Artifactory, so the bench numbers of
§3.1.1 are not recorded and the alpha stays an alpha; packument filtering
and the download backstop are untested outside the unit tests. This is
the one item of ADR-045, ADR-046 and ADR-048 that needs an environment
this repository does not have.

Builds on the dependency inventory ([ADR-045](045-built-in-dependency-inventory.md)),
the malware block and exploited-catalog gate
([ADR-032](032-kev-catalog-and-exploited-gate.md)), the EPSS mirror
([ADR-038](038-cvss-and-epss-risk-metrics.md)), "absence is not resolution"
([ADR-034](034-absence-is-not-resolution.md)), the offline modes of
[ADR-035](035-bundled-scanners-and-coverage-policy.md), triage acceptances
([ADR-023](023-triage-acceptance-ux.md)), the forge-native gate
([ADR-018](018-forge-native-quality-gate-checks.md)), the IDE and MCP
surfaces ([ADR-042](042-ide-extensions.md)) and the regulated-environment
contract ([ADR-041](041-regulated-environments-replacing-veracode.md)).
The dependency CLI ([ADR-046](046-dependency-cli.md)) is referenced where
the signals reach it; [ADR-047](047-inventory-evidence-governance.md)
(inventory evidence governance, deferred) is not affected.

## Summary

**Yes, with a narrow scope.** deps.dev's GOSSIP findings are worth consuming
as an *enrichment* of the inventory, for four things Hibou cannot produce
itself today: a release **cooldown** per version, registry **deprecation**
with its reason, **low-usage / look-alike** detection, and a **recommended
version**. They are not worth consuming for malicious or vulnerable versions,
which Hibou already gets from the same upstream sources with more context.
The signals become attributes of components, never vulnerabilities, and the
one that can gate (cooldown) is delta-scoped like every other Hibou gate.
The gate blocks the merge, not the download: a fresh version is fetched, and
its install scripts run, on the developer's machine and on CI before any
server-side check sees the lockfile. Stopping the download has to happen
where it happens, so the ADR also makes Hibou verify and generate the
package-manager cooldown settings each repository commits (§3.1), gives
registry proxies a policy endpoint, and puts a lockfile-only CLI check first
in CI.

The constraints that shape the design: the API is `v3alpha`, has no bulk
export and cannot be mirrored, so it is unavailable offline; it returns
`NOT_FOUND` at critical risk for anything not on a public registry, so
private packages must never be sent; and it covers seven ecosystems only.

## Context

### What GOSSIP is

On 2026-06-09 Open Source Insights (deps.dev, Google) announced **GOSSIP**
(Google Open Source Security Intelligence Platform) signals in its public
API: per-package and per-version *findings* that Google already uses
internally ("including powering security integrations for Antigravity").
The post gives qualitative criteria only; the API documentation and live
probes (2026-10-15) give the rest.

| Finding `type` | What it means | Observed example (2026-10-15) | Risk |
|---|---|---|---|
| `COOLDOWN` | The version was published recently; deps.dev recommends waiting until `cooldownContext.end`. Shortened for critical patches (`PATCH_VERSION`), infinite for malicious versions | `express@5.3.0`, published 2026-10-09, cooldown until 2026-10-24 | `RISK_HIGH` |
| `MALICIOUS` | Flagged by the OpenSSF Malicious Packages project (the same source as OSV `MAL-*`) | `lodahs` (npm typosquat of lodash): `MALICIOUS` plus `COOLDOWN` ending `9999-01-01` | `RISK_CRITICAL` |
| `VULNERABLE` | Affected by a **critical** advisory. A high one does not trigger it | `log4j-core@2.14.1`: yes. `lodash@4.17.20` (CVE-2021-23337, high): no finding | `RISK_CRITICAL` |
| `DEPRECATED` | Deprecated on the registry or archived upstream, with the registry's reason | `request@2.88.2`, `github.com/golang/protobuf` ("Use google.golang.org/protobuf"), `loadsh` ("This is a typosquat on the popular Lodash package") | `RISK_MEDIUM` |
| `LOW_USAGE` | Suspiciously low usage, especially when the name resembles a popular package; may carry `lowUsageContext.alternativePackages`. The post calls it "a broad-strokes preventative measure to encourage extra verification" | `lodash-es-utils` | `RISK_HIGH` |
| `NOT_FOUND` | The package or version is not on the public registry: unpublished (often a malware takedown), renamed, or **private** | `@ctrl/tinycolor@4.1.1` (Shai-Hulud, unpublished); also any `@acme-internal/billing` that never existed publicly | `RISK_CRITICAL` |
| `REMEDIATION` | Listed in the enum; not observed and not documented | | |

The response also carries `recommendedVersions[]` ("a set of low risk
versions recommended for use") and `defaultVersion`, each with their own
findings and `cooldownEnd`, and `packageFindings[]` for findings that apply
to every version.

**Cooldown windows** are not published. Measured from `publishedAt` to
`cooldown.end` on current releases:

| Ecosystem | Window observed |
|---|---|
| npm | 15 days |
| Maven, Go, Cargo | 10 days |
| PyPI | 5 days |

The post says the length is adjusted "based on a number of factors"
(ecosystem, metadata, vulnerabilities, patch information), so these values
are a snapshot, not a contract.

**API facts.** `GET /v3alpha/systems/{system}/packages/{name}[/versions/{v}]:findings`
and `POST /v3alpha/findingsbatch` (up to 5,000 requests, paginated). Systems:
`NPM`, `PYPI`, `MAVEN`, `GO`, `CARGO`, `NUGET`, `RUBYGEMS`; no OS packages,
no Terraform, Helm, Actions or OCI (ADR-045 §9–10). No API key. Responses
are `cache-control: public, max-age=3600` and the terms state "Clients are
expressly permitted to cache data served by the API"; use is under the
Google API Terms of Service, generated data under CC-BY 4.0. Rate limits are
not published. `v3alpha` carries no stability promise. There is no bulk
download of findings (the BigQuery dataset does not include them), so unlike
KEV, EPSS or OSV, this source **cannot be mirrored for an air-gapped
instance**.

Google also publishes a `SKILL.md` (`examples/skills/scan-dependencies`) that
tells coding agents to call `findingsbatch` "BEFORE any new package is
imported or added to dependencies". It sends package names straight to
Google, has no notion of private registries, and leaves the agent to decide
what blocks.

### What Hibou has today

| Signal | Hibou today |
|---|---|
| Malicious package | `MAL-*` from OSV, severity floored to critical, blocks every gate, dedicated `malware.detected` notification (ADR-032 precedent) |
| Vulnerable version | Full matching, all severities, CVSS and EPSS (ADR-038), KEV (ADR-032), triage and VEX (ADR-023), delta-scoped gates (ADR-018) |
| Release cooldown | **Nothing in Hibou.** The Renovate preset waits 3 days (`minimumReleaseAge`), which covers Renovate's PRs only: a manual bump, `npm install foo` by a developer, or a dependency added by a coding agent goes through unchecked |
| Deprecated / archived | Nothing |
| Low usage, look-alike names | Nothing (no popularity data) |
| Recommended upgrade | Fixed versions derived from advisories only |
| Unpublished version | Nothing, unless OSV has a `MAL-*` record |

### Why cooldown matters now

The 2025 npm compromises (`chalk`/`debug` in September, the Shai-Hulud worm
through `@ctrl/tinycolor` and hundreds of packages, the `nx` incident in
August) were live on the registry for hours to a couple of days before
takedown. Package managers answered with the same control: pnpm's
`minimumReleaseAge`, Dependabot's cooldown, Renovate's `minimumReleaseAge`.
Hibou gates pull requests, so it is the natural place to enforce the control
for every PR that bumps or adds a dependency, whoever authored it, and to
report it on the inventory of a release. Coding agents make this more urgent:
they add dependencies at a rate no reviewer follows, and they hallucinate
package names that squatters register ("slopsquatting"), which is what
`LOW_USAGE` and `NOT_FOUND` catch.

## Decision

### 1. What is taken from GOSSIP, and what is not

| Finding | Decision | Why |
|---|---|---|
| `COOLDOWN` | **Used.** Stored per version; drives the cooldown gate (§3) | Nothing else in Hibou provides it |
| `DEPRECATED` + reason | **Used.** Component attribute, informational | Migration planning; CRA Art. 13(5) due diligence (ADR-031). Not a gate: a deprecation is not a defect |
| `LOW_USAGE` + alternatives | **Used.** Component attribute, warns on PR-introduced packages | Typosquat and slopsquat defence; the alternatives are the actionable part |
| `NOT_FOUND` | **Used with care** (§4) | Unpublished versions are a strong signal; private packages make it a false positive |
| `recommendedVersions` | **Used** as "suggested version", labelled with its source | Better than nothing when no fixed version is known; never auto-applied |
| `MALICIOUS` | **Not a finding.** Cross-check only | Same upstream as Hibou's `MAL-*`; a second copy would double-count. If deps.dev flags a version OSV has not, a log line and a metric record the discrepancy for the OSV sync, nothing more |
| `VULNERABLE` | **Ignored** | Critical-only subset of what Hibou already matches, without triage, VEX, KEV or EPSS |
| `REMEDIATION` | Stored raw, not interpreted | Undocumented |
| `risk` | Stored, not mapped to Hibou severity | Hibou severity is for vulnerabilities (ADR-038). Signals have their own vocabulary |

### 2. Signals are component attributes, not vulnerabilities

A deprecation or a cooldown is a fact about a package version, not a weakness
in it. Modelling them as vulnerabilities would pollute severity counts,
compliance exports, SLAs and the advisory timeline with things that are not
advisories.

Storage: one row per `(system, name, version)` in `package_signals`, with
`published_at`, `cooldown_end`, `deprecated`, `deprecated_reason`,
`low_usage`, `alternatives[]`, `not_found`, `recommended_version`,
`raw` (the full finding list, for forward compatibility with `v3alpha`
changes), `source = 'depsdev'`, `fetched_at`. Components join on purl. No
per-repository data leaves the join: the same `lodash@4.17.20` row serves
every repository on the instance.

Visible wherever a component is: the Dependencies tab (badges and filters
`signal:cooldown`, `signal:deprecated`, `signal:low-usage`,
`signal:not-found`, `signal:none`), the component sources view of ADR-045
§5, the finding detail of a vulnerability on that component, the Releases
tab (counts per release), `hibou deps list` and `hibou deps scan`
(ADR-046), the LSP diagnostics on manifest lines (ADR-042) and the MCP server
(§7).

### 3. The cooldown gate

**Scope: what the PR introduces.** A gate evaluates the versions the PR adds
or changes (the dependency delta of ADR-045 §4.1.2) and reports those whose
cooldown has not ended. Existing components in cooldown are listed on the
Dependencies tab but never block, for the reason ADR-032 gives: a portfolio
gate would fail every estate at once.

**Policy**, org-level with the ADR-035 resolution order (a repository can be
stricter, not looser):

```yaml
dependencies:
  cooldown:
    window: auto          # auto (deps.dev's end) | 7d | off
    enforcement: inherit  # inherit (the gate's enforcement) | advisory | blocking
    install_config: require   # require | warn | off  (§3.1)
```

- `auto` uses `cooldown_end` as deps.dev computes it, including its
  shortening for patches and its infinite value for malicious versions. A
  fixed `window` uses `published_at + window` instead, for orgs that want a
  number they can write in a policy document. Both are evaluated locally from
  stored timestamps, so the state changes at the right moment without a new
  API call.
- **A version that fixes an open finding in that repository is never
  blocked by cooldown.** Otherwise the cooldown would fight the remediation
  SLAs of ADR-041 and the "fix available" workflow. The PR comment says so:
  "in cooldown until 2026-10-24, allowed because it fixes CVE-2026-1234".
- **Self-expiring.** The check is re-evaluated when the cooldown ends (a
  scheduled re-run of the gate, the same mechanism as a triage change
  re-publishing the check, ADR-018), so a PR blocked on Monday turns green on
  its own without a push.
- **Bypass is a triage acceptance** (ADR-023) with a reason, on the component
  version, audit-logged. No new mechanism.
- **Enforcement** follows the quality gate's `enforcement`, advisory by
  default like every Hibou gate; an org that wants the control to bite sets
  `blocking`. The malicious case is already blocking through `MAL-*`
  regardless.

Renovate's 3-day wait stays in the preset: it keeps Renovate from proposing
too-fresh versions in the first place; the gate catches everything Renovate
does not author.

#### 3.1 Enforcing before the download

The gate reads the lockfile after the push. By then `npm install` has run on
the developer's machine, and CI has run `npm ci` on a runner with secrets:
the version is downloaded and its lifecycle scripts have executed. The 2025
npm worms did their damage in `postinstall`, so a merge block arrives after
the harm. Hibou cannot stop the forge from starting CI on a push. What it
can do is make sure the control exists at each place a download happens,
ordered from earliest to last resort:

| Layer | Where the download is refused | Covers | Hibou's role |
|---|---|---|---|
| **Editor and agent** | Before the version is even written: LSP diagnostic on the manifest line (ADR-042), MCP `check_packages` (§7) | Developers using the extension, agents using the MCP | Provides the signal |
| **Package manager** | On the machine running the install, from a setting committed in the repository | npm, pnpm, Yarn, Bun, uv, pip | **Verifies the setting is present and matches the org window; generates it** |
| **Registry proxy** | At the org's Artifactory, Nexus or equivalent, for every ecosystem | Everything the proxy serves, incl. Maven, Go, Cargo, NuGet | Provides a policy endpoint and a reference Artifactory user plugin; no Xray or Curation licence needed (see below) |
| **CI ordering** | A first job that reads the lockfile only, so install jobs never start | Any ecosystem with a lockfile, incl. those without native support | `hibou deps scan --fail-on 'signal:cooldown'` (ADR-046) |
| **Merge** | The server-side gate of §3 | Everything | Backstop and audit record |

**Package-manager settings** (state of 2026-10):

| Tool | Setting | Unit | Notes |
|---|---|---|---|
| npm ≥ 11.10 | `min-release-age` in `.npmrc` | days | Off by default; `--min-release-age=0` for a first-party release that must go out now |
| pnpm | `minimumReleaseAge` in `pnpm-workspace.yaml` | **minutes** | Default on since pnpm 11 |
| Yarn Berry | `npmMinimalAgeGate` in `.yarnrc.yml` | **minutes** | Day suffixes were silently ignored in early versions; use a number |
| Bun | `minimumReleaseAge` in `bunfig.toml` | seconds | |
| uv ≥ 0.9.17 | `exclude-newer = "7 days"` in `pyproject.toml` (`[tool.uv]`) | duration | Recorded in `uv.lock` as `exclude-newer-span`; advances on re-resolution only |
| pip ≥ 26.1 | `--uploaded-prior-to` (CLI or `pip.conf`) | duration | |
| Cargo, Go, Maven, Gradle, NuGet, RubyGems | none | | Proxy or CI ordering only |

The units differ (days, minutes, seconds), which has already bitten
monorepos that use two tools. Hibou normalises: the org window is one
duration, and the generated snippet carries the tool's unit.

**What Hibou does:**

- **Verification, like lockfile hygiene** (ADR-045 §2.1). Each module gets a
  finding of its own kind, not a vulnerability: "`web/` has no install-time
  cooldown (`min-release-age` missing in `.npmrc`)" or "cooldown is 1 day,
  org policy is 7 days". `install_config: require` makes it a coverage gap
  under the ADR-035 coverage policy, so a repository without it fails the
  coverage requirement an org can enforce; `warn` only reports; `off` for
  repositories that rely on a proxy. Ecosystems without a native setting are
  reported as "no install-time control available", not as compliant.
- **Consistency with the updater.** The Renovate `minimumReleaseAge` and
  Dependabot `cooldown` of the repository are read as well; when the
  package manager's window is longer than the updater's, Hibou says so,
  because the updater will open PRs the install refuses.
- **Generation.** The Dependencies tab and `hibou deps cooldown init` write
  the snippet for each tool present in the module, with the org window in
  the right unit, as a PR. The devcontainer and CI docs recommend
  `ignore-scripts=true` next to it for npm-family tools, with the explicit
  allowlist pattern pnpm uses (`onlyBuiltDependencies`): a cooldown shortens
  the window a compromised version is installable, `ignore-scripts` removes
  what it can do at install time.
- **Policy endpoint for proxies.** `GET /orgs/{provider}/{slug}/policy/packages?purl=…`
  returns `allow | hold-until <timestamp> | deny` and the reason (cooldown
  under the org window, malicious, unpublished, private namespace), with a
  read-only token, cacheable for an hour. Hibou does not become a registry
  proxy. What the proxy side needs, per product (state of 2026-10):

  | Proxy | Cooldown without extra licence | Notes |
  |---|---|---|
  | Any proxy, npm family | **Yes, nothing to do.** `min-release-age`, `minimumReleaseAge` and `npmMinimalAgeGate` are enforced by the client from the `time` field of the packument, which Artifactory and Nexus pass through unchanged. JFrog documents the resulting `ETARGET` / `ERR_PNPM_NO_MATURE_MATCHING_VERSION` errors as expected behaviour | pnpm 11 and Yarn 4 default to a one-day gate even with no configuration |
  | Artifactory, JFrog Curation | Native "immaturity" policy | Separate product on the Xray / Advanced Security tiers. Not required |
  | Artifactory, JFrog Workers | **No.** A Before Download or Before Remote Download worker can only block when the platform is entitled to Advanced Security or Curation; otherwise the Stop response is logged and the download proceeds | Rules Workers out for an Artifactory-only licence |
  | Artifactory self-hosted Pro, user plugin (Groovy) | **Yes.** Hibou ships a reference plugin, a Groovy shim over a Java core: `storage.afterCreate` runs the policy lookup when an artifact is first cached, `download.beforeDownload` reads the stored decision on every download and throws `CancelException(message, 403)`; the ecosystem comes from the repository's `packageType`, so it works through virtual repositories; name and version are parsed from the path (npm `name/-/name-1.2.3.tgz`, Maven and PyPI via Artifactory's `FileLayoutInfo`, NuGet, gems by filename) and mapped to a purl; the decision, the reason and force-download exemptions with a justification live as **artifact properties**, so they persist across restarts and HA nodes and are editable in the UI; property changes are audit-logged; a reload execution re-reads the config. The age is the registry publish date from the policy endpoint, never the Artifactory item's `lastModified`, which would block an old version on its first fetch. For npm it also filters the packument through `altResponse` (§3.2) | Self-hosted Pro only; plugins are "still supported" but JFrog steers new work to Workers. A blocked artifact is still fetched into Artifactory's cache (the block is between Artifactory and the client), which is harmless |
  | Nexus Repository (OSS, Pro) | **No practical cooldown.** Routing rules are one Java regex per proxy, UI-managed, applied to upstream traffic, with a ReDoS warning in the docs; the sunset "cataloged versions only" option was a catalogue check. Firewall is a paid add-on and not age-based | Client gates plus CI ordering |
  | Cloudsmith | **Native cooldown policy** (Rego, one per workspace): versions younger than the window are hidden from the index and never fetched from upstream; age from upstream metadata, fails open without it. Go, Maven, npm, NuGet, PyPI | Early access on Ultra and Enterprise tiers. Hibou only verifies the policy exists and its window matches the org's |
  | ProGet (Inedo) | **Native "Recently published" compliance rule**, server-side, "Download Blocked" on the package | Forum reports of cached npm packages carrying the cache time as publish date, which defeats the rule; verify on your version. Hibou verifies the rule and window |
  | Athens (Go) | **Hook built in**: `ValidatorHook` names an HTTP endpoint consulted for every module download; a non-2xx denies. Hibou's policy endpoint implements that contract directly, no plugin | The request format is documented in the Athens source only |
  | Verdaccio (npm) | **Native** `@verdaccio/package-filter` with `minAgeDays`, `block` by scope, package or version range, `strategy: replace` to serve the nearest older version; filtered versions vanish from the packument | Hibou generates the config; a small filter plugin can ask Hibou for malicious and unpublished denies |
  | AWS CodeArtifact | No age policy. Package origin controls (`Upstream: Block`) are per package, settable by API | Hibou can push a block for a malicious package name; cooldown stays client-side and CI-side |
  | Azure Artifacts, Google Artifact Registry | Nothing version-level: upstream allow lists and cleanup policies only | Client gates plus CI ordering |
  | GitLab virtual registries | Beta in 2026 (Maven, then npm); allow/deny lists and a "dependency firewall" are on the roadmap | Revisit when GA |
  | GitHub Packages | Not an upstream proxy | Not applicable |

  The integration shapes are therefore four, and Hibou implements the first
  three once: **verify** a native cooldown policy against the org window
  (Cloudsmith, ProGet, Verdaccio, the npm-family client settings); **answer
  a hook** with the policy endpoint (Athens natively, Artifactory through
  the reference plugin); **push a denylist** for malicious and unpublished
  packages where only a per-package block exists (CodeArtifact); and
  **nothing** (Nexus, Azure, Google), where the client settings and the CI
  pre-install step carry the control.
- **CI ordering.** The reusable workflow of ADR-035 runs
  `hibou deps scan --fail-on 'signal:cooldown'` before any install step, on
  the lockfile alone, with no network beyond the Hibou server; the other
  jobs declare `needs` on it. For Maven, Gradle, Go, Cargo and NuGet this
  is the only way to stop CI from downloading a fresh version. It cannot
  protect a developer machine; the proxy can.

**Not covered**: a version pinned by hand and installed on a machine with
neither the setting nor the proxy, and anything a package's own build
fetches outside the package manager. Those are listed in the threat model
rather than pretended away.

#### 3.1.1 The Artifactory plugin must not be able to take Artifactory down

A user plugin runs in Artifactory's JVM, on the request thread of every
download, with full privileges. A slow or leaky plugin degrades or hangs
the whole instance, and JFrog's own guidance away from plugins exists for
that reason. The rules below are the contract for the reference plugin,
verified by tests in the repository and by a load test before any release.

**Do not:**

- Call any external service synchronously on the request thread, Hibou
  included. One slow upstream stalls every download thread.
- Write an artifact property, or anything else in the database, per
  request. Writes happen on decision changes only.
- Let an exception other than a deliberate `CancelException` leave a hook.
  A plugin bug must never fail a download.
- Parse or rewrite a response body per request without a size cap and a
  cache. Large packuments are tens of MB.
- Use the Artifactory item's `lastModified` as the package age. It is the
  cache time, so an old version is blocked on its first fetch.
- Activate on every repository. Local repositories, checksums and metadata
  files are not the plugin's business, and each remote is opted in.
- Ship without a kill switch and an observe mode that work without a
  restart.
- Enforce on day one. Observe first, with the load test's numbers from the
  instance itself.

**Do:**

| Rule | Mechanism |
|---|---|
| **No network on the request thread** | Decisions come from an in-memory cache. A miss returns the configured default at once (allow, in observe and fail-open modes) and queues the lookup on a bounded executor, so the next request has the answer. Optional synchronous lookup is capped at 250 ms and sits behind a circuit breaker that opens after a few failures and stays open for minutes |
| **No database writes on the hot path** | Properties are read once per artifact and cached. A block reason is written once per decision change, never per request. Exemptions (`forceDownload`) are read, never written, by the plugin |
| **O(1) pre-filter before anything else** | Repository type and package type cached per repository key; local repositories, checksums, metadata files and unknown extensions return in a few string operations. The plugin is active only on repositories listed in its configuration, starting with the npm remotes |
| **Bounded memory** | Decision cache with a maximum entry count and TTL (a few hundred thousand entries fit in tens of MB). Filtered packuments cached by size budget, and packuments above a configured size (default 2 MB) are not filtered at all, the tarball backstop applies |
| **Fail open on internal error** | Every hook is wrapped; only a deliberate `CancelException` escapes. Any other exception is counted, logged once per minute, and the download proceeds |
| **Kill switch and observe mode** | `hibou.enabled`, `hibou.mode = observe \| enforce` and a reload execution, all effective without a restart. Observe mode logs the decision it would have taken |
| **Single-flight and batching** | One in-flight lookup per purl; misses are coalesced into the policy endpoint's batch call. Negative results are cached too |
| **Metrics** | Decisions per outcome, cache hit rate, lookup latency, circuit state and executor queue depth, exposed in the log and through a plugin execution, so an operator sees the plugin's cost |

Rollout: observe mode on one npm remote, with the load test's numbers
(added p99 on cache hit, zero added latency on miss, flat heap over 24
hours) checked on that instance; then enforce on npm; then other package
types; packument filtering last, behind its own flag. The bench is an
Artifactory Pro in docker-compose with a JFrog trial licence, scripted in
the plugin's repository.

**The plugin lives in its own repository**, not in this one, like the IDE
extensions (ADR-042): it is Groovy and Java with a Maven build, released on
its own cadence to Artifactory administrators, and its only contract with
hibou is the policy endpoint, which is versioned. A plugin release states
the hibou versions it talks to; a compatibility test in that repository
runs against a hibou container.

**What stays true after all of this.** A Groovy user plugin is unsandboxed
code in a production artifact server; the budget lowers the risk, it does
not remove it. If the team operating Artifactory does not accept third-party
plugins, the control for the npm family still holds through the committed
client settings (§3.1), and for the other ecosystems the CI pre-install
step is the fallback. It touches Artifactory not at all.

#### 3.2 Indirect dependencies

Most of what a cooldown must stop arrives indirectly: the compromised
version is pulled by a range in some dependency's manifest, not typed by
anyone. Three facts shape the design.

1. **The lockfile holds the indirect versions, and most client gates do not
   re-check it.** `npm ci` installs the lockfile as written; the gate acts at
   resolution only. pnpm 11 is the same; the pnpm 12 release candidates are
   the first to re-validate lockfile entries before fetching. So a lockfile
   written by anyone without the gate pins a young indirect version that
   every later install accepts. The checks that see every pinned version
   regardless of who resolved it are the ones that read the lockfile:
   Hibou's gate and the CI pre-install step. Both count indirect entries,
   consistent with ADR-045 §1.1, and the "fixes an open finding" exemption
   applies through the chain. Where there is no lockfile (Maven, Gradle
   without locking, unpinned pip), the indirect set is unknown at gate time
   and only the proxy or CI resolve mode can enforce anything.
2. **Where the gate acts decides whether an install degrades or fails.** A
   gate applied to the *index* the resolver reads (packument, simple index,
   crate index) makes ranges resolve to the newest mature version on their
   own, and only exact pins fail. A gate applied to the *artifact* download
   fires after the resolver has committed to a tree, so the install fails
   outright on a version the developer never chose. Metadata filtering is
   therefore preferred wherever the ecosystem's index allows it, and
   artifact blocking is the backstop for lockfiles that already carry young
   pins. Exact transitive pins and brand-new majors required by a mature
   direct dependency fail under any gate; the designed exit is the per-purl
   acceptance, never a global override.
3. **Exemptions must be per version.** npm's only override,
   `--min-release-age=0`, disables the gate for the whole tree in that run
   and writes the young pins into the lockfile for everyone. pnpm, Yarn and
   Bun have per-package lists; uv has `exclude-newer-package`. Hibou's
   acceptance on the purl is the canonical exemption; for tools with a list,
   accepting also proposes the list entry in a PR so the two stay in sync.
   pnpm 12's "loose" mode auto-adds every immature pick to the exclude list,
   which defeats the control; verification (§3.1) treats loose mode as not
   configured.

Per ecosystem (state of 2026-10; "index lever" is what a proxy can filter
so that ranges resolve to older versions):

| Ecosystem | Indirect versions come from | Client gate; lockfile re-checked? per-package exemption? | Index lever at the proxy | Hibou gate sees indirect? | When only young versions satisfy |
|---|---|---|---|---|---|
| npm | `package-lock.json`; ranges in manifests | `min-release-age` (≥ 11.10, days, off by default); `npm ci` not re-checked; no per-package exemption | Packument: `versions`, `time`, `dist-tags`. The client fetches the full packument when the gate is set; the abbreviated one has no `time` | Yes | Ranges degrade to older; exact pins fail `ETARGET` |
| pnpm | `pnpm-lock.yaml` | `minimumReleaseAge` (minutes, 1 day by default since 11); 11: not re-checked, no fallback to an older version; 12 RC: lockfile re-validated, "loose" auto-excludes; `minimumReleaseAgeExclude` covers transitive | Packument | Yes | Fails with `ERR_PNPM_NO_MATURE_MATCHING_VERSION` |
| Yarn Berry | `yarn.lock` | `npmMinimalAgeGate` (minutes, on by default in recent 4.x); `npmPreapprovedPackages` (globs and locators, reported to bypass every gate, not only age) | Packument | Yes | Fails, "quarantined" |
| Bun | `bun.lock` | `minimumReleaseAge` (seconds); existing lock entries unchanged; `minimumReleaseAgeExcludes` | Packument | Yes | Fails |
| Deno | `deno.lock` | None | Packument for `npm:` specifiers; JSR metadata for `jsr:` | Later (ADR-045) | n/a |
| pip | Pinned `requirements.txt` (pip-compile) or PEP 751 lock; otherwise resolved at install | `--uploaded-prior-to` (26.0 datetime, 26.1 duration); resolution only; no per-package exemption (a constraints file pins older) | Simple index (PEP 503 / 691) with `upload-time` (PEP 700). **The proxy must pass `upload-time` through**, or the client gate fails open | Only with a pinned file | Exact pins fail; ranges degrade |
| uv | `uv.lock` | `exclude-newer` (duration since 0.9.17), stored in the lock as `exclude-newer-span`, applied on re-resolution; `exclude-newer-package` | Simple index as above | Yes | Fails at `uv lock`, not at `uv sync` |
| Poetry, PDM, Pipenv | Their lockfiles | None | Simple index | Yes | n/a |
| conda | `conda-lock` | None | `repodata.json` carries a `timestamp` per package | Later | n/a |
| Maven | Resolved at build from transitive POMs, parents and BOMs; versions are exact, ranges rare | None. A Hibou-provided enforcer rule asking the policy endpoint is possible later | **None useful**: `maven-metadata.xml` is read for ranges, `LATEST` and `SNAPSHOT` only. Artifact block (jar **and** pom) is the only lever, and it fails the build hard | **No** (no lockfile): direct only | Fails hard; exemption per purl |
| Gradle | As Maven; `gradle.lockfile` when locking is on | None. A `componentSelection` rule can reject versions, but needs an age source (Hibou endpoint) | As Maven | Only with locking | Fails hard |
| sbt / Mill | As Maven | None | As Maven | No | Fails hard |
| Go | `go.mod` (indirect listed since 1.17) + `go.sum`; MVS picks exact versions | None in the toolchain; proposal golang/go#76485 (`GOCOOLDOWN`); third-party `seasond` is an age-gating GOPROXY returning 403 | `@v/list` and `@latest` only, which matter for `go get pkg` without a version; `@v/vX.zip`, `.mod`, `.info` are exact, so a block fails hard | Yes | `go get pkg@latest` degrades; a requirement from an upstream `go.mod` fails hard |
| Cargo | `Cargo.lock` | None; third-party `cargo-cooldown` wrapper | Sparse index entries carry `yanked`: a proxy can mark young versions yanked, so new resolutions skip them while locked versions still install, exactly cargo's own semantics | Yes | `=` pins fail; ranges degrade |
| NuGet | `packages.lock.json` when enabled; otherwise resolved at restore | None (open issue) | Registration index: `listed: false` removes a version from resolution while an exact reference still restores. Floating versions (`1.2.*`) pick the highest, so filtering helps; plain references are lower bounds and pick the **lowest** match, so young versions are rarely chosen | Only with the lock file | Rare; fails only when the lower bound itself is young |
| RubyGems / Bundler | `Gemfile.lock` | Bundler 4.0.13 (2026-06) `cooldown` in days, `bundle install --cooldown 7`; exemptions not verified | Compact index (`/versions`, `/info/<gem>`) | When Bundler support lands (not in ADR-045) | Fails |
| Composer | `composer.lock` | None (open issues) | `p2/<vendor>/<pkg>.json` with `time` per version | Not in scope | n/a |
| Dart pub, Hex, Conan | Their lockfiles | None | Registry JSON with publish dates | Not in scope | n/a |
| CocoaPods, SwiftPM | Git tags | None; age is the tag's commit date | None (git) | Not in scope | n/a |
| Container images, Actions, Terraform, Helm (ADR-045 §9–10) | Digest / SHA / `.terraform.lock.hcl` / `Chart.lock` | None; Renovate's `minimumReleaseAge` on these datasources is the control today | Helm `index.yaml` has `created`; Terraform registry has publish dates; OCI has no reliable date | Yes for the pins, but **no age source**: deps.dev does not cover them | Out of this ADR; Renovate |

Consequences for the design:

- **Proxy filtering is ecosystem-specific and is worth doing for npm,
  PyPI, Cargo and NuGet**, where the index gives the resolver a graceful
  way down. For Maven, Gradle and Go-by-exact-version there is no graceful
  way: blocking the artifact is the only proxy control and it fails builds,
  so the committed client setting, where one exists, and the Hibou gate
  carry more of the weight there.
- **On Artifactory**, the reference plugin does both: `altResponse` on the
  npm packument request to drop versions younger than the window from
  `versions` and `time` and to repoint `dist-tags`, with a distinct ETag
  and a per-package cache of the filtered document; `beforeDownload` on
  artifacts as the backstop, which fires on cached artifacts too. Whether Artifactory routes generated
  metadata responses for PyPI, Cargo and NuGet through the user-plugin
  hooks is **unverified** and is the first thing the plugin spike checks;
  if not, those ecosystems get artifact blocking only.
- **The PR comment shows the chain**, not the package alone:
  "express 5.3.0 → foo 2.0.0 (indirect, in cooldown 6 more days)".
- **Maven and Gradle without locking stay partial**: the gate reports
  "indirect cooldown not evaluated: no lockfile", the same wording ADR-045
  uses for indirect vulnerabilities, and CI resolve mode fills it after the
  build.
- **Expected friction** is a legitimate bump stopped for the length of the
  window when it needs a young exact transitive pin or a new major. The
  per-purl acceptance is the exit; shortening the window globally is not.

### 4. Private packages and `NOT_FOUND`

deps.dev answers `NOT_FOUND` with `RISK_CRITICAL` for any name it does not
know, and HTTP 200. For a private `@acme/*` package, a Maven artifact from
an internal Nexus or a Go module on an internal host, that is a false
positive, and sending the name was an unnecessary disclosure in the first
place.

Rules:

- **Only public-registry components are queried.** ADR-045's extraction
  records where a lockfile resolved each package (`resolved` in
  `package-lock.json` and `pnpm-lock.yaml`, `source` in `Cargo.lock`, the
  index in `Pipfile.lock` and `uv.lock`, the Go module's host). A component
  resolved from anything other than the ecosystem's public registry is
  tagged `registry: private` and never sent. Components without a recorded
  source (manifest-only, Maven) are sent unless they match a namespace rule.
- **Namespace rules**, org-level, with `.hibou.yaml` additions:
  `private_namespaces: ["pkg:npm/@acme/*", "pkg:maven/com.acme.*",
  "pkg:golang/git.acme.example/*"]`. Hibou proposes entries from what it
  observes (scopes that always resolve to a private registry).
- **`NOT_FOUND` on a public-sourced version** is shown as **unpublished**:
  "this version was on the registry when the lockfile was written and is not
  any more". It warns on the Dependencies tab and in the PR comment; it
  blocks only when OSV also has a `MAL-*` record, which is the existing
  malware block. `NOT_FOUND` on a whole package introduced by a PR is a
  warning with the `LOW_USAGE` alternatives when present: the typical
  slopsquat is a name that does not exist at all.

### 5. What leaves the instance, and when it is off

What is sent: `system`, `name`, `version` of public open-source components,
batched and deduplicated across the instance. This is the same disclosure
class as the OSV queries Hibou already sends by default (`osv.url`), and it
gets the same controls:

- `HIBOU_DEPSDEV_ENABLED` (default `true`, like OSV, KEV and EPSS) and
  `HIBOU_DEPSDEV_URL` (default `https://api.deps.dev`, for an egress proxy).
  A per-org opt-out exists for mixed instances.
- Offline mode (ADR-035) disables it. Mirror-only mode disables it too, since
  there is nothing to mirror. **Signals are then "not evaluated"**, shown as
  such (ADR-034): a component without a cooldown badge in an offline instance
  is not a component out of cooldown. The cooldown gate reports "not
  evaluated" and does not block.
- ADR-041's rule holds: code and findings never leave the customer. Names
  and versions of public packages do, as they already do for OSV.
  `docs/THREAT-MODEL.md` gains the line.
- No credentials, no key. The Google API Terms of Service apply; whether an
  org accepts them is the same question as for OSV.dev and is answered with
  the switch.

### 6. Refresh and resilience

- Fetched in the daily advisory pass for every distinct public version in
  the snapshots that pass still scans (default branches, eager branches,
  pinned releases), through `findingsbatch` in chunks of 5,000, with backoff
  on 429 and 5xx. New versions seen in a PR delta are fetched on the spot
  (one batch per PR evaluation), so the gate has the data when it runs.
- Cached per version with a 24-hour TTL; cooldown state is computed from the
  stored timestamps, so most reads need no refresh. The API's own
  `max-age=3600` is honoured for retries inside the hour.
- Unknown `type` or `risk` values are kept in `raw` and ignored. The adapter
  lives in `internal/provider/depsdev` behind the existing provider
  interface; an API change breaks one package and one set of fixtures.
- A failed fetch leaves the previous row with its `fetched_at`; the UI shows
  the age when it exceeds 48 hours, the way KEV freshness is shown.
- **Source health has one home.** deps.dev gets a card on Settings →
  Advisory activity next to the CVE feed and the exploited catalogs:
  enabled, URL, mode (upstream, proxy, offline), last pass and its duration,
  versions looked up, cache size, last error and circuit state, and "not
  evaluated" when disabled. That view today lists only mirrored feeds; the
  live providers (OSV, Trivy) and the EPSS mirror have no card, which is a
  gap outside this ADR. The card shape proposed here is the one they should
  get too, fed by the advisory scan pass that already runs every six hours.

### 7. Agents ask Hibou, not Google

ADR-042 §7 already routes agents through the MCP server. A `check_packages`
tool takes the same input as Google's skill (system, name, optional
version) and returns Hibou's answer: cooldown state under the org's policy,
deprecation, alternatives, unpublished status, plus what the skill cannot
know: private namespaces (no `NOT_FOUND` on `@acme/*`), the org's existing
triage on that version, open vulnerabilities in Hibou's own data, and the
`shipped` context of ADR-045. The MCP server runs the request through the
same egress rules as the server, so an agent in an offline instance gets
"not evaluated" instead of a direct call to Google. A Hibou `SKILL.md` for
the hibou MCP mirrors the deps.dev one so agents adopt it the same way.

### 8. Where the signals show

- **PR comment and check** (ADR-018, ADR-045 §4.1.2): a line per introduced
  version with its signals, in the existing Dependencies section:

  ```text
  Dependencies: 2 added, 1 updated

    ⏳ cooldown   express 5.3.0 (direct, shipped)         until 2026-10-24 · advisory
    ⚠ low usage  lodash-es-utils 2.0.9 (direct)          did you mean lodash-es?
    ⚠ deprecated request 2.88.2 (indirect via foo)       "request has been deprecated, see …"
  ```

- **Dependencies tab**: badges, filters, and a per-release count ("3 in
  cooldown, 12 deprecated") next to the shipped and relationship counts of
  ADR-045 §12.
- **Finding detail**: when the fixed version is unknown or itself in
  cooldown, the recommended version is shown as "suggested by deps.dev".
- **LSP** (ADR-042): a diagnostic on the manifest line, with the deprecation
  reason, and a quick fix to the recommended version.
- **CLI** (ADR-046): a `signals` column in `hibou deps scan` and
  `hibou deps list`, and `--fail-on 'signal:cooldown'` for teams that want it
  in CI.

## Consequences

- Every public dependency on the instance gets cooldown, deprecation and
  usage context without configuration, for the seven deps.dev ecosystems.
  Terraform, Helm, Actions, OCI and OS packages get nothing from this ADR.
- The cooldown gate closes the gap left by Renovate's wait: manual and
  agent-authored dependency changes are covered. Advisory by default, so no
  rollout shock; orgs opt into blocking.
- Hibou verifies rather than enforces the install-time cooldown: the
  download is refused by the package manager or the proxy, from settings
  Hibou checks and generates. Where no native setting exists, the honest
  state is "no install-time control", and CI ordering is the fallback.
- Repositories without the setting get one more hygiene finding, and orgs
  that set `install_config: require` turn it into a coverage requirement.
- A new outbound dependency on a Google-run `v3alpha` API with unpublished
  rate limits and no mirror. Offline and mirror-only instances lose the
  feature entirely and say so. Churn is contained in one provider package.
- Package names of public dependencies are sent to a second third party
  (after OSV.dev). Same switch, same documentation, same threat-model entry.
- Private packages are protected by registry provenance and namespace rules;
  a misconfigured namespace shows a spurious "unpublished" warning, never a
  block.
- Two sources now describe malicious packages. Only OSV creates findings; a
  disagreement is a metric, which also makes OSV sync lag observable.
- A new `package_signals` table, one provider, one gate category, filters,
  badges, an MCP tool and an LSP diagnostic. Small compared with ADR-045, and
  dependent on its registry provenance for §4.

## Alternatives considered

- **Do nothing; rely on Renovate's `minimumReleaseAge`.** Leaves manual and
  agent-made changes uncovered and gives no deprecation or usage signal.
- **Compute the signals from the registries directly** (publish dates from
  the npm registry, PyPI JSON, crates.io, the Go proxy `.info`, Maven Central
  search; deprecation from npm `deprecated`, Go `// Deprecated:`, PyPI
  project status). Seven clients to maintain, no popularity data, and the
  same egress. Kept as a later fallback for publish dates in mirror-only
  instances, where internal registry mirrors could answer.
- **ecosyste.ms** as the aggregator: open data with dependents counts and
  maintenance status, but no cooldown logic, a smaller operator, and a
  share-alike data licence to review. A second provider behind the same
  interface if deps.dev proves unstable.
- **OpenSSF Scorecard** through deps.dev's `GetProject`: maintenance and
  security-practice scores per upstream repository. Useful, different scope
  (projects, not versions); its own ADR if wanted.
- **Commercial feeds** (behavioural-analysis SaaS): richer behavioural
  analysis, but SaaS subscriptions that Hibou does not resell (ADR-041).
- **Let agents use Google's skill directly.** No private-namespace
  awareness, no org policy, no triage, one more direct egress per developer
  machine. Hibou's MCP tool gives the same ergonomics with the org's rules.
- **Treat GOSSIP findings as vulnerabilities.** Simplest to store, wrong
  everywhere a severity count is read. Rejected (§2).
- **Block on cooldown by default.** The control is most effective blocking,
  but every Hibou gate starts advisory and orgs have not asked for an
  exception yet. Revisit after a quarter of advisory data.

## Open questions

- Should `auto` be the default window, trusting a window Google can change
  without notice, or a fixed `7d` that orgs can write into policy? Proposed:
  `auto`, because it already shortens for patches and extends for malware.
- Whether the per-org opt-out is needed, or the instance switch is enough.
- Whether `REMEDIATION` findings and `recommendedVersions` for packages
  without a Hibou-known fix are reliable enough to show in the finding
  detail from day one, or should wait for a fixture review.
- `v3alpha` graduation: watch for a `v3` findings endpoint and move when it
  exists.
- Whether `install_config` should default to `require` or `warn`. Proposed:
  `warn` until the generator exists, then `require`.

## Rollout

1. `internal/provider/depsdev`: client, batch, cache, fixtures from the
   probes above (express cooldown, `lodahs`, `loadsh`, `request`,
   `github.com/golang/protobuf`, `lodash-es-utils`, `@ctrl/tinycolor@4.1.1`,
   an unknown private-looking scope).
2. `package_signals` table and the daily fetch; registry provenance and
   `private_namespaces` (needs ADR-045 step 3).
3. Dependencies tab badges and filters; finding detail suggested version.
4. PR delta signals and the cooldown gate, advisory; scheduled re-evaluation
   at cooldown end; acceptance bypass.
4b. Install-time cooldown verification and generation (§3.1): detection of
   the settings per tool, the hygiene finding, `install_config` in the
   coverage policy, `hibou deps cooldown init`, the policy endpoint, the
   reference Artifactory user plugin in its own repository (spike first:
   which metadata responses reach `altResponse`, per package type), and the
   pre-install step in the reusable workflow. Indirect handling per §3.2.
5. MCP `check_packages` and the Hibou `SKILL.md`; LSP diagnostic.
6. CLI column and `--fail-on` (with ADR-046).
