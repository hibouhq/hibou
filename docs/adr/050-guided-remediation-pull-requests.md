# ADR-050: Batched dependency-fix patches for a branch or a release

## Status

Proposed (2026-10-17); **initial engine choice accepted and initial public-npm
local profile implemented 2026-11-11**. Broader ecosystem coverage and continuous
maintenance-line automation remain proposed. **Managed Kubernetes execution is
opt-in and disabled by default**, using the shared infrastructure in
[ADR-056](056-secure-kubernetes-workload-execution.md). The previous host-runtime
driver is removed. Native Job, mirror-only remediation and independent
verification paths are implemented; live admission/CNI/node/runtime qualification
is an operator rollout gate, not established by unit/chart tests.

Implementation increment (2026-11-11):

- `internal/remediation` now contains the shared disposable-workspace batch
  transaction, discovery-input hash binding, bounded Git patch generation,
  independent-verifier requirement, explicit native relock supervision,
  fail-closed output checks and reviewed artifact application. The SCALIBR
  manifest adapter uses injected resolution/advisory clients; tests exercise
  actual npm remediation against offline fixtures and an opt-in real public
  registry/native-npm fixture with a synthetic advisory.
- Native relock command adapters exist for npm, pip-tools, Poetry and Pipenv,
  with preinstalled exact-version tools, a minimal environment, bounded output/
  deadlines and process-group cancellation on Linux/macOS. These adapters
  still require a separately trusted/isolated execution environment and a
  manager-specific independent verifier; they are not advertised as fully
  validated production coverage.
- The initial qualified local adapter supports independent public npm
  package-lock v3 modules, authoritative advisory/private-namespace/policy
  matching, automatic/exact/Gossip choices, declaration-style preservation,
  explicit upgrade/prerelease consent and strict native `npm ci` verification
  before and after updates. Workspaces, aliases, complex manual declarations,
  repository npmrc, custom-registry profiles and unqualified runtime pins
  fail explicitly rather than switching managers or weakening verification.
- VS Code exposes a module/version-selection workspace, read-only diff,
  patch/artifact export and guarded batch application through shared CLI/LSP
  code. A separately confirmed Create PR action regenerates on Hibou at the
  same accessible commit, requires review of that managed diff and then calls
  authorized publication. It does not upload/trust a local artifact as managed
  execution evidence. Other IDE clients can adopt the capability-negotiated
  protocol; equivalent client presentation is not implied by the LSP methods.
- Managed job/revision/artifact state, a routed website workspace, GitHub atomic
  publication and operator-allowlisted maintenance targets are retained.
  Preparation/generation fail closed with HTTP 503 unless an enabled installation
  has a matching live Kubernetes controller; stale runtime heartbeats cannot
  activate them. ADR-056 defines isolated native Jobs, mandatory Linux user
  namespaces, dedicated execution namespace and bounded HTTPS attempt transport.
  The API pod never executes package managers; repository CI is not a prerequisite.
- The initial API prefix is repository-relative `/remediation` (singular).
  Maintenance mappings/settings are organization-scoped managed settings;
  broader `.hibou.yaml` examples and all-maintained-line policy below remain
  design proposals, not currently parsed configuration. See the actual
  endpoints, profile provisioning and deployment boundary in
  [Managed remediation](../MANAGED_REMEDIATION.md).
- Still deferred: public `hibou fix`, additional qualified ecosystem/lockfile
  local profiles, fully disconnected resolver-data bundles and continuous
  all-maintained-line orchestration. The initial managed Kubernetes profile
  acquires through approved internal mirrors without public fallback. Required
  package/advisory/policy evidence must be imported beforehand. Preloaded
  executables alone do not make the local public-registry resolver offline.
- Upstream compatibility findings: v0.5.3's npm lockfile writer constructs
  its own registry client; it cannot yet use Hibou's injected resolver for
  all metadata access. The manifest adapter avoids that path and binds
  injectable resolver/enricher calls to the job context because upstream
  starts from `context.Background`. Unresolved/metadata errors remain fatal.

The revision makes a downloadable patch the primary deliverable, shared by
the release page, CLI and IDE. **SCALIBR is the chosen initial remediation
engine** (2026-11-11); Renovate and Dependabot are not required integrations.
Version selection includes automatic targets, explicit deps.dev suggestions
and user-specified exact versions. These are Hibou adapter controls, not a
claim that every proposed control exists in SCALIBR's public API.

- **Initial scope:** qualified public npm v3 execution and the managed/local
  workflows above; do not infer Maven/Python/other lockfile production
  coverage from a generic command adapter or inventory extraction support.
- **Prerequisite for each supported strategy:** a compatibility spike that
  proves complete manifest/lockfile updates and enforceable version choices.
  Tool-executing strategies additionally need local or isolated execution.
- **Required optional delivery surface:** forge branch/PR publication when
  capability and consent allow it, alongside download and IDE batch apply.
  Optional means users can choose it, not that it is excluded from delivery.
- **Deferred extension:** continuously scheduled update-bot mode.
- **Included managed execution:** Hibou runs supported package managers to
  regenerate/verify dependency files in isolated toolchain runners. This is
  server-side product functionality, not a required user CI process. IDE
  generation preferentially runs the same shared logic with local tooling.
- **Execution boundary, not a feature exclusion:** package managers and
  repository-controlled build code never run in the API server or ordinary
  worker pod. Approved manager operations run only locally with consent or
  inside the isolated execution boundary; arbitrary repository commands are
  not accepted as job inputs.
- **Outside this proposal:** automatically merging PRs, creating release tags
  or publishing packages/images/releases. Creating proposal branches and
  opening PRs is included, not meant by "release publishing".
- **Initial coverage limitation:** ecosystems/lock formats without a validated
  SCALIBR integration are reported as unsupported. Additional coverage can be
  added through a tested integration or future engine decision; it is not
  permanently forbidden.
- This proposal has **not been dropped**.

Builds on [ADR-024](024-release-tracking.md)
(releases derived from tags, clients and deployments),
[ADR-045](045-built-in-dependency-inventory.md) (OSV-SCALIBR as a library,
§7 security of server-side work), [ADR-046](046-dependency-cli.md) (CLI,
offline advisory database) and [ADR-035](035-bundled-scanners-and-coverage-policy.md)
(approved network locations, isolated runners).

Related: [ADR-042](042-ide-extensions.md) (thin IDE clients and the shared
language server), [ADR-052](052-forge-write-access-least-privilege.md)
(patch mode without forge writes), [ADR-048](048-depsdev-gossip-signals.md)
(GOSSIP recommendations and the shared package-policy evaluator).

[ADR-055](055-headless-library-boundaries-and-dependency-footprint.md) records
the deferred headless-SCALIBR/dependency-footprint follow-up. Importing the
existing module's remediation package is not a zero-cost dependency change.

**Proposed direction:** Hibou owns vulnerability selection, target resolution,
upgrade policy, validation and the patch API. Use SCALIBR `guidedremediation`
for graph-aware file changes rather than build an updater per ecosystem.
Do not make either a hosted bot or an updater's internal result format the
public API. Strategy and version-control support are gated on the spike below;
unsupported ecosystems stay explicit rather than pulling in a second engine.

## Context

A user looking at the vulnerabilities of a branch or a release (ADR-024)
wants one reviewable batch of dependency upgrades, not a series of manual
version edits or one PR per advisory. The same change should be downloadable
from a release page and applicable from an IDE on a chosen branch.

Generating a patch needs read access to source, not permission to push.
A release also has two distinct targets: its exact shipped commit, and the
current head of its maintenance branch. Neither can silently stand in for
the other.

What exists:

- `github.com/google/osv-scalibr` v0.5.3 is already a dependency. Its
  `guidedremediation` package exposes `FixVulns(options.FixVulnsOptions)`:
  it resolves the dependency graph, computes candidate remediation patches,
  rewrites the manifest or lockfile on disk and returns a `result.Result`
  (vulnerabilities, patches with fixed/introduced IDs, unactionable ones).
  Options cover what a PR needs: `ExplicitVulns`, `IgnoreVulns`,
  `MaxUpgrades`, `NoIntroduce`, `MaxDepth`, `DevDeps`, per-package
  `upgrade.Config` (major/minor/patch), `ProjectRoot`.
- Forges already implement `CreateBranch`, `CreateOrUpdateFile` and
  `CreatePullRequest` (`internal/forge/forge.go`), used by the onboarding
  PR (`internal/repoconfig/onboarding.go`).
- Releases are derived from tags matching `releases.tag_pattern`; each
  points at a tag ref and a snapshot (commit). Clients and deployments say
  who runs which release.

What the original investigation measured on SCALIBR v0.5.3 (candidate
capabilities, not a promise of Hibou support):

| Ecosystem | File | Strategy | Executes a tool |
| --- | --- | --- | --- |
| npm | `package.json` | relax | `npm install --package-lock-only --ignore-scripts` when a lockfile is passed |
| npm | `package-lock.json` | in-place | No |
| Maven | `pom.xml` | override (`dependencyManagement`) | No |
| pip | `requirements.in` / standalone `requirements.txt` | relax | `pip-compile` when a lockfile is passed |
| Poetry | `pyproject.toml` | relax | `poetry lock` when a lockfile is passed |
| Pipenv | `Pipfile` | relax | `pipenv lock` when a lockfile is passed |

Gaps: no Go modules, Gradle, NuGet, Cargo, Composer, Bundler. Maven parent
POMs outside `ProjectRoot` are not updated. Resolution needs registry
metadata (a `resolve.Client`, plus a Maven registry client), so it needs
the network. The vulnerability source must be an enricher whose name
starts with `vulnmatch/` (upstream ships `osvdev`, online, and
`osvlocal`, downloaded OSV exports). The package README warns that on
untrusted projects the package manager may run scripts or follow
registries declared in the project.

Lockfiles are a cross-ecosystem requirement, not an npm feature. The table
above describes SCALIBR's current remediation paths, not all lockfiles Hibou
must recognize when deciding whether it can safely fix a project. Inventory
extraction coverage is broader than remediation coverage; detecting a file
does not authorize rewriting it.

What does not exist: knowing which branch carries a release's code line,
and which lines a team still maintains. That second fact is a company
policy, and companies differ: "last two minors", "LTS majors until a
date", "whatever a client still runs", or a hand-kept list.

### Goals

1. From any accessible branch or release, generate one Git-applicable patch
   for selected (or all actionable) dependency vulnerabilities.
2. Reuse the same API and patch artifact in the web UI, CLI and IDE, without
   requiring server-side forge write access.
3. Show which release lines are maintained without hard-coding one
   maintenance model; later support one independently validated patch per
   maintained line. For one target, support download, IDE batch apply and
   explicit Hibou branch/PR creation as alternative completion actions.
4. Keep ADR-045 §7: the API server and ordinary worker pods execute no
   package managers or repository-controlled scripts. Managed package-manager
   execution is included through separately isolated toolchain runners;
   local IDE execution uses the same logic with explicit trust/consent.
5. Managed generation works from the website/IDE without repository-specific
   pipelines, scripts, agents or CI configuration. Operators provision Hibou
   execution capacity once per installation; repository users only select
   fixes, review and download/apply them.
6. The IDE prefers existing compatible local tooling through the shared
   CLI/LSP, with workspace trust and execution consent. Managed execution is
   the website default and an explicit IDE alternative, not a requirement
   to send local source to the server.

### Non-goals

- Ecosystems no validated adapter covers. Findings there show
  "no automated fix" with the fixed version Hibou already knows.
- Cherry-picking code fixes (first-party vulnerabilities, SAST findings).
- Merging, tagging or publishing a release. Hibou opens the PR; the team
  merges and tags, and ADR-024 derives the new release from the tag.
- Running continuously as an update bot. Patches are generated on request;
  Renovate can remain the repository's scheduled updater.
- Automatically changing application code to accommodate breaking upgrades.
- Requiring users to set up a CI job, webhook callback, external workflow or
  their own background process to generate a patch. CI-triggered generation
  and per-repository runner installation are excluded from this workflow.
- Claiming a patched source tree fixes a binary, image or deployed release
  without rebuilding and rescanning that deliverable.

## Decision

### 1. Separate Hibou's planner from the upgrade engine

| Candidate | Strength for this use case | Limitation / decision |
| --- | --- | --- |
| Renovate | Broad managers, grouping, multiple base branches, mature scheduled PR automation | Not selected as a patch engine: experimental `platform=local` supports extraction/lookup, not full updates or branch creation. A hosted bot is a separate workflow, not an on-demand patch API |
| Dependabot Core via CLI | Broad ecosystems; CLI runs update jobs and returns file-change data without creating PRs; security jobs can receive advisory ranges | Not selected initially: the Go CLI still runs Ruby-based updater/toolchain environments, with an additional job/output integration boundary |
| SCALIBR `guidedremediation` | Already pinned in Go; graph-aware remediation with fixed/introduced/unactionable results | Chosen initial engine for validated npm/Maven/Python strategies; other ecosystems remain unsupported |
| Native package managers directly | Authoritative lockfile generation | Necessary under some adapters, not a common vulnerability planner; do not build a parallel updater for every ecosystem |

Prefer the smaller in-process Go integration over a second bot runtime.
This is an operational choice, not a measured claim that Go resolution is
always faster: registries, graph size and relocking can dominate runtime.
Measure cold/warm latency, peak memory, registry traffic and deployment size
on the corpus. The plan names the SCALIBR version and strategy. Do not fork
upstream or build a general plugin system speculatively; record specific
capability gaps before extending the integration.

- **Vulnerability source:** Hibou's advisory data and repository triage,
  not GitHub alerts or a hosted bot's independent findings. Normalize aliases,
  ecosystem version ranges and package identity into engine inputs. Unsupported
  range translations block that item rather than guessing a fixed version.
  The SCALIBR adapter uses `vulnmatch/hibou`; its upstream prefix convention
  requires a pinned-version compatibility test.
- **Selection:** use the same open-risk semantics as the vulnerability UI.
  Not-affected/suppressed findings are excluded; accepted risk remains visible
  and selectable, with an explicit option to exclude it. A selection identifies
  package occurrences (manager, module/manifest path, package and version),
  not just an advisory ID that might occur in several modules.
- **Defaults:** include dev dependencies; do not introduce known
  vulnerabilities. Use SCALIBR's strategy-specific selection within policy,
  not a claim of globally minimal or always-lowest versions. Patch/minor upgrades only
  by default; crossing a major boundary requires preview and explicit consent,
  including on the default branch. Respect existing ADR-048 cooldown policy;
  any security exception is explicit and recorded.
- **Batching:** resolve all selected upgrades together per dependency graph.
  A shared lockfile/workspace is one resolution unit. Reconcile all resulting
  file changes against the same base; never concatenate independent patches
  that touch the same manifest or lockfile. A transitive fix may require a
  direct-parent upgrade; explain that dependency path in the plan. Unrelated
  upgrades are excluded unless required by the resolver and shown in preview.
- **Outcome:** per occurrence, report `changed`, `already_safe`, `no_fix`,
  `blocked_by_policy`, `version_conflict`, `unsupported`, `unmapped_source` or
  `failed`, with reasons. An advisory's fixed version alone is not evidence
  that the project can resolve to it.

#### 1.1 How an automatic target is computed

The target is not a version number invented by Hibou or taken blindly from
an advisory's first `fixed` event:

1. Read the source occurrence, manifest constraints and resolved/locked graph.
2. Obtain published version/dependency metadata through approved registries
   or mirrors, and match against Hibou's complete advisory view.
3. Apply per-package upgrade limits and strategy-specific resolution.
4. Evaluate proposed targets with the existing ADR-048 package-policy
   evaluator, then validate the resulting combined graph and required files.

Observed in pinned v0.5.3: Maven's override strategy considers higher versions
in ascending order, choosing the smallest one that removes as many relevant
findings as possible before re-resolving. npm lockfile in-place remediation
searches newest-first for a non-affected version that fits incoming constraints
and the existing dependency graph. npm manifest relaxation widens constraints
in steps and can choose newer versions within the permitted band. Thus
**Automatic does not mean latest, lowest, or globally minimal**. Show the
actual proposed version, declared constraint and strategy; explain the
upgrade boundary and relevant dependency path.

SCALIBR exposes `UpgradeConfig` levels (`patch`, `minor`, `major`, `none`),
`ExplicitVulns` and `NoIntroduce`; v0.5.3's public `FixVulnsOptions` has no
per-package exact-version map and no built-in Gossip preference. Hibou must
implement and test that selection boundary rather than label upstream's
upgrade-level setting an exact-version override.

#### 1.2 Three explicit version choices per change unit

| Choice | Meaning | Validation / failure behavior |
| --- | --- | --- |
| **Automatic** (default) | Let the validated SCALIBR strategy propose a target within effective policy | Show the concrete proposal and rationale; never promise the smallest release |
| **Suggested by deps.dev** | Explicitly choose a GOSSIP-recommended version for this package | Snapshot its exact version, source and fetch time; check all Hibou advisories, policy and graph constraints, not just GOSSIP findings |
| **Exact version** | User chooses a published version from the list or types one literal version | Treat it as a hard target for the selected occurrence/change unit, not a preference; reject unresolvable/disallowed choices without silently substituting another version |

Never auto-switch an automatic selection to Gossip because it looks newer.
ADR-048's `recommendedVersions` means low-risk suggestions, not compatibility
with this project's graph or a guarantee of fixing every Hibou advisory.
The current normalization can fall back to a recommendation with findings;
therefore its `recommended_version` string alone is not an approval.
Re-evaluate that target through `packagepolicy`, preserve `evaluated: false`
as **not evaluated**, and show source age/warnings. No recommendation, stale
or unavailable data, unsupported ecosystems and offline/private packages have
explicit reasons; private package identities never leave approved boundaries.
An unavailable suggestion does not prevent Automatic or Exact choices if
their required resolution/policy evidence is available.

Exact selection is scoped to an occurrence and resolution unit, not a
package-name-wide force. Show whether the selected version is the vulnerable
transitive package or a direct parent whose upgrade is required. If a
shared constraint/lockfile makes several occurrences inseparable, present one
linked change unit listing all affected occurrences; conflicting targets in
that unit must be resolved by the user. Separate resolution units can retain
different versions of the same package.

Use ecosystem-aware version parsing/order. Reject ranges, moving tags such
as `latest`, arbitrary URLs/commands and unknown/unavailable versions in the
exact-version control. No downgrades in the initial fix workflow; prereleases
and major upgrades need explicit consent where policy permits. A selection
changes the resolved target, not necessarily the declaration to a permanent
exact pin: preserve the project's range style where supported and show the
actual constraint edit. Persistent pinning is a separate, deferred feature.

The integration spike must prove each advertised version-control mode per
strategy using supported resolver/manifest boundaries and graph-aware
regeneration. Candidate restrictions must not hide current vulnerable versions
from baseline analysis or falsify metadata. Validate that the final resolved
version equals every explicit target after relocking, including all linked
occurrences; never enforce a target by post-hoc text replacement in a lockfile.
If the engine cannot honor a target, report a structured conflict or unsupported
mode. Do not silently relax the choice, bypass policy or replace SCALIBR with
hand-written dependency resolution. Upstream extension work, if needed, is a
named implementation prerequisite rather than an assumed existing capability.

Major-upgrade consent changes the request's allowed upgrade level only where
the caller is authorized to do so. Choosing a version is not a policy override:
mandatory denies remain blocked. An authorized cooldown/policy acceptance uses
the existing ADR-048 workflow with reason/expiry; return to and regenerate
the plan afterward, never add an unchecked `force` flag.

### 2. Where it runs

The managed lifecycle/security/deployment design in this section is governed
by [ADR-056](056-secure-kubernetes-workload-execution.md). The initial opt-in
Kubernetes/mirror profile is implemented and reflected in the threat model.
Broader profiles below remain proposals, and real-cluster qualification is
required before enabling production execution.

| Mode | Strategies | Who runs it |
| --- | --- | --- |
| **Server worker, no execution** | Only individually proven pure SCALIBR file-rewrite strategies | Hibou, on a read-only-credential clone pinned to the base SHA |
| **Managed isolated runner** | Validated engine/manager pairs, including lockfile regeneration | Hibou installation component; per-job disposable environment separate from the application server, with no repository-side setup |
| **Local CLI/LSP** | Validated strategies using an available trusted toolchain | Preferred IDE path after trust/consent and compatibility checks; no CI workflow and no source upload. Optional for website users |

The release-page API dispatches to an available safe execution mode; it
does not bypass isolation because the output is "only a patch". Without
a suitable runner or pure strategy, return a capability limitation and a
local-command alternative, not a manifest-only patch with a stale lockfile.

Runner requirements before enabling broad coverage:

- No application-server Docker socket, host mounts, cloud metadata access,
  forge write token or ambient credentials. A container alone is not the
  isolation design. Use per-job resource/time/output limits and cleanup.
- Allow only approved registry/mirror and source endpoints (ADR-035/045).
  Repository config cannot redirect traffic or supply arbitrary commands.
  Disable lifecycle scripts, plugins and post-upgrade commands where possible;
  ecosystems that evaluate build code remain untrusted execution regardless.
- Supply narrowly scoped registry/source credentials through an approved
  credential proxy where supported; never include them in patches or logs.
  Verify that the SCALIBR clients/toolchains honor those credential and
  egress boundaries; never assume that disabling install scripts is sufficient.
- Pin CLI, engine and toolchain images by version/digest. Audit their identities,
  policy and inputs. Online resolution need not be byte-for-byte reproducible:
  retries producing different bytes create a new artifact, never overwrite one.

The CLI shares the planner and artifact contract; it does not duplicate
selection and upgrade policy. Local execution uploads neither source nor dirty
working-tree contents. Offline mode requires the ADR-046 advisory export and
all resolver metadata/artifacts locally available; an advisory export alone
cannot make dependency resolution offline.

#### 2.1 Preserve each project's dependency-file contract

Determine the actual manager, its version, workspace boundaries, manifest
inputs, constraints and lock/checksum files before selecting a remediation
strategy. A file named `pyproject.toml` does not mean Poetry; a `package.json`
does not mean npm. Honor the declared manager and corroborating lockfiles.
Conflicting manager declarations/lockfiles require an explicit choice, not
silently converting the repository to whichever manager the engine supports.

| Manager / ecosystem | Files to consider together (examples, not an exhaustive detector) | Initial remediation boundary |
| --- | --- | --- |
| npm | `package.json`, workspace manifests, `package-lock.json` or `npm-shrinkwrap.json` | Validate each supported lock format/version separately; shrinkwrap support is not implied by package-lock support |
| Yarn / pnpm / Bun | Workspace manifests/config and `yarn.lock`, `pnpm-lock.yaml`, `bun.lock` or older binary `bun.lockb` | Unsupported by pinned SCALIBR remediation; never generate an npm lockfile instead. Binary lockfile edits are outside the text-patch contract |
| pip-tools | Input requirements/constraints, compiled requirements and their hashes/includes | Validate SCALIBR's supported input/output pair; a standalone requirements file can be a manifest, not necessarily a lockfile |
| Poetry / Pipenv | `pyproject.toml` + `poetry.lock`; `Pipfile` + `Pipfile.lock` | Validate the actual manager/lockfile versions and all required workspace inputs |
| uv / PDM / Python lock standards | `pyproject.toml`, workspace inputs and `uv.lock`, `pdm.lock` or `pylock.toml` | Unsupported by pinned SCALIBR remediation; do not relock with Poetry merely because the manifest is TOML |
| Cargo | Workspace/member manifests and `Cargo.lock` | Unsupported initially; workspace and target-specific resolution still matter |
| Composer / Bundler | `composer.json` + `composer.lock`; `Gemfile`/gemspec inputs + `Gemfile.lock` | Unsupported initially; preserve manager-specific metadata/platform constraints in any future integration |
| NuGet / Gradle | Project/central-version files + `packages.lock.json`; Gradle build inputs + project/configuration lockfiles and verification metadata where used | Unsupported initially; generated build output is not a substitute for the committed dependency contract |
| Go modules/workspaces | `go.mod`, `go.sum`, and `go.work`/workspace sums where present | Unsupported initially; `go.sum` is a checksum database, not an exact dependency lockfile |
| Maven | POMs, parent/BOM/property inputs and any project-specific locking mechanism | SCALIBR override candidate; Maven has no universal standard lockfile, so do not invent one or claim a POM override proves every build variant |

Support is a tested tuple of **manager + manager version + lockfile format +
workspace layout + strategy + execution mode**, not one `supports_lockfiles`
boolean. Capability discovery, draft rows and the final verification report
must name that tuple and the required file set. Unknown formats, unsupported
locking plugins and missing workspace/constraint inputs block the affected
resolution unit rather than falling back to manifest-only output.

Preserve an existing lockfile as a resolution input; update it using the
manager's supported targeted workflow where available. Do not delete it to
produce a fresh unconstrained graph, change managers or remove hashes/markers
just to make resolution pass. Generate a previously absent lockfile only when
that is an explicitly reviewed supported project workflow, not an automatic
side effect of discovering a manifest. A valid lock-only fix is allowed if
the current manifest already permits it and independent consistency checks
pass; it need not introduce a cosmetic manifest edit.

For manifest strategies requiring relocking, the initial Hibou integration
should **own and supervise the native relock command**, rather than delegate
to SCALIBR's built-in manifest-plus-lockfile execution path. Let SCALIBR write
the manifest through a validated no-relock path, retain the original locked
graph as baseline, then invoke the pinned manager under Hibou's execution
controls. SCALIBR v0.5.3 can log relock failures without returning them, and
its npm relocker removes the existing lockfile and retries with
`--legacy-peer-deps`. Neither a missing lockfile nor a silent weakening of
dependency checks is acceptable. No automatic peer/constraint bypass,
cross-manager fallback or suppressed subprocess failure.

Every native invocation needs an observed exit status, bounded/sanitized
diagnostics, deadline and cancellation handling. If a necessary command
cannot be run safely or its output cannot be verified, block generation.
SCALIBR returning `nil` is never the success criterion for the whole batch.

#### 2.2 Provision tools before jobs; keep the runtime image shell-free

Keep the current shell-free Wolfi/apko server image and ordinary worker image
unchanged. Do not add Node, Python, JVMs, package managers, an installer or
a shell to them to support relocking. Existing secret scanning illustrates
the useful parts of the pattern: Gitleaks is installed at image build time
through the locked apko package set; Betterleaks is copied from a
checksum-verified build stage. The provider discovers an already installed
executable and invokes it directly with a minimal environment, timeout and
explicit error/report handling. Neither downloads its executable per scan.

Reuse that **preprovision, verify, supervise** pattern, not the assumption
that a package manager is as self-contained or safe as Gitleaks. npm requires
Node; Python managers require Python and locked installer dependencies;
other future managers can require JVM/.NET/Ruby runtimes or native libraries.
Some evaluate repository-controlled build code even with install scripts off.
Copying one binary into the server or adding an environment allowlist does
not provide the required runtime closure or execution isolation.

Use three responsibilities, with one job/artifact contract:

1. **API/control plane:** authorize, discover/select supported capabilities,
   persist drafts/jobs and serve previews/artifacts. No tool installation or
   package-manager execution.
2. **Pure remediation workers:** reuse Hibou's same-binary worker and lease
   patterns for proven non-executing SCALIBR strategies. Add an explicit
   remediation loop switch and separate resource/concurrency budget; default
   it off on request-serving replicas. Existing dependency extraction is not
   already worker-only and must not be presented as such.
3. **Managed toolchain execution:** the normal relock delivery path uses
   preprovisioned, operator-approved toolchain profiles
   and disposable per-job sandboxes. Initial profiles cover only validated
   SCALIBR manager/lockfile combinations, not every ecosystem in §2.1.
   Managed relocking is required before advertising a locked workflow as
   available from the release-page API. The IDE also supports the same
   workflows through compatible preinstalled local tools; that does not
   substitute for the website's managed capability.

For managed execution, prefer a runner agent claiming compatible leased jobs
outbound, rather than giving the API pod a Docker socket or Kubernetes Job
creation privileges. A trusted runner supervisor creates the job sandbox using
the operator's approved execution backend; only the supervisor has lifecycle
permissions, never repository tools. Provision the runner outside the ordinary
Hibou pod/secret boundary. The exact sandbox backend is an implementation
prerequisite under ADR-035, not an already implemented managed-runner feature.
Package the supported runner integration as an installation-level Hibou
deployment option, with readiness/capability checks and no per-repository
registration. Deliver managed generation for the initial supported workflows,
not a CI-first detour. Keep lifecycle orchestration in the runner supervisor,
not the application server. Fully disconnected deployments can have their
operators provision local images and resolution data once under §2.4.

Provision small **per-toolchain OCI images** by default for managed runners,
not one all-managers image: for example a tested Node/npm pair or a tested
Python/Poetry pair. Pin images by digest and record the actual binary versions,
OS/architecture, runtime and command-adapter revision. A profile may require a
shell for its own ecosystem; that is confined to the isolated toolchain image,
not a reason to weaken the shell-free server image. No runtime `curl | sh`,
`npx`, `pip install`, Corepack download, Volta/asdf/mise bootstrap or automatic
runtime installation while a remediation job is executing.

IDE/local environments preferentially use a verified, preinstalled
toolchain or an operator-imported relocatable bundle where the adapter proves
its full runtime/native dependency closure. They need not run an OCI image,
but use the same profile/validation contract and show **local execution**.
Never execute a binary just found on an untrusted repository-prepended PATH.
Resolve an approved absolute tool path, verify identity/version before use,
and reject mismatch. Trust/consent for local execution remains explicit;
the website never requires running a local command to complete a supported
managed-generation job.

#### 2.3 Select the toolchain version from repository intent and a catalog

Package-manager version is separate from the dependency version chosen in §1.
The lockfile's format number alone rarely identifies the exact producer
version. The draft must resolve a complete tuple: manager, exact manager
version, language/runtime version, target platform, lock format, profile
digest and adapter revision.

Select deterministically:

1. Discover exact declarations and constraints **without executing repository
   scripts**: applicable `packageManager`/`devEngines`/engine fields, supported
   tool-version files, static CI declarations, lockfile producer metadata and
   manager-specific configuration. Label whether each is an exact pin,
   constraint or weak hint. Distinguish application runtime requirements from
   the runtime needed to execute the package manager; respect both where the
   adapter requires them. Workspace-specific declarations override only where
   the manager's actual semantics permit it.
2. An exact declared version must match an approved available profile. Do not
   substitute the nearest installed version. Conflicting authoritative pins,
   incompatible runtime constraints or an unreadable dynamic declaration
   produce a visible conflict, not execution of CI/scripts to guess.
3. With ranges rather than pins, intersect repository constraints, lock-format
   compatibility and operator policy with the supported catalog. Use the
   catalog's explicitly designated compatible default, if unique; show the
   exact chosen tuple and its selection source before Generate. No live
   "latest" lookup. If there is no unique compatible default, request an
   explicit profile choice in the draft.
4. With no usable declaration, offer a tested operator-approved default only
   when compatibility can be established; label **No repository toolchain pin;
   using approved profile ...** and require acknowledgment. Otherwise block
   with concrete required profiles. Do not infer the original toolchain with
   false precision from a lock format.
5. Pin the selected tuple to the draft revision, job and artifact. A catalog
   update cannot change a queued job's toolchain; a revoked profile blocks it.
   The runner advertises verified profile availability and rechecks the tuple
   before executing. A worker with another version cannot claim that job as
   equivalent.

Users may choose among compatible approved profiles; a package-version override
is not permission to override an exact repository toolchain pin. Changing that
pin/runtime or migrating the lockfile format is separate, explicitly reviewed
work, not silent collateral remediation. Old release lines may need an older
profile: keep supported profiles by policy rather than always using the
newest manager. Unsupported/EOL profiles have explicit operator lifecycle
rules; no automatic download or downgrade of security requirements to make
an old release patchable.

Repository wrappers, Yarn `yarnPath`, Corepack metadata and similar mechanisms
must not execute or acquire an arbitrary repo-supplied binary. Use an approved
equivalent distribution only where the adapter can prove compatibility and
honor the declared version; otherwise report the workflow as unsupported.
Profiles declare the commands and necessary environment/configuration; job
requests cannot submit arbitrary shell commands or installer URLs.

#### 2.4 Connected, internal-mirror and fully disconnected operation

Extend ADR-035's catalog/distribution and verified-import model for toolchain
profiles rather than create a separate trust/version system. The existing
scanner bundle implementation is prior art, not proof it already supports
package-manager images or complete toolchains. New profile/artifact kinds,
imports and runner capability reporting need explicit implementation.

All modes preprovision executable tools before job execution:

| Deployment mode | Toolchain acquisition | Resolution dependencies |
| --- | --- | --- |
| Connected | Trusted preparation/build pipeline acquires pinned tools; publish verified profiles to the approved registry/store | Jobs use only approved source/registry endpoints under egress policy |
| Mirror-only / air-gapped from the public Internet | Import or mirror approved images/bundles; no public fallback, including package-manager bootstrap | Use internal forge, registry/metadata mirrors and CA trust; missing mirror content is an explicit failure |
| Fully disconnected execution | Preload verified images/bundles on the execution host, with offline verification material | Materialize the exact source snapshot, advisory export and resolver metadata/artifact closure before disabling networking |

Separate **no executable downloads** from **no network at all**. Internal
mirrors still use a network, while true offline jobs must not perform source
fetches, DNS/API lookups, telemetry, runtime/tool downloads or online signature/
transparency verification. Use manager offline modes when available, plus
enforced network denial: an offline flag alone is insufficient. Verify both
successful and missing-cache paths without network access.

A connected preparation/export step selects exact profile IDs and platforms,
produces digest-pinned images or complete runtime bundles, and includes a
versioned manifest, signatures/provenance where available, licenses/SBOMs,
trust material and adapter compatibility metadata. Verify all content against
trusted catalog digests before activating imports; reject path traversal,
unsafe links and incomplete architecture/runtime closure. Operator mirror
overrides change location, not identity or pinned contents.

Executable closure alone is insufficient for offline relocking. Prepare
project/target-specific registry metadata, packages, wheels/build backends,
plugins and transitive dependencies needed for candidate selection,
regeneration and verification, together with the exact source snapshot and
advisory/triage view. Some managers cannot resolve offline from their download
cache alone; only advertise offline support when the tested metadata/cache
format or local registry snapshot suffices. A proposed new version not in the
imported closure yields **Missing offline dependency data**, not a manifest-only
patch or an upstream retry. Gossip may be unavailable (§1.2); do not secretly
refresh it online.

Expose a preflight **toolchain ready / missing toolchain / missing resolution
data** report with exact required artifact/profile IDs, architecture, approved
import/mirror instructions and evidence timestamps. Catalog-only checks must
not masquerade as proof that every transitive package is cached; later cache
misses remain explicit failures. Do not ask a developer to approve an Internet
download from a supposedly offline Generate button.

#### 2.5 Workspace lifetime, caches and operational limits

Reuse the exact-commit checkout/auth foundations of dependency extraction,
but create a distinct writable workspace/diff base for remediation. Fetch only
strategy-required manifests, lockfiles, workspace and parent inputs where
possible; widen to source only when required by the supported manager. An
incomplete sparse checkout must block or widen explicitly, never resolve a
different graph. No long-lived checkout while a user edits version choices:
persist draft inputs/hashes, release discovery scratch, and rematerialize and
verify the same base when Generate is requested.

Keep the worker's temporary checkout and tool caches out of PostgreSQL and
the artifact store. Persist draft/job metadata, provenance and expiring patches;
do not persist complete repository copies by default. Per-job private homes,
temporary caches and registry credentials are destroyed after completion/
cancellation. Add ownership-aware stale-workspace cleanup after crashes,
scratch quotas and disk-pressure metrics; normal deferred cleanup is not
sufficient after process/node loss.

Runner image layers can be cached on the execution host. Optional resolver
caches are bounded, versioned and separated by manager/runtime/platform and
registry/tenant trust boundary; untrusted jobs cannot publish executable tools
or arbitrary data into a shared trusted cache. Private-package caches must not
cross tenants. Do not share writable package-manager homes between concurrent
jobs. Warm-cache use never skips artifact integrity checks or profile revocation.

Start with one remediation slot per worker/runner, separate from extraction
and secret scanning, plus global/per-org queue bounds. Configure CPU, memory,
ephemeral disk, deadlines and output limits per tested profile. Reuse job
leases/heartbeats and fence result publication; a cancelled or lost-claim job
must terminate its sandbox and cannot later publish a patch. Report phase time,
queue wait, checkout bytes, registry traffic, cache hits, peak memory/scratch
and failures; benchmark cold/warm runs before setting default capacities or
advertising latency. Toolchain image pulls affect cold start and node storage;
large profiles are an optional runner cost, not hidden API-pod growth.

### 3. Immutable target first; maintenance branch only when requested

Every job resolves to one immutable `base_sha` before work starts:

- **Release, default `exact`:** use the release's recorded shipped commit,
  with its release/snapshot identity. Do not follow a moved tag or change the
  release. Unresolved release divergence (ADR-024) blocks generation until
  reconciled. A patch can be generated without any maintenance branch.
- **Branch:** resolve the named branch to its current head and require the
  caller's `expected_head_sha` to match. A stale request returns a conflict;
  it never quietly generates against a newer head.
- **Commit:** support accessible, repository-bound commits, including detached
  IDE HEADs; arbitrary SHAs do not grant access to another repository.
- **Release, explicit `maintenance`:** select a maintenance branch as below,
  then pin its head. Preview both the shipped SHA and the actual patch base.
  Re-extract/rematch that base; old release findings are selection intent, not
  proof that the same vulnerable version still exists on the branch.

A branch/commit does not require an existing Hibou snapshot: extract source
and match it against the authorized advisory/triage view for this job.
Artifact-only inventory without a traceable editable source occurrence is
`unmapped_source`, not permission to guess a manifest.

A release R has a tag T, a commit C and a version V. Its **line** is the
version prefix that a maintenance branch tracks: `major.minor` by default,
`major` when configured (§4).

For maintenance mode, resolve by the following priority; ambiguity within a
step requires confirmation, not a first-name match:

1. **Declared**: `.hibou.yaml` (default branch) or the release manager's
   setting maps R's line to a branch (§4).
2. **Pattern**: branches matching `releases.branch_patterns` with R's line
   substituted. The default tries common shapes: `release/{line}`,
   `release-{line}`, `{line}.x`, `v{line}`, `support/{line}`,
   `maintenance/{line}`. A candidate qualifies only if C is an ancestor of
   its head.
3. **Default branch**: if C is an ancestor of its head and R's line is
   the newest line (no later line has been released from it).
4. **None**: offer an exact-release patch or explicit branch creation (§5).

Several qualifying candidates are shown to the user. Saving a choice as a
declaration requires a separate **Remember for this release line** action and
release-manager permission; selecting a target alone does not change policy.
When R is not the
newest release of its line, the UI says so: the fix lands on the line's
branch, not on R's exact commit.

Ancestry needs a forge call: a new `IsAncestor(ctx, owner, repo, base,
head)` on the forge interface, implemented with each forge's compare
endpoint or a bounded local Git ancestry check on authorized source. If
ancestry remains unknown, show candidates as unverified and require explicit
confirmation; never silently target a name match.

#### 3.1 Suggest a target; do not infer a support promise

For **Open pull request** on a release, first offer **Where should this fix
land?** with ranked existing-branch suggestions and **Create maintenance
branch...**. Patch download retains the exact-shipped-source default. An
explicit configured mapping can preselect a branch, but the resolved name/head
remains visible and confirmed with the publication plan. Inferred candidates
are suggestions only, never automatic forge writes.

Rank with explainable evidence, not an unexplained probability percentage:
declared mapping first; verified line-pattern match next; verified lineage
with matching release-line history next; eligible default branch last.
Use configured dependency-analysis branches only as an additional candidate
source, not evidence that they maintain this line. List evidence and
contradictions: tag ancestry, later releases/lines, name match, configuration
source and head SHA. Recent activity alone is not proof of maintenance.
Multiple plausible branches, diverged/cherry-picked history or unknown ancestry
require explicit user choice. Permit searching all accessible branches; unusual
names or non-ancestor backport branches are not forbidden, but require a
visible explanation/confirmation and source rematching. Do not silently relax
ancestry checks for automatic suggestions.

If no candidate qualifies, show **No verified maintenance branch found**,
not "this release cannot be fixed". Offer a manually chosen branch, a new
maintenance branch (§5) or an exact-source patch. Non-semver releases and
repositories with several independent version streams need explicit mappings
or manual targets when a line cannot be derived unambiguously.

Changing the PR base changes the remediation source: create a new draft and
regenerate against that base, retaining selected findings/version intent only
where revalidated. Never apply an exact-tag patch to a guessed branch head.

### 4. Release lines and maintenance: facts plus a declared policy

Hibou does not guess a maintenance policy. It shows facts for every line
and evaluates a declared policy over them; a line no rule covers is
**unknown**, never "unmaintained".

Facts per line, all already known or derived: its releases, latest
release and date, branch (if resolved), open vulnerabilities on the
latest release, and active deployments (ADR-024 clients).

Policy, in `.hibou.yaml` on the default branch, editable by a release
manager in the UI (stored per repository; the file wins when present):

```yaml
releases:
  tag_pattern: "^v\\d+\\.\\d+\\.\\d+$"
  line: minor                      # major | minor
  branch_patterns:                 # optional ordered suggestion templates
    - "support/{line}"
    - "{major}.x"
  new_branch_template: "support/{line}" # optional creation-name suggestion
  maintained:
    latest: 2                      # the newest N lines
    deployed: true                 # any line a client still runs
    lines:                         # explicit entries win over the rules
      - line: "3.4"
        branch: support/3.4-lts
        until: 2027-06-30
      - line: "2.*"
        maintained: false
```

The rule kinds map to the practices seen in the field: newest N lines,
dated support windows, "supported while deployed", and an explicit list.
An organization can set defaults that repositories inherit and override.
The UI states the source of each verdict ("maintained: latest 2",
"maintained: deployed at 3 clients", "unknown: no rule").

These branch keys are proposed configuration, not currently parsed fields.
Keep three concerns distinct:

- `dependencies.branches` already controls which extra branches get inventory
  extraction on pushes; quality-gate branch selectors control gate policy.
  Neither maps a release line to a maintenance target.
- `releases.branch_patterns`, explicit line mappings and
  `new_branch_template` describe remediation intent/suggestions. Templates
  support validated `{line}`, `{major}` and `{minor}` tokens where available,
  with Git-ref validation after expansion; unmatched tokens are an error.
  A creation template does not force any `release/*` naming convention.
- ADR-052's operator `release_branch_patterns` is a forge-write allowlist,
  not a target-discovery setting. Repository configuration cannot grant
  write capability or expand that allowlist.

Reuse shared branch pickers/pattern helpers where semantics match, not one
configuration value for these different decisions. With no naming config,
common-name suggestions still work and the branch picker always permits
manual selection. Offer adding an explicitly confirmed mapping to the UI
settings or a configuration PR; do not silently edit the default-branch file.

The useful warning falls out of the facts, policy or not: **deployed but
unmaintained**, a line clients run that no rule keeps alive.

"Fix all maintained lines" later produces one job/patch per distinct target
base, each with its own policy and failures, not one patch spanning commits.
Optional publication opens one PR per target; unresolved lines remain visible.

### 5. Creating a release branch

Patch generation never creates a branch. In the explicit publication workflow,
when step 4 of §3 is reached, the user can create the line's branch from
the newest tag of that line (not necessarily R), named by
`new_branch_template` (with an editable suggested name, not a mandatory
`release/*` prefix). This is an exception to the
normal `hibou/**` write namespace: it requires the operator's separate
release-branch allowlist and the checks in ADR-052, not an unrestricted call
to the existing `CreateBranch`. Only admins and release managers may do it (same Casbin
role as ADR-024's lifecycle endpoints). The branch is created before the
PR and recorded in publication provenance; saving it as the line's declared
branch requires the explicit remember action in §3. Branch protection is the
team's business; Hibou only opens a PR into it.

Preview the chosen starting tag/release and immutable commit. Default to the
newest release of that line, but show when it differs from the release being
viewed and allow explicitly selecting the viewed release's recorded commit.
Changing this source invalidates the plan and requires regeneration. Refuse
an existing branch-name collision unless the user switches to that branch
as an existing target and regenerates; never reset or repoint it.

Distinguish two branches: the **maintenance target**, such as `stable-3.4`,
and the **Hibou proposal branch**, such as `hibou/fix-stable-3-4-<digest>`.
Normally Hibou creates only the latter and opens a PR into an existing target.
Creating a previously absent maintenance target is a separate confirmed write,
gated by release-manager rights, ADR-052 consent/allowlist and actual forge
protection rules. If disallowed, keep download available and explain the
missing installation capability; do not instruct every repository to create
a CI workflow. Never create/move a release tag, merge or publish a release.
Publication records each successful side effect so a PR-creation failure after
branch creation can be retried without duplicate branches; do not delete or
repurpose a branch automatically during recovery.

### 6. Optional publication, after patch review

The default product needs no forge writes. Publication is a separate explicit
action on an already reviewed immutable artifact, gated by ADR-052's Propose
tier, organization consent and current repository permissions. Recheck the
target branch head; a moved base requires regeneration and another preview.

- **Commit**: one commit with every changed file. A new forge method
  `CommitFiles(ctx, owner, repo, branch, message, files)` uses each
  forge's multi-file API (GitHub git trees, GitLab commit actions,
  Gitea/Forgejo change-files). `CreateOrUpdateFile` per file remains the
  fallback only if partial publication cannot expose an incomplete change;
  otherwise report that atomic multi-file publication is unsupported.
- **Branch name**: `hibou/fix-{target-slug}-{digest}` by default, with exactly
  one slash. The shared `BranchName` helper hashes the original target,
  immutable base and patch digest so slug collisions cannot alias proposals. A
  request whose artifact/base matches an existing Hibou PR reuses it instead
  of opening another (needs a `FindPullRequest(head, base)` forge method).
  Encode/sanitize target names with a collision-resistant suffix and validate
  full ref length/syntax. Never overwrite user commits, force-push or update a
  previously reviewed PR with different bytes without explicit fresh review.
- **Body**: per patch, the packages and versions changed, direct or
  transitive, the vulnerability IDs fixed with severity, KEV and EPSS
  (ADR-032, ADR-038), introduced IDs if the user allowed any, and the
  unactionable ones with why. Generated from Hibou's normalized plan, not an
  engine-specific `result.Result`, so all clients produce the same text.
- **Link back**: the findings fixed by the PR show it; the next scan of
  the merged branch resolves them through the normal presence rules
  (ADR-034). Nothing is marked fixed when the PR is opened.
- **Permissions**: maintainers of the repository open PRs; creating a
  branch needs release manager (§5). Every request is audited.

Publication requires repository-scoped content/PR write capabilities,
organization consent and caller permission; possessing an App installation
alone is insufficient. Report effective actions/reasons in capability discovery.
Use an idempotency key and fenced publication operation with durable states
for target creation, proposal commit and PR creation; expose created refs/PR
URLs and recoverable errors. Cancel before writes where possible; after a
write, report what happened rather than promising a rollback.

No background scheduler or recurring bot is required for this feature.
After the user chooses **Create branch and PR**, Hibou performs the authorized
forge steps itself. It may reuse a reviewed artifact from either managed or
local generation. Local IDE publication requires explicit upload of that
artifact and authorized source/base/graph verification before the server
writes; do not accept an arbitrary client diff as a trusted remediation result.
Alternatively the developer may explicitly push with their own credentials;
that is a distinct capability/path, not a silent fallback from a denied App.

### 7. Prepare a draft, resolve choices, then freeze an artifact

Proposed paths are relative to the existing repository API prefix
`/api/v1/orgs/{provider}/{slug}/repos/{repo}`:

| Operation | Contract |
| --- | --- |
| `GET .../remediations/capabilities` | Allowed actions, SCALIBR version, tested manager/version/lock-format/workspace/strategy tuples, version-choice support, safe execution modes and limits with structured reasons |
| `GET .../remediations` | Authorized, cursor-paginated recent drafts/jobs with target, status and expiry; supports resuming without storing source in browser state |
| `POST .../remediations` | Validate access/capability, pin target and selection, enqueue discovery; `202` with draft/job ID and status URL. No branch, PR or finding mutation |
| `GET .../remediations/{id}` | State/phase, draft revision, normalized preview, change units, per-item results, verification and artifact metadata |
| `GET .../remediations/{id}/candidates?change_unit_id=...` | Bounded/paginated version candidates for a draft unit, including automatic and Gossip proposals, signal/policy evidence and pending graph checks |
| `PATCH .../remediations/{id}` | Save version choices, exclusions and permitted policy changes on an editable draft with `If-Match` revision; invalidate affected proposals, never mutate an artifact |
| `POST .../remediations/{id}/generate` | Freeze the reviewed draft revision and exact choices; `202` for combined resolution, file generation and verification |
| `GET .../remediations/{id}/patch` | Download the immutable patch when available; explicit not-ready, failed or expired response otherwise |
| `POST .../remediations/{id}/cancel` | Cancel a queued/running job; clean up execution resources |
| `GET .../remediations/targets?release_id=...` | Authorized, bounded target suggestions with head SHAs, ranking evidence, warnings and permitted maintenance-branch creation options |
| `POST .../remediations/{id}/pull-request` | Separately authorized, idempotent publication of the reviewed artifact; requires expected target head and artifact digest, or explicit maintenance-target creation name/source SHA |
| `GET .../release-lines` | Later, maintenance facts and policy verdicts (§4) |

Example preparation request from an IDE (illustrative schema, not implemented):

```json
{
  "target": {
    "kind": "branch",
    "name": "support/3.4-lts",
    "expected_head_sha": "<full commit SHA>"
  },
  "selection": {
    "mode": "selected",
    "occurrences": [
      {
        "manager": "npm",
        "manifest_path": "package.json",
        "purl": "pkg:npm/example-package@1.2.3",
        "advisory_ids": ["CVE-YYYY-NNNN"]
      }
    ]
  },
  "policy": {
    "upgrade_level": "minor",
    "no_introduce": true,
    "allow_partial": false
  }
}
```

Discovery returns server-assigned `occurrence_id`, `resolution_unit_id` and
`change_unit_id` values bound to this draft/base. These distinguish duplicate
packages and coupled graph nodes without exposing upstream object identities.
Clients submit choices by change unit, for example:

```json
{
  "version_choices": [
    {
      "change_unit_id": "unit-a",
      "mode": "exact",
      "version": "1.2.8"
    },
    {
      "change_unit_id": "unit-b",
      "mode": "gossip",
      "candidate_id": "candidate-b"
    }
  ]
}
```

Omitted units default to `automatic`; resetting a choice explicitly saves
`{change_unit_id: "...", mode: "automatic"}`. Gossip candidate IDs are
draft-scoped and resolve server-side to an immutable package/version/source
snapshot; clients cannot label an arbitrary version "recommended".
Candidates carry `version`, `source`, `fetched_at`, `policy_decision`,
`policy_evaluated`, `warnings`, `addresses_selected_advisories` and
`graph_validation` (`pending`, `passed`, `conflict`, `unsupported`) plus
structured reasons. Cheap metadata checks can pass before graph validation;
do not return one ambiguous `safe: true` flag.

Do not fully resolve the graph on every keystroke. Fetch curated candidates
first; lazily page published versions through approved metadata clients and
validate a typed version on commit/blur using the candidates endpoint's optional
exact `version` query. Metadata lookups are bounded,
cancellable and cached with provenance. The final Generate request supplies
the expected revision (via `If-Match`) and acknowledged warning IDs; the
server verifies both. Candidate/preflight checks are not a substitute for
final combined resolution and post-generation verification.
Before freezing the draft, recheck the branch head and mandatory inputs;
a moved target or invalidated policy/recommendation snapshot requires a
refreshed draft and confirmation, not an unnoticed target/version change.

Toolchain selection uses a server-issued `toolchain_profile_id`, never a
client-supplied executable/image URL. Capability and draft responses report the
exact tuple, selection evidence, runner availability, distribution mode and
missing offline artifact IDs from §2.3–2.4. Draft edits may select a compatible
approved profile; that invalidates resolution/verification and requires
generation again. Generation freezes the profile digest along with version
choices. Distinguish no compatible toolchain (`toolchain_unavailable`),
conflicting pins (`toolchain_conflict`), revoked/changed identity
(`toolchain_mismatch`) and incomplete disconnected data (`offline_data_missing`).

Draft edits are allowed only while `awaiting_selection` or a recoverable
`blocked` state before an artifact exists. No editing a generating or finished
job. A ready/failed generation is immutable: **Revise choices** creates a new
draft with `based_on: "<job id>"`, retaining valid choices but revalidating all
inputs. Changing repository/target always creates a new draft and reruns
discovery. A second browser/IDE editing the same draft gets a revision conflict
and a compare/reload action, never last-writer-wins loss of choices.

Release targets use `{kind: "release", id: "...", mode: "exact"}` by
default; maintenance mode additionally requires confirmation of the resolved
branch/head. Commit targets use `{kind: "commit", sha: "..."}`.
Selection is either explicit occurrences or `all_actionable`; reject empty
explicit selections. Resolve caller policy against operator/repository limits;
clients cannot relax a mandatory policy. Expose supported managers and
execution modes so clients do not assume extraction coverage means fix coverage.

Target suggestions are read-only and never create refs. Publication target
creation is an explicit tagged choice (existing branch versus new maintenance
branch), not a `create_branch: true` flag with an inferred name/source. The
new branch's source SHA must equal the reviewed artifact base. For existing
targets, recheck head equality immediately before publication and use
conditional forge operations where available; a concurrent target advance is
reported as stale, never represented as the reviewed base.
External forge races cannot be made transactional with Hibou's database;
reconcile the resulting refs/PR base and expose drift rather than claiming
an atomic cross-system transaction.

Jobs are `queued`, `running`, `awaiting_selection`, `ready`, `no_changes`,
`blocked`, `failed`, `cancelled` or `expired`; `running` additionally names
`discovering`, `resolving`, `writing` or `verifying`. Discovery ends at
`awaiting_selection` unless there are no changes or a blocking condition.
`ready` means a patch exists, not that every
vulnerability is fixed or every test passed. By default any selected item that
cannot be addressed blocks a downloadable batch; `allow_partial` must be
explicit and the preview/download labels then say **partial**. Independent
unsupported modules may be omitted only in that mode; a failed/shared graph
cannot yield a supposedly valid partial lockfile.
Omitting a required parent/collateral change is not a partial-resolution
option: remove the dependent fix from the selection or resolve its graph.

Structured errors use stable codes such as `target_moved`, `draft_conflict`,
`unsupported_strategy`, `exact_version_unsupported`, `version_not_found`,
`constraint_conflict`, `policy_denied`, `policy_not_evaluated`,
`registry_unavailable`, `unsupported_lockfile`, `ambiguous_package_manager`,
`relock_failed`, `lockfile_inconsistent` and `verification_failed`, with affected unit IDs,
human-readable detail and permitted next actions. Use normal HTTP semantics:
validation errors are not success responses, revision/head conflicts are
conflicts, and quota/rate-limit responses include retry guidance. A job that
fails asynchronously exposes its failure explicitly in the status resource.

The preview includes:

- repository identity, requested ref/release, resolved `base_sha`, source tree
  identity, advisory/triage/policy revisions and engine/toolchain versions;
- per module/package: old/new versions, direct/transitive relationship,
  why a parent or collateral package changes, addressed advisory aliases,
  remaining/new findings and structured unactionable reasons; choice mode,
  requested exact/recommended version, resolved version, declaration edits
  and recommendation/policy provenance;
- changed paths, before/after hashes and file modes, patch byte count/SHA-256,
  expiry and validation results (`passed`, `failed`, `not_run`, `unsupported`).

For each resolution unit, include `required_files`, detected manager/version,
lock format and individual `lock_consistency`/graph verification results with
sanitized diagnostic references. A required consistency check cannot be
`not_run`, `failed` or `unsupported` in a ready artifact. Keep these mandatory
results separate from optional build/test checks, whose `not_run` is valid.

Produce a single standard Git diff against the pinned base, with manifests
and their required lockfiles/workspace metadata together. Validate it with
`git apply --check` against a clean copy of that base. No commit metadata is
needed (`git apply`, not `git am`); never interpolate filenames into a shell
command. Reject paths outside the source root, symlink escapes, submodule
edits, binary diffs, unexpected executable-mode changes and unrelated files.
Run Git with hooks, external diff, textconv and unsafe repository config
disabled. Bound patch size and changed-file count.

Creation and Generate accept idempotency keys, scoped to actor/repository,
operation and normalized inputs; retries do not duplicate jobs/generation,
and reusing a key with different inputs is a conflict. Any result cache also
keys version choices, recommendation snapshots, immutable base, policy,
advisory/triage inputs and engine versions, and never bypasses current access
checks. Downloads use normal repository authorization, not a public artifact
URL. Patches contain proprietary source context: use private storage, bounded
retention/expiry, no patch bodies or credentials in logs, and audit creation,
download and publication. Recheck organization/repository binding and access
for every job operation; inaccessible jobs must not leak cross-tenant metadata.

Patch generation is a bounded, audited computation over already authorized
source, not a repository-write permission. For API tokens, define a dedicated
repository-scoped remediation-generation capability under ADR-020 rather
than silently extending existing read-only/IDE tokens to expensive jobs.
Publish requires a separate write capability plus forge checks. Apply normal
session CSRF protection, per-user/repository concurrency limits and quotas;
cancellation and retries must use fenced job claims. GET status includes a
bounded polling hint and phase timestamps; disconnecting a client is not
cancellation. Use existing job observability patterns, not an additional
WebSocket service just for this workflow.

### 8. Release page, IDE and CLI

#### 8.1 Shared interaction model: prepare, choose, review

Use one durable remediation workspace, not a stack of nested finding dialogs
or a mandatory long wizard. The same mental model in both clients:

1. **Prepare:** confirm target and selection; discovery pins the source and
   groups findings into editable change units.
2. **Choose versions:** automatic proposals are populated by default; change
   only the exceptions. Candidate checks are labelled preliminary.
3. **Generate and review:** resolve the combined batch, inspect the actual
   diff/evidence, then download or explicitly apply it.

Generation never changes the repository. Review is an intentional boundary,
not a modal that disappears into an automatic apply. Keep draft choices,
selection and scroll position across navigation; durable server drafts allow
reopening from a recent-jobs link. Unsaved input is visibly unsaved, and failed
draft saves cannot masquerade as persisted choices.

Always distinguish **findings**, **package occurrences**, **change units** and
**files**. For example, "12 selected findings -> 4 dependency changes in 2
modules", not "12 fixes". Post-generation counts describe observed results:
"10 selected findings addressed; 2 remain; tests not run". Alias duplicates
are not counted twice. "Addressed" refers to this proposed source tree, not
the shipped release.

#### 8.2 Website entry points and layout

- **Releases:** add **Generate fix patch...** to each release's actions and
  expanded details, without hijacking the row's expand/collapse click.
  Default to **This release's source** with tag and recorded SHA. The optional
  **Maintenance branch** choice shows a different branch/head and explains
  that it is not the shipped tree. Keep the Releases tab's independence from
  the analysis ref selector (ADR-024).
- **Vulnerabilities:** add **Prepare dependency fixes** to the existing
  batch-selection bar. Explicitly show selected eligible dependency findings
  and excluded SAST/secret/unmapped items. "Select all matching" freezes the
  full server-side selection and count across pages; a limit requires narrowing
  the selection, never silently patching the first page or first N rows.
- **Finding drawer:** add **Prepare fix** in dependency remediation details,
  beside the existing "Fixed in" and "Suggested by deps.dev" evidence. Selecting
  either version preselects a choice in the shared workspace, not an immediate
  manifest edit. Advisory fixed boundaries still need resolver validation.
- **Dependencies:** package actions open the same workspace only where there
  are actionable findings; ordinary non-security upgrades are not silently
  included in this feature.

The workspace is a routed repository subpage (proposed
`.../remediations/:id`), not a narrow modal on top of a drawer. Entry actions
can show a compact target/selection confirmation before creating the draft.
Keep a breadcrumb back to the originating release/ref/filter, and a persistent
target strip with repository, release/branch, short SHA (full SHA on demand)
and execution mode. Selection filters are only display controls after discovery;
they never silently change the submitted batch.

On desktop use a dense change table and contextual side inspector:

```text
api / v3.4.2 / a1b2c3d       This release's source       Remote worker
12 findings selected       4 change units / 2 modules

Dependency / module   Current   Target choice              Result
package-a / web       1.2.3     Automatic -> 1.2.8          Check pending
package-b / web       2.0.1     deps.dev -> 3.0.0            Major blocked
package-c / service   3.1.0     Exact: 3.1.7                Check pending

[Reset choices]                 [Generate patch]
```

Versions here are illustrative, not claims about the named engine. A row
expands into affected findings, dependency paths, direct-parent implications,
constraints, target rationale and linked occurrences. Required collateral
changes are labelled **Required by this fix**, not independently removable
checkboxes. Group by resolution unit/module so shared-lockfile coupling is
visible before the user makes incompatible choices.

The inspector's target picker has three labelled modes, not an overloaded
version dropdown. Show Automatic's concrete proposal/rationale; show the
Gossip suggestion with source/age and **not project-validated** until checked;
offer a searchable published-version list plus **Enter exact version**.
Display per-candidate evidence: advisories addressed/remaining, upgrade level,
cooldown end, policy verdict and compatibility status. Keep blocked choices
visible with explanations; do not omit them and leave users guessing.
Use **Suggested by deps.dev**, not an unqualified **Recommended / Safe**.

Changing a choice marks affected units **Needs resolution**, preserving other
edits; it never leaves an old green result attached to new input. Allow
**Reset this choice** and **Reset all to automatic**. A batch shortcut may
choose **Use available deps.dev suggestions** only after summarizing the
specific versions/unsupported units; never overwrite existing exact choices
without explicit confirmation. No bulk text version applied across unrelated
packages.

After generation the same workspace has **Summary / Changes / Unresolved**
views: a unified/split diff, file tree, requested-versus-resolved versions,
collateral changes and check results. Download is the primary web action;
**Open in IDE** is optional when a supported client handoff exists, otherwise
offer a copyable `hibou fix apply ID` command with no embedded credentials.
Do not invent an unregistered IDE URI scheme. **Create branch and PR** is
an available alternative when authorized, not a feature postponed behind
multi-line automation. It shows the exact target and proposal branches before
confirmation; denied capabilities leave download usable with a clear reason.

Both web and IDE review show the detected manager/lock format and complete
dependency-file set per module/workspace. Display **Dependency files
consistent** only when mandatory verification passed, separately from
**Build/tests not run**. Relock failures show the affected manager, files,
failed phase and a sanitized diagnostic with retry/local-execution guidance.
There is no "Download anyway" or "Apply manifest only" escape for a failed
required lockfile; local execution is offered only for a supported strategy.

The target strip also shows **Toolchain: manager@version / runtime@version**
and **Local / Isolated runner / No tool execution**, with a disclosure for
profile digest and why it was chosen. Missing profiles/data link to an
operator-facing provisioning report, not an installer prompt. Fully disconnected
mode is explicit. Changing a profile never changes package-version choices
silently, and neither generating nor opening a draft downloads executables.

On narrow screens the inspector becomes an inline expandable row and the diff
is a full-width view. Reuse existing Hibou surfaces, typography and semantic
tokens: calm density, one focal action, no new visual brand. Warnings use
text/icons as well as color, and normal selection is not a success badge.

#### 8.3 IDE: native entry points, one shared planner

VS Code calls through the CLI/LSP (ADR-042), not a second planner in
TypeScript. Add **Hibou: Prepare Dependency Fixes** to the command palette,
the findings panel's selected-dependency actions, and a manifest diagnostic's
**Prepare dependency fix...** code action. All open a dedicated **Dependency
Fixes** review tab with the same change-unit/version-choice model. A lightbulb
must not immediately rewrite dependencies.

The findings panel supports multi-selection across dependency findings and
**Prepare batch fixes** (including a confirmed all-matching selection); the
command also allows choosing affected modules rather than fixing only the
active diagnostic. Use the same change-unit/version controls and shared-lockfile
rules as the website. After review, offer **Apply locally**, **Export patch**
and, when authorized, **Create branch and PR with Hibou**. The latter uses
the release/branch target picker and explicit local-artifact upload boundary
in §6; it need not modify or push the current working tree.

Use the existing IDE findings panel as the entry point; do not add a competing
activity-bar product. Use native theme/accessibility tokens in the review tab,
native progress/notifications for lifecycle events, and native read-only diff
editors for generated files. Avoid a chain of Quick Picks that loses graph
context; Quick Picks are acceptable for choosing a repository in multi-root
workspaces or an initial target, not for reviewing a batch.

The target header always shows the actual repository root, branch or detached
HEAD and exact SHA. Never mix repositories in one batch. Detect current HEAD
when opening and immediately before generation/apply. If findings came from an
older snapshot, say so and rematch committed HEAD; do not present old finding
counts as current. An unpushed/inaccessible HEAD offers local generation with
explicit toolchain/execution consent, not an automatic source upload.

Prefer **Local tooling** when a supported manager/runtime is already installed
and matches the selected toolchain requirements. The CLI/LSP discovers and
verifies those tools; the UI shows their exact versions/paths and obtains
workspace trust/execution consent before running them. No separate daemon,
repository scripts or CI installation is required beyond the existing Hibou
extension/CLI. Do not automatically install missing managers or bootstrap
versions from repository config.

Generate in a temporary local checkout at committed HEAD, not directly in
the working tree; reuse approved local metadata/package caches safely and
allow native registry credentials only under the developer's explicit local
execution trust boundary. Keep credentials out of the plan/logs and scope
network access to approved endpoints. Generation remains separate from Apply.
No source or generated patch is uploaded by default: fetch authorized advisory/
policy inputs as needed (or use supported offline exports), resolve/write/
verify locally, and produce the same normalized plan/patch contract.

Use the shared Go planner/validators in-process through CLI/LSP, not a local
HTTP server. Local drafts/jobs are stored in the user's private application
state with the same revision, provenance, expiry and cancellation semantics;
they are not fabricated server job IDs and do not require REST draft creation.
Job handles explicitly identify `local` versus `managed`, and the CLI/LSP
routes requests accordingly. A copied local handle is not a web-shareable job.
Before optional publication, require explicit artifact transfer/consent and
normal server authorization; no silent sync of proprietary source context.

If local tools are missing/incompatible, show the reason and offer **Use
managed runner** for a server-accessible committed target, or operator-approved
tool provisioning guidance. Never switch execution location or upload source
without confirmation. Choosing managed generation then uses the shared REST
API. An unpushed commit stays local unless a separate explicit source-transfer
feature is designed; no such upload is implied here.

Choose **Current committed HEAD** by default. Local changes and unsaved buffers
are never part of a remote request. Show a persistent note if the workspace is
dirty; unrelated edits need not block remote preparation, but affected paths
must pass the apply checks below. No automatic save-all, stash, checkout,
credential elevation or snapshot upload. Remote generation may continue after
the tab closes; **Cancel job** is separate from **Close tab**.

Keep HTTP auth, polling, policy, version interpretation, artifact verification
and execution in the shared CLI/LSP. Add capability-negotiated requests
(proposed `hibou/remediationPrepare`, `hibou/remediationGet`,
`hibou/remediationCandidates`, `hibou/remediationUpdate`,
`hibou/remediationGenerate`, `hibou/remediationCancel`,
`hibou/remediationApply`) using ADR-042's existing protocol handshake.
Requests carry an explicit workspace root and job/revision, not an inferred
active editor. Fall back to the browser with an upgrade explanation when the
server/client lacks support. The same contract can serve IntelliJ without
reimplementing resolution logic; client-specific presentation belongs to the
IDE repository.

#### 8.4 Apply and completion

**Apply patch to working tree** is the IDE's explicit primary completion action,
enabled only after a ready artifact is reviewed and local preconditions pass:
verify digest, repository and exact base HEAD; check index/working-tree hashes,
unsaved editor buffers and path/file-mode safety for every affected file; run
the dry-run apply check. Apply all files as one operation, never `--reject`,
partial application or a silent three-way merge. Prevent duplicate in-flight
applies and coordinate editor-buffer versions/file saves with the apply operation;
if a precondition changes, abort without clobbering user edits.

Keep the UI in an applying state until the local operation is acknowledged;
an interrupted response is **outcome unknown**, not an invitation to retry
blindly. Reconcile all affected file hashes against the artifact before offering
a retry: fully matching output is **Already applied**, mixed output requires
inspection, and unchanged input may be retried after normal preflight.

On success show **Applied locally - review in Source Control** with affected
files and **Build/tests not run** where appropriate. Do not claim the release
or findings are fixed, auto-commit or auto-push. Preserve the plan/diff so the
developer can inspect it after applying. Revert uses the developer's normal
Source Control workflow, not an automatic destructive rollback. Web completion
says **Patch downloaded**, not **Fix applied**.

CLI generation uses the same prepare/choice/generate API and artifact contract:
proposed `hibou fix --release V --output fix.patch` or
`hibou fix --branch B --output fix.patch`; `--local` runs the contract locally.
Non-interactive mode defaults to Automatic, reports all resulting versions
and blocks unacknowledged major/partial choices. Exact/Gossip CLI overrides
must identify a manifest/change unit, not an ambiguous package name.
`hibou fix apply ID` retrieves, previews and applies an artifact; pushing/PR
creation is separate opt-in using the developer's credentials (ADR-052).
A downloaded patch remains usable without the CLI:

```bash
git switch --detach <base_sha>   # or use a clean worktree at that commit
git apply --check fix.patch
git apply fix.patch
```

#### 8.5 Non-happy paths, accessibility and performance

| State / problem | Required feedback and action |
| --- | --- |
| No actionable dependency findings | Explain the selection; no empty successful patch |
| Unsupported manager/strategy/version mode | Name the limitation and show manual guidance; local mode is offered only if it actually supports that strategy |
| No source mapping / moved release tag | Show missing evidence or divergence; link to the existing inventory/release-resolution workflow |
| Registry unavailable / discovery failure | Keep saved choices, show failing phase and sanitized reason, offer bounded retry |
| Exact version conflicts | Name the selected version, unit and conflicting parent/constraint; offer candidate alternatives or reset to Automatic, never replace it automatically |
| Suggestion missing or not evaluated | Explain absent/private/offline/stale evidence; allow other modes subject to policy, never label unknown as safe |
| Shared-unit target conflict | Highlight all linked rows and require one coherent selection |
| Branch/head or mandatory policy changed | Mark the plan stale, offer a new draft with revalidated choices; no forced apply |
| Some selected fixes impossible | Block download by default; offer **Generate partial patch** only with an explicit remaining-findings summary and permission |
| Client disconnected / permission expired | Reconnect/re-auth and reload authorized job state; do not automatically rerun generation or elevate token scope |
| Quota / no isolated runner | Explain retry timing or the supported local alternative |
| Artifact expired | Retain permitted audit metadata, offer regeneration; no broken download link masquerading as ready |

Use keyboard-operable rows/pickers, labelled fields, focus restoration when
an inspector closes, and a focusable error summary linking to affected units.
Announce phase changes with restrained live regions, not every polling tick.
Do not rely on hover-only disabled-button tooltips; limitations need readable,
focusable explanations. Expose read-only diffs as accessible text and respect
reduced motion. Long lists/diffs use pagination or accessible virtualization,
with totals; hidden/offscreen rows must not disappear from the batch.

Progress shows real phases (discover, resolve, write, verify), elapsed time
and cancellation, not fabricated percentages or an unverified ETA. Separate
candidate metadata from expensive combined resolution; cache shared graph and
registry work, debounce/cancel superseded lookups, and bound polling/concurrency.
Navigating away does not lose a job. Disabled actions explain whether the
cause is permissions, missing capability, unsaved choices, pending resolution
or stale evidence, rather than one generic "cannot fix" message.

### 9. Verify resolution, then report the limits of the evidence

**Manifest/lockfile consistency is mandatory, not an optional test.** A ready
patch contains the complete consistent dependency-file set for every included
resolution unit, whether npm, Python or a future ecosystem. It may be
manifest-only or lock-only only when that is valid for the detected workflow;
it must never leave a required file missing, stale or deliberately omitted.

Before making a patch downloadable:

1. **Validate the baseline:** identify and parse required inputs, detect
   existing manifest/lock drift and unsupported formats, and record file
   hashes/manager/toolchain identity. Do not silently repair pre-existing drift
   as collateral remediation; explain the prerequisite or include such repair
   only as a separately reviewed supported workflow.
2. **Generate in a disposable workspace:** retain originals, apply the
   combined changes and observe every required write/relock step. Missing
   tools, nonzero exits, timeouts, lost claims and cancellation fail the job,
   even when SCALIBR's outer return value appears successful.
3. **Check the output contract:** parse every required output, verify existence
   and expected lock format, validate manifest constraints and workspace links,
   preserve/validate required integrity hashes, markers and platform metadata,
   and verify all requested exact targets. Do not treat a file timestamp or
   non-empty lockfile as proof of correctness.
4. **Use manager-native strict validation where required:** a frozen/locked
   consistency check or its manager-specific equivalent must pass in the
   permitted execution environment, without silently rewriting the reviewed
   files. Record commands/checks and supported target environments. If a second
   lock-generation pass is used as the consistency check, require no further
   dependency-file changes under the same captured inputs. A format without
   an adequate independent verifier is unsupported until that gap is closed.
   Pure lockfile strategies may use a proven independent graph/format validator
   instead of executing a package manager; parser success alone is insufficient.
5. **Verify the final graph, not just manifest declarations:** extract the
   actual locked versions where present, compare to the baseline and selected
   targets, check all included occurrences and rematch vulnerabilities/policy.
   Record supported platform/feature/marker coverage and unknowns rather than
   treating one resolved environment as universal evidence.
6. **Publish atomically:** only after every required check succeeds, store
   the immutable patch and mark the job ready. Before that, candidate diffs
   are non-downloadable previews, not reusable patch artifacts. Failure
   produces an explicit phase/reason and no ready/downloadable artifact.

`allow_partial` can exclude whole independent unsupported/blocked resolution
units only after explicit review. It cannot waive consistency checks, omit a
failed lockfile in an included unit, or publish half a workspace update.

Re-extract and rematch the changed dependency graphs against the same pinned
advisory view, then revalidate against current mandatory policy/advisory data
before publication. `no_introduce` fails closed if resolution is incomplete
or matching cannot establish the comparison. A newer advisory/policy revision
requiring different changes makes the artifact stale; regenerate it rather
than modifying reviewed bytes.

Report dependency-file/lock consistency separately from application checks:
the former must pass for supported locked workflows. Build/tests are optional, separately trusted
runner/CI steps: mark them `not_run` unless executed successfully. Do not
equate "Git-applicable" with "build passes", or source findings with artifact
coverage. If a security fix requires application-code changes or unsupported
tooling, report it as blocked/manual work.

Generating, downloading, applying or opening a PR never marks findings fixed.
Normal post-change scanning and presence rules (ADR-034) remain authoritative;
shipped artifacts/deployments stay affected until rebuilt/released and scanned.

## Rollout

1. **SCALIBR compatibility/version-control spike:** exercise npm, Maven and
   the supported Python formats on authorized checkouts. Include two vulnerable
   packages sharing a lockfile, transitive/parent upgrades, incompatible
   constraints, major-only fixes, private mirrors, no-fix cases and introduced
   advisories. Verify the actual strategy-specific automatic targets, manual
   exact targets, Gossip choices and preservation of declaration style. Record
   where upstream extension work is needed; do not advertise unsupported modes.
2. Prove pure-file strategies versus isolated/local relocking, combined batch
   correctness and post-resolution exact-target enforcement. Record supported
   manager/lockfile/version combinations, file preservation, cold/warm latency,
   peak memory, registry traffic, deployment footprint, credential isolation
   and egress behavior. Go and other unsupported ecosystems get honest
   limitations, not a speculative second engine. Cover npm, pip-tools, Poetry
   and Pipenv locked workflows independently; recognition of Yarn/pnpm/Bun,
   uv/PDM/pylock, Cargo, Composer, Bundler, NuGet, Gradle and Go files must
   produce honest unsupported/ambiguous results where no validated strategy
   exists, never manager substitution.
   Verify preprovisioned profiles on each advertised architecture; no package
   managers/runtimes/shell enter the ordinary server/worker images. Test exact
   pins, conflicting declarations, ranged/default profile selection, runtime
   incompatibility, old release profiles, revoked digests and absent profiles.
   Test connected and mirror-only preparation/import plus truly network-denied
   execution with complete and deliberately incomplete offline metadata/package
   closure. Assert no bootstrap, telemetry, public fallback or repository-
   supplied executable runs. Exercise bounded cache isolation, crash cleanup,
   resource exhaustion and claim-loss termination before enabling managed runners.
   Deliver the installation-level managed runner integration for the initial
   supported locked workflows before declaring API/UI generation ready.
3. Implement normalized plans, fenced jobs, authorization/quotas, private
   immutable artifacts and the API. Test patch application and full resulting
   file bytes, not just version strings; include shared-graph conflicts,
   conflicting exact versions in a shared unit, rejected/stale Gossip targets,
   unknown policy evidence, stale draft revisions/heads, moved tags, duplicate
   Generate requests, expiry/cancellation and cross-repository access denial.
   Inject relock nonzero exits and missing tools, library-success/subprocess-
   failure, deleted/stale/malformed lockfiles, shared-workspace drift,
   incompatible peer requirements, hash/marker loss and strict-validator
   failure. Each must prevent a ready patch, including with `allow_partial`
   for that same resolution unit. Include valid lock-only and intentionally
   unlocked workflows as positive cases.
   Exact-release and arbitrary-branch targets
   do not depend on maintenance policy or forge writes.
4. Wire the routed web review workspace, release/finding/bulk entry points and
   CLI/LSP/IDE choice/preview/apply flow to the same API. Exercise keyboard-only
   use, narrow layouts, large batches, reconnect/resume, mixed eligibility,
   partial opt-in, revision conflicts and accessible error recovery. Verify
   no source upload for local edits, no applying over dirty affected files or
   unsaved buffers, and no lost edits/false success on interrupted apply.
   IDE-client work belongs to its repository.
   Acceptance includes an enrolled repository with no Hibou CI workflow,
   generation scripts or repository-local agent: website and IDE can generate
   and retrieve a validated patch using installation-managed execution alone.
   Missing runner capacity reports an installation readiness problem with an
   operator action, not instructions to create a pipeline.
   Separately verify the preferred IDE local path with compatible preinstalled
   tools, including unpushed HEAD: no REST job/source/patch upload, no working-
   tree modification during generation, identical validation requirements,
   consent/cancellation and a reviewed Apply. Missing local tools must not
   trigger automatic install or an unconfirmed switch to managed execution.
5. Deliver single-target branch suggestions/manual selection, configurable
   mappings/naming, confirmed maintenance-target creation and authorized
   branch/PR publication from both web and IDE under ADR-052. Test unusual
   branch names, ambiguous/no ancestry, moved heads, non-semver releases,
   collisions, permission/allowlist denial, local artifact verification,
   duplicate publication requests and recovery after partial forge writes.
   Download and local apply remain available independently of forge writes.
   Broader maintenance-policy automation and all-maintained-line orchestration
   can follow; they do not postpone single-release PR creation.

## Consequences

- Patch-first delivery works with read-only forge access. Write permissions
  are needed only for optional branch/PR publication, never to download a patch.
- The initial engine is the existing Go SCALIBR dependency, not an embedded
  Renovate/Dependabot service. Its remediation imports and any required
  toolchains still have a measurable footprint; do not call it zero-cost.
- Coverage is deliberately limited to validated SCALIBR strategies. Exact
  version/Gossip selection needs a Hibou integration boundary and possibly
  upstream work; it is not already provided by `UpgradeConfig`.
- Approved registries/mirrors remain necessary. Disconnected installations
  need resolver data as well as an advisory export.
- Keep the shell-free runtime and same-binary pure workers; preprovisioned
  managed toolchain runners carry package-manager/runtime weight for locked
  workflows. This is installation infrastructure, not a process each repository
  team must assemble.
  Exact toolchain selection, offline closures and profile lifecycle are
  operational responsibilities, not per-request installer behavior.
- IDE generation reuses compatible local tools by default after consent,
  reducing managed-runner load and keeping unpushed source local. Shared
  planner/validation contracts do not require local execution to call the
  server's job API or upload a patch.
- One patch per base is simple to review/apply, but not a promise of one
  patch that fixes every release or every unfixable vulnerability.
- The maintenance policy is a new piece of configuration; with none set,
  every line shows as unknown and the feature still works per branch.
- The prepare/choose/generate boundary adds draft state, but avoids expensive
  resolution per keystroke and makes human choices durable and auditable.
- Upstream library APIs are compatibility risks; pin versions and rerun
  corpus/contract tests on upgrades.

## Alternatives considered

- **CI-first patch generation.** Requires repository workflows, trigger
  permissions, job tracking and artifact callbacks before the release-page
  button works. Rejected: managed generation is the primary workflow;
  existing CI can optionally test the resulting changes, but is not a
  generation dependency.
- **Running package managers in the API server or ordinary worker pod.**
  Breaks ADR-045 §7 (execution, project-controlled registries). Rejected in
  those processes, not rejected as managed functionality: isolated toolchain
  runners provide the planned server-side execution.
- **Installing tools on demand or shipping every manager in one image.**
  Runtime bootstrap adds mutable acquisition, cold-start and offline failure
  paths; a full image expands every deployment and still cannot match every
  release's toolchain pins. Use per-toolchain preprovisioned profiles instead.
- **Naive version bumps from Hibou's fixed versions.** Works for any
  ecosystem and direct dependencies, ignores the graph: transitive fixes,
  conflicts and newly introduced vulnerabilities are missed. Kept only as
  the "no automated fix" hint.
- **Hard-coding one maintenance model** (for example "newest two
  minors"). Simple, wrong for most companies. Rejected for facts plus a
  declared policy.
- **Inferring maintenance from branch activity.** Recent commits on a
  branch say little about a support promise and would label lines
  unmaintained by accident. Shown as a fact, never used as a verdict.
- **Making Renovate the synchronous patch endpoint.** Its local platform is
  not a full-update engine; dry-run output is not a supported patch contract.
  Revisit only if a supported integration proves the same artifact contract.
- **Delegating the entire workflow to a hosted update bot.** Still useful
  for routine updates, but it does not own Hibou's release/triage/selection
  semantics or the IDE's exact HEAD. Reuse updater machinery, not its product
  workflow. Do not require installing a second forge App to download a patch.
- **SCALIBR-only forever.** Lowest initial integration cost, but leaves Go
  and other important ecosystems outside automated remediation. SCALIBR-only
  is the explicit initial scope, not a promise never to extend it. A future
  engine/toolchain needs a concrete ecosystem requirement and separate decision.
- **Trusting a Gossip recommendation or a manual version as inherently safe.**
  Neither proves the complete project graph resolves, fixes all selected
  advisories or meets organization policy. Validate both through the same
  planner/checks as Automatic.
- **Independent one-package diffs concatenated into a batch.** Shared
  lockfiles and constraints make that unsafe. Resolve and verify the combined
  graph instead.

## Upstream references

Reviewed 2026-11-11; pin and verify the selected release during the spike.

- [SCALIBR guided remediation](https://github.com/google/osv-scalibr/blob/v0.5.3/guidedremediation/README.md)
  and [public options](https://github.com/google/osv-scalibr/blob/v0.5.3/guidedremediation/options/options.go):
  graph-aware file updates and upgrade-level limits, not an exact-target API.
- Pinned strategy implementations:
  [npm in-place selection](https://github.com/google/osv-scalibr/blob/v0.5.3/guidedremediation/internal/strategy/inplace/inplace.go),
  [Maven overrides](https://github.com/google/osv-scalibr/blob/v0.5.3/guidedremediation/internal/strategy/override/override.go)
  and [npm constraint relaxation](https://github.com/google/osv-scalibr/blob/v0.5.3/guidedremediation/internal/strategy/relax/relaxer/npm.go).
- [Renovate local platform](https://docs.renovatebot.com/modules/platform/local/):
  experimental; only extract/lookup dry runs, no branch creation.
- [Renovate distributions](https://docs.renovatebot.com/getting-started/running/):
  default installs tools at runtime with caching; full preinstalls most tools
  at substantial image size. Borrow separation of tool provisioning and
  manager-aware execution, not runtime installation or a universal full image.
- [Renovate npm manager](https://docs.renovatebot.com/modules/manager/npm/):
  manager-specific native lockfile generation and version selection. Hibou
  additionally requires preapproved/preprovisioned versions with no Corepack
  bootstrap during jobs.
- [Renovate execution/security model](https://docs.renovatebot.com/security-and-permissions/)
  and [self-hosted controls](https://docs.renovatebot.com/self-hosted-configuration/):
  script/plugin restrictions are not a substitute for execution isolation.
- [Dependabot Core](https://github.com/dependabot/dependabot-core):
  updater libraries and CLI recommendation; returns dependency diffs without
  requiring PR creation.
- [Dependabot CLI](https://github.com/dependabot/cli):
  job files, security-advisory inputs, recorded API output and credential
  proxy. Its job format is not formally documented; broader coverage is not
  enough to justify an additional runtime/toolchain integration initially.
