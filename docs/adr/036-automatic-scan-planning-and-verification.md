# ADR-036: Automatic scan planning and evidence-based verification

## Status

Accepted (2026-10-10). Discovery, persisted plans, mode selection and the
taint resolution rule of §6 are implemented (rollout steps 1–2); no adapter has
validated incremental support yet, so every plan scans whole applicable scopes,
and rollout steps 3–4 wait for workload measurements. See
[the implementation plan](034-036-implementation-plan.md). It complements [ADR-035](035-bundled-scanners-and-coverage-policy.md)
and refines its scope and incremental-analysis contracts. For flow-sensitive
findings, the verification rules below amend the sink-file-only change/coverage
heuristic in [ADR-034](034-absence-is-not-resolution.md); the other persistence
and explicit-assertion policies remain unchanged.

## Context

The sample repository's `java-opengrep` target passes one authored rules file and
one known Java source directory to OpenGrep. That is a useful smoke test, not a
production integration: arbitrary repositories have different languages,
frameworks, module roots, build inputs, dependency boundaries, and sizes.

Repository owners should not enumerate every source file or author security rules
to receive baseline coverage. Conversely, automatically discovering files cannot
invent trustworthy framework models or guarantee complete taint analysis.
Analysis budgets, depth bounds, unsupported syntax, reflection, and runtime
dispatch can limit results even when every file was visited.

Do not assume another product uses random taint sampling without verified
evidence. Static-analysis engines generally apply configured rules and dataflow
algorithms; timeout-dependent or unstable results are possible without deliberate
random selection. Our contract must make selection and limitations inspectable.

## Decision

### 1. Engines perform analysis; Hibou plans and tracks it

OpenGrep remains a SAST engine. It performs source-pattern matching and taint
analysis supported by the selected engine build, language, and rules. Enabling
cross-file taint does not disable ordinary pattern rules. Other SAST, bytecode,
dependency, secret, and IaC producers retain their own analysis responsibilities.

Hibou owns applicability detection, policy resolution, maintained adapter/preset
selection, scan scheduling, artifact ingestion, coverage evidence, and finding
lifecycle. Engine-specific adapters translate an engine-neutral plan into verified
commands and interpret exits, skipped inputs, and reports. Hibou does not rebuild
each engine's call graph or implement a generic taint engine.

Passing a repository/module root does not require enumerating taint entrypoint
functions: source scanners discover supported files themselves, while selected
rules/framework models identify untrusted inputs, sinks, and sanitizers. The
planner automates suitable roots and maintained model selection, not a mandatory
user-authored list of source functions. OpenGrep analyzes Java source, not `.class`
files; compiled artifacts are prerequisites for bytecode engines such as SpotBugs.

Advanced analysis options are set only for supported engine/language/rule
combinations. No automatic downgrade from required cross-file capability to a
weaker engine; surface unsupported coverage. Continue ordinary pattern scans
independently where supported, retaining their separate outcomes.

### 2. Automatic scope is the default; configuration is refinement

Given a checked-out commit and effective org/repo policy, inspect tracked files
and recognized workspace/build manifests. Detect module roots, languages,
framework indicators, compiler outputs, and scanner applicability. Forge language
statistics are hints, not file-selection authority. Manifest parsing does not
execute untrusted build scripts.

Use versioned discovery recipes for Maven/Gradle, Go modules, Node workspaces,
Cargo workspaces, and supported IaC layouts. Unknown layouts fall back to an
eligible repository-level source scope when the engine supports it; otherwise
report unsupported or unknown applicability and request a module-root override.
Do not silently drop a language because its manifest is unfamiliar.

Discovery proposes generated/vendor/build-output exclusions with concrete
reasons. Record excluded paths and allow inspection. Build adapters distinguish
generated code needed for semantics from disposable output; exclusions cannot
remove required analysis context unnoticed. Tests get a declared profile, not an
undocumented blanket exclusion. Org controls from ADR-035 govern scope reduction.

Responsibility is explicit:

| Owner | Responsibility |
|---|---|
| Hibou maintainers | Versioned discovery adapters, supported presets/framework models, licenses, compatibility tests, and limitation disclosures |
| Org admins | Required capabilities, approved providers/presets, freshness, budgets, exclusions/exception approval |
| Repo maintainers | Enable/inherit defaults; supply existing build/artifact contract; refine ambiguous modules and exceptional exclusions |
| Scanner engine | Rule matching, semantic/dataflow analysis, native incremental algorithms, engine-supported caches and diagnostics |

Users may add custom rules, sources, sinks, and sanitizers, but baseline scanning
does not require them. A sanitizer override can hide findings, so required-policy
changes follow the same trusted-config/approval path as exclusions. Do not
automatically treat arbitrary validation methods as sanitizers.

Presets select language and framework rules plus capability requirements, pinned
as in ADR-035. An engine can run successfully with no relevant rules: that is
not adequate language/security coverage. The POC's two authored rules remain
smoke tests, not the maintained baseline distribution.

### 3. Persist a reproducible plan before execution

A plan records repo/commit, target/base commits for a comparison, discovery and
policy revisions, module graph, selected scanner/distribution/ruleset digests, module
input and context scopes, exclusion reasons, prerequisite artifact contracts,
budgets, and selection rationale. Each job has a stable ID and plan digest.

Execution reports declared versus observed scope. Record version/config changes,
timeouts, parse errors, missing inputs, rule-level failures, unknown diagnostics,
and whether the adapter can substantiate coverage. SARIF findings alone are not
a complete coverage manifest. Legacy/external reports without sufficient evidence
remain accepted, but coverage is unknown and cannot meet strict coverage policy.

Separate three quantities: eligible scope, processed scope, and supported analysis
capability. "All files processed" is not "all possible flows explored". Record
depth/resource limits and known semantic limitations. Use full-input or partial
labels rather than claims of mathematical completeness.

### 4. Three scan modes, selected deterministically

| Mode | Trigger | Purpose |
|---|---|---|
| Baseline | Onboarding, no compatible baseline, discovery/policy/engine/ruleset changes | Analyze all eligible scopes under declared limits |
| Change-impact | PR/push with compatible baseline and verified adapter support | Check changed behavior and affected context quickly |
| Full sweep | Default-branch cadence and manual request | Refresh all eligible scopes and discover issues outside PR focus |

Hibou does not execute CI, so it does not schedule sweeps itself: a scheduled
CI workflow runs `hibou scan --mode sweep`, and a scope whose last run is older
than the required freshness shows as stale.

First release uses whole applicable scopes and native engine diff support where
validated. No hand-rolled change-impact pruning is needed to ship discovery.
The compatibility contract includes engine, rules, framework models, policy,
discovery, dependencies, compiler/artifacts, and source scope; a material change
invalidates the relevant baseline/cache, not necessarily every unrelated module.

Change-impact planning considers modified/deleted/renamed files, changed public
symbols, dependencies, manifests, rule models, and prior finding context. For
cross-file analysis, changed files are reporting/priority inputs, not the only
files supplied to the engine. Unchanged callers, callees, sources, and sanitizers
can affect new behavior. Let the engine compute the needed semantic graph.

Use native incremental analysis only if its context and invalidation semantics
are tested for that adapter. Filtering a full report to changed lines is a
presentation optimization, not faster or more complete analysis. Without valid
incremental support, scan the entire applicable scope. If budget prevents that,
return partial evidence and queue a full continuation; never call it a full pass.

Do not combine old modules and fresh modules into a supposed full scan of a new
commit without a verified dependency-aware reuse contract. Missing base commits,
ambiguous rename mapping, or unknown module dependencies require conservative
fallback rather than inferred coverage.

### 5. Large repositories: preserve semantics while bounding cost

Reuse ADR-035's dependency-aware scheduler and build artifacts. Source scans can
overlap compilation; bytecode scans require classes/classpath, not necessarily
tests or packaging. Some Java engines operate directly on source.

Parallelize independent languages and engine-declared independent analysis units.
A directory or Maven module is not automatically an independent taint boundary:
shared libraries and callers may require broader context. Adapters declare safe
partitioning and cross-partition dependencies. If unknown, retain whole-project
context; do not split arbitrary chunks of files to gain apparent throughput.
Pattern-only rules can have different partition semantics from taint rules.

Use engine-supported caches only, with dependency/config-aware invalidation and
tenant/trust separation. Never reuse a taint report based solely on sink-file
hash. Record queue, discovery, build, index, analysis and report time where
available, peak resources, retries, and rejected/skipped analysis units.

Within budgets, prioritize deterministically: required checks, changed affected
scopes, verification of known findings, then oldest insufficiently covered units.
Reserve sweep capacity and age queued units to prevent unchanged modules from
starving. Persist continuation state and completed units; resume only when the
engine supports it, otherwise rerun the incomplete unit. Do not invent resumable
engine state. Expired freshness remains a gap even when a sweep is queued.

Random sampling is not the default and cannot satisfy full coverage or establish
a fix. If optional exploratory sampling is ever offered, label it sampled,
record selection/seed, and keep its lifecycle/gating evidence distinct.

### 6. Verify prior findings without pretending absence proves repair

Prior findings inform scheduling but must not narrow scanning to known bugs:
new sources and flows still need discovery. A verification job reruns the relevant
rules using the engine's supported context; it does not merely inspect old line
numbers or test that a code string disappeared.

For taint findings, retain source/sink/trace and semantic dependencies when
reported. A change to a source, intermediate method, sanitizer, dependency or
framework model may affect a finding whose sink file did not change. Conversely,
editing the sink file's formatting is not evidence that a flow was repaired.
Trace locations are supporting evidence, not an exhaustive dependency graph.

The producing adapter declares a finding recheck scope: flow-aware context when
it can prove it, otherwise the whole applicable project/ruleset. Only successful
compatible analysis of that scope establishes disappearance evidence. If context
coverage cannot be established, leave the finding not re-checked or unconfirmed
under ADR-034, even if a sink-local partial scan is empty.

Record lifecycle reasons separately:

- Reported again: preserve identity and triage; update confirmation and trace.
- Missing/partial/failed recheck: keep open, with gap reason and last confirmation.
- Absent in compatible, covered analysis after relevant code change: resolved,
  no longer detected after code change; do not claim proof of exploit elimination.
- Absent after rule/engine/config change: producer-changed evidence, not a code fix.
- Suppressed or excluded: acceptance/policy evidence, never a repair claim.

If a relevant change cannot be established, retain ADR-034's unconfirmed policy;
do not fall back to labeling a taint finding fixed from coverage alone. Manual/AI
assertions still use explicit resolution. Deleted/renamed files need mapping and
flow-context evaluation rather than disappearance of an old path alone.

Finding keys remain producer-aware; use stable engine fingerprints and validated
pairing across versions/renames. Do not merge all scanners' findings by line.
Cross-producer corroboration may be displayed without erasing individual evidence.

### 7. UI and API expose automatic decisions

Repo onboarding offers applicable maintained presets and automatic module scope.
Preview shows detected languages/frameworks, selected rules/capabilities, build
requirements, exclusions and unsupported areas. Advanced overrides are optional;
an ordinary Java repo does not require a manual source-file list.

Scan detail shows mode, baseline compatibility, scope/context, selection reasons,
completed/deferred units, budgets and coverage age. Explain "full scope required
because incremental analysis is unsupported" or "bytecode scan waits for classes"
as actual states. Never present an enabled checkbox as evidence of execution.

Finding detail shows verification commit, producing rule/version, observed flow,
last confirmation, recheck scope and resolution reason. Org inventory from ADR-035
includes rule/capability coverage and pending/stale/partial scopes, with separate
unknown applicability. Owners can request a full scan or preview override impact.

Planning and execution APIs share effective configuration. A signed/trusted CI
plan binds report provenance to commit and job; it does not make an arbitrary
self-reported coverage statement trustworthy. Enforced external-producer coverage
requires the same authenticated execution/provenance policy as ADR-035.

## Rollout and validation

1. Discover scopes, select pinned presets, and show a plan; execute full eligible
   scopes using existing engines. Keep the POC target unchanged as a smoke test.
2. Record observed scope and limits; connect producer evidence to ADR-034 lifecycle
   and ADR-035 org coverage. Ship baseline and full-sweep scheduling.
3. Add native incremental support per adapter with full-scan equivalence tests;
   unsupported engines retain conservative full-scope execution.
4. Add finding verification priority, safe engine-declared partitioning, and
   dependency-aware caching only after evidence and workload measurements exist.

Fixtures include mixed/no-code repos, custom module roots, missing manifests,
framework and generated-code cases, and cross-module Java flows. Compare PR
results against full scans at identical commits with identical rules/limits.
Change only an unchanged-sink caller or sanitizer and verify detection updates;
test dependency/model changes, renames, timeouts, and incompatible baselines.
Ensure an empty partial report never repairs a known cross-file finding.

Measure recall/false positives on independent corpora, baseline/PR/sweep latency,
resource cost, oldest uncovered scope, fallback frequency, and false-resolution
rate. Finding-count parity alone is not an acceptance criterion.

## Alternatives and consequences

- Manual file lists and custom rules everywhere: high onboarding cost and scope
  drift; retain only as advanced overrides, not the baseline integration.
- Changed files only: cheap but can miss cross-file flows and falsely clear
  findings; reject unless engine can substantiate the semantic context contract.
- Always full-scan synchronously: conservative first version, but poor PR latency
  at scale; add native incremental support and sweeps, not arbitrary pruning.
- Recheck only previous findings: misses new weaknesses; verification augments
  discovery, never replaces it.
- Random file selection: unpredictable gaps and invalid absence evidence; cannot
  meet enforced full-coverage requirements.

Automatic presets move adapter/ruleset maintenance onto Hibou maintainers and
introduce compatibility and evidence storage costs. Engines with weak coverage
diagnostics will need conservative whole-scope reruns or remain unknown for strict
policies. Explicit fallback is preferable to unsupported accuracy claims.

## Open questions

- Initial maintained framework/ruleset distributions and redistribution licenses.
- Which adapters can prove incremental context and per-rule completion reliably.
- Full-sweep cadence and resource budgets by repository size and org policy.
- How much native dependency/trace evidence to retain under artifact retention.