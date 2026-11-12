# ADR-055: Headless library boundaries and justified dependency footprint

## Status

Proposed (2026-11-11). Dependency minimization is the design direction;
the SCALIBR packaging improvement is a **deferred follow-up**, not a blocker
for the initial remediation implementation. No fork or upstream PR has been
created by this ADR.

Related: [ADR-050](050-guided-remediation-pull-requests.md) (shared remediation
engine), [ADR-035](035-bundled-scanners-and-coverage-policy.md) (small control
plane and separately provisioned tools), [ADR-045](045-built-in-dependency-inventory.md)
(inventory and shipping evidence), [ADR-051](051-third-party-notices.md)
(dependency licensing and attribution), [ADR-011](011-reproducible-builds.md).

## Context

Using an already required Go module does not make importing another package
from it free. A package can bring additional language adapters, interactive
frontends and their transitive dependencies into the build graph.

The concrete example is OSV-SCALIBR v0.5.3. Hibou calls the programmatic
`guidedremediation.FixVulns` API, but the same package imports its interactive
terminal UI. That import brings Bubble Tea, Bubbles, Lip Gloss, terminal
rendering/input, clipboard and Unicode-width dependencies. None is needed for
Hibou's website or IDE presentation. The package also imports multiple
ecosystem implementations regardless of which remediation strategy we invoke.

The dependency audit for the initial integration found 27 newly required
modules: 23 terminal/UI-related modules and four functional helpers
(Python resolution, Maven XML writing, CVSS and JSON editing). Four existing
requirements also became direct imports without a version change. These
counts describe that audit, not a permanent budget or a measurement of linked
binary bytes. Re-run the audit when imports or upstream versions change.

Effects can include download/build cost, module maintenance and license
obligations, vulnerability noise, initialization behavior and shipped size.
Go's linker may eliminate unreachable functions, so the module graph alone
does not quantify the binary-size or runtime impact. Conversely, never calling
an interactive function does not remove its package imports and initialization
dependencies.

## Decision

### 1. Prefer narrow, headless library boundaries

Reuse maintained libraries when they provide the required correctness and
coverage. Prefer a programmatic package that imports only its execution
requirements, without its CLI, TUI, web frontend or optional integrations.

Before adding a dependency or importing a broader part of an existing one:

- Record the capability it supplies and why existing helpers are insufficient.
- Inspect the resulting direct/transitive import graph, including unexpected
  optional interfaces and runtimes.
- Explain the dependency delta; "indirect" is an origin classification, not
  an exemption from review.
- Check maintenance, license, initialization/execution behavior and whether
  the dependency belongs in the API, local client, controller or toolchain image.
- Measure meaningful cost before promising savings or declaring something
  lightweight: clean/cached build cost, stripped executable size, relevant
  module/build metadata and compressed/uncompressed image size.

Keep the simplest implementation that preserves behavior. Do not rewrite
dependency resolution, cryptography or package formats merely to reduce a
module count.

Reusable process/Git primitives belong in shared application infrastructure,
not in a feature package. The remediation integration now reuses
`internal/gitexec` for command/environment policy and `internal/executil` for
bounded subprocess output; IDE Git queries, secret scanning and CVE feed work
share the Git infrastructure. Keep explicit differences between trusted user
configuration, isolated worker configuration and permitted network transports.
Domain adapters may add context, but must not copy the subprocess machinery.
Do not generalize every feature helper prematurely: extract demonstrated
reuse, preserve security profiles and test the existing consumers. DRY lowers
maintenance burden; any executable-size benefit still needs measurement.

### 2. Prefer an upstream fix; use a constrained fork only if necessary

For SCALIBR, investigate a headless remediation package/API with the same
resolution, file-writing and result semantics. Suitable upstream designs include:

- A new pure `guidedremediation/core` or headless package, with the existing
  package retained as a compatibility facade for interactive users.
- A future API revision moving interactive entry points into a dedicated
  subpackage, with explicit migration/deprecation guidance.
- Separating ecosystem adapters where practical without duplicating algorithms.

Moving a TUI function to another file in the same package is insufficient.
Keeping a root-package forwarding function that imports the TUI also preserves
the unwanted dependency. The package Hibou actually imports must have a
headless transitive import graph.

Prepare a minimal upstream PR with dependency-graph evidence and behavioral
tests. If an upstream release cannot meet our needs promptly, a temporary fork
may carry that focused packaging change. It must:

- Preserve the upstream license, notices and attribution.
- Pin an immutable revision and document the patch and update/rebase process.
- Retain remediation correctness and security tests; avoid unrelated changes.
- Have an explicit removal path when an acceptable upstream release is available.

Do not silently edit the Go module cache, remove required checksums, provide
fake replacement modules, or vendor arbitrary upstream internals as a shortcut.
No automatic external PR creation is authorized by this proposal.

### 3. Separate runtime footprint from inventory classification

Distinguish:

| Evidence | Meaning |
| --- | --- |
| `go.sum` | Checksums, including historical module metadata and upstream test dependencies; not a delivery manifest |
| `go.mod` | Declared module requirements, potentially including main-module tests and tooling |
| Normal non-test import graph | Packages contributing to the selected build, subject to build tags/platform |
| Built-artifact inventory/SBOM | Stronger evidence of dependencies present in a particular delivered artifact |
| Explicit `dependencies.not_shipped` configuration | A declared classification with provenance, not removal of code or imports |

Test-only dependencies do not enter a normal executable through `_test.go`
imports. For modern Go versions, the current SCALIBR Go extractor inventories
`go.mod` requirements rather than treating every `go.sum` entry as a component.
A dependency present in `go.mod` can still be test-only, and the manifest alone
does not establish that fact.

Hibou already supports `dependencies.not_shipped` PURL patterns and explicit
`dependencies.shipped` overrides. Use them for known, reviewed exclusions,
including verified test-only requirements when needed. Preserve the reason/
source of the decision in the UI and exports. Existing authoritative SBOM
evidence takes precedence where the shipping policy specifies it.

Do not mark all `// indirect` requirements not shipped: many are real runtime
dependencies. Do not use a not-shipped rule to hide unmeasured terminal-library
imports. Classification cannot reduce executable size, eliminate dependency
initialization, or substitute for fixing the library boundary.

### 4. Keep current remediation work unblocked, with an explicit exception

Retain the pinned SCALIBR integration for now. Its terminal dependencies are
accepted as documented upstream packaging baggage, not intentional Hibou UI
features. Add no further UI framework solely because that graph is already
present.

Revisit the exception at the next SCALIBR upgrade or dedicated footprint work.
Do not impose a new helper process, separate module or executable split without
measuring the benefit and the distribution/compatibility cost. A separate
binary can isolate a delivery surface, but does not automatically remove the
dependency from a shared Go module or from the other executables importing it.

## Verification for the follow-up

1. Capture the selected non-test import graph, dependency explanation and
   executable/image baselines using the same toolchain, flags and platform.
2. Introduce the headless boundary or focused upstream patch.
3. Prove the headless consumer no longer imports the terminal/UI packages.
   Merely reducing lines in `go.mod` or `go.sum` is not acceptance evidence.
4. Run batch-remediation, lockfile consistency, exact/Gossip-target,
   cancellation, patch integrity and publication regression tests unchanged.
5. Compare footprint/build measurements and inspect generated SBOM/notices.
   Do not relabel test/checksum dependencies as delivered code to explain a
   module-count change.
6. Document any residual ecosystem/CVSS/JSON dependencies and their purposes.

## Consequences

- Dependency additions need a capability and footprint explanation, not a
  blanket zero-dependency rule.
- The initial remediation feature can ship without an immediate dependency fork.
- An upstream package split is preferred to maintaining our own remediation
  algorithms or copying internal packages.
- Inventory classification remains evidence-based and configurable, distinct
  from actual code-removal work.
