# ADR-029: License policy — categories, delta scope, and waivers as the unblock path

## Status

Accepted — implemented (2026-08-25). Policy ownership is superseded by
[ADR-030](030-org-license-policy-and-repo-override.md); everything else here
still stands. Builds on the license gating shipped in
`00f7b70` (2026-07-27) and reuses the acceptance model of
[ADR-023](023-triage-acceptance-ux.md).

Implementation notes:

- The gate shipped in `00f7b70` **never ran in production.** `evaluateLicenseGate`
  reaches the store through an optional interface assertion
  (`s.store.(componentLister)`), and the production `delta.StoreAdapter` — an
  explicit method-forwarding adapter — never forwarded
  `ListComponentsBySnapshot`. The assertion failed on every call, the function
  returned `nil, nil`, and the check reported "passed" without reading a single
  component. Its unit test passed throughout because it injects a mock that
  does implement the interface. Fixed by forwarding the method and pinning both
  optional interfaces with compile-time assertions
  (`var _ componentLister = (*StoreAdapter)(nil)`) so the same omission is now a
  build failure rather than a silent no-op.
- SPDX expressions are parsed by a real recursive-descent parser
  (`internal/license/expression.go`). The previous `splitExpression` discarded
  `AND` and `OR` alike and cleared an expression on the first passing atom, so
  `GPL-3.0-only AND MIT` passed a copyleft-denying policy. Real SBOMs emit
  conjunctions — this repo's own apko SPDX output carries `MPL-2.0 AND MIT`.
- Catalog gaps closed after categorizing every distinct license string in this
  repo's own SBOMs: `CC-BY-4.0` and `CC-PDDC` fell through to `unknown` and were
  therefore blocked by `deny_unknown`'s true default. `CC-PDDC` is a
  public-domain dedication.
- `make lint` 0 issues; `go test ./...` green.

## Context

A license gate has one failure mode that matters more than any other: getting
switched off. It is advisory infrastructure with no incident to point at, so the
first time it blocks a pull request for a reason a developer judges stupid, the
policy gets loosened or deleted. Every decision below is chosen to protect
against that, not to maximize what the gate catches.

Four specific ways the original design invited it:

1. **It judged the whole tree.** `evaluateLicenseGate` evaluated every component
   in the head snapshot, and its reason string said `X@Y introduces denied
   license Z`. Enabling a policy on an existing repository therefore blamed the
   current pull request for dependencies that had been on the target branch for
   years. Every other gate section (`VulnerabilityThresholds`,
   `SecretThresholds`, weaknesses) is delta-scoped; licenses were the exception.
2. **There was no way to exempt a package.** `allow` and `deny` match license
   identifiers, not packages, so "this one linter is fine" was inexpressible.
   The only available action was to weaken the policy for everything.
3. **`unknown` conflated two different problems** with different owners: an SBOM
   that carried no license at all (fix the generator) and a license string the
   catalog did not recognize (fix the catalog). Both rendered as the same
   failure, and the reason for a missing license read as a denied license named
   `""`.
4. **Policy lived only in `.hibou.yaml`.** A pull request author can loosen the
   policy in the same diff the policy would have blocked.

## Decision

### Categories, not identifier lists

Policies name categories (`permissive`, `weak-copyleft`, `copyleft`,
`network-copyleft`, `source-available`, `public-domain`, `unknown`), because what
an administrator means is "no copyleft", not an enumeration of 600+ SPDX ids that
grows monthly. Individual ids and globs remain available on top, and `allow`
always wins.

`unknown` ranks **most restrictive**, above `source-available`. An unreviewed
license is an unmade decision, and defaulting it open would make the gate
skippable by any ecosystem with poor metadata.

### `deny_unknown` defaults to true — and this is now measured, not assumed

The original plan flagged this default as risky, on the assumption that
license coverage was poor. Measured with trivy 0.72.0: this repo's own `go.mod`
tree is 80 libraries with 1 missing license (its own root module), `site/` is 44
with 0 missing, and the sample npm tree with dev dependencies included is 185
with 0 missing. Coverage is ~100% for Go and npm, so the fail-closed default
costs almost nothing and the assumption behind the concern was wrong.

### SPDX operators are honoured, and the two directions disagree on purpose

Within one expression, `OR` is a choice and `AND` is cumulative:

- `MIT OR GPL-3.0-only` **passes** a copyleft-denying policy — a consumer picks
  MIT and copyleft never applies.
- `MPL-2.0 AND MIT` is judged on its **most restrictive** operand — both sets of
  obligations apply at once.

Separate entries in a component's license list are conjunctive: each is an
independent grant that applies, so every entry must pass.

Consequently `Policy.Evaluate` and `CategorizeAll` deliberately disagree on `OR`
expressions: the gate clears them via the permissive alternative, while a
display category shows what a consumer would actually end up under. Anything
that summarizes exposure must therefore call `Evaluate` rather than sum category
tiles, and the org license table flags `AND` and `OR` expressions explicitly so
the page does not look like it contradicts the check that ran.

### The gate is delta-scoped by default

`licenses.evaluate` is `new` (default) or `all`. `GateConfig` carries
`BaseSnapshotID` alongside `HeadSnapshotID`; all four call sites already held the
target snapshot. Component identity for the comparison is `purl@version` — the
version is **included** on purpose, because a version bump can change the
license, so an upgrade is a new decision rather than an inherited one.

Pre-existing violations are counted and disclosed ("N pre-existing license
violation(s) on the target branch were not counted") but do not fail the gate.
Suppressing them silently would hide real exposure; blaming the pull request for
them is what gets the gate deleted.

With no base snapshot the delta is unknowable, so the gate **fails closed** to
whole-tree evaluation rather than passing everything.

### Exemptions are per-package, disclosed, and distinct from `allow`

`exempt_purls` takes purl globs, matched case-insensitively with a `*` that
crosses `/` (purls are not paths, and `pkg:npm/@types/*` must match a scoped
name — `path.Match` refuses this). The distinction from `allow` is the axis:
`allow` names a license id, `exempt_purls` names a package.

Every exemption and every waiver appends its own disclosure ("N component(s)
exempted by policy") to `GateResult.Notes`, surfaced in the compare view. A
suppression nobody can see is worse than the false positive it hides — though
note these do not reach the forge check run itself; see ADR-030's limitation.

### Waivers, not config edits, are the unblock path

A license violation is waived through `finding_acceptances` — the same table,
reason-required flow, expiry, and audit trail as any other finding
(ADR-023) — rather than by editing the policy.

**Status caveat:** the gate HONOURS a waiver row (it filters accepted
fingerprints), but no code path yet CREATES one for a license violation: both
acceptance writers require an existing `vulnerabilities` row, and license
violations are not persisted as findings. Until they are, a waiver has to be
inserted directly. Materializing license violations as rows is the open item. Expired waivers resurface as
failures because the query already excludes them.

The fingerprint is `sha256("license:" + purl + ":" + normalized_license_id)`,
and **excludes the version**. The trade is explicit: including the version would
revoke a deliberately-granted waiver on every patch bump, re-breaking the gate
on an unrelated upgrade. Excluding it means a package whose license changes
between versions keeps its waiver — mitigated because the license atom is part of
the key, so a change to a *different* denied license produces a different
fingerprint and re-fires the gate. The `license` label distinguishes these rows
for the compliance view without pattern-matching fingerprints.

### `unknown` is split at the reporting layer, not in the taxonomy

`license.Declared()` separates "no metadata" from "unrecognized identifier", and
the gate words them differently ("introduces no license metadata (unreviewed)"
versus "introduces unrecognized license X"). No new category was added: doing so
would change `rank()` and the `deny_categories` vocabulary in
`hibou-config.schema.json` for a distinction that is about *whose bug it is*,
not about how restrictive the license is.

### The org overview reports exposure, never enforcement

`GET /orgs/{provider}/{slug}/licenses` aggregates the current default-branch
snapshot of every enrolled repository, reusing `currentRepoSnapshots` so its
population is identical to the Dependencies and Vulnerabilities tabs — two org
tabs disagreeing about how many components exist is a credibility bug.

It reuses `apitoken.CapComponents`: `isKnownCapability` is a closed switch over
persisted scopes, so a new `CapLicenses` would 403 every token already issued.

Coverage denominators (repos enrolled / with a snapshot / with components,
undeclared, unrecognized) ship in the same response and render above the totals,
because the dangerous output of this page is an unqualified "no AGPL anywhere".
Categories are always emitted including empty ones — a partition with holes reads
as missing data rather than as absence of exposure. Category names come from the
API rather than being re-derived in TypeScript, so a duplicated prefix table
cannot drift from `internal/license`.

## Consequences

- Enabling a policy on an existing repository now blocks only what the pull
  request adds, which makes it adoptable without a cleanup campaign first.
- The gate is stricter in one direction and looser in another than before, both
  intentional: `AND` expressions now block where they silently passed, and
  pre-existing violations now pass where they wrongly blocked.
- Because the gate never actually ran before this change, its first real
  activation will surface violations on repositories whose checks have been
  green. That is a disclosure, not a regression, and the delta scope keeps it
  proportionate.
- Org-level policy is now implemented; see
  [ADR-030](030-org-license-policy-and-repo-override.md), which supersedes this
  ADR's treatment of policy ownership. `.hibou.yaml` remains loosenable by the
  author of the pull request it would block, and ADR-030 addresses that by
  making the loosening visible rather than by forbidding it.

## Limitations (measured, not speculative)

- **The shipped-versus-not-shipped axis does not exist.** Both formats can carry
  it — CycloneDX `component.scope`, SPDX `*_DEPENDENCY_OF` — but trivy emits
  neither. Measured across Go, npm and Maven: `scope` is null on every
  component, always. Trivy separates dev dependencies by *omission* instead
  (`--include-dev-deps` opts them in, and scope stays null), which means hibou
  cannot distinguish "dev dependency" from "not scanned". A copyleft build tool
  is therefore invisible rather than correctly classified, and the parsers now
  declare the fields so the signal is retained the moment a generator supplies
  it.
- **A missing lockfile yields zero components, silently.** `trivy fs` on a
  directory with a `Cargo.toml` and no `Cargo.lock` exits 0 with no components,
  so a repository reads as license-clean because nothing was scanned. The org
  page's coverage block makes this visible; nothing prevents it.
- **Maven projects trip `deny_unknown` on their own artifact.** The parser
  ingests components carrying both a purl and a version; Go's root module has a
  purl but no version and is filtered, while Maven's root artifact has both and
  no license. Not fixable in-band: trivy writes a file name (`pom.xml`) into
  `metadata.component`, so the SBOM's own subject is unidentifiable. Open.

## Alternatives considered

- **Whole-tree evaluation as the default**, with delta as opt-in. Rejected: the
  default decides adoption, and the whole-tree default is what makes a first
  enablement look like the tool is broken.
- **A `not-shipped` category in the taxonomy.** Rejected: distribution is
  orthogonal to restrictiveness, and with the underlying signal 100% absent it
  would be a column of `unknown` masquerading as an answer.
- **Version-inclusive waiver fingerprints.** Rejected as the default; see the
  trade above.
- **Activating `license_policies` for org policy now.** Deferred at the time,
  because a second policy source without documented precedence would let the gate
  and the org page disagree. Precedence has since been decided and the table
  completed — see [ADR-030](030-org-license-policy-and-repo-override.md).
- **A dedicated `CapLicenses` token capability.** Rejected: it would 403 every
  existing token, and component licenses are component data.
