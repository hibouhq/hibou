# ADR-030: Org license policy, repository override, and making loosening visible

## Status

Accepted — implemented (2026-08-25). Supersedes the policy-ownership sections of
[ADR-029](029-license-policy-model.md); the rest of that ADR still stands.

Implementation notes:

- Storage completes the `license_policies` table (migration `00034`) rather than
  adding columns to `quality_gates`.
- `internal/license/spec.go` introduces `Spec` — the declared policy, distinct
  from `Policy` (the evaluation-time subset) — plus `Compare`, which returns a
  strictness `Relation` and the axis-by-axis differences.
- Resolution lives in `internal/delta` (`resolveLicensePolicy`), because both
  gate-config paths already reach `EvaluateGatesWithConfig` with the org id; the
  alternative would have meant threading the policy through two separate config
  loaders including the forge publisher's.
- `GetOrgLicensePolicy` is reached through an optional interface, so it is pinned
  with `var _ licensePolicyReader = (*StoreAdapter)(nil)` — the omission of
  exactly such a forward is what left the license gate inert for a release cycle
  (ADR-029).
- `make lint` 0 issues; `go test ./...` green.

## Context

ADR-029 deferred org-level policy and, in doing so, left the policy loosenable by
the author of the pull request it would block — `.hibou.yaml` was the only
source. The original plan's answer was to forbid repository-level policy outright
and route every exception through a waiver.

That answer is wrong for two reasons that only became clear once the org overview
existed:

1. **Repositories legitimately differ.** An internal build tool, a
   customer-facing service, and a published SDK are not under the same license
   obligations. Forcing all three through one org policy plus per-package waivers
   makes the waiver list the real policy, which is worse than an explicit
   override.
2. **What made repo-level policy dangerous was invisibility, not existence.** A
   PR author loosening the policy in the same diff is a problem precisely because
   nobody else sees it. That is fixable without removing the capability.

## Decision

### The org holds one policy; repositories inherit it

Stored in `license_policies`, one enabled row per org, enforced by a partial
unique index (`WHERE enabled`). "The org policy" cannot be ambiguous.

The table was chosen over adding columns to `quality_gates` because a license
policy is **one legal stance per organization, not one per gate row**. N gate
rows each carrying a policy would have undefined precedence — the same
competing-sources problem, moved inside the schema. The existing
`allowed_licenses` / `denied_licenses` columns already *are* `allow` and `deny`,
so migration `00034` completes the row rather than replacing it: it adds the
category axis, package exemptions, the unknown-license stance, and the delta
scope.

Retiring a policy sets `enabled = false` rather than deleting the row, so the
last enforced policy stays inspectable. Re-enabling revives that row; the change
history itself lives in `audit_logs`.

`license_exceptions` is now genuinely orphaned — superseded by
`finding_acceptances` — and has no generated queries. It is left in place rather
than dropped, because dropping a table is destructive and it holds nothing.

### A repository overrides, and the override replaces

A `licenses:` section in `.hibou.yaml` **replaces** the org policy for that
repository. It does not merge.

Merging was considered and rejected: combining two partial policies produces a
third that neither side wrote, and no reader could predict the result. "Which
policy applies here?" must have a one-word answer.

Resolution order: repository section if present, otherwise the org policy,
otherwise no license gate. An org policy therefore applies to a repository whose
`.hibou.yaml` says nothing about licenses at all — which is the entire point of
having one.

An org policy that denies nothing is not a policy and does not switch the gate
on. `nil` (no policy) and an empty policy stay distinguishable, so the gate never
invents a fail-closed default the org did not choose.

### Loosening is made visible, in two places

This is what makes the override safe, and it is the whole of the answer to the
concern ADR-029 raised.

**On the comparison view.** When a repository's policy is looser or mixed
relative to the org's, the gate emits a note naming the loosened axes, carried on
the comparison API's `gate.notes` and rendered in the compare view's
"Noted, not blocking" block. A stricter override is disclosed too, but plainly,
because it needs no action.

**Limitation, and it is a real one.** Notes are NOT propagated to the forge check
run, and `pr_checks` has no column for them, so the persisted verdict a reviewer
sees on the pull request itself carries only the failure reasons. A reviewer who
never opens the comparison view does not see the loosening. Closing that needs a
`pr_checks` column plus a change to the check body, and is deliberately left as
follow-up rather than claimed here.

**In an org compliance view.** `GET /orgs/{provider}/{slug}/licenses/policy`
returns the org policy plus, per repository, whether it inherits or overrides,
the strictness relation, and the specific differences.

`Relation` has four values, and `Mixed` is first-class rather than a failure to
decide: a policy can genuinely deny more categories while also allowing more
unknowns, and netting those off would hide the half a compliance reader cares
about.

**Only `looser` and `mixed` count as departures.** A repository tightening its
own policy needs no oversight, and presenting it as an exception would train
people to ignore the list. `unreadable` — a config that could not be fetched — is
counted separately and ranked above compliant overrides, because an unknown is
not a pass.

### The compliance endpoint is separate, and deliberately not on page load

Knowing a repository's declared policy means reading its `.hibou.yaml` from the
forge: one fetch per repository. ADR-029 already refused a per-repo forge fan-out
on a dashboard, and that still holds — so this is its own endpoint, behind an
explicit user action, rather than part of the license overview the tab loads.

A dashboard must be cheap; a compliance check a human asks for may be slow. A
single unreachable repository degrades to `unreadable` for that row rather than
failing the whole report.

### Comparison is normalized

Strictness comparison runs through `NormalizeID` and case-folds, so `COPYLEFT`
versus `copyleft`, or `(MIT)` versus `MIT`, is not reported as a policy
difference. Spelling is not a departure.

## Consequences

- A repository can now be held to a policy it never wrote, which is new
  behaviour: setting an org policy immediately gates every inheriting repository.
  The delta scope (ADR-029) keeps the first activation proportionate — only what a
  change introduces fails — and the gate discloses whose policy applied.
- Loosening is possible and auditable rather than forbidden and worked around.
  The trade is explicit: we accept that a PR author can loosen their repository's
  policy, and we make that fact visible to their reviewer and to the org.
- Waivers (ADR-029) remain the right tool for one package, and an override for a
  repository whose obligations genuinely differ. Neither replaces the other.
- Two paths can still disagree in one narrow way: the compliance view reads each
  repository's default-branch config, while the gate resolves against the pull
  request's target branch. A repository whose `.hibou.yaml` matches different
  gates per branch can therefore show a compliance relation that does not match
  what a given PR check applied. Both call the same `Compare`, so the discrepancy
  is one of branch scope, not of logic — documented rather than papered over.

## Alternatives considered

- **Forbid repository-level policy; waivers only.** The original plan. Rejected
  on the reasoning above: it makes the waiver list the de facto policy, and it
  treats repositories with genuinely different obligations as identical.
- **Merge org and repository policies** (union of denials, intersection of
  allowances). Rejected: produces a policy neither side authored, and no reader
  could predict which rule fired.
- **An org lock forbidding override.** Deliberately not built. It is the obvious
  next step if visibility proves insufficient, but adding an enforcement knob
  before there is evidence that disclosure fails would be speculative — and a lock
  is meaningless until the org can first *see* who overrides.
- **Columns on `quality_gates`.** Rejected: N enabled gate rows would each carry a
  policy with no defined precedence.
- **Persisting the resolved policy per snapshot** to make the compliance view
  cheap. Deferred: it is the right fix for the forge fan-out, but it needs a
  decision about where that cache lives and when it invalidates, and the
  explicitly-triggered endpoint is honest in the meantime.
