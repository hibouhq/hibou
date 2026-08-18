# Review — ADR-020 Fine-grained API tokens

Reviewer: Claude (2026-08-05). Scope: the full uncommitted ADR-020 change set —
~26 tracked files (+1,377/−111) plus the new untracked files (migrations
`00009`/`00010`, `apitoken/`, `route_scope.go`, `org_apikeys.go`,
`audit_partitions.go`, `TokenScopeEditor.vue`, `FindingOriginBadge.vue`, tests).
Everything below was verified against the code, not the reports.

## Verdict

The implementation is sound and, in a few places, better than the ADR asked
for. The security model is layered correctly: deny-by-default at the router,
capability checks in handlers as defense-in-depth, fail-closed scope parsing,
schema-level CHECK constraints for provenance, and session-only token
management. Three real defects were found during review and fixed in-tree
(§ Fixed during review). What remains below are recommendations, not blockers —
except the migration rehearsal, which I'd treat as a hard gate before shipping.

---

## What's genuinely good (keep these properties)

- **The route table is test-enforced.** `TestEveryAuthenticatedRouteDeclaresScope`
  walks the chi router and fails when any route lacks a `routeScopes`
  declaration. Nobody can add an endpoint that scoped tokens slip through —
  the failure mode of every "opt-in middleware" design is structurally
  impossible here. This test is the single most valuable artifact in the
  change set; never weaken it.
- **Same idea on MCP**: `scopedTool` makes the capability declaration part of
  tool registration itself. A new tool without one doesn't compile into the
  transport.
- **Fail-closed everywhere it matters.** Malformed scope → scoped + zero scope
  → denies all. Unknown capability/level/mode/owner → parse error. Unmatched
  route → 403. `AllowsOrgWide` requires `repos.mode=all`, so a repo-list token
  can never widen itself through an aggregation endpoint.
- **Enforcement is additive.** Sessions and legacy unscoped tokens bypass the
  guard entirely and still go through full RBAC. Nothing existing changed
  behavior — verified in the middleware and in tests.
- **Provenance is un-forgeable at the storage layer**, not just the handler:
  CHECK constraints require an accountable principal for `human` and `agent`
  findings, and the token name/owner are denormalized so revoking a token
  doesn't erase who filed what. `q=agent:<token-id>` makes "revoke the token,
  review its findings" a one-liner — exactly the ADR's auditability story.
- **Rotate preserves identity.** Same key id → scope, provenance, and audit
  history survive a secret rotation. Easy to get wrong; done right.

## Fixed during review (documented for the record)

1. `audit_logs.actor_id` had an FK to `users(id)` while ADR-020 writes API-key
   ids into it. Every token-authenticated audit insert violated the FK and was
   silently swallowed — token actions were **unaudited**, the exact property
   Phase 5 exists to guarantee. Fixed in migration `00010`.
2. Scoped tokens could be minted or edited with **no expiry** despite the ADR's
   "mandatory, ≤ 1 year". `validateScopedExpiry` now gates every create/update
   path; the UI's "No expiry" option is gone.
3. User-scoped key queries matched `id AND user_id` only, so an org-owned key's
   creator could keep managing it through the personal endpoints after losing
   org admin. All five queries now also require `owner_type='user'`.

---

## Recommendations

### Security / correctness

1. **CLI tokens are still unscoped** (`internal/server/cli_token.go` passes a
   `nil` scope). Every `hibou auth login` mints a full-RBAC token. That was the
   right compat call for this change set, but it means the most common token in
   circulation ignores the entire scope model. Recommend a follow-up: default
   CLI tokens to a broad-but-scoped grant (e.g. `repos.mode=all` +
   uploads/coverage/vulns/components, no `admin`, no `quality_gates:write`),
   with a `--full-access` escape hatch during a deprecation window.

2. **Denial messages don't say which permission was missing.** The ADR
   explicitly says "Denials return 403 with which permission was missing";
   today both the guard and `enforceTokenCapability` return a generic
   "token scope does not permit this action". For a human this is a support
   ticket; for an agent it's an unrecoverable dead end. The guard already knows
   the required capability+level — include them:
   `"token scope does not permit this action (requires vulnerabilities:write on acme/api)"`.
   Same for MCP tool errors, which agents actually parse.

3. **Audit writes still swallow errors** (`_, _ = s.queries.CreateAuditLog`).
   The FK bug stayed invisible precisely because of this. Keep the
   don't-fail-the-request semantics, but log a warning and/or increment a
   metric on audit-write failure so the next silent-drop bug surfaces in ops
   instead of in a review.

4. **`POST /secret-scan/check` is declared `secrets:read` with no org
   binding** — any scoped token holding `secrets:read` in *any* org can submit
   patches for a verdict. It persists nothing and RBAC still applies, so it's
   not a leak, but it is the one route where the declared scope doesn't bind to
   a resource. Consider requiring the caller to name a repo (the pre-receive
   hook knows it) so the check can bind properly.

5. **Org-owned tokens still act as their creator** (`api_keys.user_id` drives
   the RBAC intersection). The caveat is documented in `org_apikeys.go`, but
   it's the biggest remaining gap between the ADR's promise ("survives any
   member's departure") and reality: management survives, authorization
   doesn't. Longer-term this wants a service-principal model — org tokens
   authorize against the org itself, not a member. Worth an ADR of its own.

6. **Hibou should detect its own tokens.** `hibou_pat_` + checksum was designed
   for greppability, and `apitoken.LooksLike`/`HasValidChecksum` exist — but
   the secret-scanning pipeline (gitleaks-based) has no rule for them. A leaked
   Hibou token in a scanned repo should be Hibou's easiest possible catch, and
   with the checksum it can validate shape with zero false positives.

### Migration / operations

7. **Rehearse `00010` before shipping — hard gate.** It rebuilds `audit_logs`
   (create partitioned table → copy all rows → drop → rename → recreate six
   indexes) inside one migration. On the dogfood install that's fine; on any
   install with millions of audit rows it holds locks for the duration of the
   copy. Neither `00009` nor `00010` has ever executed against a real database
   (no Postgres in this devcontainer). Run `make test`, run the up/down pairs,
   and eyeball `EXPLAIN`-level sanity on the partition pruning.

8. **`last_used_at` is written on every bearer request**
   (`UpdateAPIKeyLastUsed` in the auth path — pre-existing, not introduced
   here). With agents polling via MCP this becomes one UPDATE per request on a
   hot row. Throttle it (skip if updated < 5 min ago) before agent traffic
   grows.

9. **Partition maintenance only runs when background retention is enabled**
   (`background.retention.enabled`, default true — but a pod with it disabled
   never creates next month's partition). Harmless thanks to the DEFAULT
   partition, but worth a line in the deployment docs: at least one replica
   must run the retention loop.

### Product / UX

10. **There's no way to edit a token in the UI.** The `PATCH` endpoint exists
    (name, description, scope, expiry) and is audited, but the settings page
    only offers rotate/revoke. Renaming a token or tightening its scope
    currently means revoke-and-recreate, which defeats the point of stable key
    ids. An "Edit" affordance reusing `TokenScopeEditor` is cheap — the
    component is already model-driven.

11. **Scope summaries are write-only.** The list shows a compact
    `org · N repo(s) · caps` line, but there's no way to inspect *which* repos
    a repo-list token covers without reading the JSON. An expandable detail
    row would answer the security-review question ("what exactly can this
    token touch?") in one click.

12. **Expiring tokens are invisible until they're dead.** `last_used_at` and
    `expires_at` are displayed, and there's a `stale` badge — good — but
    nothing warns *before* expiry. The notification system (rules, dispatcher)
    already exists; an "expires in 7 days" notification to the owner (or org
    admins for org keys) closes the loop the ADR opened with "the UI surfaces
    last use and warns on stale tokens".

13. **Org tokens live only under personal settings.** The merged list works,
    but an org admin thinking "what tokens can act on my org?" will look in
    the org's settings/admin area, not their personal page. When an org
    settings UI grows an admin section, mirror the org-token list there —
    the endpoints already exist. Related: the list can't answer "which
    *unscoped* legacy tokens can touch my org?" — that's the actual risk
    surface during the migration period, and today it's invisible to admins.

14. **Nudge legacy-token migration.** The amber `unscoped` badge is honest but
    passive. Since `PATCH` can add a scope to an existing key, a "Restrict
    this token…" action on unscoped keys (pre-filled editor, keeps the same
    secret) would actively shrink the unscoped population instead of waiting
    for churn.

15. **Preset drift is untested.** The three UI presets are the product's
    security recommendations, but nothing pins them — a later edit to
    `TokenScopeEditor.vue` could silently make "Read-only agent" grant a
    write. A trivial vitest asserting each preset's permissions (esp.
    `read-only ⇒ no write anywhere, admin ⇒ none`) would lock that in.

16. **Docs gap.** The capability → route mapping exists only as Go source
    (`route_scope.go`). Users building CI integrations or agent scopes need a
    documentation page: capabilities, what read vs write means per surface
    (the vulns-vs-triage split is subtle and is the ADR's best idea), and
    worked examples. Generating the table from `routeScopes` at build time
    would keep it honest.

### Testing

17. The pure-logic coverage is strong (route matrix, scope parsing, expiry,
    origin derivation, audit attribution, partition math — all Postgres-free
    and running). The gaps are all end-to-end: DB-backed handler tests skip in
    this environment, and the new endpoints (create-finding, token
    edit/rotate, org api-keys) plus migrations have never run against real
    Postgres. One CI job with a service container closes all of it at once —
    higher value than any additional unit test at this point.

18. Two micro-nits, not worth churn now: the 90-day `stale` threshold is
    hardcoded client-side (fine, but it'll drift from any future server
    policy), and `TokenScopeEditor` loads the full repo list unpaginated —
    orgs with hundreds of repos will want a search box.

---

## Bottom line

Ship-worthy once `00010` has been rehearsed against a real database. The
deny-by-default table + its exhaustiveness test is the piece to protect as the
codebase grows. The highest-leverage follow-ups, in order: CI job with
Postgres (§17), scoped CLI tokens (§1), capability names in 403s (§2),
edit-token UI (§10), and expiry warnings (§12).

---

## Outcome (2026-08-05, follow-up session)

Every recommendation above was implemented (§5/§13 as backlog entries, per
their own conditional wording; §4 resolved as an in-handler gate with the
resource binding deliberately declined — the endpoint is a stateless verdict
about the caller's own patch). §1 went further than recommended under alpha
rules: the dead CLI-token endpoint was deleted and **scope is now mandatory at
mint everywhere** — no unscoped token can be created at all.

The hard gate was executed for real: Postgres came up in the devcontainer,
migrations `00009`/`00010` round-trip down/up cleanly, and live tests now
cover partition maintenance (including the stray-row move) and the
actor_id-FK regression. Vindication for §17: the first-ever run of the
DB-backed tests caught a latent `ESCAPE '\\'` bug that 500'd every real
search term in the org search paths, plus two born-broken tests. Full
`make lint` + `make test` (with DB) green. See
`TODO-FEAT-fine-grained-api-tokens.md` Phase 8 for the itemized record.

## Caveat rework (same day, carte blanche)

The three caveats above were then reworked:

1. **§13 is now code**: an org **Access** tab lists org-owned tokens
   (rotate/revoke) and the *unscoped-token exposure* — legacy full-access
   tokens owned by org members (`…/api-keys/exposure`, admin-only). The
   "invisible risk surface" this review complained about is visible.
2. **§5 is now a design, not a wish**: ADR-022 (org service principals,
   Proposed) specifies the authorization change; implementation remains
   backlogged because it is a handler-wide sweep.
3. **§17 was reverted by explicit user decision** — CI runners are too small
   for a Postgres side-container right now. The wiring is preserved in the
   `ci.yml` note and `backlog.md`; DB tests run locally before shipping.

Building §13 uncovered a **fourth bug**, the worst of the set:
`api_keys.scopes` was `NOT NULL DEFAULT '[]'`, so the "legacy NULL scope"
model underpinning Phases 2–3 never matched the schema — every real pre-ADR
token parses as malformed ⇒ deny-all, i.e. **upgrading would have bricked all
existing tokens**. Migration `00011` normalizes the legacy array sentinels to
the jsonb `null` document (SQL NULL was tried first and rejected:
`database/sql` cannot scan it into `json.RawMessage`). Rehearsed down/up;
`TestLegacyUnscopedKeySemanticsLive` pins it. Every phase of this exercise —
review, DB rehearsal, and even reworking the review's own caveats — found a
bug that nothing else had.
