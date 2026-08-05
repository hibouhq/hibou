# ADR-022: Organization service principals

## Status

Accepted — implemented (2026-08-05), with simplifications over the proposal
below (alpha, no compat window):

- **No feature flag / per-token `principal` switch** — org-owned keys became
  service principals directly; no org-scoped tokens existed in the wild.
- `api_keys.user_id` is nullable with `ON DELETE SET NULL` (migration
  `00012`); `GetAPIKeyByHash` LEFT JOINs the user; a user-owned key whose
  creator is gone is rejected at auth, an org-owned key keeps working.
- Authentication attaches **no user** for org keys — `TokenAuth` is the
  principal (`IsServicePrincipal`/`ActsForOrg`).
- Authorization centralizes in `Server.principalOrgRole`: a service principal
  acting for its own org resolves to `admin` when its scope grants
  `admin:write`, else a member-equivalent `developer`; empty anywhere else.
  All membership checks (loaders, requireOrgAdmin, uploads, MCP) route
  through it; `hasPrincipal` preserves 401 semantics.
- Attribution stays nil-tolerant everywhere (`accepted_by`, VEX
  `created_by`, gate override `by`, audit actor = the token).
- Casbin is bypassed for service principals (no user subject); their
  authority is org ownership + token scope, both enforced.
Verified live: `TestOrgKeySurvivesCreatorDeletionLive` (delete the creator,
the org key still authenticates), `TestPrincipalOrgRoleServicePrincipal`
(cross-org isolation), migration `00012` down/up rehearsed.

## Context

ADR-020 gave org-owned tokens org-level **management**: any current org admin
can list, edit, rotate, or revoke them, and they survive their creator leaving.
But **authorization** still flows through the creating user: `api_keys.user_id`
is joined at authentication, the request runs as that user, and every handler's
RBAC check (`GetOrgMemberRole(org, user)`) is the intersection partner of the
token scope.

Consequences:

1. **Deprovisioning the creator kills the token.** The user row disappears (or
   loses membership) → `GetAPIKeyByHash`'s join fails or RBAC denies → the CI
   pipeline breaks, precisely the failure org ownership was meant to prevent.
   Management survives; acting does not.
2. **The effective permission depends on who happened to mint it.** An org
   token created by an org admin can do more than the same scope minted by a
   developer, because the RBAC intersection differs. That's surprising for a
   token whose owner is the org.
3. **Audit attribution is subtly wrong**: the request executes as a person who
   may have had nothing to do with it for years.

## Decision (proposed)

Introduce a **service-principal identity** for org-owned tokens: the request's
principal is the token itself, acting *for the organization*, with the token
scope as the sole authority — no user in the loop at request time.

- `api_keys.user_id` becomes nullable and means "created by" only (already
  recorded in the audit trail); a partial index keeps user-owned lookups fast.
- Authentication for `owner_type='org'` attaches a synthetic principal:
  `Principal{Kind: service, OrgID, KeyID, Scope}` instead of a `store.User`.
- Authorization: handlers currently do RBAC-then-scope. For a service
  principal, RBAC is replaced by an org-membership-equivalent check derived
  from the token's org (`scope.Org == resolved org`), and the scope check is
  unchanged. The deny-by-default route guard already binds org/repo from the
  URL, so most of the work is `UserFromContext`-nil-safety in handlers.
- Scope ceiling: since there is no user role to intersect with, the mintable
  scope must be bounded at creation — an org admin can grant at most what org
  admins hold (which today is everything in the org), and edits re-validate.
- Provenance/audit: unchanged shape — the actor is already the token; the
  `acting_user_id` context field becomes optional.

## Consequences

- Org tokens finally match their promise: fully decoupled from any member's
  lifecycle.
- Every handler that assumes `UserFromContext != nil` after `SessionAuth` must
  tolerate a service principal (or the org loader must synthesize the
  membership answer). This is the bulk of the work and the reason this is an
  ADR, not a patch: doing it piecemeal risks a handler that half-trusts a nil
  user.
- The RBAC enforcer (casbin) needs a subject that is not a user id, or a
  bypass path for service principals gated on the route guard.

## Migration

1. Nullable `user_id` + backfill nothing (existing rows keep their creator).
2. Feature-flag the principal switch per token (`principal='user'|'org'`),
   default `user` for existing rows, `org` for newly minted org tokens once
   the handler sweep is done.
3. Delete the flag after one release.

## Amendment: member-requested tokens with admin approval (implemented, 2026-08-05)

Today only org admins can mint org tokens (the scope ceiling is "what org
admins hold", and the create endpoint requires the admin role). Like GitHub's
fine-grained PATs targeting an organization, non-admin members should be able
to **request** an org token; an org admin then reviews the request and
approves or rejects it.

- **Creation**: any org member can create an org-owned token. If the creator
  is not an org admin at creation time, the token is stored with
  `approval_status='pending'` (org-admin creators mint `approved` directly,
  as today). The secret is shown once at creation as usual — the value does
  not change on approval.
- **Not valid until approved**: a pending token **fails authentication**. The
  API returns a distinct error so the caller knows exactly what to do:
  `401 {"error": "token pending approval: ask an org admin to review it in
  Settings → API keys"}`. Same for `rejected` (with "was rejected" wording).
  It must be impossible to confuse this with a bad/revoked credential.
- **Review**: org admins see pending requests in the org token list
  (requester, name, scopes, expiry) and approve or reject; both actions are
  audited (`token.approve` / `token.reject`) with the reviewing admin as
  actor. Approval re-validates the scope ceiling at review time.
- **Edits re-trigger review**: a non-admin widening the scopes of an approved
  token drops it back to `pending` (narrowing or rotating does not).
- Schema: `api_keys.approval_status` enum (`pending|approved|rejected`),
  `approved_by uuid NULL`, `approved_at timestamptz NULL`. Existing rows
  backfill to `approved`.

### Expiry date picker (UI)

Token creation/edit currently offers preset expiry durations only. The form
must additionally let the user pick a **precise expiration date** (calendar
date picker, min = tomorrow, capped by any org max-lifetime policy), sent as
the exact `expires_at` timestamp.

### Implementation notes

- Migration `00014`: `api_key_approval_status` enum, `approval_status`
  (default/backfill `approved`), `approved_by` (SET NULL on user delete),
  `approved_at`. Down deletes non-approved rows so a rollback cannot activate
  a never-approved credential.
- `authenticateBearerToken` (and the MCP transport, which mirrors it) rejects
  pending/rejected keys; `auth.SessionAuth` answers those two errors directly
  with the specific 401 so the generic handler message can't mask them.
- Creation (`POST /orgs/{provider}/{slug}/api-keys`) is open to all org
  members; non-admin creations land `pending`. Approve/reject are
  `POST .../api-keys/{keyID}/{approve|reject}` (admin-only, audited as
  `token.approve`/`token.reject`, scope ceiling re-validated on approve).
- Members can edit keys they created; `apitoken.Scope.Widens` decides whether
  the edit re-triggers review (level raised, repo added, list→all). Narrowing
  keeps the status; admin edits never demote.
- Verified live: `TestOrgTokenApprovalFlow` (pending 401 message through the
  real middleware → approve → authenticates → reject → distinct 401; audit
  rows), `TestOrgTokenWideningResetsApproval`, `TestScopeWidens`; migration
  `00014` down/up rehearsed.

Both items are tracked in `TODO-FEAT-fine-grained-api-tokens.md` (Phase 7).

## Alternatives considered

- **Re-bind `user_id` to another admin on departure** — keeps the current
  model but silently changes what the token can do; rejected.
- **Keep a hidden bot user per org** — a real user row with org membership;
  simple, but reintroduces exactly the "person-shaped automation" problem
  GitHub machine-users have, plus seat/identity noise. Workable fallback if
  the handler sweep proves too invasive.
