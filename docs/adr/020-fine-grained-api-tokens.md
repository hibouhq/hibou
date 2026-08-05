# ADR-020: Fine-grained API tokens

## Status

Accepted — implemented (2026-08). Token format, scope model, deny-by-default
enforcement (HTTP + MCP), finding provenance, audit, partitioned audit
retention, and the token-management UI (user- and org-owned) are all in place.

## Context

API keys today are a single coarse capability. [`api_keys`](../../internal/store/migrations/00001_initial_schema.up.sql)
stores `user_id`, `name`, a SHA-256 `key_hash`, a `scopes` JSON column, and
`expires_at`. The auth middleware ([auth/middleware.go](../../internal/auth/middleware.go))
resolves a key to its owning **user** and hands the request that user's full
identity — the `scopes` column is written but never read. Consequences:

- A token minted for one job (a CI runner that only uploads coverage) can do
  **everything its owner can**: read every org and repo the user belongs to,
  triage findings, override gates, mint more keys.
- Blast radius of a leaked token = the owner's entire account. There is no way
  to scope a token to one repository or to read-only.
- Nothing distinguishes a Hibou token in logs, git history, or third-party
  secret scanners — it is opaque random bytes with no prefix.

GitHub solved the same problem with **fine-grained personal access tokens**:
choose a resource owner, select specific repositories, grant per-capability
read/write permissions, and set a mandatory expiry. We adopt that model.

### Agentic / MCP consumers make this urgent

Hibou already exposes an MCP server ([mcp/server.go](../../internal/mcp/server.go))
that authenticates with these same API keys. Handing a key to an AI agent today
grants it the owner's **entire account** — read and write, every org and repo.
The safe primitive an agent needs is the opposite: a **read-only, narrowly
scoped** token (often one org, sometimes one repo) that can *observe* coverage,
findings, and components but cannot triage, override gates, or mint keys. This
is not a secondary nicety; it is the difference between "an agent can look at my
security posture" and "an agent can silently accept every finding." The scope
model below must therefore make a read-only agent token trivial to express and
impossible to escalate.

## Decision

Tokens carry an explicit, enforced scope. A token can never exceed its owner's
own RBAC — the effective permission is the **intersection** of the token scope
and the user's role.

### Token format

```
hibou_pat_<base62-random(32)><checksum(6)>
```

- Identifiable `hibou_pat_` prefix so the token is greppable and recognizable by
  secret scanners (ours and third parties), enabling leak detection.
- A short checksum suffix lets a scanner validate shape without a server call.
- Storage is unchanged: only the SHA-256 hash is persisted; the raw token is
  shown **once** at creation.

### Token metadata

Every token carries a **required name** and an **optional description**. The name
is the human handle used everywhere it is listed ("prod-ci-uploader"); the
description captures intent for the next person ("uploads coverage from the
release pipeline — owned by the platform team"). `name` already exists on
[`api_keys`](../../internal/store/migrations/00001_initial_schema.up.sql); a
`description` column is added. Both are editable after creation without
re-issuing the token.

### Scope model

The existing `scopes` column becomes a structured, versioned document:

```jsonc
{
  "org": "acme",                       // required: single resource owner
  "repos": { "mode": "all" },          // or { "mode": "list", "slugs": ["api", "web"] }
  "permissions": {
    "coverage":        "read",         // none | read | write
    "vulnerabilities": "read",         // write = create findings
    "triage":          "none",         // write = change state of existing findings (accept/dismiss/VEX)
    "quality_gates":   "none",         // write = override a gate
    "components":      "read",
    "secrets":         "none",
    "uploads":         "write",
    "admin":           "none"          // manage keys, org settings
  }
}
```

- **Resource selection** — one org per token, repos either all or an explicit
  allowlist. Cross-org access requires separate tokens (matches GitHub).
- **Permissions** — per capability, one of `none` / `read` / `write`. Capability
  set maps to the product surfaces, not to routes, so it stays stable as the API
  grows.

### Ownership: user-owned vs org-owned

A token that belongs to a person is a liability for shared automation: when they
change company and their account is deprovisioned, the CI pipeline, the deployed
agent, and the integration all break at once — and no teammate could rotate the
token even if they wanted to, because it was never theirs to manage. GitHub
solves this by letting an **organization own** the token.

A token therefore has an **owner** that is either a user or an org:

```jsonc
{ "owner": { "type": "org",  "id": "acme" } }   // or { "type": "user", "id": "<uuid>" }
```

- **User-owned** — created and managed by that user, dies with the account.
  Right for a person's own automation and interactive use.
- **Org-owned** — created by an org admin but **owned by the org**. It survives
  any member's departure and is listable, rotatable, and revocable by **any org
  admin**, not just its creator. Right for CI, deployed agents, and shared
  integrations.

The acting admin is recorded at each mint/rotate so there is always a human in
the audit trail, but authority to manage the token is the org role, not the
individual.

### Enforcement

A new authorization step runs after key resolution and before the handler:

1. Middleware resolves the key to `(user, tokenScope)`.
2. The route declares the capability + access level it needs (e.g.
   `uploads:write`, `vulnerabilities:read`) and the target org/repo from the
   path.
3. The request is allowed only if **both** the token scope grants it **and** the
   user's RBAC grants it. Denials return `403` with which permission was missing.

Session-cookie auth (browser) is unaffected — it continues to use the user's
full RBAC with no token scope.

### Finding provenance

`vulnerabilities:write` is the power to **create** findings; `triage:write` is the
separate power to **change the state** of existing ones (accept, dismiss,
false-positive, VEX). Splitting them lets an agent file findings it reasoned
about without also being able to silence findings someone else raised — e.g.
`vulnerabilities:write` + `triage:none`. Created findings must never be
indistinguishable from scanner output or from each other, so every finding
records its **origin**:

- `scanner:<tool>` — produced by an ingested tool report (today's default).
- `human:<user_id>` — added manually through the UI/API by a person.
- `agent:<token_id> (owner: <user_id|org>)` — created by an API token acting for
  an agent. The token's **owner** is recorded alongside the token, so there is
  always an accountable human (or org) behind the agent, not just an opaque
  token. For an org-owned token the creating admin is on record too (from mint).

The origin is derived from the authenticated principal at creation time (session
user vs API token) — the caller cannot spoof it. The UI badges human- and
agent-created findings distinctly from scanner findings and shows the agent's
owner ("filed by agent `release-bot`, owned by j.gonzalez"), and the token id
makes an agent's findings filterable and revocable as a set (revoke the token,
flag its findings for review). This keeps automated triage auditable: you can
always ask "which findings did this agent create or accept, and on whose
authority."

### Read-only agent tokens (MCP)

An agent token is just a scope whose every permission is `none` or `read` —
no special token type. The MCP transport resolves the token to the same
`(user, tokenScope)` and applies the same authorization check, so an MCP tool
that would write (accept a finding, override a gate) is refused for a read-only
token exactly as the REST API refuses it. A "read-only agent" preset in the
creation UI sets every capability to at most `read` and defaults to a short
expiry, making the safe token the easy one to mint. Because enforcement is the
intersection with the owner's RBAC, an agent token can never see or do more than
the human who created it.

### Lifecycle

- **Expiry is mandatory** (bounded, e.g. ≤ 1 year); no non-expiring tokens.
- `last_used_at` continues to be tracked; the UI surfaces last use and warns on
  stale tokens.

### Audit

Everything a token touches is auditable — no silent automation.

- **Token lifecycle** is logged: create/mint, scope edit, name/description edit,
  rotate, and revoke, each with the acting principal (the human admin, even for
  org-owned tokens) and the target token.
- **Every action performed with a token** is written to the audit log with the
  **token id and its owner** as the actor, not an anonymous "api key" — so a
  finding created, a finding triaged, a gate overridden, or an upload made via a
  token is traceable to that token and the human/org behind it. `audit.ActorAPIKey`
  already exists; entries carry the token id and owner alongside it.
- This is the write-side twin of finding provenance: provenance answers "where
  did this record come from", the audit log answers "what did this token do,
  when, and on whose authority".

### Audit storage & sustainability

Audit lives in the Postgres `audit_logs` table
([schema](../../internal/store/migrations/00001_initial_schema.up.sql)) — an
**append-only** log of narrow rows: a few UUIDs, short text (`actor_type`,
`action`, `resource_type/id`, ip, user-agent), a small `jsonb` context, and a
`created_at`. On the order of a few hundred bytes per row. It is already indexed
for the read paths (org, actor, action, resource) **and carries a BRIN index on
`created_at`** — a tiny, append-friendly index that keeps time-range and
pagination scans cheap no matter how large the table gets. So the per-event cost
is low and the query cost stays flat; the write path is not the concern.

The concern is **unbounded growth**: there is no retention on `audit_logs` today,
and this ADR *increases* write volume (every token action, not just human
clicks). At, say, 10k events/day that is ~3.6M rows/year — Postgres handles tens
of millions of narrow rows comfortably, so this is fine for a long while, but not
forever. To keep it sustainable we reuse the tiered-retention pattern already
built for snapshots (ADR-014):

- **Range-partition `audit_logs` by month.** Expiring an old window becomes a
  `DROP PARTITION` (O(1), no bloat) instead of a large `DELETE` + vacuum.
- **Configurable hot-retention window** (keep N months queryable), with
  **optional cold archival** to the object store / a compliance export before
  the partition is dropped — so regulated tenants retain years cheaply without
  paying for it in the hot table.
- BRIN + monthly partitions keep both writes and range queries cheap at scale.

This is a follow-up to the token work, not a blocker: the log is sustainable at
current and near-term volumes as-is; partitioning + retention is the lever we
pull before it would ever become a problem.

### UX

Token management is a first-class settings surface, split into **personal** and
**organization** tokens (the latter visible to org admins).

**List view** — one row per token, columns:

| Name | Owner | Scope summary | Last used | Expires | Created by |
|---|---|---|---|---|---|
| `prod-ci-uploader` | acme (org) | 2 repos · uploads:write | 3 min ago | in 89 days | j.gonzalez |

- **Last used** is surfaced prominently (relative time, exact on hover) from the
  already-tracked `last_used_at`; "never used" is called out so dead tokens are
  obvious. Rows that are stale (unused > N days) or **expiring soon** get a
  subtle warning affordance so cleanup is easy.
- The scope summary is a compact, readable digest (repo count + granted
  capabilities), expandable to the full permission list.
- Sort/filter by owner (personal vs each org), last used, and expiry.

**Create flow** — mirrors GitHub's fine-grained PAT screen, top to bottom:

1. **Name** (required) and **description** (optional).
2. **Resource owner** — yourself or an org you administer.
3. **Repository access** — `All repositories` or `Only select repositories` with
   a searchable multi-select of the org's repos.
4. **Permissions** — a searchable list of every capability, each with an
   access-level selector so you grant exactly the ones you want (one or many):

   | Permission | Access |
   |---|---|
   | Coverage | No access ▾ / **Read** / Read & write |
   | Vulnerabilities | No access ▾ / **Read** / Read & write (create findings) |
   | Triage | **No access** ▾ / Read / Read & write (accept/dismiss/VEX on existing) |
   | Quality gates | **No access** ▾ / Read / Read & write (override) |
   | Components / SBOM | No access ▾ / **Read** / Read & write |
   | Secrets | **No access** ▾ / Read / Read & write |
   | Uploads | No access ▾ / Read / **Read & write** |
   | Admin | **No access** ▾ / Read / Read & write |

   Default is `No access` for every row (opt-in, never opt-out). A live summary
   counts what's granted ("4 permissions · 2 read, 1 write"). Presets seed the
   grid in one click — **Read-only agent** (every row ≤ Read), **CI uploader**
   (Uploads: write, Coverage: read) — and remain fully editable afterward.
5. **Expiry** (required, bounded).

On submit the raw token is shown **once** with a copy button and a "store it
now — you won't see it again" warning.

**Detail / manage** — edit name and description, view the exact scope, see full
usage (last used, created, expires), **rotate** (issue a new secret, same scope,
short overlap window), and **revoke**. For org-owned tokens every one of these
is available to any org admin, not just the creator.

### Clean cut (alpha)

Hibou is pre-1.0, so there is no legacy tier and no grandfathering. The scoped
model is the **only** model: the change drops any existing alpha keys and the
enforced scope becomes mandatory on every token from day one. No `version: 0`
fallback, no "full access as the owner" compatibility path — one code path, one
shape. Anyone with an old key re-issues a scoped one.

## Consequences

- Least-privilege is the default and the only option; a leaked CI token no longer
  implies full account compromise.
- Route handlers must declare their required capability — a one-time annotation
  pass, enforced centrally so it cannot be forgotten silently (routes without a
  declaration deny token auth by default).
- The prefix makes tokens detectable by our own secret scanner, closing the loop
  with ADR-010.
- Agentic access becomes safe by construction: a read-only MCP token is a normal
  scope, enforced on the same path as everything else, so there is no separate
  "agent auth" surface to get wrong.

## Alternatives considered

- **Keep coarse keys, document the risk.** Rejected: the risk is the point.
- **OAuth apps / installation tokens for machine access.** Heavier to operate
  for the CI-token use case; fine-grained PATs cover it with far less ceremony.
  OAuth remains the path for third-party apps, not user-minted automation.
- **Route-list scopes (like classic PAT scopes).** Rejected: brittle as the API
  changes; capability-based scopes are stable and readable.
