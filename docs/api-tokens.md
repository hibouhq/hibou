# API tokens

Hibou API tokens are **fine-grained** ([ADR-020](adr/020-fine-grained-api-tokens.md)):
every token is scoped to one organization, a repository selection, and an
explicit per-capability grant. A token can never do more than the person who
created it — enforcement is the *intersection* of the token's scope and the
creator's own role.

Create tokens in **Settings → API keys**. The secret is shown **once**; only
its hash is stored.

```
hibou_pat_<random(30)><checksum(6)>
```

The `hibou_pat_` prefix makes leaked tokens greppable, and the checksum lets a
scanner validate a candidate without calling the server. Hibou's own secret
scanning detects these tokens natively (rule `hibou-pat`), reporting
checksum-valid matches as *verified*.

## Scope document

```jsonc
{
  "org": "acme",                        // exactly one organization per token
  "repos": { "mode": "all" },           // or { "mode": "list", "slugs": ["api", "web"] }
  "permissions": {
    "coverage":        "read",          // none | read | write
    "vulnerabilities": "read",
    "uploads":         "write"
  }
}
```

- **One org per token.** Cross-org automation uses one token per org.
- **`repos.mode`** — `all` covers every repository, including ones enrolled
  later, and is required for org-wide reads (dashboard, org vulnerabilities,
  global search, compliance exports). `list` restricts the token to named
  repositories.
- **Unlisted capabilities are `none`.** Enforcement is deny-by-default: a
  scoped token is refused on any endpoint whose required capability it does
  not hold, and denials name the missing grant
  (`requires vulnerabilities:write on acme/api`).

## Capabilities

| Capability | `read` | `write` |
|---|---|---|
| `coverage` | Coverage, tests, per-file coverage sources | — |
| `vulnerabilities` | Findings, facets, rules, org dashboard/search¹ | **File new findings** (`POST …/findings`) |
| `triage` | Finding acceptances, VEX statements | **Change the state of existing findings** — accept, dismiss, VEX |
| `quality_gates` | PR gate results, gate definitions¹ | Override a gate; manage gate definitions¹ |
| `components` | SBOM, dependency graphs, component search¹, clients¹ | Trigger component scans; manage clients¹ |
| `secrets` | Secret-scan jobs; the synchronous push-check² | Trigger secret scans |
| `uploads` | Upload status, snapshot files | Submit scan artifacts (`POST /upload`), create releases |
| `admin` | Org settings, members, teams, integrations, audit log¹ | Change them¹ |

¹ Org-level surface: requires `repos.mode: "all"` — a repo-restricted token
can never read or write across the whole organization.
² `POST /secret-scan/check` is deliberately not bound to a repository: it
scans only the patch you submit and stores nothing, so `secrets:read` is the
whole requirement.

**`vulnerabilities:write` vs `triage:write`** is the split that keeps agents
honest: an agent can *file* findings it reasoned about without being able to
*silence* findings someone else raised. Grant both only when you mean both.

### What tokens can never do

Regardless of scope, a token cannot create, edit, rotate, or revoke API keys
(including itself), manage notifications, create or delete organizations, or
enumerate your other organizations. Those are browser-session actions.

## Lifecycle

- **Scope is mandatory.** Unscoped tokens cannot be minted; pre-existing
  unscoped tokens keep working and show an amber *unscoped* badge with a
  **Restrict…** action that applies a scope without changing the secret.
- **Expiry is mandatory and ≤ 1 year.** You get an in-app notification about
  a week before a token expires (org-owned tokens notify every org admin).
- **Rotate keeps the identity.** Rotation issues a new secret under the same
  key id, so scope, audit history, and finding provenance stay attached. The
  old secret stops working immediately.
- **Editing never re-issues the secret.** Name, description, scope, and
  expiry are all editable in place.

## Ownership

- **User-owned** — created and managed by you, dies with your account. Right
  for personal automation.
- **Org-owned** — created by an org admin under
  **Settings → API keys → Owner: Organization-owned**. Any current org admin
  can list, edit, rotate, or revoke it; it survives its creator leaving. Right
  for CI and shared agents. Org-owned tokens are always scoped to their org.

  > Current limitation: an org-owned token still *authorizes* as its creating
  > user. If that account is deprovisioned the token stops working until an
  > admin re-creates it. Managing survives the creator; acting does not yet —
  > [ADR-022](adr/022-org-service-principals.md) (proposed) closes this.

### The org Access tab

Org admins get an **Access** tab on the organization page showing every
org-owned token (with rotate/revoke) and the **unscoped-token exposure**:
legacy full-access tokens owned by org members, each able to act on the org
with its owner's full role. Those tokens can no longer be minted; the list
exists so admins can chase owners to restrict them (or wait them out — expiry
is mandatory on everything new). Visibility only: personal tokens stay managed
by their owners.

## Provenance & audit

Every finding records its **origin**: `scanner` (ingested tool report),
`human` (filed in the UI/API by a person), or `agent` (filed with a token —
recording the token id, name, and owner). The origin is derived from the
authenticated principal and cannot be spoofed, survives token revocation, and
is filterable: `origin:agent` or `agent:<token-id>` in any findings search —
so "revoke the token, review everything it filed" is one query.

Every token-authenticated action is written to the audit log with the
**token** as the actor (`actor_type=api_key`) and the acting human in the
context; token lifecycle events (`token.create/update/rotate/revoke`) record
the acting admin and a scope summary.

## Presets

| Preset | Grants | For |
|---|---|---|
| **Read-only agent** | every surface `read`, nothing `write` | MCP/AI agents that observe your security posture |
| **CI uploader** | `uploads:write`, `quality_gates:read`, `coverage:read` | pipelines that submit artifacts and read the gate verdict |
| **Triage agent** | `vulnerabilities:write`, `triage:write`, `coverage:read`, `components:read` | automation that files and triages findings — no gate override, no admin |

## Examples

CI upload token (org `acme`, only the `api` repo):

```jsonc
{
  "org": "acme",
  "repos": { "mode": "list", "slugs": ["api"] },
  "permissions": { "uploads": "write", "quality_gates": "read" }
}
```

```bash
curl -H "Authorization: Bearer hibou_pat_..." \
  -F file=@sbom.cdx.json \
  https://hibou.example.com/api/v1/upload
```

Read-only MCP agent across the whole org:

```jsonc
{
  "org": "acme",
  "repos": { "mode": "all" },
  "permissions": {
    "coverage": "read", "vulnerabilities": "read",
    "components": "read", "triage": "read", "quality_gates": "read"
  }
}
```

The MCP transport applies the same scope: a read-only token is refused by any
tool that would change state, with the missing grant named in the error.
