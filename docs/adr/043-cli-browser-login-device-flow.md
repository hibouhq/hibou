# ADR-043: CLI browser login — `hibou login <url>` with the OAuth 2.0 device flow

## Status

Accepted and implemented (2026-10-13). Specifies the login flow that
[ADR-042 §3](042-ide-extensions.md) chose for the IDE extensions and makes it
the CLI's default. Mints tokens under the fine-grained token model of
[ADR-020](020-fine-grained-api-tokens.md), which §4 amends: a device-login
token covers every org the user belongs to, like `gh`.

## Context

`hibou login` today asks for two things in the terminal:

```
$ hibou login
Hibou server URL: hibouhq.com
API token: █
```

To answer the second prompt the user must open the web UI, sign in, go to
Settings › API Keys, pick an org, pick permissions, pick an expiry, create the
key, copy it, and paste it back. `hibou login --sso` only opens the settings
page and prints those steps (`cmd/login.go`). Problems:

- **Drop-off.** It is the slowest step of onboarding, and every new laptop,
  devcontainer and Codespace repeats it.
- **Over-scoped, long-lived tokens.** Users facing the scope picker under time
  pressure choose "everything, one year". ADR-020's safe defaults only help if
  the safe token is the easy one.
- **Pasted secrets leak.** Tokens end up in shell history (`--token hb_…`),
  chat messages and notes.
- **The URL prompt is fragile.** `hibouhq.com` (no scheme) is accepted as-is
  and later fails with an unhelpful HTTP error.
- **`hibou logout` only clears the local file.** The token stays valid on the
  server until it expires.

Comparable CLIs (`gh auth login`, `az login --use-device-code`,
`gcloud auth login --no-launch-browser`, `fly auth login`, `tailscale up`)
print a URL and a short code, the user approves in a browser where they are
already signed in, and the CLI receives its credential. This is the "URL-style
connection" this ADR adds.

### Constraints from existing decisions

- **Tokens must be scoped** (ADR-020, `normalizeCreateScope`): one org, a repo
  selection, per-capability permissions, a mandatory expiry ≤ 1 year. A login
  flow cannot mint a full-RBAC token. One org per token does not fit a CLI,
  though: `gh` works in every org the user belongs to once logged in, and a
  hibou user who uploads to several orgs would need one login per org. §4
  amends ADR-020 for this case.
- **Tokens are minted only from a browser session** (`handleCreateAPIKey`
  rejects token auth). The device flow keeps that rule: the approval is a
  session action.
- **Remote environments.** Devcontainers, Codespaces and SSH hosts cannot
  receive a `localhost` redirect from the user's browser. ADR-042 rejected
  loopback-redirect OAuth (RFC 8252) for this reason.
- **Self-hosted, multi-replica servers** (ADR-041 positioning,
  `TODO-ARCH-stateless.md`). Pending login state must live in PostgreSQL, not
  in process memory.

## Decision

### 1. CLI UX

```
$ hibou login hibouhq.com

  One-time code:  WDJB-MJHT

Open https://hibouhq.com/device?user_code=WDJB-MJHT
Press Enter to open it in your browser (Ctrl-C to cancel)…
Waiting for approval in the browser (expires in 10 min)…

✓ Approved: token "CLI — devbox" · all your orgs · preset cli · expires 2027-01-11
Verifying credentials... ok
Logged in to https://hibouhq.com
Config saved to ~/.config/hibou/config.yaml
```

- **The server URL is a positional argument** (`hibou login <url>`), in
  addition to `--server`, `HIBOU_SERVER`, the saved config and the prompt, in
  that order of precedence.
- **URL normalisation**: no scheme → `https://` (`http://` for a loopback host,
  i.e. a local dev server); trailing `/`, query and fragment removed; a path is
  kept (sub-path deployments). `http://` to a non-loopback host still needs
  `--insecure-http`, as before.
  The CLI then calls `GET /api/v1/version` (already
  public) to confirm the URL points at a hibou server before anything else, and
  says so clearly if not.
- **Device flow is the default when the session is interactive** (stdin is a
  TTY) and no token was supplied.
- **The browser is opened only after Enter**, so the user reads the code first.
  `--no-browser` skips that; the CLI also skips it when no opener works
  (SSH, containers) and just prints the URL. The existing `openBrowser` is
  reused.
- **Token paths are unchanged for CI and scripts**: `--token`, `--token-stdin`
  (keeps the token out of shell history), `HIBOU_TOKEN`, and a non-TTY stdin
  keep today's behaviour.
- **`--sso` becomes a deprecated alias** of the browser flow; it also forces
  the flow when stdin is not a terminal.
- **Old servers**: if `POST /api/v1/auth/device/code` returns 404, the CLI
  falls back to today's token prompt and says the server is too old for browser
  login.
- **Preset choice**: `--scope cli` (default) or `--scope read-only`. The user
  can still change it on the approval page; the CLI reports what was granted.

### 2. Protocol: RFC 8628 device authorization grant

Two unauthenticated JSON endpoints, following RFC 8628 field names and error
codes so a standard OAuth client library can drive them:

**`POST /api/v1/auth/device/code`**

```jsonc
// request
{ "client_id": "hibou-cli", "client_name": "devbox", "scope": "cli" }
// 200
{
  "device_code": "<43 chars, 256-bit random>",
  "user_code": "WDJB-MJHT",
  "verification_uri": "https://hibouhq.com/device",
  "verification_uri_complete": "https://hibouhq.com/device?user_code=WDJB-MJHT",
  "expires_in": 600,
  "interval": 5
}
```

- `client_id` is one of a fixed list (`hibou-cli`, `hibou-vscode`,
  `hibou-intellij`), used for display and audit, not as a secret. `client_name`
  is free text (the hostname), truncated to 64 characters and shown escaped.
- `user_code`: 8 characters from the RFC 8628 §6.1 alphabet
  `BCDFGHJKLMNPQRSTVWXZ` (no vowels, no look-alike digits), shown as
  `XXXX-XXXX`; input is case-insensitive and ignores the dash.
- URLs are built from `HIBOU_BASE_URL`, never from request headers, so a
  spoofed `Host` cannot point the user elsewhere.

**`POST /api/v1/auth/device/token`**

```jsonc
// request
{ "grant_type": "urn:ietf:params:oauth:grant-type:device_code", "device_code": "…", "client_id": "hibou-cli" }
// 400 while waiting: { "error": "authorization_pending" | "slow_down" | "access_denied" | "expired_token" }
// 200 once approved
{
  "access_token": "hibou_pat_…",
  "token_type": "Bearer",
  "expires_in": 7776000,
  "token_id": "<uuid>",
  "token_name": "CLI — devbox",
  "orgs": "memberships",
  "preset": "cli",
  "user": "ggjulio"
}
```

- Polling faster than `interval` returns `slow_down` and adds 5 s to that
  request's interval (RFC 8628 §3.5).
- **The raw token is generated at the successful poll**, not at approval, and
  returned exactly once. It is never stored; only its hash goes into
  `api_keys`, as today. The device request is then marked `consumed`, so a
  replayed `device_code` gets `expired_token`.

### 3. Approval page: `/device` (SPA route)

1. Requires a browser session. Without one, the page goes through the normal
   forge sign-in and returns to `/device?user_code=…`. The OAuth callback
   always lands on `/`, so the SPA's router guard remembers the page that
   required sign-in in `sessionStorage` (same tab, survives the forge round
   trip) and resumes it. Only in-app paths are accepted
   (`site/src/lib/returnTo.ts`); the server-side OAuth state is unchanged.
2. Shows the code for the user to **compare with the terminal**, even when it
   came prefilled from `verification_uri_complete`. Approval is always an
   explicit click; nothing is auto-approved.
3. Shows the request details: client (`hibou CLI`), device name, requesting IP
   address, and how long ago it was started, with the warning *"Approve only
   if you started this login yourself in the last few minutes."*
4. The user picks:
   - **Preset**: `cli` or `read-only`, preselected from the request. There is
     no org picker: the token covers the user's memberships (§4). Anyone who
     wants a single-org or custom scope creates one under Settings › API Keys.
   - **Expiry**: 90 days by default, at most one year.
   The page lists the orgs the token will reach today, and marks those whose
   policy restricts or blocks login tokens (§4).
5. **Approve** calls `POST /api/v1/auth/device/approve`; **Deny** calls
   `POST /api/v1/auth/device/deny`. Both are session-only (token auth gets
   403, as for key management) and use the existing session CSRF protection.
6. The page cannot be framed: every SPA response already carries
   `Content-Security-Policy: frame-ancestors 'none'` and `X-Frame-Options: DENY`.

**Presets**

| Preset | Permissions | Use |
|---|---|---|
| `cli` | `uploads:write`, `secrets:read`, `vulnerabilities:read`, `coverage:read`, `components:read`, `quality_gates:read`, everything else `none`; repos `all` | `hibou upload`, `scan`, `analyze`, `release`, `gate`, `secret-scan`, `repos`, `status` |
| `read-only` | ADR-020 "read-only agent" preset | IDE extensions (ADR-042 phase 1), MCP, browsing |

The minted token is **user-owned**, named `CLI — <device name>` (or
`IDE — <editor> on <device name>`), with a description recording the client,
requesting IP and approval time. It is listed, editable and revocable under
Settings › API Keys like any other token. User-owned tokens need no org-admin
approval (that rule applies to org-owned tokens only), so the flow never
leaves the user waiting on someone else.

### 4. Amendment to ADR-020: membership-wide login tokens

ADR-020 binds every token to one org. A device-login token instead carries:

```jsonc
{
  "owner": { "type": "user", "id": "<uuid>" },
  "orgs": { "mode": "memberships" },   // replaces "org"
  "repos": { "mode": "all" },
  "permissions": { "uploads": "write", "vulnerabilities": "read", … }
}
```

- **Only user-owned tokens** can use `orgs.mode = memberships`, and **only the
  device flow mints them**. `POST /users/me/api-keys` and the org key
  endpoints keep requiring a single `org`; an org-owned token is always
  single-org.
- **The scope check accepts any org; RBAC decides.** Effective access in an org
  is the intersection of the preset and the user's role there *at request
  time*. A user removed from an org loses that org at once; one who joins a new
  org gets it without logging in again. Org-less routes that carry the org in
  the body (`POST /upload`) already re-check the role in the handler.
- `repos` is always `all`, so repository visibility comes from the user's role
  and forge grants, as for a browser session.
- **Org policy: "CLI and IDE login tokens"**, an org setting with three
  values, enforced wherever a membership-wide token resolves the user's role in
  an org (`principalOrgRole`, and the MCP server's org resolution):

  | Value | Effect in this org |
  |---|---|
  | `allow` (default) | Role as stored |
  | `read_only` | Role capped at `viewer`: writes are refused |
  | `deny` | No role: the org answers 404, as for a non-member |

  This is GitHub's "OAuth app access restrictions". It does not affect
  single-org tokens, which the org already governs through ADR-020.

### 5. Storage

New table `device_authorizations`:

| Column | Notes |
|---|---|
| `id` | uuid |
| `device_code_hash` | SHA-256, unique |
| `user_code_hash` | SHA-256 of the normalised code, unique among live rows |
| `client_id`, `client_name`, `requested_preset` | from the request |
| `requester_ip`, `requester_user_agent` | for the approval page and audit |
| `status` | `pending` → `approved` / `denied`; `approved` → `consumed`. Expiry is `expires_at`, not a status |
| `poll_interval_seconds`, `last_polled_at` | `slow_down` bookkeeping (RFC 8628 §3.5) |
| `approved_by`, `approved_preset`, `token_expires_at`, `decided_at` | set at approval or denial; the scope is rebuilt from the preset at mint time |
| `api_key_id` | set when the token is minted |
| `created_at`, `expires_at` | `expires_at` = created + 10 min; approval extends it to at least now + 2 min so a last-second approval can still be collected |

Rows an hour past `expires_at` are deleted every 15 minutes by the
`device_auth_cleanup` background loop (leader-locked, listed with the other
loops, [ADR-025](025-instance-jobs-observability.md)). Codes are compared by
hash, so a database read does not reveal a live `device_code` (a user code is
short enough to brute-force from its hash, but it is useless without the
matching device code and expires in minutes).

Token minting moves out of `handleCreateAPIKey` into a shared function used by
both the settings page and the device flow, so validation
(`normalizeCreateScope`, `validateScopedExpiry`) and the `token.create` audit
entry are identical.

### 6. Logout revokes

`hibou logout` calls a new `DELETE /api/v1/users/me/api-keys/current`, which
lets a user-owned token revoke **itself and nothing else**. It is the only
key-management action allowed with token auth. If the call fails (server
unreachable, token already expired) the CLI still clears the local config and
prints a warning with the Settings › API Keys URL. `--keep-token` clears only
the local copy.

Re-running `hibou login` against the same server revokes the previously saved
token the same way after the new one is verified, so repeated logins do not
pile up live tokens.

Both only apply to a token that browser login created: `cliconfig` records its
`token_id`. A token the user pasted may also be used by CI or another machine,
so it is cleared locally and never revoked; logout says so and links to
Settings › API Keys.

### 7. Abuse controls and audit

- **Rate limits** (whenever `rate_limit.enabled`): 10 code requests per minute
  per client IP, on top of the `/auth/*` bucket; polling bounded by `interval`
  / `slow_down`; lookup, approve and deny limited to 10 per minute per
  signed-in user, then 429. With 20⁸ ≈ 2.6 × 10¹⁰ codes and a 10-minute
  lifetime, guessing a live code is not practical.
- **At most 10 pending requests per IP**; a new one beyond that is refused
  (10, not fewer, because a team behind one NAT shares an address).
- **Audit actions**: `device.approve`, `device.deny`, plus the existing
  `token.create` with `{via: "device_flow", client_id, client_name,
  requester_ip, preset}` and `token.revoke` (`via: "self"`) for logout. An
  unapproved code request is not audited: it is unauthenticated, so auditing it
  would let anyone write into the audit log. It is in the request log.
- **`docs/THREAT-MODEL.md`** gains a "Device Login Flow" data flow and the
  STRIDE entries below.

| Threat | Mitigation |
|---|---|
| **Device-code phishing**: an attacker starts a flow and sends the victim the approval link | Approval page shows the requester IP, device name and age and warns explicitly; 10-minute lifetime; resulting token is preset-scoped, capped by the victim's role per org, user-owned, revocable and audited; orgs can cap or block login tokens (§4); no auto-approve |
| Brute-forcing user codes | Code space and lifetime above, per-session lookup limit |
| Replay of a `device_code` | One successful exchange, then `consumed` |
| Token leaked in terminal scrollback or logs | Token never printed; written only to the config file (`0600`, as today) |
| Host-header poisoning of `verification_uri` | URLs built from `HIBOU_BASE_URL` only |
| Clickjacking the approve button | `frame-ancestors 'none'` on `/device` |

### Non-goals

- **Loopback-redirect login** (RFC 8252). Rejected in ADR-042 because it fails
  in remote environments. It could be added later as an optimisation; the
  device flow stays the baseline.
- **OAuth refresh tokens.** The result is an ordinary ADR-020 token with an
  expiry. When it expires the user runs `hibou login` again.
- **OS keychain storage.** The CLI keeps writing `cliconfig` as today. Keychain
  support is a separate change; the IDE clients use their own secret stores
  (ADR-042).
- **Org-owned tokens for CI.** CI keeps using org-owned tokens created in the
  UI. A device-approved token belongs to a person and dies with the account.

## Consequences

- **Positive**
  - Login is one command, one click, no copy-paste, and works in SSH,
    devcontainers and Codespaces.
  - The default token is narrow (`cli` preset, 90 days) because the safe
    choice is the preselected one.
  - Tokens are never typed or pasted, so they stay out of shell history and
    chat.
  - Logout actually revokes, and re-login replaces rather than accumulates.
  - The same endpoints serve the IDE extensions (ADR-042), so they are built
    once.
- **Negative**
  - New unauthenticated endpoints and a new approval page to secure, test and
    rate-limit.
  - A new table and cleanup job.
  - Device-code phishing cannot be eliminated by design, only made visible and
    limited in blast radius.
  - Token self-revocation is the first key-management action allowed with
    token auth; it must stay limited to the calling token.

## Alternatives considered

| Alternative | Why not |
|---|---|
| **Keep paste-a-token, improve the instructions** | Leaves every problem in Context in place. |
| **Loopback redirect** (`http://127.0.0.1:<port>/callback`) | Fails when the browser and the CLI are on different machines (SSH, devcontainers, Codespaces), which is common for this audience. |
| **Mint the token at approval and hold it until the poll** | Stores a raw token, even briefly and encrypted. Minting at the poll avoids that at no cost. |
| **Log in with the forge's token** (`gh auth token`, GitLab PAT) | Couples hibou auth to one forge, gives hibou a forge credential it must not keep, and breaks for instances with several forges. |
| **One single-org token per org** (approval page with an org multi-select, `cliconfig` keyed by org) | Logins multiply with orgs, a new org needs a new login, and the CLI must guess which token a repo needs. A membership-wide token with a per-org policy gives the same control with one credential. |
| **Full-RBAC session token for the CLI** | Violates ADR-020 (every token is scoped) and recreates the over-privileged token the ADR removed. |
| **Server-sent events instead of polling** | Polling every 5 s for at most 10 minutes is negligible load, survives proxies that buffer streams, and is what RFC 8628 clients expect. |

## Success criteria

- From `hibou login <url>` to a verified, saved token in under 30 seconds for
  a user already signed in to the web UI, with no manual token creation.
- Works unchanged from a local terminal, an SSH session and a devcontainer.
- `hibou logout` makes the token fail authentication on the next request.
- No raw token appears in the database, server logs or audit entries.
- `hibou login --token …`, `HIBOU_TOKEN` and non-TTY usage behave exactly as
  before.

## Resolved questions

1. **`cli` preset contents.** Checked against the routes each subcommand calls:
   `secret-scan` needs `secrets:read` (`POST /secret-scan/check`), so the preset
   includes it. Nothing needs `vulnerabilities:write` or `triage`.
2. **Multi-org users.** Membership-wide token (§4).
3. **Admin controls.** Per-org policy `allow` / `read_only` / `deny` (§4).
4. **Default expiry.** 90 days for both presets.

## Security hardening (2026-10-13)

A security review after the first implementation tightened the flow. The wire
API of `/auth/device/code` and `/auth/device/token` is unchanged.

- **No one-click approval from a link.** `/device?user_code=…` no longer looks
  the code up. The user types the code their own device shows, and it must
  match the link; the page states *"Only approve if you started this sign-in
  yourself on this device."* The device name is labelled as reported by the
  device (unverified), and the requester IP as best effort. This supersedes §3
  item 2.
- **Presets can only go down.** The page offers the requested preset and lower
  ones (`read-only` < `cli`); approve refuses a higher preset with 400. The page
  preselects `read-only` unless the request came from `hibou-cli`. IDE clients
  still default to `read-only`.
- **Key cap at mint time.** The per-user API key cap is re-checked inside the
  transaction that mints the key, under a per-user advisory lock. Over the cap,
  the request is spent and the poll gets `access_denied`.
- **User-code guessing.** Failed lookups, approvals and denials are limited per
  client IP (30 per minute) and globally (300 per minute, per replica), then
  429 with `Retry-After` until the window ends. This limit is always on,
  whatever `rate_limit.enabled` says (supersedes the brute-force row of §7).
- **Org-owned tokens** refuse an `orgs` selector: membership-wide scopes are for
  personal login tokens only.
- **Not done: session recency.** Approving does not yet require a recently
  issued session. The session cookie carries its issue time, but `internal/auth`
  does not expose it; adding an accessor there is the follow-up.
